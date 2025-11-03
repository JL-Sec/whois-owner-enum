#!/usr/bin/env bash
# whois_owner_enum.sh
# Extract inetnum/NetRange, netname, and descr from whois output for targets and export CSV.
# Handles multiple WHOIS blocks by selecting the block that contains the queried IP (most specific).

set -euo pipefail
IFS=$'\n\t'

INPUT=""
OUTPUT="owners.csv"
THREADS=4
TIMEOUT_SEC=100

usage(){
  cat <<EOF
Usage: $0 -i input_file [-o output.csv] [-t threads] [-w whois_timeout]

 -i  Input file (one IP/hostname per line)
 -o  Output CSV (default: owners.csv)
 -t  Concurrent workers (default: ${THREADS})
 -w  whois timeout per query in seconds (default: ${TIMEOUT_SEC})

Dependencies: whois, timeout (coreutils), xargs, grep, sed, awk, nl, tr
EOF
  exit 1
}

while getopts ":i:o:t:w:" opt; do
  case ${opt} in
    i) INPUT=${OPTARG} ;;
    o) OUTPUT=${OPTARG} ;;
    t) THREADS=${OPTARG} ;;
    w) TIMEOUT_SEC=${OPTARG} ;;
    *) usage ;;
  esac
done

if [[ -z "${INPUT}" || ! -f "${INPUT}" ]]; then
  echo "Input file required and must exist." >&2
  usage
fi

# Count total (skip comments & blanks)
TOTAL=$(grep -v '^\s*$' "${INPUT}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -v '^#' | wc -l)
if [[ "${TOTAL}" -eq 0 ]]; then
  echo "No targets found in ${INPUT}" >&2
  exit 1
fi

# CSV header (updated as requested)
printf '%s\n' "ip,net_range,owner,description" > "${OUTPUT}"

# CSV escape helper
csv_escape() {
  local v="$1"
  v="${v//\"/\"\"}"     # double-up quotes
  printf '%s' "\"${v}\""
}

# convert dotted IPv4 to integer (works for IPv4 only)
ip2int() {
  local ip="$1"
  awk -F. '{print ($1 * 256 * 256 * 256) + ($2 * 256 * 256) + ($3 * 256) + $4}' <<< "${ip}"
}

# process single target (args: target index total)
process_target() {
  local target="$1"
  local idx="$2"
  local total="$3"

  printf '[%s/%s] %s START %s\n' "${idx}" "${total}" "${target}" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" >&2

  local raw
  raw=$(timeout "${TIMEOUT_SEC}s" whois "${target}" 2>&1 || true)

  # Convert target to integer if IPv4, otherwise no-range matching will be possible
  local target_is_ipv4=0
  local target_int=0
  if [[ "${target}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    target_is_ipv4=1
    target_int=$(ip2int "${target}")
  fi

  # Split raw into blank-line separated blocks using awk (RS="") and iterate
  local best_block=""
  local best_block_size=""
  local fallback_block=""   # first block with NetRange/inetnum (if we find none matching IP)

  while IFS= read -r -d '' block; do
    block="${block//$'\r'/}"

    local rng_line
    rng_line=$(awk 'BEGIN{IGNORECASE=1} /^(NetRange|inetnum)[[:space:]]*:/ {print; exit}' <<<"${block}" || true)

    if [[ -z "${rng_line}" ]]; then
      continue
    fi

    if [[ -z "${fallback_block}" ]]; then
      fallback_block="${block}"
    fi

    local start_ip end_ip
    if awk 'BEGIN{IGNORECASE=1} { if(match($0, /([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[[:space:]]*-[[:space:]]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/,m)) { print m[1] " " m[2]; exit } }' <<<"${rng_line}" >/dev/null 2>&1; then
      read -r start_ip end_ip < <(awk 'BEGIN{IGNORECASE=1} { if(match($0, /([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[[:space:]]*-[[:space:]]*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/,m)) { print m[1] " " m[2]; exit } }' <<<"${rng_line}")
    else
      start_ip="" ; end_ip=""
    fi

    if [[ -n "${start_ip}" && -n "${end_ip}" && "${target_is_ipv4}" -eq 1 ]]; then
      local s_int e_int
      s_int=$(ip2int "${start_ip}")
      e_int=$(ip2int "${end_ip}")

      if (( s_int > e_int )); then
        local tmp=${s_int}; s_int=${e_int}; e_int=${tmp}
      fi

      if (( target_int >= s_int && target_int <= e_int )); then
        local size=$(( e_int - s_int ))
        if [[ -z "${best_block}" || "${size}" -lt "${best_block_size}" ]]; then
          best_block="${block}"
          best_block_size="${size}"
        fi
      fi
    fi
  done < <(awk 'BEGIN{RS=""; ORS="\0"} {gsub(/\r/,""); print $0}' <<< "${raw}")

  local chosen_block="${best_block}"
  if [[ -z "${chosen_block}" ]]; then
    chosen_block="${fallback_block:-${raw}}"
  fi

  # now extract inetnum/NetRange/netname/descr from chosen_block
  local inetnum
  inetnum=$(awk 'BEGIN{IGNORECASE=1} 
    /^NetRange[[:space:]]*:/ { sub(/^[^:]*:[[:space:]]*/, ""); print; exit }
    /^inetnum[[:space:]]*:/ { sub(/^[^:]*:[[:space:]]*/, ""); print; exit }' <<< "${chosen_block}" | tr -d '\r' || true)

  local netname
  netname=$(awk 'BEGIN{IGNORECASE=1} 
    /^NetName[[:space:]]*:/ { sub(/^[^:]*:[[:space:]]*/, ""); print; exit }
    /^netname[[:space:]]*:/ { sub(/^[^:]*:[[:space:]]*/, ""); print; exit }' <<< "${chosen_block}" | tr -d '\r' || true)

  # descr: collect from chosen block ONLY
  local descr
  descr=$(awk 'BEGIN{IGNORECASE=1}
    /^descr[[:space:]]*:/ { sub(/^[^:]*:[[:space:]]*/, ""); lines[++n]=$0 }
    /^Description[[:space:]]*:/ { sub(/^[^:]*:[[:space:]]*/, ""); lines[++n]=$0 }
    /^OrgName[[:space:]]*:/ { sub(/^[^:]*:[[:space:]]*/, ""); lines[++n]=$0 }
    END {
      for(i=1;i<=n;i++){ if(i>1) printf " | "; printf "%s", lines[i] }
    }' <<< "${chosen_block}" | tr -d '\r' || true)

  # Fallbacks: if chosen block lacked some fields, fall back to first occurrences in entire raw
  if [[ -z "${inetnum}" ]]; then
    inetnum=$(printf '%s' "${raw}" | grep -iE '^(inetnum|NetRange)[[:space:]]*:' | head -n1 | sed -E 's/^[^:]*:[[:space:]]*//I' | tr -d '\r' || true)
  fi
  if [[ -z "${netname}" ]]; then
    netname=$(printf '%s' "${raw}" | grep -iE '^(netname|NetName)[[:space:]]*:' | head -n1 | sed -E 's/^[^:]*:[[:space:]]*//I' | tr -d '\r' || true)
  fi
  if [[ -z "${descr}" ]]; then
    descr=$(printf '%s' "${raw}" | grep -iE '^(descr|OrgName|Description)[[:space:]]*:' | sed -E 's/^[^:]*:[[:space:]]*//I' | awk '{printf "%s | ", $0} END { if (NR==0) printf "" }' | sed 's/ | $//' | tr -d '\r' || true)
  fi

  # Build CSV row (columns: ip,net_range,owner,description)
  local row
  row="$(csv_escape "${target}"),$(csv_escape "${inetnum}"),$(csv_escape "${netname}"),$(csv_escape "${descr}")"
  printf '%s\n' "${row}" >> "${OUTPUT}"

  printf '[%s/%s] %s DONE  %s\n' "${idx}" "${total}" "${target}" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" >&2
}

export -f process_target
export OUTPUT TIMEOUT_SEC
export -f csv_escape
export -f ip2int

# Prepare numbered list (index target), skip blanks/comments
tmpfile=$(mktemp)
grep -v '^\s*$' "${INPUT}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -v '^#' | nl -ba -w1 -s' ' > "${tmpfile}"

# Run with xargs: each line has "<idx> <target>" -> use -n2 to pass both
# NOTE: "$2" is the target and "$1" is the index inside the bash -c wrapper
cat "${tmpfile}" | xargs -n2 -P "${THREADS}" bash -c 'process_target "$2" "$1" '"${TOTAL}"' ' _

rm -f "${tmpfile}"

echo "Done. Results written to ${OUTPUT}" >&2
