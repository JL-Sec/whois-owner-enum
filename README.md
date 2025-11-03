# whois-owner-enum.sh

Designed for external infrastructure pentests where you want to quickly validate ownership of multiple IPs.

A fast, parallel WHOIS lookup tool to extract IP ownership details from multiple targets. It extracts the **IP range**, **owner name**, and **organization info** from WHOIS results.

---

### 🧩 Features
- Handles multi-block WHOIS results (picks the most specific range)
- Runs multiple lookups in parallel
- Exports results to a clean CSV:

---

### ⚙️ Usage

```bash
./whois_owner_enum.sh -i targets.txt -o owners.csv -t 8 

Option	Description	Default
-i	Input file (one IP/host per line)	required
-o	Output CSV file	owners.csv
-t	Threads (parallel lookups)	4
-w	Timeout per WHOIS query (seconds)
