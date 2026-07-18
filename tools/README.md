# Tools / Dev Helpers

These scripts are utility helpers for setting up and verifying a local DVWA instance before running the main scanner. They are **not** part of the core scanner.

| Script | Purpose |
|--------|---------|
| `get_cookies.py` | Logs into DVWA and saves the session cookie to `cookies.txt` |
| `set_security.py` | Sets DVWA security level to Low and refreshes `cookies.txt` |
| `find_path.py` | Probes common DVWA URL paths to find the correct SQLi endpoint |
| `diagnostic.py` | Runs 3 manual test probes against DVWA and prints raw responses |
| `manual_test.py` | Quick GET-based sanity check — normal request vs single-quote injection |
| `test_dvwa.py` | Tests normal vs boolean-injection response side by side |

## Typical workflow

```bash
# 1. Get your session cookie
python tools/get_cookies.py

# 2. Confirm the DVWA path
python tools/find_path.py

# 3. Run the main scanner
python scanner.py \
  --url "http://localhost/vulnerabilities/sqli/" \
  --data "id=1&Submit=Submit" \
  --cookie "PHPSESSID=<value>; security=low" \
  --log results.log
```
