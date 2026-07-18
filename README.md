# SQL Injection Scanner

A Python tool that probes web form inputs for SQL injection vulnerabilities using error-based and time-based blind detection techniques.

> **Legal / Ethical Notice:** Only use this tool against targets you own or have
> explicit written permission to test — e.g. DVWA, bWAPP, local vulnerable apps.
> Unauthorized scanning is illegal.

---

## Project Structure

```
.
├── scanner.py          # Core scanner (GET/POST, error-based + time-based blind)
├── scanner_csrf.py     # CSRF-aware scanner for token-protected targets (e.g. DVWA)
├── requirements.txt
├── tools/              # Dev helpers for DVWA setup and manual testing
│   ├── get_cookies.py
│   ├── set_security.py
│   ├── find_path.py
│   ├── diagnostic.py
│   ├── manual_test.py
│   └── test_dvwa.py
└── tools/README.md
```

---

## Features

- **Error-based detection** — recognises MySQL, MSSQL, PostgreSQL, SQLite, and Oracle error strings
- **Time-based blind detection** — flags slow responses caused by `SLEEP` / `WAITFOR` payloads
- **CSRF token support** — `scanner_csrf.py` fetches a fresh token before every probe (handles token rotation)
- **Concurrency** — configurable thread pool for faster scanning
- **Rate limiting** — per-request delay with random jitter
- **Flexible input** — GET or POST, cookie support, URL or `--data` params
- **Logging** — stdout + optional file logging

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Usage

### Basic GET scan
```bash
python scanner.py \
  --url "http://localhost/vulnerabilities/sqli/" \
  --data "id=1&Submit=Submit" \
  --cookie "PHPSESSID=abc123; security=low" \
  --log results.log
```

### POST form scan
```bash
python scanner.py \
  --url "http://localhost/login" \
  --method POST \
  --data "username=admin&password=test" \
  --threads 3 \
  --rate-limit 1.0
```

### URL with query params (auto-extracted)
```bash
python scanner.py --url "http://localhost/page?id=1&cat=2"
```

### CSRF-protected target (e.g. DVWA)
```bash
python scanner_csrf.py \
  --url "http://localhost/vulnerabilities/sqli/" \
  --data "id=1&Submit=Submit" \
  --method POST \
  --cookie "PHPSESSID=abc123; security=low" \
  --log results.log
```

Use `--no-csrf` to disable token extraction if the target doesn't use CSRF tokens:
```bash
python scanner_csrf.py --url "http://localhost/page?id=1" --no-csrf
```

---

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | *(required)* | Target URL |
| `--data` | — | URL-encoded params: `'id=1&Submit=Submit'` |
| `--method` | `GET` | HTTP method (`GET` or `POST`) |
| `--cookie` | — | Cookie string: `'PHPSESSID=abc; security=low'` |
| `--threads` | `5` | Concurrent worker threads |
| `--rate-limit` | `0.5` | Seconds between requests per thread |
| `--timeout` | `10` | Request timeout in seconds |
| `--time-threshold` | `3.0` | Response time (s) to flag time-based blind SQLi |
| `--log` | — | Path to log file |
| `--no-csrf` | — | *(scanner_csrf.py only)* Disable CSRF token extraction |

---

## Detection Techniques

| Technique | How it works |
|-----------|-------------|
| Error-based | Matches known DB error strings in the response body |
| Time-based blind | Flags responses slower than `--time-threshold` when `SLEEP`/`WAITFOR` payloads are used |

---

## CSRF Token Handling

`scanner_csrf.py` is designed for targets that include a rotating CSRF token in every form (like DVWA's `user_token`). Before each probe it:

1. Makes a GET request to the target page using a **per-thread session** (so cookies are preserved)
2. Extracts the fresh `user_token` from the HTML
3. Injects it into the probe request alongside the SQLi payload

This ensures every request carries a valid token even when the server rotates it after each response.

---

## Setting up DVWA (Test Target)

1. Install [DVWA](https://github.com/digininja/DVWA) via Docker:
   ```bash
   docker run --rm -it -p 80:80 vulnerables/web-dvwa
   ```
2. Visit `http://localhost`, log in (`admin` / `password`), set security to **Low**.
3. Grab your session cookie:
   ```bash
   python tools/get_cookies.py
   ```
4. Run the scanner:
   ```bash
   python scanner_csrf.py \
     --url "http://localhost/vulnerabilities/sqli/" \
     --data "id=1&Submit=Submit" \
     --method POST \
     --cookie "PHPSESSID=<your_value>; security=low"
   ```
   ## Author
**Silwalkg** — Syntecxhub Cybersecurity Internship

