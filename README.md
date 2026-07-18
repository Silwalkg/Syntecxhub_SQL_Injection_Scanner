# SQL Injection Scanner

A Python script that probes web form inputs for common SQL injection patterns.

> **Legal / Ethical Notice:** Only use this tool against targets you own or have
> explicit written permission to test — e.g. DVWA, bWAPP, local vulnerable apps.
> Unauthorized scanning is illegal.

---

## Features

- **Error-based detection** — recognises MySQL, MSSQL, PostgreSQL, SQLite, Oracle error strings
- **Time-based blind detection** — flags slow responses caused by `SLEEP` / `WAITFOR` payloads
- **Concurrency** — configurable thread pool for faster scanning
- **Rate limiting** — per-request delay with random jitter to stay polite
- **Flexible input** — GET or POST, cookie support, URL or `--data` params
- **Logging** — stdout + optional file logging

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Usage

### Basic GET scan (DVWA low security)
```bash
python scanner.py \
  --url "http://localhost/dvwa/vulnerabilities/sqli/" \
  --data "id=1&Submit=Submit" \
  --cookie "PHPSESSID=YOUR_SESSION; security=low" \
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

---

## Detection Techniques

| Technique | How it works |
|-----------|-------------|
| Error-based | Matches known DB error strings in the response body |
| Time-based blind | Flags responses slower than `--time-threshold` when `SLEEP`/`WAITFOR` payloads are used |

---

## Setting up DVWA (Test Target)

1. Install [DVWA](https://github.com/digininja/DVWA) via Docker:
   ```bash
   docker run --rm -it -p 80:80 vulnerables/web-dvwa
   ```
2. Visit `http://localhost`, log in (`admin`/`password`), set security to **Low**.
3. Run the scanner against the SQLi page.
