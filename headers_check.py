# headers_check.py
import argparse
import sys

import requests

from osint.models import ScanError
from osint.report.console import Console
from osint.security_headers import SECURITY_HEADERS, check_security_headers


def main():
    p = argparse.ArgumentParser(description="Check HTTP security headers of a URL.")
    p.add_argument("url")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args()
    ui = Console(color=False if args.no_color else None)
    ui.banner("headers-check 1.0", args.url)
    try:
        r, rows, leaks = check_security_headers(args.url)
    except (ScanError, requests.exceptions.RequestException, OSError, TimeoutError,
            ValueError) as exc:
        ui.line(f"error: {type(exc).__name__}: {exc}"); return 1

    ui.line(f"Security headers report for {r.url}  (HTTP {r.status_code})")
    ui.table(["HEADER", "STATE", "VALUE"], rows)
    ui.line()
    if leaks:
        ui.line("Information disclosure:")
        ui.table(["HEADER", "STATE", "VALUE"], leaks)
        ui.line()
    found = sum(row[1] == "present" for row in rows)
    ui.line(f"Done: {found}/{len(SECURITY_HEADERS)} security headers present")
    return 0


if __name__ == "__main__":
    sys.exit(main())