# headers_check.py
import argparse
import sys

import requests

from osint.models import ScanError
from osint.report.console import Console
from osint.report.header_check import build_header_report
from osint.report.html_report import write_html
from osint.report.json_writer import write_json
from osint.report.serialize import to_dict
from osint.security_headers import SECURITY_HEADERS, check_security_headers, report_rows


def main():
    p = argparse.ArgumentParser(description="Check HTTP security headers of a URL.")
    p.add_argument("url")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--i-have-permission", action="store_true", required=True,
                   help="Confirm explicit authorisation for this active check")
    p.add_argument("--json", action="store_true", help="Write a JSON report")
    p.add_argument("--html", action="store_true", help="Write an HTML report")
    p.add_argument("--out", default="output", help="Report directory")
    args = p.parse_args()
    ui = Console(color=False if args.no_color else None)
    ui.banner("headers-check 1.0", args.url)
    try:
        r, rows, leaks = check_security_headers(args.url)
    except (ScanError, requests.exceptions.RequestException, OSError, TimeoutError,
            ValueError) as exc:
        ui.line(f"error: {type(exc).__name__}: {exc}"); return 1

    ui.line(f"Security headers report for {r.url}  (HTTP {r.status_code})")
    headers, report_data = report_rows(r, rows, leaks)
    ui.table(headers, report_data)
    found = sum(row[1] == "present" for row in rows)
    ui.line(f"Coverage: {found}/{len(SECURITY_HEADERS)} security headers observed as present; "
            "this is not a security score.")
    data = to_dict(build_header_report(r, rows, leaks))
    if args.json:
        ui.line(f"JSON report: {write_json(data, args.out)}")
    if args.html:
        ui.line(f"HTML report: {write_html(data, args.out)}")
    ui.line(f"SHA-256: {data['integrity']['sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())