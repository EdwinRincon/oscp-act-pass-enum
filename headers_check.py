# headers_check.py
import argparse
import sys

from osint.http_client import HttpClient
from osint.report.console import Console

SECURITY_HEADERS = ("Strict-Transport-Security", "Content-Security-Policy",
                    "X-Frame-Options", "X-Content-Type-Options",
                    "Referrer-Policy", "Permissions-Policy")
LEAKY = ("Server", "X-Powered-By")


def main():
    p = argparse.ArgumentParser(description="Check HTTP security headers of a URL.")
    p.add_argument("url")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args()
    url = args.url if "://" in args.url else f"https://{args.url}"
    ui = Console(color=False if args.no_color else None)

    ui.banner("headers-check 1.0", url)
    try:
        r = HttpClient().get(url)
    except Exception as exc:
        ui.line(f"error: {type(exc).__name__}: {exc}"); return 1

    ui.line(f"Security headers report for {r.url}  (HTTP {r.status_code})")
    rows = [(h, "present" if h in r.headers else "missing", r.headers.get(h, "-"))
            for h in SECURITY_HEADERS]
    ui.table(["HEADER", "STATE", "VALUE"], rows)
    ui.line()
    leaks = [(h, "exposed", r.headers[h]) for h in LEAKY if h in r.headers]
    if leaks:
        ui.line("Information disclosure:")
        ui.table(["HEADER", "STATE", "VALUE"], leaks)
        ui.line()
    found = sum(row[1] == "present" for row in rows)
    ui.line(f"Done: {found}/{len(SECURITY_HEADERS)} security headers present")
    return 0


if __name__ == "__main__":
    sys.exit(main())