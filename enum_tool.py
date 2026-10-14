# enum_tool.py
import argparse
import sys

from osint import __version__
from osint.models import ScanError
from osint.registry import SPECS
from osint.report.console import Console
from osint.report.html_report import write_html
from osint.report.json_writer import write_json
from osint.report.serialize import to_dict
from osint.service import prepare, run_scan


def parse_args():
    p = argparse.ArgumentParser(description="Passive/active domain enumeration (authorised use only).")
    p.add_argument("-d", "--domain")
    p.add_argument("-m", "--mode", choices=("passive", "active", "all"), default="passive")
    p.add_argument("--only", metavar="IDS", help="comma-separated module ids (implies --mode all)")
    p.add_argument("--exclude", metavar="IDS", help="comma-separated module ids to skip")
    p.add_argument("--list-modules", action="store_true")
    p.add_argument("--json", action="store_true", help="write JSON report")
    p.add_argument("--html", action="store_true", help="write HTML report")
    p.add_argument("--out", default="output", help="report directory (default: output)")
    p.add_argument("--operator", default="", help="analyst name recorded in the report")
    p.add_argument("--note", default="", help="engagement/ticket reference recorded in the report")
    p.add_argument("--timeout", type=int, default=10)
    p.add_argument("--no-color", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true", help="summary only")
    p.add_argument("--i-have-permission", action="store_true",
                   help="required for active modules: you own or are authorised to test the target")
    return p.parse_args()


def csv(value):
    return [v.strip() for v in value.split(",") if v.strip()] if value else None


def main():
    args = parse_args()
    ui = Console(color=False if args.no_color else None)
    if args.list_modules:
        ui.table(["ID", "PHASE", "KIND", "CONFIDENCE", "SOURCE"],
                 [(s.id, s.phase, s.kind, s.confidence, s.source) for s in SPECS])
        return 0
    if not args.domain:
        ui.line("error: -d/--domain is required"); return 2

    mode = "all" if args.only else args.mode
    try:
        domain, specs = prepare(args.domain, mode, csv(args.only), csv(args.exclude),
                                args.i_have_permission)
    except ScanError as exc:
        ui.line(f"error: {exc}"); return 2

    if not args.quiet:
        ui.banner(f"osint-enum {__version__}", domain, "custom" if args.only else args.mode)
    report = run_scan(domain, mode, csv(args.only), csv(args.exclude), args.timeout,
                      args.operator, args.note, args.i_have_permission,
                      on_result=None if args.quiet else ui.module)
    data = to_dict(report)
    ui.summary(report.results, report.duration)
    if args.json:
        ui.line(f"JSON report: {write_json(data, args.out)}")
    if args.html:
        ui.line(f"HTML report: {write_html(data, args.out)}")
    ui.line(f"SHA-256: {data['integrity']['sha256']}")
    return 1 if all(r.status == "failed" for r in report.results) else 0


if __name__ == "__main__":
    sys.exit(main())