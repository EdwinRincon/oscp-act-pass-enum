# web_server.py
import argparse
import sys

from osint import __version__
from osint.report.console import Console
from osint.web.app import make_server

LOOPBACK = ("127.0.0.1", "localhost")


def main():
    p = argparse.ArgumentParser(description="osint-enum web interface (local, single user, no login).")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--allow-remote", action="store_true",
                   help="bind to a non-loopback address. The UI has NO authentication.")
    args = p.parse_args()
    ui = Console()
    if args.host not in LOOPBACK and not args.allow_remote:
        ui.line("error: refusing to bind a non-loopback address without --allow-remote"); return 2
    server = make_server(args.host, args.port, args.allow_remote)
    ui.banner(f"osint-enum web {__version__}", f"http://{args.host}:{args.port}")
    ui.line(ui.paint("Listening. Ctrl+C to stop.", "dim"))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        ui.line("\nStopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())