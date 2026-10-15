import argparse
import time

from osint.report.console import Console
from osint.user_agent_capture import UserAgentCapture


def main():
    parser = argparse.ArgumentParser(description="HTTP server that logs User-Agent headers.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")

    ui = Console()
    capture = UserAgentCapture(console=ui)
    try:
        address = capture.start(args.host, args.port)
    except OSError as exc:
        ui.line(f"error: {type(exc).__name__}: {exc}")
        return 1
    ui.banner("ua-server 1.0", f"{address['host']}:{address['port']}")
    ui.line("Listening. Ctrl+C to stop.")
    ui.line("TIME      CLIENT           REQ  PATH                  USER-AGENT")
    ui.line(f"Log: {capture.log_file}")
    try:
        while capture.running:
            time.sleep(0.5)
    except KeyboardInterrupt:
        ui.line("\nStopped.")
    finally:
        capture.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
