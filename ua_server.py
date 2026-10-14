# ua_server.py
import argparse
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from osint.report.console import Console

ui = Console()
LOG_FILE = Path("output/user_agents.log")


class UAHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        ua = self.headers.get("User-Agent", "-")
        stamp = time.strftime("%H:%M:%S")
        ip = self.client_address[0]
        ui.line(f"{stamp}  {ip:<15}  {self.command:<4} {self.path:<20}  {ua}")
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}\t{ip}\t{self.path}\t{ua}\n")
        body = f"Your User-Agent: {ua}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # silence the default log; we print our own


def main():
    p = argparse.ArgumentParser(description="HTTP server that logs User-Agent headers.")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    args = p.parse_args()
    LOG_FILE.parent.mkdir(exist_ok=True)

    server = HTTPServer((args.host, args.port), UAHandler)
    ui.banner("ua-server 1.0", f"{args.host}:{args.port}")
    ui.line(ui.paint("Listening. Ctrl+C to stop.", "dim"))
    ui.line(ui.paint("TIME      CLIENT           REQ  PATH                  USER-AGENT", "bold"))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        ui.line("\nStopped.")


if __name__ == "__main__":
    main()