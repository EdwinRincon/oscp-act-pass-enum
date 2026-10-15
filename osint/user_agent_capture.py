# osint/user_agent_capture.py
import logging
import os
import re
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from osint.report.console import Console

log = logging.getLogger(__name__)
DEFAULT_LOG_FILE = Path("output/user_agents.log")
MAX_EVENTS = 200
MAX_FIELD_LENGTH = 512
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _clean(value, limit=MAX_FIELD_LENGTH) -> str:
    """Neutraliza caracteres de control (incluidas secuencias ANSI) y acota la longitud."""
    return CONTROL_RE.sub("?", str(value))[:limit]


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _make_handler(capture):
    class Handler(BaseHTTPRequestHandler):
        def _serve(self, send_body):
            event = capture.record(self.client_address[0], self.command, self.path,
                                   self.headers.get("User-Agent", "-"))
            body = f"Your User-Agent: {event['user_agent']}\n".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if send_body:
                self.wfile.write(body)

        def do_GET(self):
            self._serve(send_body=True)

        def do_HEAD(self):
            self._serve(send_body=False)

        def log_message(self, *_args):
            return

    return Handler


class UserAgentCapture:
    """Servidor HTTP de laboratorio que registra la IP, la ruta y el User-Agent (en UTC)."""

    def __init__(self, log_file=DEFAULT_LOG_FILE, console=None):
        self.log_file = Path(log_file)
        self.console = console or Console()
        self._events_lock = threading.Lock()
        self._file_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._events = []
        self._server = None
        self._thread = None

    @property
    def running(self):
        with self._state_lock:
            return self._server is not None

    @property
    def address(self):
        with self._state_lock:
            if not self._server:
                return None
            host, port = self._server.server_address[:2]
            return {"host": host, "port": port}

    def events(self):
        with self._events_lock:
            return list(self._events)

    def record(self, ip, method, path, user_agent):
        """Registra una petición en memoria, en el log y en consola. Devuelve el evento."""
        event = {"time": _utc_stamp(), "ip": _clean(ip, 64), "method": _clean(method, 16),
                 "path": _clean(path), "user_agent": _clean(user_agent)}
        self._append_to_log(event)
        with self._events_lock:
            self._events.append(event)
            del self._events[:-MAX_EVENTS]
        self.console.line(
            f"{event['time'][11:]}  {event['ip']:<15}  "
            f"{event['method']:<4} {event['path'][:20]:<20}  {event['user_agent']}")
        return event

    def _append_to_log(self, event):
        line = "\t".join(event[key] for key in ("time", "ip", "path", "user_agent")) + "\n"
        try:
            with self._file_lock:
                self.log_file.parent.mkdir(parents=True, exist_ok=True)
                descriptor = os.open(self.log_file,
                                     os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                with os.fdopen(descriptor, "a", encoding="utf-8") as stream:
                    stream.write(line)
        except OSError:
            log.exception("could not write User-Agent capture log")

    def start(self, host="127.0.0.1", port=8080):
        with self._state_lock:
            if self._server:
                raise RuntimeError("User-Agent capture server is already running")
            server = ThreadingHTTPServer((host, port), _make_handler(self))
            server.daemon_threads = True
            self._server = server
            self._thread = threading.Thread(target=server.serve_forever, daemon=True)
            self._thread.start()
            actual_host, actual_port = server.server_address[:2]
            return {"host": actual_host, "port": actual_port}

    def stop(self):
        with self._state_lock:
            server, thread = self._server, self._thread
            if server is None:
                return
            self._server = self._thread = None
        server.shutdown()
        server.server_close()
        if thread:
            thread.join(timeout=2)