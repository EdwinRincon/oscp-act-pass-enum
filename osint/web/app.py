# osint/web/app.py
import json
import logging
import threading
import uuid
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import requests

from osint import __version__
from osint.active.rustscan import (DEFAULT_BATCH, DEFAULT_EXECUTION_TIMEOUT, DEFAULT_PORTS,
                                   MAX_BATCH, MAX_EXECUTION_TIMEOUT, MIN_BATCH,
                                   MIN_EXECUTION_TIMEOUT)
from osint.http_client import DEFAULT_UA
from osint.models import ScanError
from osint.registry import SPECS, is_available
from osint.report.html_report import render_html
from osint.report.serialize import to_dict
from osint.security_headers import check_security_headers
from osint.service import (MAX_TIMEOUT, MIN_TIMEOUT, prepare, run_scan,
                           validate_http_options, validate_module_options)
from osint.user_agent_capture import UserAgentCapture

log = logging.getLogger(__name__)

STATIC = Path(__file__).parent / "static"
FILES = {"/": ("index.html", "text/html; charset=utf-8"),
         "/static/app.js": ("app.js", "application/javascript; charset=utf-8"),
         "/static/style.css": ("style.css", "text/css; charset=utf-8")}
UI_CSP = "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
MAX_BODY, MAX_JOBS = 16384, 20
MAX_DOMAIN_LENGTH = 253
SOCKET_TIMEOUT = 30
LOOPBACK_HOSTS = ("127.0.0.1", "localhost")


class BusyError(Exception):
    pass


class RequestError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code, self.message = code, message


class Job:
    def __init__(self, total):
        self.id = uuid.uuid4().hex[:12]
        self.status, self.total, self.current = "running", total, ""
        self.results, self.report, self.error = [], None, ""

    def view(self):
        return {"id": self.id, "status": self.status, "total": self.total, "current": self.current,
                "progress": [{"name": r["name"], "status": r["status"], "elapsed": r["elapsed"]}
                             for r in self.results],
                "report": self.report, "error": self.error}


class Jobs:
    def __init__(self):
        self._items, self._lock = {}, threading.Lock()

    def start(self, params, total):
        with self._lock:
            if any(j.status == "running" for j in self._items.values()):
                raise BusyError()
            job = Job(total)
            self._items[job.id] = job
            while len(self._items) > MAX_JOBS:
                self._items.pop(next(iter(self._items)))
        threading.Thread(target=self._work, args=(job, params), daemon=True).start()
        return job

    @staticmethod
    def _work(job, params):
        try:
            report = run_scan(**params,
                              on_start=lambda spec: setattr(job, "current", spec.title),
                              on_result=lambda res: job.results.append(asdict(res)))
            job.report, job.status = to_dict(report), "done"
        except ScanError as exc:
            job.status, job.error = "error", str(exc)
        except Exception:
            log.exception("scan job %s failed", job.id)
            job.status, job.error = "error", "internal error"

    def get(self, job_id):
        with self._lock:
            return self._items.get(job_id)


def modules_payload():
    return {
        "version": __version__,
        "modules": [
            {"id": s.id, "title": s.title, "phase": s.phase, "source": s.source,
             "kind": s.kind, "confidence": s.confidence,
             "optional": bool(s.executable),
             "opt_in": s.opt_in,
             "requires": list(s.requires),
             "available": is_available(s)}
            for s in SPECS],
        "http": {"default_user_agent": DEFAULT_UA,
                 "min_timeout": MIN_TIMEOUT, "max_timeout": MAX_TIMEOUT,
                 "default_rustscan_ports": DEFAULT_PORTS,
                 "default_rustscan_timeout": DEFAULT_EXECUTION_TIMEOUT,
                 "min_rustscan_timeout": MIN_EXECUTION_TIMEOUT,
                 "max_rustscan_timeout": MAX_EXECUTION_TIMEOUT,
                 "default_rustscan_batch": DEFAULT_BATCH,
                 "min_rustscan_batch": MIN_BATCH,
                 "max_rustscan_batch": MAX_BATCH},
    }


def build_scan_params(body):
    """Valida el cuerpo JSON y devuelve los parámetros de run_scan. Lanza ScanError."""
    if not isinstance(body, dict):
        raise ScanError("request body must be a JSON object")
    modules = body.get("modules", [])
    if not isinstance(modules, list) or not modules:
        raise ScanError("no modules selected")
    domain = str(body.get("domain", ""))
    if len(domain) > MAX_DOMAIN_LENGTH:
        raise ScanError(f"domain is too long (maximum {MAX_DOMAIN_LENGTH} characters)")
    timeout, user_agent, headers = validate_http_options(
        body.get("timeout", 10), body.get("user_agent", DEFAULT_UA), body.get("headers", []))
    return {
        "domain": domain,
        "mode": "all",
        "only": [str(module) for module in modules],
        "timeout": timeout,
        "user_agent": user_agent,
        "headers": [f"{name}: {value}" for name, value in headers.items()],
        "module_options": {
            "rustscan_ports": body.get("rustscan_ports", DEFAULT_PORTS),
            "rustscan_timeout": body.get("rustscan_timeout", DEFAULT_EXECUTION_TIMEOUT),
            "rustscan_batch": body.get("rustscan_batch", DEFAULT_BATCH),
            "exploit_query": body.get("exploit_query", "")},
        "operator": str(body.get("operator", ""))[:80],
        "note": str(body.get("note", ""))[:300],
        "authorised": body.get("authorised") is True,
    }


class Handler(BaseHTTPRequestHandler):
    server_version, sys_version = "osint-enum", ""
    timeout = SOCKET_TIMEOUT  # evita que un cliente lento bloquee un hilo indefinidamente

    def log_message(self, fmt, *args):
        log.debug("%s %s", self.address_string(), fmt % args)

    # ---------- respuesta ----------

    def _send(self, code, body, ctype, csp=UI_CSP):
        self.send_response(code)
        for key, value in (("Content-Type", ctype), ("Content-Length", str(len(body))),
                           ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"),
                           ("X-Frame-Options", "DENY"), ("Referrer-Policy", "no-referrer"),
                           ("Cross-Origin-Resource-Policy", "same-origin"),
                           ("Cross-Origin-Opener-Policy", "same-origin"),
                           ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
                           ("Content-Security-Policy", csp)):
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj).encode(), "application/json")

    def _serve_static(self, name, ctype):
        try:
            body = (STATIC / name).read_bytes()
        except OSError:
            log.exception("static file %s is unavailable", name)
            return self._json(500, {"error": "static file unavailable"})
        self._send(200, body, ctype)

    # ---------- seguridad y entrada ----------

    def _guard(self):
        host, origin = self.headers.get("Host", ""), self.headers.get("Origin")
        if not self.server.allow_remote and host not in self.server.allowed_hosts:
            return False
        return origin is None or origin == f"http://{host}"

    def _read_json_object(self):
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            raise RequestError(415, "content-type must be application/json")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise RequestError(400, "invalid Content-Length") from None
        if length <= 0:
            raise RequestError(400, "request body is required")
        if length > MAX_BODY:
            raise RequestError(413, "request body too large")
        try:
            body = json.loads(self.rfile.read(length))
        except ValueError:
            raise RequestError(400, "request body is not valid JSON") from None
        if not isinstance(body, dict):
            raise RequestError(400, "request body must be a JSON object")
        return body

    # ---------- enrutado ----------

    def _handle(self, route):
        if not self._guard():
            return self._json(403, {"error": "forbidden host or origin"})
        try:
            route()
        except RequestError as exc:
            self._json(exc.code, {"error": exc.message})
        except ScanError as exc:
            self._json(400, {"error": str(exc)})
        except BusyError:
            self._json(409, {"error": "a scan is already running"})
        except TimeoutError:
            self._json(408, {"error": "request timed out"})
        except (BrokenPipeError, ConnectionResetError):
            log.debug("client disconnected before the response was sent")
        except Exception:
            log.exception("unhandled error for %s %s", self.command, self.path)
            self._json(500, {"error": "internal error"})

    def do_GET(self):
        self._handle(self._get)

    def do_POST(self):
        self._handle(self._post)

    # ---------- GET ----------

    def _get(self):
        path = self.path.split("?")[0]
        if path in FILES:
            return self._serve_static(*FILES[path])
        if path == "/api/modules":
            return self._json(200, modules_payload())
        if path == "/api/user-agent":
            capture = self.server.user_agent_capture
            return self._json(200, {"running": capture.running, "address": capture.address,
                                    "log_file": str(capture.log_file),
                                    "events": capture.events()})
        parts = path.split("/")  # ['', 'api', 'scan', id, optional file]
        if len(parts) in (4, 5) and parts[1:3] == ["api", "scan"]:
            return self._get_scan(parts)
        raise RequestError(404, "not found")

    def _get_scan(self, parts):
        job = self.server.jobs.get(parts[3])
        if not job:
            raise RequestError(404, "unknown scan")
        if len(parts) == 4:
            return self._json(200, job.view())
        if job.report and parts[4] == "report.json":
            return self._send(200, json.dumps(job.report, indent=2, ensure_ascii=False).encode(),
                              "application/json", REPORT_CSP)
        if job.report and parts[4] == "report.html":
            return self._send(200, render_html(job.report).encode(),
                              "text/html; charset=utf-8", REPORT_CSP)
        raise RequestError(404, "not found")

    # ---------- POST ----------

    def _post(self):
        route = self.POST_ROUTES.get(self.path.split("?")[0])
        if route is None:
            raise RequestError(404, "not found")
        status, payload = route(self, self._read_json_object())
        self._json(status, payload)

    def _post_scan(self, body):
        params = build_scan_params(body)
        _, specs = prepare(params["domain"], "all", params["only"], None, params["authorised"])
        params["module_options"] = validate_module_options(params["module_options"], specs)
        job = self.server.jobs.start(params, len(specs))
        return 202, job.view()

    def _post_headers(self, body):
        try:
            response, rows, leaks = check_security_headers(
                body.get("url"), body.get("timeout", 10))
        except requests.exceptions.RequestException as exc:
            log.warning("security-header request failed: %s", exc)
            raise RequestError(502, f"{type(exc).__name__}: {str(exc)[:200]}") from exc
        return 200, {"url": response.url, "status": response.status_code,
                     "rows": rows, "leaks": leaks}

    def _post_capture_start(self, body):
        host, port = body.get("host", "127.0.0.1"), body.get("port", 8080)
        if host != "127.0.0.1" or type(port) is not int or not 1 <= port <= 65535:
            raise RequestError(
                400, "capture server must bind to 127.0.0.1 and a port from 1 to 65535")
        capture = self.server.user_agent_capture
        try:
            address = capture.start(host, port)
        except RuntimeError as exc:
            raise RequestError(409, str(exc)) from exc
        except OSError as exc:
            raise RequestError(
                400, f"could not bind {host}:{port}: {exc.strerror or type(exc).__name__}"
            ) from exc
        return 200, {"running": True, "address": address,
                     "log_file": str(capture.log_file), "events": []}

    def _post_capture_stop(self, _body):
        capture = self.server.user_agent_capture
        capture.stop()
        return 200, {"running": False, "address": None, "events": capture.events()}

    POST_ROUTES = {
        "/api/scan": _post_scan,
        "/api/headers": _post_headers,
        "/api/user-agent/start": _post_capture_start,
        "/api/user-agent/stop": _post_capture_stop,
    }


class OsintServer(ThreadingHTTPServer):
    def __init__(self, address, handler, allow_remote=False, user_agent_capture=None):
        super().__init__(address, handler)
        self.allow_remote = allow_remote
        self.jobs = Jobs()
        self.user_agent_capture = user_agent_capture or UserAgentCapture()
        port = self.server_address[1]
        self.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    def server_close(self):
        self.user_agent_capture.stop()
        super().server_close()


def make_server(host, port, allow_remote=False):
    if not allow_remote and host not in LOOPBACK_HOSTS:
        raise ValueError(
            f"refusing to bind to {host!r} without allow_remote; "
            "this interface has no authentication")
    return OsintServer((host, port), Handler, allow_remote)