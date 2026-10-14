# osint/web/app.py
import json
import shutil
import threading
import uuid
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from osint import __version__
from osint.active.rustscan import (DEFAULT_EXECUTION_TIMEOUT, DEFAULT_PORTS,
                                   MAX_EXECUTION_TIMEOUT, MIN_EXECUTION_TIMEOUT)
from osint.http_client import DEFAULT_UA
from osint.models import ScanError
from osint.registry import SPECS
from osint.report.html_report import render_html
from osint.report.serialize import stem, to_dict
from osint.service import (MAX_TIMEOUT, MIN_TIMEOUT, prepare, run_scan,
                           validate_http_options, validate_module_options)

STATIC = Path(__file__).parent / "static"
FILES = {"/": ("index.html", "text/html; charset=utf-8"),
         "/static/app.js": ("app.js", "application/javascript; charset=utf-8"),
         "/static/style.css": ("style.css", "text/css; charset=utf-8")}
UI_CSP = "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
MAX_BODY, MAX_JOBS = 16384, 20


class BusyError(Exception):
    pass


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
            job.status, job.error = "error", "internal error"

    def get(self, job_id):
        return self._items.get(job_id)


class Handler(BaseHTTPRequestHandler):
    server_version, sys_version = "osint-enum", ""

    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype, csp=UI_CSP):
        self.send_response(code)
        for key, value in (("Content-Type", ctype), ("Content-Length", str(len(body))),
                           ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"),
                           ("X-Frame-Options", "DENY"), ("Referrer-Policy", "no-referrer"),
                           ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
                           ("Content-Security-Policy", csp)):
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj).encode(), "application/json")

    def _guard(self):
        host, origin = self.headers.get("Host", ""), self.headers.get("Origin")
        if not self.server.allow_remote and host not in self.server.allowed_hosts:
            return False
        return origin is None or origin == f"http://{host}"

    def do_GET(self):
        if not self._guard():
            return self._json(403, {"error": "forbidden host or origin"})
        path = self.path.split("?")[0]
        if path in FILES:
            name, ctype = FILES[path]
            return self._send(200, (STATIC / name).read_bytes(), ctype)
        if path == "/api/modules":
            return self._json(200, {"version": __version__, "modules": [
                {"id": s.id, "title": s.title, "phase": s.phase, "source": s.source,
                 "kind": s.kind, "confidence": s.confidence,
                 "optional": bool(s.executable),
                 "auto_when_active": s.auto_when_active,
                 "available": not s.executable or bool(shutil.which(s.executable))}
                for s in SPECS],
                "http": {"default_user_agent": DEFAULT_UA,
                         "min_timeout": MIN_TIMEOUT, "max_timeout": MAX_TIMEOUT,
                         "default_rustscan_ports": DEFAULT_PORTS,
                         "default_rustscan_timeout": DEFAULT_EXECUTION_TIMEOUT,
                         "min_rustscan_timeout": MIN_EXECUTION_TIMEOUT,
                         "max_rustscan_timeout": MAX_EXECUTION_TIMEOUT}})
        parts = path.split("/")  # ['', 'api', 'scan', id, optional file]
        if len(parts) in (4, 5) and parts[1:3] == ["api", "scan"]:
            job = self.server.jobs.get(parts[3])
            if not job:
                return self._json(404, {"error": "unknown scan"})
            if len(parts) == 4:
                return self._json(200, job.view())
            if job.report and parts[4] == "report.json":
                return self._send(200, json.dumps(job.report, indent=2, ensure_ascii=False).encode(),
                                  "application/json", REPORT_CSP)
            if job.report and parts[4] == "report.html":
                return self._send(200, render_html(job.report).encode(),
                                  "text/html; charset=utf-8", REPORT_CSP)
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self._guard():
            return self._json(403, {"error": "forbidden host or origin"})
        if self.path != "/api/scan":
            return self._json(404, {"error": "not found"})
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            return self._json(415, {"error": "content-type must be application/json"})
        length = int(self.headers.get("Content-Length") or 0)
        if not 0 < length <= MAX_BODY:
            return self._json(413, {"error": "bad body size"})
        try:
            body = json.loads(self.rfile.read(length))
            timeout, user_agent, headers = validate_http_options(
                body.get("timeout", 10),
                body.get("user_agent", DEFAULT_UA),
                body.get("headers", []))
            params = {"domain": str(body.get("domain", ""))[:253], "mode": "all",
                      "only": [str(m) for m in body.get("modules", [])],
                      "timeout": timeout, "user_agent": user_agent,
                      "headers": [f"{name}: {value}" for name, value in headers.items()],
                      "module_options": {"rustscan_ports": body.get("rustscan_ports", DEFAULT_PORTS),
                                         "rustscan_timeout": body.get(
                                             "rustscan_timeout", DEFAULT_EXECUTION_TIMEOUT),
                                         "exploit_query": body.get("exploit_query", "")},
                      "operator": str(body.get("operator", ""))[:80],
                      "note": str(body.get("note", ""))[:300],
                      "authorised": body.get("authorised") is True}
            if not params["only"]:
                raise ScanError("no modules selected")
            _, specs = prepare(params["domain"], "all", params["only"], None, params["authorised"])
            params["module_options"] = validate_module_options(params["module_options"], specs)
            job = self.server.jobs.start(params, len(specs))
        except ScanError as exc:
            return self._json(400, {"error": str(exc)})
        except BusyError:
            return self._json(409, {"error": "a scan is already running"})
        except (ValueError, TypeError, AttributeError):
            return self._json(400, {"error": "bad request"})
        self._json(202, job.view())


def make_server(host, port, allow_remote=False):
    server = ThreadingHTTPServer((host, port), Handler)
    server.jobs, server.allow_remote = Jobs(), allow_remote
    server.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    return server