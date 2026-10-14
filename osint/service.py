# osint/service.py
import platform
import re
import time
import uuid
from datetime import datetime, timezone

from osint import __version__
from osint.http_client import DEFAULT_UA, HttpClient
from osint.models import Report, ScanError
from osint.registry import select
from osint.runner import run_all

DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$", re.I)


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def prepare(domain, mode, only, exclude, authorised):
    """Single validation point for CLI and web. Raises ScanError."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        raise ScanError("invalid domain")
    specs = select(mode, only, exclude)
    if not specs:
        raise ScanError("no modules selected")
    if any(s.phase == "active" for s in specs) and not authorised:
        raise ScanError("active modules require confirmation that you own or are authorised to test the target")
    return domain, specs


def run_scan(domain, mode="passive", only=None, exclude=None, timeout=10, operator="",
             note="", authorised=False, on_start=None, on_result=None) -> Report:
    domain, specs = prepare(domain, mode, only, exclude, authorised)
    started, t0 = _utc_now(), time.time()
    results = run_all(specs, HttpClient(timeout=timeout), domain, on_start, on_result)
    phases = {s.phase for s in specs}
    return Report(
        tool="osint-enum", version=__version__, run_id=uuid.uuid4().hex[:12], target=domain,
        mode="+".join(p for p in ("passive", "active") if p in phases),
        operator=operator, note=note, authorised=authorised,
        started_at=started, finished_at=_utc_now(), duration=round(time.time() - t0, 1),
        timeout=timeout, modules_selected=[s.id for s in specs],
        environment={"os": platform.platform(), "python": platform.python_version(),
                     "user_agent": DEFAULT_UA, "timestamps": "UTC"},
        results=results,
    )