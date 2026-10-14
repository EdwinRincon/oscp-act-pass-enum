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
HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
RESERVED_HEADERS = {"connection", "content-length", "host", "transfer-encoding", "user-agent"}
MIN_TIMEOUT, MAX_TIMEOUT = 3, 30


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


def validate_http_options(timeout, user_agent=DEFAULT_UA, headers=None):
    if type(timeout) is not int or not MIN_TIMEOUT <= timeout <= MAX_TIMEOUT:
        raise ScanError(f"timeout must be between {MIN_TIMEOUT} and {MAX_TIMEOUT} seconds")
    if not isinstance(user_agent, str) or len(user_agent) > 512 or "\r" in user_agent or "\n" in user_agent:
        raise ScanError("User-Agent must be at most 512 characters and contain no line breaks")
    user_agent = user_agent.strip() or DEFAULT_UA

    if headers is None:
        headers = []
    if not isinstance(headers, list) or len(headers) > 40:
        raise ScanError("custom headers must be a list of 'Name: value' lines")

    normalized, seen = {}, set()
    header_bytes = 0
    for line in headers:
        if not isinstance(line, str) or ":" not in line or "\r" in line or "\n" in line:
            raise ScanError("each custom header must use the format 'Name: value'")
        name, value = line.split(":", 1)
        name, value = name.strip(), value.strip()
        key = name.lower()
        if not HEADER_NAME_RE.fullmatch(name) or len(value) > 4096:
            raise ScanError("custom header name or value is invalid")
        if key in RESERVED_HEADERS:
            raise ScanError(f"custom header '{name}' cannot be overridden")
        if key in seen:
            raise ScanError(f"custom header '{name}' is duplicated")
        header_bytes += len(name) + len(value)
        if header_bytes > 8192:
            raise ScanError("custom headers exceed the 8192-character limit")
        seen.add(key)
        normalized[name] = value
    return timeout, user_agent, normalized


def run_scan(domain, mode="passive", only=None, exclude=None, timeout=10, operator="",
             note="", authorised=False, on_start=None, on_result=None,
             user_agent=DEFAULT_UA, headers=None) -> Report:
    domain, specs = prepare(domain, mode, only, exclude, authorised)
    timeout, user_agent, headers = validate_http_options(timeout, user_agent, headers)
    started, t0 = _utc_now(), time.time()
    results = run_all(specs, HttpClient(timeout=timeout, user_agent=user_agent, headers=headers),
                      domain, on_start, on_result)
    phases = {s.phase for s in specs}
    return Report(
        tool="osint-enum", version=__version__, run_id=uuid.uuid4().hex[:12], target=domain,
        mode="+".join(p for p in ("passive", "active") if p in phases),
        operator=operator, note=note, authorised=authorised,
        started_at=started, finished_at=_utc_now(), duration=round(time.time() - t0, 1),
        timeout=timeout, modules_selected=[s.id for s in specs],
        environment={"os": platform.platform(), "python": platform.python_version(),
                     "user_agent": user_agent, "custom_header_names": list(headers),
                     "timestamps": "UTC"},
        results=results,
    )