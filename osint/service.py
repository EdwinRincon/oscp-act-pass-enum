# osint/service.py
import ipaddress
import platform
import re
import shlex
import time
import uuid
from datetime import datetime, timezone

from osint import __version__
from osint.active.rustscan import (DEFAULT_EXECUTION_TIMEOUT, DEFAULT_PORTS,
                                   MAX_EXECUTION_TIMEOUT, MIN_EXECUTION_TIMEOUT)
from osint.http_client import DEFAULT_UA, HttpClient
from osint.models import Report, ScanError
from osint.registry import select
from osint.runner import run_all

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)
HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
RESERVED_HEADERS = {"connection", "content-length", "host", "transfer-encoding", "user-agent"}
MIN_TIMEOUT, MAX_TIMEOUT = 3, 30


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def prepare(domain, mode, only, exclude, authorised):
    """Single validation point for CLI and web. Raises ScanError."""
    domain = (domain or "").strip().lower().rstrip(".")
    try:
        ipaddress.IPv4Address(domain)
        valid_target = True
    except ipaddress.AddressValueError:
        valid_target = bool(DOMAIN_RE.fullmatch(domain))
    if not valid_target:
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


def validate_module_options(options=None, specs=None):
    if options is None:
        options = {}
    if not isinstance(options, dict):
        raise ScanError("module options must be an object")

    ports = options.get("rustscan_ports") or DEFAULT_PORTS
    if not isinstance(ports, str) or len(ports) > 320:
        raise ScanError("RustScan ports must be a comma-separated list")
    port_values = [value.strip() for value in ports.split(",") if value.strip()]
    if not port_values or len(port_values) > 64:
        raise ScanError("RustScan requires between 1 and 64 selected ports")
    if any(not re.fullmatch(r"[0-9]+", value) or not 1 <= int(value) <= 65535
           for value in port_values):
        raise ScanError("RustScan ports must be numbers between 1 and 65535")
    numeric_ports = [int(value) for value in port_values]
    if len(set(numeric_ports)) != len(numeric_ports):
        raise ScanError("RustScan ports must not contain duplicates")

    rustscan_timeout = options.get("rustscan_timeout", DEFAULT_EXECUTION_TIMEOUT)
    if (type(rustscan_timeout) is not int
            or not MIN_EXECUTION_TIMEOUT <= rustscan_timeout <= MAX_EXECUTION_TIMEOUT):
        raise ScanError(
            f"RustScan timeout must be between {MIN_EXECUTION_TIMEOUT} "
            f"and {MAX_EXECUTION_TIMEOUT} seconds")

    query = options.get("exploit_query", "")
    if not isinstance(query, str) or len(query) > 200 or any(ord(char) < 32 for char in query):
        raise ScanError("exploit search query must be at most 200 characters")
    try:
        terms = shlex.split(query)
    except ValueError as exc:
        raise ScanError("exploit search query has invalid quoting") from exc
    if len(terms) > 12 or any(term.startswith("-") for term in terms):
        raise ScanError("exploit search query must contain at most 12 terms and no options")
    return {"rustscan_ports": ",".join(map(str, numeric_ports)),
            "rustscan_timeout": rustscan_timeout,
            "exploit_query": " ".join(terms)}


def run_scan(domain, mode="passive", only=None, exclude=None, timeout=10, operator="",
             note="", authorised=False, on_start=None, on_result=None,
             user_agent=DEFAULT_UA, headers=None, module_options=None) -> Report:
    domain, specs = prepare(domain, mode, only, exclude, authorised)
    timeout, user_agent, headers = validate_http_options(timeout, user_agent, headers)
    module_options = validate_module_options(module_options, specs)
    module_options["timeout"] = timeout
    selected_ids = {spec.id for spec in specs}
    recorded_options = {}
    if "rustscan" in selected_ids:
        recorded_options["rustscan_ports"] = module_options["rustscan_ports"]
        recorded_options["rustscan_timeout"] = module_options["rustscan_timeout"]
    if "searchsploit" in selected_ids and module_options["exploit_query"]:
        recorded_options["exploit_query"] = module_options["exploit_query"]
    started, t0 = _utc_now(), time.time()
    results = run_all(specs, HttpClient(timeout=timeout, user_agent=user_agent, headers=headers),
                      domain, on_start, on_result, module_options)
    phases = {s.phase for s in specs}
    return Report(
        tool="osint-enum", version=__version__, run_id=uuid.uuid4().hex[:12], target=domain,
        mode="+".join(p for p in ("passive", "active") if p in phases),
        operator=operator, note=note, authorised=authorised,
        started_at=started, finished_at=_utc_now(), duration=round(time.time() - t0, 1),
        timeout=timeout, modules_selected=[s.id for s in specs],
        environment={"os": platform.platform(), "python": platform.python_version(),
                     "user_agent": user_agent, "custom_header_names": list(headers),
                     "module_options": recorded_options,
                     "timestamps": "UTC"},
        results=results,
    )