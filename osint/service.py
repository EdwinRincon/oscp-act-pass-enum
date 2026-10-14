# osint/service.py
import ipaddress
import platform
import re
import shlex
import shutil
import subprocess
import time
import uuid
from datetime import datetime, timezone

from osint import __version__
from osint.active.rustscan import (DEFAULT_BATCH, DEFAULT_EXECUTION_TIMEOUT, DEFAULT_PORTS,
                                   MAX_BATCH, MAX_EXECUTION_TIMEOUT, MIN_BATCH,
                                   MIN_EXECUTION_TIMEOUT)
from osint.http_client import DEFAULT_UA, HttpClient
from osint.models import Report, ScanError
from osint.registry import select
from osint.runner import run_all

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)  # el TLD empieza por letra
HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
RESERVED_HEADERS = {"connection", "content-length", "host", "transfer-encoding", "user-agent"}
MIN_TIMEOUT, MAX_TIMEOUT = 3, 30
MAX_HEADERS, MAX_HEADER_BYTES = 40, 8192
TOOL_VERSION_ARGS = {"rustscan": ("--version",)}


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _is_int(value, low, high):
    return type(value) is int and low <= value <= high


def normalize_target(raw):
    """Devuelve un IPv4 o dominio (IDN en punycode) normalizado, o lanza ScanError."""
    value = (raw or "").strip().lower().rstrip(".")
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        pass
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScanError("invalid domain") from exc
    if not DOMAIN_RE.fullmatch(value):
        raise ScanError("invalid domain")
    return value


def prepare(domain, mode, only, exclude, authorised):
    """Punto único de validación para CLI y web. Lanza ScanError."""
    domain = normalize_target(domain)
    specs = select(mode, only, exclude)
    if not specs:
        raise ScanError("no modules selected")
    if any(s.phase == "active" for s in specs) and not authorised:
        raise ScanError("active modules require confirmation that you own "
                        "or are authorised to test the target")
    return domain, specs


def _validate_user_agent(user_agent):
    if (not isinstance(user_agent, str) or len(user_agent) > 512
            or "\r" in user_agent or "\n" in user_agent):
        raise ScanError("User-Agent must be at most 512 characters and contain no line breaks")
    return user_agent.strip() or DEFAULT_UA


def _parse_header(line):
    if not isinstance(line, str) or ":" not in line or "\r" in line or "\n" in line:
        raise ScanError("each custom header must use the format 'Name: value'")
    name, value = (part.strip() for part in line.split(":", 1))
    if not HEADER_NAME_RE.fullmatch(name) or len(value) > 4096:
        raise ScanError("custom header name or value is invalid")
    if name.lower() in RESERVED_HEADERS:
        raise ScanError(f"custom header '{name}' cannot be overridden")
    return name, value


def validate_http_options(timeout, user_agent=DEFAULT_UA, headers=None):
    if not _is_int(timeout, MIN_TIMEOUT, MAX_TIMEOUT):
        raise ScanError(f"timeout must be between {MIN_TIMEOUT} and {MAX_TIMEOUT} seconds")
    user_agent = _validate_user_agent(user_agent)

    headers = [] if headers is None else headers
    if not isinstance(headers, list) or len(headers) > MAX_HEADERS:
        raise ScanError("custom headers must be a list of 'Name: value' lines")

    normalized, seen, size = {}, set(), 0
    for line in headers:
        name, value = _parse_header(line)
        if name.lower() in seen:
            raise ScanError(f"custom header '{name}' is duplicated")
        size += len(name) + len(value)
        if size > MAX_HEADER_BYTES:
            raise ScanError(f"custom headers exceed the {MAX_HEADER_BYTES}-character limit")
        seen.add(name.lower())
        normalized[name] = value
    return timeout, user_agent, normalized


def _validate_ports(options):
    ports = options.get("rustscan_ports") or DEFAULT_PORTS
    if not isinstance(ports, str) or len(ports) > 320:
        raise ScanError("RustScan ports must be a comma-separated list")
    values = [v.strip() for v in ports.split(",") if v.strip()]
    if not values or len(values) > 64:
        raise ScanError("RustScan requires between 1 and 64 selected ports")
    if any(not re.fullmatch(r"[0-9]{1,5}", v) or not 1 <= int(v) <= 65535 for v in values):
        raise ScanError("RustScan ports must be numbers between 1 and 65535")
    numbers = [int(v) for v in values]
    if len(set(numbers)) != len(numbers):
        raise ScanError("RustScan ports must not contain duplicates")
    return ",".join(map(str, numbers))


def _validate_rustscan_numbers(options):
    timeout = options.get("rustscan_timeout", DEFAULT_EXECUTION_TIMEOUT)
    if not _is_int(timeout, MIN_EXECUTION_TIMEOUT, MAX_EXECUTION_TIMEOUT):
        raise ScanError(f"RustScan timeout must be between {MIN_EXECUTION_TIMEOUT} "
                        f"and {MAX_EXECUTION_TIMEOUT} seconds")
    batch = options.get("rustscan_batch", DEFAULT_BATCH)
    if not _is_int(batch, MIN_BATCH, MAX_BATCH):
        raise ScanError(f"RustScan batch size must be between {MIN_BATCH} and {MAX_BATCH}")
    return timeout, batch


def _validate_exploit_query(options):
    query = options.get("exploit_query", "")
    if not isinstance(query, str) or len(query) > 200 or any(ord(c) < 32 for c in query):
        raise ScanError("exploit search query must be at most 200 characters")
    try:
        terms = shlex.split(query)
    except ValueError as exc:
        raise ScanError("exploit search query has invalid quoting") from exc
    if len(terms) > 12 or any(term.startswith("-") for term in terms):
        raise ScanError("exploit search query must contain at most 12 terms and no options")
    return " ".join(terms)


def validate_module_options(options=None, specs=None):
    """`specs` se acepta por compatibilidad con los llamadores existentes."""
    options = {} if options is None else options
    if not isinstance(options, dict):
        raise ScanError("module options must be an object")
    timeout, batch = _validate_rustscan_numbers(options)
    return {"rustscan_ports": _validate_ports(options),
            "rustscan_timeout": timeout,
            "rustscan_batch": batch,
            "exploit_query": _validate_exploit_query(options)}


def _recorded_options(selected_ids, module_options):
    recorded = {}
    if "rustscan" in selected_ids:
        for key in ("rustscan_ports", "rustscan_timeout", "rustscan_batch"):
            recorded[key] = module_options[key]
    if "searchsploit" in selected_ids and module_options["exploit_query"]:
        recorded["exploit_query"] = module_options["exploit_query"]
    return recorded


def _tool_versions(selected_ids):
    versions = {}
    for tool, args in TOOL_VERSION_ARGS.items():
        executable = shutil.which(tool) if tool in selected_ids else None
        if not executable:
            continue
        try:
            proc = subprocess.run([executable, *args], stdin=subprocess.DEVNULL,
                                  capture_output=True, text=True, timeout=5, check=False)
            versions[tool] = (proc.stdout or proc.stderr).strip()[:80] or "unknown"
        except (OSError, subprocess.SubprocessError):
            versions[tool] = "unknown"
    return versions


def run_scan(domain, mode="passive", only=None, exclude=None, timeout=10, operator="",
             note="", authorised=False, on_start=None, on_result=None,
             user_agent=DEFAULT_UA, headers=None, module_options=None) -> Report:
    domain, specs = prepare(domain, mode, only, exclude, authorised)
    timeout, user_agent, headers = validate_http_options(timeout, user_agent, headers)
    module_options = validate_module_options(module_options, specs)
    module_options["timeout"] = timeout
    selected_ids = {spec.id for spec in specs}

    started, t0 = _utc_now(), time.perf_counter()
    client = HttpClient(timeout=timeout, user_agent=user_agent, headers=headers)
    results = run_all(specs, client, domain, on_start, on_result, module_options)
    phases = {s.phase for s in specs}
    return Report(
        tool="osint-enum", version=__version__, run_id=uuid.uuid4().hex[:12], target=domain,
        mode="+".join(p for p in ("passive", "active") if p in phases),
        operator=operator, note=note, authorised=authorised,
        started_at=started, finished_at=_utc_now(),
        duration=round(time.perf_counter() - t0, 1),
        timeout=timeout, modules_selected=[s.id for s in specs],
        environment={"os": platform.platform(), "python": platform.python_version(),
                     "user_agent": user_agent, "custom_header_names": list(headers),
                     "module_options": _recorded_options(selected_ids, module_options),
                     "tools": _tool_versions(selected_ids),
                     "timestamps": "UTC"},
        results=results,
    )