# osint/active/rustscan.py
import ipaddress
import re
import shutil
import subprocess

from osint.base import Module

DEFAULT_PORTS = "21,22,25,53,80,110,139,143,443,445,993,995,1433,3306,3389,5432,5900,8080,8443"
DEFAULT_EXECUTION_TIMEOUT = 60
MIN_EXECUTION_TIMEOUT, MAX_EXECUTION_TIMEOUT = 10, 300
DEFAULT_BATCH, MIN_BATCH, MAX_BATCH = 500, 10, 4500
CONNECT_TIMEOUT_MS = 1500
ULIMIT = 5000

HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
PORT_RE = re.compile(r"[0-9]{1,5}")
GREPPABLE_RE = re.compile(r"->\s*\[([0-9,\s]*)\]")
LEGACY_OPEN_RE = re.compile(r"\bOpen\s+(?:[^\s:]+:)?(\d{1,5})\b", re.I)


def validate_target(target):
    value = str(target).strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if not HOST_RE.fullmatch(value) or ".." in value:
        raise ValueError(f"invalid port-scan target: {value!r}")
    return value


def normalize_ports(value):
    parts = [part.strip() for part in str(value).split(",") if part.strip()]
    if not parts or not all(PORT_RE.fullmatch(p) and 1 <= int(p) <= 65535 for p in parts):
        raise ValueError("ports must be a comma-separated list of numbers from 1 to 65535")
    return ",".join(parts)


def bounded_int(value, low, high, default):
    if type(value) is not int:
        return default
    return max(low, min(high, value))


def build_command(executable, host, ports, batch):
    return [executable, "-a", host, "-p", ports, "-g",
            "--timeout", str(CONNECT_TIMEOUT_MS),
            "--batch-size", str(batch),
            "--ulimit", str(ULIMIT)]


def parse_open_ports(stdout):
    found = set()
    for chunk in GREPPABLE_RE.findall(stdout):
        found.update(int(p) for p in re.findall(r"\d+", chunk))
    if not found:  # compatibilidad con salidas antiguas
        found.update(int(p) for p in LEGACY_OPEN_RE.findall(stdout))
    return sorted(p for p in found if 1 <= p <= 65535)


class RustScan(Module):
    name, phase = "RustScan port discovery", "active"

    def __init__(self, context):
        self.context = context

    def run(self, target):
        executable = shutil.which("rustscan")
        if not executable:
            raise RuntimeError("rustscan is not installed or is not on PATH")

        options = self.context.options
        try:
            host = validate_target(target)
            ports = normalize_ports(options.get("rustscan_ports") or DEFAULT_PORTS)
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc
        timeout = bounded_int(options.get("rustscan_timeout"), MIN_EXECUTION_TIMEOUT,
                              MAX_EXECUTION_TIMEOUT, DEFAULT_EXECUTION_TIMEOUT)
        batch = bounded_int(options.get("rustscan_batch"), MIN_BATCH, MAX_BATCH, DEFAULT_BATCH)

        stdout = self._execute(build_command(executable, host, ports, batch), timeout)
        open_ports = parse_open_ports(stdout)
        return self.result(["PORT", "STATE"], [(port, "open") for port in open_ports])

    @staticmethod
    def _execute(command, timeout):
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                                    text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"rustscan exceeded the {timeout}-second execution limit") from exc
        if result.returncode:
            detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic output"
            raise RuntimeError(f"rustscan exited with status {result.returncode}: {detail[:240]}")
        return result.stdout