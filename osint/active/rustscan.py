import re
import shutil
import subprocess

from osint.base import Module

DEFAULT_PORTS = "21,22,25,53,80,110,139,143,443,445,993,995,1433,3306,3389,5432,5900,8080,8443"
DEFAULT_EXECUTION_TIMEOUT = 60
MIN_EXECUTION_TIMEOUT = 10
MAX_EXECUTION_TIMEOUT = 300
CONNECT_TIMEOUT_MS = 1500
OPEN_PORT_RE = re.compile(r"\bOpen\s+(?:[^\s:]+:)?(\d{1,5})\b", re.I)


class RustScan(Module):
    name, phase = "RustScan port discovery", "active"

    def __init__(self, context):
        self.context = context

    def run(self, target):
        executable = shutil.which("rustscan")
        if not executable:
            raise RuntimeError("rustscan is not installed or is not on PATH")

        ports = self.context.options.get("rustscan_ports", DEFAULT_PORTS)
        timeout = self.context.options.get("rustscan_timeout", DEFAULT_EXECUTION_TIMEOUT)
        command = [executable, "-a", target, "-p", ports, "--timeout",
                   str(CONNECT_TIMEOUT_MS),
                   "--ulimit", "5000"]
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                                    text=True, timeout=timeout,
                                    check=False)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"rustscan exceeded the configured {timeout}-second execution limit") from exc
        if result.returncode:
            detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic output"
            raise RuntimeError(f"rustscan exited with status {result.returncode}: {detail[:240]}")

        ports_found = sorted({int(port) for port in OPEN_PORT_RE.findall(result.stdout)})
        return self.result(["PORT", "STATE"], [(port, "open") for port in ports_found])
