# osint/security_headers.py
import re
from typing import NamedTuple
from urllib.parse import urlsplit

from osint.http_client import HttpClient
from osint.models import ScanError
from osint.service import normalize_target, validate_http_options

SECURITY_HEADERS = ("Strict-Transport-Security", "Content-Security-Policy",
                    "X-Frame-Options", "X-Content-Type-Options",
                    "Referrer-Policy", "Permissions-Policy")
LEAKY = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
         "X-Generator")
MAX_URL_LENGTH = 2048
MAX_VALUE_LENGTH = 500
SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
INVALID_URL = "enter a valid HTTP or HTTPS URL without credentials"


class HeaderRow(NamedTuple):
    name: str
    status: str
    value: str


def _display(value) -> str:
    """Valor seguro para terminal e informes: sin caracteres de control y acotado."""
    return CONTROL_RE.sub("?", str(value))[:MAX_VALUE_LENGTH]


def _validate_port(parts) -> None:
    try:
        port = parts.port
    except ValueError as exc:
        raise ScanError("URL contains an invalid port") from exc
    if port == 0:
        raise ScanError("URL contains an invalid port")


def _validate_host(host: str) -> None:
    if host == "localhost":
        return
    try:
        normalize_target(host)
    except ScanError as exc:
        raise ScanError(INVALID_URL) from exc


def check_url(url) -> str:
    if not isinstance(url, str):
        raise ScanError("URL must be text")
    url = url.strip()
    if (not url or len(url) > MAX_URL_LENGTH
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in url)):
        raise ScanError("URL must be at most 2048 characters and contain no "
                        "whitespace or control characters")
    try:
        parts = urlsplit(url if SCHEME_RE.match(url) else f"https://{url}")
    except ValueError as exc:
        raise ScanError(INVALID_URL) from exc
    if (parts.scheme not in ("http", "https") or not parts.hostname
            or parts.username or parts.password):
        raise ScanError(INVALID_URL)
    _validate_port(parts)
    _validate_host(parts.hostname)
    return parts.geturl()


def check_security_headers(url, timeout=10, client=None):
    """Devuelve (respuesta, cabeceras de seguridad, cabeceras que revelan tecnología)."""
    url = check_url(url)
    timeout, user_agent, headers = validate_http_options(timeout)
    client = client or HttpClient(timeout=timeout, user_agent=user_agent, headers=headers)
    response = client.get(url)
    received = response.headers
    rows = [HeaderRow(name, "present" if name in received else "missing",
                      _display(received.get(name, "-")))
            for name in SECURITY_HEADERS]
    leaks = [HeaderRow(name, "exposed", _display(received[name]))
             for name in LEAKY if name in received]
    return response, rows, leaks