from __future__ import annotations

import logging
import re
import socket
from typing import Mapping

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger(__name__)

DEFAULT_UA = "Mozilla/5.0 (compatible; osint-enum/1.0)"
MAX_REDIRECTS = 5
DEFAULT_MAX_BYTES = 5 * 1024 * 1024
RETRY_STATUSES = (429, 502, 503, 504)

# RFC-1123 style hostname; underscores allowed (e.g. _dmarc, _acme-challenge).
_HOST_RE = re.compile(
    r"(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*"
    r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?",
    re.IGNORECASE,
)
_FORBIDDEN_PATH_CHARS = frozenset("\r\n \t")


class ResponseTooLarge(requests.exceptions.RequestException):
    """Raised when a response body exceeds the configured byte cap."""


def _build_retry(retries: int, raise_on_status: bool) -> Retry:
    return Retry(
        total=retries,
        read=0,
        connect=0,
        backoff_factor=0.5 if retries else 0,
        status_forcelist=RETRY_STATUSES,
        raise_on_status=raise_on_status,
    )


def is_resolution_error(error: BaseException) -> bool:
    """Walk the exception graph looking for a DNS resolution failure."""
    pending: list = [error]
    visited: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in visited:
            continue
        visited.add(id(current))
        if isinstance(current, socket.gaierror) or \
                type(current).__name__ == "NameResolutionError":
            return True
        pending.extend(getattr(current, "args", ()))
        for attribute in ("reason", "__cause__", "__context__"):
            nested = getattr(current, attribute, None)
            if nested is not None:
                pending.append(nested)
    return False


def _validate_target(domain: str, path: str) -> None:
    if not isinstance(domain, str) or not _HOST_RE.fullmatch(domain):
        raise ValueError(f"invalid host: {domain!r}")
    if not path.startswith("/") or any(c in _FORBIDDEN_PATH_CHARS for c in path):
        raise ValueError(f"invalid path: {path!r}")


class HttpClient:
    """Thin requests wrapper: shared session, retries, scheme/DNS caching.

    raise_on_status=True keeps the legacy behaviour (RetryError on 429/5xx
    once retries are exhausted). Set it to False to receive the response.
    """

    def __init__(
        self,
        timeout: int | float | tuple[float, float] = 10,
        user_agent: str = DEFAULT_UA,
        retries: int = 0,
        headers: Mapping[str, str] | None = None,
        raise_on_status: bool = True,
    ):
        self.timeout = timeout
        self._scheme: dict[str, str] = {}
        self._resolution_errors: dict[str, BaseException] = {}
        self.session = requests.Session()
        self.session.max_redirects = MAX_REDIRECTS
        adapter = HTTPAdapter(max_retries=_build_retry(retries, raise_on_status))
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.session.headers["User-Agent"] = user_agent
        self.session.headers.update(headers or {})

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def close(self) -> None:
        self.session.close()

    def get(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        return self.session.get(url, **kwargs)

    def get_capped(self, url: str, max_bytes: int = DEFAULT_MAX_BYTES,
                   **kwargs) -> requests.Response:
        """GET with a hard cap on body size; body is available via .content."""
        kwargs["stream"] = True
        response = self.get(url, **kwargs)
        try:
            declared = response.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise ResponseTooLarge(f"{declared} bytes exceeds {max_bytes}")
            body = bytearray()
            for chunk in response.iter_content(chunk_size=65536):
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise ResponseTooLarge(f"body exceeds {max_bytes} bytes")
            response._content = bytes(body)
            response._content_consumed = True
            return response
        except Exception:
            response.close()
            raise

    def get_site(self, domain: str, path: str = "/", **kwargs) -> requests.Response:
        _validate_target(domain, path)
        if domain in self._resolution_errors:
            raise self._resolution_errors[domain]

        schemes = [self._scheme[domain]] if domain in self._scheme else ["https", "http"]
        last: requests.exceptions.RequestException | None = None
        for scheme in schemes:
            try:
                response = self.get(f"{scheme}://{domain}{path}", **kwargs)
            except requests.exceptions.SSLError:
                raise
            except requests.exceptions.RequestException as exc:
                if is_resolution_error(exc):
                    self._resolution_errors[domain] = exc
                    raise
                last = exc
            else:
                self._scheme[domain] = scheme
                return response
        assert last is not None
        raise last