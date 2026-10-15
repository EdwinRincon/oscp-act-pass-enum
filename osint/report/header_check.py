import platform
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

try:
    from datetime import UTC
except ImportError:  # Python 3.10
    UTC = timezone.utc  # noqa: UP017

from osint import __version__
from osint.models import ModuleResult, Report, Status
from osint.security_headers import report_rows


def _utc_now():
    return datetime.now(UTC).isoformat(timespec="seconds")


def build_header_report(response, rows, leaks, timeout=10):
    headers, report_rows_data = report_rows(response, rows, leaks)
    started = _utc_now()
    target = urlsplit(response.url).hostname or response.url
    result = ModuleResult(
        name="HTTP security headers",
        phase="active",
        status=Status.OK,
        headers=headers,
        rows=report_rows_data,
        id="security_headers",
        source="Direct HTTP(S) request to the target",
        confidence="High",
        started_at=started,
    )
    return Report(
        tool="osint-enum",
        version=__version__,
        run_id=uuid.uuid4().hex[:12],
        target=target,
        mode="active web configuration",
        operator="",
        note="",
        authorised=True,
        started_at=started,
        finished_at=_utc_now(),
        duration=0.0,
        timeout=timeout,
        modules_selected=["security_headers"],
        environment={
            "os": platform.platform(),
            "python": platform.python_version(),
            "timestamps": "UTC",
        },
        results=[result],
    )
