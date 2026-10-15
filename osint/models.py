from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

try:
    from enum import StrEnum  # Python 3.11+
except ImportError:  # pragma: no cover
    from enum import Enum

    class StrEnum(str, Enum):
        def __str__(self) -> str:
            return str(self.value)


class ScanError(ValueError):
    """User-facing validation error (bad domain, missing authorisation, ...)."""


class Status(StrEnum):
    OK = "ok"
    FAILED = "failed"
    SKIPPED = "skipped"


class Kind(StrEnum):
    FINDING = "finding"
    LEAD = "lead"


@dataclass
class ModuleResult:
    name: str
    phase: str
    status: str = Status.OK            # ok | failed | skipped
    headers: list[str] = field(default_factory=list)
    rows: list[Any] = field(default_factory=list)
    error: str = ""
    elapsed: float = 0.0
    id: str = ""
    source: str = ""
    kind: str = Kind.FINDING           # finding | lead
    confidence: str = ""               # High | Moderate | n/a
    started_at: str = ""               # UTC, ISO-8601


@dataclass
class Report:
    tool: str
    version: str
    run_id: str
    target: str
    mode: str
    operator: str
    note: str
    authorised: bool
    started_at: str
    finished_at: str
    duration: float
    timeout: int
    modules_selected: list[str]
    environment: dict[str, Any]
    results: list[ModuleResult]
    integrity: dict[str, Any] = field(default_factory=dict)