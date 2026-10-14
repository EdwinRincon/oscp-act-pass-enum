# osint/models.py
from dataclasses import dataclass, field


class ScanError(ValueError):
    """User-facing validation error (bad domain, missing authorisation, ...)."""


@dataclass
class ModuleResult:
    name: str
    phase: str
    status: str = "ok"            # ok | failed | skipped
    headers: list = field(default_factory=list)
    rows: list = field(default_factory=list)
    error: str = ""
    elapsed: float = 0.0
    id: str = ""
    source: str = ""
    kind: str = "finding"         # finding | lead
    confidence: str = ""          # High | Moderate | n/a
    started_at: str = ""          # UTC, ISO-8601


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
    modules_selected: list
    environment: dict
    results: list
    integrity: dict = field(default_factory=dict)