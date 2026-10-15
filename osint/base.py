from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Iterable, Protocol

import requests

from osint.models import ModuleResult, Status


class HttpClientLike(Protocol):
    """Minimal HTTP surface modules depend on (eases faking in tests)."""

    def get(self, url: str, **kwargs: Any) -> requests.Response: ...

    def get_site(self, domain: str, path: str = "/", **kwargs: Any) -> requests.Response: ...


@dataclass
class ScanContext:
    client: HttpClientLike
    options: dict[str, Any] | None = None
    results: list[ModuleResult] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.options = self.options or {}

    def get(self, *args, **kwargs):
        return self.client.get(*args, **kwargs)

    def get_site(self, *args, **kwargs):
        return self.client.get_site(*args, **kwargs)


class Module(ABC):
    name: str = ""
    phase: str = ""

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        run = cls.__dict__.get("run")
        is_concrete = run is not None and not getattr(run, "__isabstractmethod__", False)
        if is_concrete and not (cls.name and cls.phase):
            raise TypeError(f"{cls.__name__} must define non-empty `name` and `phase`")

    @abstractmethod
    def run(self, domain: str) -> ModuleResult:
        """Return a ModuleResult. May raise; the runner isolates failures."""

    def result(self, headers: Iterable[str], rows: list) -> ModuleResult:
        return ModuleResult(self.name, self.phase, Status.OK, list(headers), rows)