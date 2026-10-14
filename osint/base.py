from abc import ABC, abstractmethod

from osint.models import ModuleResult


class ScanContext:
    def __init__(self, client, options=None):
        self.client = client
        self.options = options or {}
        self.results = []

    def get(self, *args, **kwargs):
        return self.client.get(*args, **kwargs)

    def get_site(self, *args, **kwargs):
        return self.client.get_site(*args, **kwargs)


class Module(ABC):
    name: str = ""
    phase: str = ""

    @abstractmethod
    def run(self, domain: str) -> ModuleResult:
        """Return a ModuleResult. May raise; the runner isolates failures."""

    def result(self, headers, rows) -> ModuleResult:
        return ModuleResult(self.name, self.phase, "ok", list(headers), rows)