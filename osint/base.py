from abc import ABC, abstractmethod
from osint.models import ModuleResult


class Module(ABC):
    name: str = ""
    phase: str = ""

    @abstractmethod
    def run(self, domain: str) -> ModuleResult:
        """Return a ModuleResult. May raise; the runner isolates failures."""

    def result(self, headers, rows) -> ModuleResult:
        return ModuleResult(self.name, self.phase, "ok", list(headers), rows)