# osint/registry.py
from __future__ import annotations

import shutil
from dataclasses import dataclass
from typing import Callable

from osint.active.dns_records import DnsRecords
from osint.active.fingerprint import Fingerprint
from osint.active.rustscan import RustScan
from osint.active.security_headers import SecurityHeaders
from osint.active.well_known import WellKnown
from osint.base import Module, ScanContext
from osint.models import ScanError
from osint.passive.crtsh import CrtSh
from osint.passive.dork_links import DorkLinks
from osint.passive.searchsploit import SearchSploit
from osint.passive.wayback import Wayback
from osint.passive.whois_lookup import WhoisLookup

MODES = ("passive", "active", "all")


@dataclass(frozen=True)
class ModuleSpec:
    id: str
    title: str
    phase: str
    source: str
    kind: str
    confidence: str
    factory: Callable[[ScanContext], Module]
    executable: str = ""
    opt_in: bool = False     # solo se ejecuta con --only (intrusivo)
    requires: tuple[str, ...] = ()  # ids de módulos cuyo resultado necesita


# El orden importa: los módulos con `requires` van después de sus dependencias.
SPECS = (
    ModuleSpec("whois", "WHOIS (RDAP)", "passive", "RDAP registry data via rdap.org",
               "finding", "High", WhoisLookup),
    ModuleSpec("crtsh", "Certificate Transparency", "passive",
               "crt.sh (third-party CT log search)", "finding", "Moderate", CrtSh),
    ModuleSpec("wayback", "Web archive", "passive", "archive.org Availability API",
               "finding", "Moderate", Wayback),
    ModuleSpec("dorks", "Search links", "passive", "generated links, no request sent",
               "lead", "n/a", lambda _context: DorkLinks()),
    ModuleSpec("dns", "DNS records", "active", "direct DNS query (system resolver)",
               "finding", "High", lambda _context: DnsRecords()),
    ModuleSpec("wellknown", "robots.txt / sitemap.xml", "active",
               "direct HTTP(S) request to target", "finding", "High", WellKnown),
    ModuleSpec("fingerprint", "Technology fingerprint", "active",
               "direct HTTP(S) request to target", "finding", "High", Fingerprint),
    ModuleSpec("security_headers", "HTTP security headers", "active",
               "direct HTTP(S) request to target", "finding", "High",
               SecurityHeaders, opt_in=True),
    ModuleSpec("rustscan", "RustScan port discovery", "active",
               "external port scanner; selected ports only", "finding", "High",
               RustScan, executable="rustscan", opt_in=True),
    ModuleSpec("searchsploit", "SearchSploit references", "passive",
               "local Exploit-DB database; searches detected banners",
               "finding", "Moderate", SearchSploit,
               executable="searchsploit", requires=("fingerprint",)),
)


def validate_specs(specs) -> None:
    """Falla pronto ante ids duplicados, dependencias desconocidas o mal ordenadas."""
    ids = [s.id for s in specs]
    duplicated = sorted({i for i in ids if ids.count(i) > 1})
    if duplicated:
        raise ValueError(f"duplicate module id(s): {', '.join(duplicated)}")
    seen: set[str] = set()
    known = set(ids)
    for spec in specs:
        unknown = set(spec.requires) - known
        if unknown:
            raise ValueError(f"{spec.id} requires unknown module(s): {', '.join(sorted(unknown))}")
        if not set(spec.requires) <= seen:
            raise ValueError(f"{spec.id} must be listed after its dependencies")
        seen.add(spec.id)


validate_specs(SPECS)


def is_available(spec):
    return not spec.executable or bool(shutil.which(spec.executable))


def _phases(mode):
    return {"passive", "active"} if mode == "all" else {mode}


def candidates(mode):
    """Módulos que el usuario puede elegir para un perfil (solo los disponibles)."""
    phases = _phases(mode)
    return [s for s in SPECS if s.phase in phases and is_available(s)]


def unavailable(mode):
    """Módulos del perfil cuya herramienta externa no está instalada."""
    phases = _phases(mode)
    return [s for s in SPECS if s.phase in phases and not is_available(s)]


def default_ids(mode):
    return {s.id for s in select(mode)}


def select(mode="passive", only=None, exclude=None):
    if mode not in MODES:
        raise ScanError(f"unknown mode: {mode} (expected one of {', '.join(MODES)})")
    only, exclude = set(only or ()), set(exclude or ())
    unknown = (only | exclude) - {s.id for s in SPECS}
    if unknown:
        raise ScanError(f"unknown module(s): {', '.join(sorted(unknown))}")
    if only & exclude:
        raise ScanError(
            f"module(s) both included and excluded: {', '.join(sorted(only & exclude))}")
    if only:
        return [s for s in SPECS if s.id in only]

    phases = _phases(mode)
    base_ids = {s.id for s in SPECS
                if s.phase in phases and not s.opt_in and not s.requires
                and s.id not in exclude}
    selected = []
    for spec in SPECS:
        if spec.id in base_ids:
            selected.append(spec)
        elif (spec.requires and not spec.opt_in and spec.id not in exclude
              and set(spec.requires) <= base_ids and is_available(spec)):
            selected.append(spec)
    return selected