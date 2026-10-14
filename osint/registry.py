# osint/registry.py
from dataclasses import dataclass
from typing import Callable

from osint.active.dns_records import DnsRecords
from osint.active.fingerprint import Fingerprint
from osint.active.well_known import WellKnown
from osint.models import ScanError
from osint.passive.crtsh import CrtSh
from osint.passive.dork_links import DorkLinks
from osint.passive.wayback import Wayback
from osint.passive.whois_lookup import WhoisLookup


@dataclass(frozen=True)
class ModuleSpec:
    id: str
    title: str
    phase: str
    source: str
    kind: str
    confidence: str
    factory: Callable


SPECS = (
    ModuleSpec("whois", "WHOIS (RDAP)", "passive", "RDAP registry data via rdap.org",
               "finding", "High", WhoisLookup),
    ModuleSpec("crtsh", "Certificate Transparency", "passive", "crt.sh (third-party CT log search)",
               "finding", "Moderate", CrtSh),
    ModuleSpec("wayback", "Web archive", "passive", "archive.org Availability API",
               "finding", "Moderate", Wayback),
    ModuleSpec("dorks", "Search links", "passive", "generated links, no request sent",
               "lead", "n/a", lambda _client: DorkLinks()),
    ModuleSpec("dns", "DNS records", "active", "direct DNS query (system resolver)",
               "finding", "High", lambda _client: DnsRecords()),
    ModuleSpec("wellknown", "robots.txt / sitemap.xml", "active", "direct HTTP(S) request to target",
               "finding", "High", WellKnown),
    ModuleSpec("fingerprint", "Technology fingerprint", "active", "direct HTTP(S) request to target",
               "finding", "High", Fingerprint),
)


def select(mode="passive", only=None, exclude=None):
    known = {s.id for s in SPECS}
    for bad in set(only or []) | set(exclude or []):
        if bad not in known:
            raise ScanError(f"unknown module: {bad}")
    specs = [s for s in SPECS if mode == "all" or s.phase == mode]
    if only:
        specs = [s for s in specs if s.id in only]
    if exclude:
        specs = [s for s in specs if s.id not in exclude]
    return specs