# osint/active/dns_records.py
import dns.exception
import dns.resolver
from osint.base import Module

TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA")


class DnsRecords(Module):
    name, phase = "dns", "active"

    def run(self, domain):
        rows = []
        for rtype in TYPES:
            try:
                for rdata in dns.resolver.resolve(domain, rtype, lifetime=5):
                    rows.append((rtype, rdata.to_text()))
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                rows.append(("-", "NXDOMAIN (domain does not exist)"))
                break
            except dns.exception.DNSException as exc:
                rows.append((rtype, f"error: {type(exc).__name__}"))
        return self.result(["TYPE", "VALUE"], rows)