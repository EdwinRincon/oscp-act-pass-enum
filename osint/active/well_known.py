# osint/active/well_known.py
import requests
from osint.base import Module

PATHS = ("/robots.txt", "/sitemap.xml")


class WellKnown(Module):
    name, phase = "well-known", "active"

    def __init__(self, client):
        self.client = client

    def run(self, domain):
        rows = []
        for path in PATHS:
            try:
                r = self.client.get_site(domain, path, timeout=5)
            except requests.exceptions.RequestException as exc:
                rows.append((path, "failed", type(exc).__name__))
                continue
            if r.status_code == 200:
                lines = [l for l in r.text.splitlines() if l.strip() and not l.startswith("#")]
                rows.append((path, "open", f"{len(lines)} entries ({r.url.split(':')[0]})"))
                if path == "/robots.txt":
                    rows += [("", "", l.strip()) for l in lines
                             if l.lower().startswith(("disallow:", "allow:"))]
            else:
                rows.append((path, "closed", f"HTTP {r.status_code}"))
        return self.result(["PATH", "STATE", "NOTE"], rows)