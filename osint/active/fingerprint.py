# osint/active/fingerprint.py
import re
from osint.base import Module

GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
SIGNALS = ("Server", "X-Powered-By", "Via", "X-Generator")


class Fingerprint(Module):
    name, phase = "fingerprint", "active"

    def __init__(self, client):
        self.client = client

    def run(self, domain):
        r = self.client.get_site(domain, timeout=5)
        rows = [("url", r.url), ("status", f"HTTP {r.status_code}")]
        if r.url.startswith("http://"):
            rows.append(("tls", "HTTPS unavailable, fell back to HTTP"))
        for h in SIGNALS:
            if h in r.headers:
                rows.append((h.lower(), r.headers[h]))
        m = GENERATOR.search(r.text)
        if m:
            rows.append(("meta-generator", m.group(1)))
        rows += [("cookie", c.name) for c in r.cookies]
        return self.result(["SIGNAL", "VALUE"], rows)