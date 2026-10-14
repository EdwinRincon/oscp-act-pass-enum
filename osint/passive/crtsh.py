# osint/passive/crtsh.py
import re
from osint.base import Module

HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def belongs_to(name: str, domain: str) -> bool:
    return bool(HOST_RE.match(name)) and (name == domain or name.endswith("." + domain))


class CrtSh(Module):
    name, phase = "crt.sh", "passive"

    def __init__(self, client):
        self.client = client

    def run(self, domain):
        r = self.client.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
        
        if r.status_code == 404:
            return self.result(["SUBDOMAIN", "FIRST SEEN"], [])
        r.raise_for_status()
        seen = {}
        for entry in r.json():
            first = entry.get("not_before", "")[:10]
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lower()
                if belongs_to(name, domain):
                    seen[name] = min(seen.get(name, first), first)
        return self.result(["SUBDOMAIN", "FIRST SEEN"], sorted(seen.items()))