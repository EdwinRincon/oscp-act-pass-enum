# osint/passive/wayback.py
from osint.base import Module

API = "https://archive.org/wayback/available"


class Wayback(Module):
    name, phase = "wayback", "passive"

    def __init__(self, client):
        self.client = client

    def _closest(self, domain, timestamp=None):
        params = {"url": domain}
        if timestamp:
            params["timestamp"] = timestamp
        r = self.client.get(API, params=params, timeout=15)
        r.raise_for_status()
        snap = r.json().get("archived_snapshots", {}).get("closest")
        return snap if snap and snap.get("available") else None

    def run(self, domain):
        rows = []
        for label, ts in (("first (approx.)", "19960101"), ("latest", None)):
            snap = self._closest(domain, ts)
            if snap:
                t = snap["timestamp"]
                rows.append((label, f"{t[:4]}-{t[4:6]}-{t[6:8]}",
                             snap.get("status", "-"), snap["url"]))
        rows.append(("all snapshots", "-", "-", f"https://web.archive.org/web/*/{domain}"))
        if len(rows) == 1:
            rows.insert(0, ("result", "-", "-",
                            "API returned no snapshot (inconclusive; check the link)"))
        return self.result(["WHEN", "DATE", "HTTP", "URL"], rows)