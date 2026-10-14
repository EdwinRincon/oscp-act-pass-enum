# osint/passive/whois_lookup.py
from osint.base import Module


class WhoisLookup(Module):
    name, phase = "whois (RDAP)", "passive"

    def __init__(self, client):
        self.client = client

    def run(self, domain):
        labels = domain.split(".")
        data, queried = None, ""
        for i in range(len(labels) - 1):
            queried = ".".join(labels[i:])
            r = self.client.get(f"https://rdap.org/domain/{queried}")
            if r.status_code == 200:
                data = r.json()
                break
        if data is None:
            raise RuntimeError("no RDAP record found")
        rows = [("queried", queried), ("status", ", ".join(data.get("status", [])) or "-")]
        for ev in data.get("events", []):
            rows.append((ev.get("eventAction", "event"), ev.get("eventDate", "-")))
        for ent in data.get("entities", []):
            if "registrar" in ent.get("roles", []):
                vcard = ent.get("vcardArray", [None, []])[1]
                rows.append(("registrar", next((v[3] for v in vcard if v[0] == "fn"), "-")))
        for ns in data.get("nameservers", []):
            rows.append(("nameserver", ns.get("ldhName", "-").lower()))
        return self.result(["FIELD", "VALUE"], rows)