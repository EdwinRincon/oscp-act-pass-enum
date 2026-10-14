# osint/passive/dork_links.py
from urllib.parse import quote_plus
from osint.base import Module


class DorkLinks(Module):
    """Builds search URLs only. Nothing is requested or scraped."""
    name, phase = "dork-links", "passive"

    def run(self, domain):
        q = quote_plus
        g = "https://www.google.com/search?q="
        links = [
            ("google", g + q(f"site:{domain} filetype:pdf")),
            ("google", g + q(f"site:{domain} inurl:admin")),
            ("google", g + q(f'site:{domain} intitle:"Index of"')),
            ("google", g + q(f'site:{domain} intext:"password" | intext:"contraseña"')),
            ("github", f"https://github.com/search?type=code&q={q(domain)}"),
            ("pastebin", g + q(f"site:pastebin.com {domain}")),
            ("shodan", f"https://www.shodan.io/search?query={q('hostname:' + domain)}"),
            ("censys", f"https://search.censys.io/certificates?q={q(domain)}"),
            ("zoomeye", f"https://www.zoomeye.org/searchResult?q={q(domain)}"),
            ("dnsdumpster", "https://dnsdumpster.com/"),
            ("archive.ph", f"https://archive.ph/{domain}"),
        ]
        return self.result(["TOOL", "URL"], links)