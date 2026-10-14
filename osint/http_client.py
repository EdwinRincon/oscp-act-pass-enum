# osint/http_client.py
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_UA = "Mozilla/5.0 (compatible; osint-enum/1.0)"


class HttpClient:
    def __init__(self, timeout: int = 10, user_agent: str = DEFAULT_UA,
                 retries: int = 2, headers: dict | None = None):
        self.timeout = timeout
        self._scheme = {}  # domain -> scheme that worked last time
        self.session = requests.Session()
        retry = Retry(total=retries, read=0, connect=0, backoff_factor=1,
                      status_forcelist=(429, 502, 503, 504))
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.session.headers["User-Agent"] = user_agent
        self.session.headers.update(headers or {})

    def get(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        return self.session.get(url, **kwargs)

    def get_site(self, domain: str, path: str = "/", **kwargs) -> requests.Response:
        schemes = [self._scheme[domain]] if domain in self._scheme else ["https", "http"]
        last = None
        for scheme in schemes:
            try:
                response = self.get(f"{scheme}://{domain}{path}", **kwargs)
                self._scheme[domain] = scheme
                return response
            except requests.exceptions.RequestException as exc:
                last = exc
        raise last