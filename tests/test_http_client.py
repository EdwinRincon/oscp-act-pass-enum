import json
import socket
from dataclasses import asdict

import pytest
import requests

from osint.base import Module, ScanContext
from osint.http_client import HttpClient, ResponseTooLarge, is_resolution_error
from osint.models import ModuleResult, Status


class Boom(requests.exceptions.RequestException):
    pass


class FakeResponse:
    def __init__(self, chunks, headers=None):
        self._chunks = chunks
        self.headers = headers or {}
        self.closed = False

    def iter_content(self, chunk_size=1):
        yield from self._chunks

    def close(self):
        self.closed = True


def make_client(monkeypatch, behaviour):
    client = HttpClient()
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return behaviour(url)

    monkeypatch.setattr(client, "get", fake_get)
    return client, calls


# --- get_site: scheme selection and caching -------------------------------

def test_https_first_then_scheme_cached(monkeypatch):
    client, calls = make_client(monkeypatch, lambda url: object())
    client.get_site("example.com")
    client.get_site("example.com")
    assert calls == ["https://example.com/", "https://example.com/"]


def test_falls_back_to_http_and_caches_it(monkeypatch):
    def behaviour(url):
        if url.startswith("https"):
            raise Boom("down")
        return object()

    client, calls = make_client(monkeypatch, behaviour)
    client.get_site("example.com")
    assert calls == ["https://example.com/", "http://example.com/"]
    client.get_site("example.com")
    assert calls[-1] == "http://example.com/"
    assert len(calls) == 3


def test_all_schemes_fail_raises_last_error(monkeypatch):
    def behaviour(url):
        raise Boom("down")

    client, calls = make_client(monkeypatch, behaviour)
    with pytest.raises(Boom):
        client.get_site("example.com")
    assert len(calls) == 2


def test_ssl_error_does_not_fall_back(monkeypatch):
    def behaviour(url):
        raise requests.exceptions.SSLError("bad cert")

    client, calls = make_client(monkeypatch, behaviour)
    with pytest.raises(requests.exceptions.SSLError):
        client.get_site("example.com")
    assert len(calls) == 1


def test_dns_failure_is_cached(monkeypatch):
    def behaviour(url):
        raise requests.exceptions.ConnectionError(socket.gaierror("nx"))

    client, calls = make_client(monkeypatch, behaviour)
    for _ in range(2):
        with pytest.raises(requests.exceptions.ConnectionError):
            client.get_site("nx.example")
    assert len(calls) == 1


# --- get_site: input validation -------------------------------------------

@pytest.mark.parametrize(
    "host", ["", "a/b", "x\r\ny", "-bad.com", "a b.com", "example.com\n"]
)
def test_invalid_host_rejected(host):
    with pytest.raises(ValueError):
        HttpClient().get_site(host)


@pytest.mark.parametrize("host", ["example.com", "sub.example.co.uk", "_dmarc.example.com"])
def test_valid_hosts_accepted(monkeypatch, host):
    client, calls = make_client(monkeypatch, lambda url: object())
    client.get_site(host)
    assert calls == [f"https://{host}/"]


@pytest.mark.parametrize("path", ["no-slash", "/a b", "/a\r\nHost: x", "/tab\there"])
def test_invalid_path_rejected(path):
    with pytest.raises(ValueError):
        HttpClient().get_site("example.com", path)


# --- is_resolution_error --------------------------------------------------

def test_is_resolution_error_detects_nested_gaierror():
    wrapped = requests.exceptions.ConnectionError(socket.gaierror("nx"))
    assert is_resolution_error(wrapped)


def test_is_resolution_error_ignores_other_errors():
    assert not is_resolution_error(requests.exceptions.Timeout("slow"))


def test_old_private_name_is_gone():
    assert not hasattr(HttpClient, "_is_resolution_error")


# --- get_capped -----------------------------------------------------------

def test_get_capped_rejects_oversized_body(monkeypatch):
    client = HttpClient()
    fake = FakeResponse([b"x" * 600, b"x" * 600])
    monkeypatch.setattr(client, "get", lambda url, **kw: fake)
    with pytest.raises(ResponseTooLarge):
        client.get_capped("https://example.com", max_bytes=1000)
    assert fake.closed


def test_get_capped_rejects_declared_length(monkeypatch):
    client = HttpClient()
    fake = FakeResponse([b"x"], {"Content-Length": "999999"})
    monkeypatch.setattr(client, "get", lambda url, **kw: fake)
    with pytest.raises(ResponseTooLarge):
        client.get_capped("https://example.com", max_bytes=1000)
    assert fake.closed


def test_get_capped_returns_body_within_limit(monkeypatch):
    client = HttpClient()
    fake = FakeResponse([b"abc", b"def"])
    monkeypatch.setattr(client, "get", lambda url, **kw: fake)
    response = client.get_capped("https://example.com", max_bytes=1000)
    assert response is fake
    assert fake._content == b"abcdef"
    assert not fake.closed


# --- lifecycle ------------------------------------------------------------

def test_context_manager_closes_session(monkeypatch):
    closed = []
    with HttpClient() as client:
        monkeypatch.setattr(client.session, "close", lambda: closed.append(True))
    assert closed == [True]


# --- models and base ------------------------------------------------------

def test_result_json_is_unchanged():
    result = ModuleResult("n", "passive")
    data = json.loads(json.dumps(asdict(result)))
    assert data["status"] == "ok" and data["kind"] == "finding"
    assert result.status == "ok"


def test_module_requires_name_and_phase():
    with pytest.raises(TypeError):
        class Bad(Module):
            def run(self, domain):
                return ModuleResult("x", "y")


def test_module_result_helper_and_fake_client():
    class Good(Module):
        name, phase = "good", "passive"

        def run(self, domain):
            return self.result(["h"], [["r"]])

    class FakeClient:
        def get(self, url, **kw): ...
        def get_site(self, domain, path="/", **kw): ...

    ctx = ScanContext(FakeClient())
    assert ctx.options == {}
    result = Good().run("example.com")
    assert result.status == Status.OK
    assert result.headers == ["h"] and result.rows == [["r"]]