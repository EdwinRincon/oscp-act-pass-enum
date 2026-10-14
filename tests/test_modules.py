# tests/test_modules.py
import io
import unittest
from unittest.mock import patch

import dns.resolver

from osint.active.dns_records import DnsRecords
from osint.active.well_known import WellKnown
from osint.http_client import DEFAULT_UA, HttpClient
from osint.models import Report, ScanError
from osint.passive.crtsh import CrtSh, belongs_to
from osint.report.console import Console
from osint.report.serialize import to_dict, verify
from osint.service import run_scan, validate_http_options


class FakeResponse:
    def __init__(self, status=200, text="", data=None):
        self.status_code, self.text, self._data = status, text, data
        self.url = "http://fake/"

    def json(self):
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(self.status_code)


class FakeClient:
    def __init__(self, response):
        self.response = response

    def get(self, *args, **kwargs):
        return self.response

    get_site = get


class CrtShTests(unittest.TestCase):
    def test_belongs_to(self):
        self.assertTrue(belongs_to("www.example.com", "example.com"))
        self.assertFalse(belongs_to("m.testexample.com", "example.com"))
        self.assertFalse(belongs_to("user@example.com", "example.com"))

    def test_filters_noise_and_wildcards(self):
        data = [{"name_value": "www.example.com\nuser@example.com\n*.example.com",
                 "not_before": "2020-01-01T00:00:00"}]
        res = CrtSh(FakeClient(FakeResponse(data=data))).run("example.com")
        self.assertEqual(res.rows, [("www.example.com", "2020-01-01")])

    def test_404_means_no_data(self):
        res = CrtSh(FakeClient(FakeResponse(status=404))).run("example.com")
        self.assertEqual(res.rows, [])


class DnsTests(unittest.TestCase):
    @patch("osint.active.dns_records.dns.resolver.resolve",
           side_effect=dns.resolver.NXDOMAIN())
    def test_nxdomain_is_reported(self, _):
        res = DnsRecords().run("nope.invalid")
        self.assertIn("NXDOMAIN", res.rows[0][1])


class WellKnownTests(unittest.TestCase):
    def test_robots_open_with_rules(self):
        text = "User-agent: *\nDisallow: /admin\n"
        res = WellKnown(FakeClient(FakeResponse(text=text))).run("example.com")
        self.assertEqual(res.rows[0][:2], ("/robots.txt", "open"))
        self.assertTrue(any("Disallow: /admin" in row[2] for row in res.rows))

    def test_404_is_closed(self):
        res = WellKnown(FakeClient(FakeResponse(status=404))).run("example.com")
        self.assertEqual(res.rows[0][1], "closed")


class ConsoleTests(unittest.TestCase):
    def test_columns_are_aligned(self):
        buf = io.StringIO()
        Console(color=False, stream=buf).table(["A", "B"], [("x", "1"), ("longer", "2")])
        lines = buf.getvalue().splitlines()
        self.assertEqual(lines[1].index("1"), lines[2].index("2"))


class IntegrityTests(unittest.TestCase):
    def test_hash_detects_tampering(self):
        rep = Report("osint-enum", "1.1", "abc", "example.com", "passive", "", "", False,
                     "t0", "t1", 0.1, 10, ["dns"], {}, [])
        data = to_dict(rep)
        self.assertTrue(verify(data))
        data["target"] = "evil.com"
        self.assertFalse(verify(data))


class HttpConfigurationTests(unittest.TestCase):
    def test_timeout_range_is_shared_and_enforced(self):
        self.assertEqual(validate_http_options(3)[0], 3)
        self.assertEqual(validate_http_options(30)[0], 30)
        for timeout in (2, 31, "10", True):
            with self.subTest(timeout=timeout), self.assertRaises(ScanError):
                validate_http_options(timeout)

    def test_custom_headers_are_validated_and_normalized(self):
        _, user_agent, headers = validate_http_options(
            10, "  test-agent  ", ["X-Engagement: exercise"])
        self.assertEqual(user_agent, "test-agent")
        self.assertEqual(headers, {"X-Engagement": "exercise"})
        for lines in (["X-Test: first", "x-test: second"], ["Host: example.com"],
                      ["X-Test: safe\r\nInjected: yes"], ["Bad Name: value"]):
            with self.subTest(lines=lines), self.assertRaises(ScanError):
                validate_http_options(10, headers=lines)

    def test_http_client_applies_user_agent_and_custom_headers(self):
        client = HttpClient(user_agent="practice-agent", headers={"X-Engagement": "lab"})
        self.assertEqual(client.session.headers["User-Agent"], "practice-agent")
        self.assertEqual(client.session.headers["X-Engagement"], "lab")

    @patch("osint.service.run_all", return_value=[])
    def test_report_records_effective_agent_and_header_names_only(self, _):
        report = run_scan("example.com", only=["dorks"], user_agent="practice-agent",
                          headers=["X-Engagement: private-value"])
        self.assertEqual(report.environment["user_agent"], "practice-agent")
        self.assertEqual(report.environment["custom_header_names"], ["X-Engagement"])
        self.assertNotIn("private-value", str(report.environment))
        self.assertEqual(DEFAULT_UA, HttpClient().session.headers["User-Agent"])


if __name__ == "__main__":
    unittest.main()