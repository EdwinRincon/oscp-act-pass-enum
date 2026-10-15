# tests/test_modules.py
import io
import json
import socket
import subprocess
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import dns.resolver
import requests

from enum_tool import ScanArgs, app, run_wizard
from osint.active.dns_records import DnsRecords
from osint.active.rustscan import (DEFAULT_BATCH, DEFAULT_EXECUTION_TIMEOUT,
                                   DEFAULT_PORTS, RustScan, normalize_ports,
                                   parse_open_ports, validate_target)
from osint.active.well_known import WellKnown
from osint.http_client import DEFAULT_UA, HttpClient
from osint.models import ModuleResult, Report, ScanError
from osint.passive.crtsh import CrtSh, belongs_to
from osint.passive.searchsploit import SearchSploit, inferred_queries
from osint.report.console import Console
from osint.report.serialize import to_dict, verify
from osint.registry import ModuleSpec, select
from osint.runner import INTERRUPTED, order_by_dependencies, run_all
from osint.service import (normalize_target, prepare, run_scan,
                           validate_http_options, validate_module_options)
from osint.security_headers import check_security_headers, check_url
from osint.user_agent_capture import UserAgentCapture
from osint.web.app import make_server
from typer.testing import CliRunner


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


class UtilityToolTests(unittest.TestCase):
    def test_header_check_normalizes_url_and_rejects_non_http_schemes(self):
        self.assertEqual(check_url("example.com"), "https://example.com")
        with self.assertRaisesRegex(ScanError, "HTTP or HTTPS"):
            check_url("file:///etc/passwd")

    @patch("osint.security_headers.HttpClient")
    def test_header_check_reports_security_and_disclosure_headers(self, client_class):
        response = FakeResponse()
        response.url = "https://example.com/"
        response.status_code = 200
        response.headers = {"Strict-Transport-Security": "max-age=1", "Server": "example"}
        client_class.return_value.get.return_value = response
        checked, rows, leaks = check_security_headers("example.com")
        self.assertEqual(checked, response)
        self.assertEqual(rows[0], ("Strict-Transport-Security", "present", "max-age=1"))
        self.assertEqual(leaks, [("Server", "exposed", "example")])

    def test_user_agent_capture_logs_requests_and_stops(self):
        with tempfile.TemporaryDirectory() as directory:
            log_file = Path(directory) / "agents.log"
            capture = UserAgentCapture(log_file=log_file, console=Console(stream=io.StringIO()))
            address = capture.start(port=0)
            try:
                response = requests.get(
                    f"http://127.0.0.1:{address['port']}/capture",
                    headers={"User-Agent": "test-agent"}, timeout=2)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(capture.events()[0]["user_agent"], "test-agent")
                self.assertIn("test-agent", log_file.read_text(encoding="utf-8"))
            finally:
                capture.stop()
            self.assertFalse(capture.running)

    def test_web_header_check_endpoint_uses_shared_checker(self):
        server = make_server("127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        with patch("osint.web.app.check_security_headers") as checker:
            checker.return_value = (FakeResponse(), [("X", "present", "yes")], [])
            try:
                response = requests.post(
                    f"http://127.0.0.1:{port}/api/headers",
                    json={"url": "example.com"}, timeout=2)
            finally:
                server.shutdown()
                server.server_close()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["rows"], [["X", "present", "yes"]])

    def test_web_user_agent_api_starts_and_stops_loopback_server(self):
        server = make_server("127.0.0.1", 0)
        with tempfile.TemporaryDirectory() as directory:
            server.user_agent_capture = UserAgentCapture(
                log_file=Path(directory) / "agents.log",
                console=Console(stream=io.StringIO()))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_address[1]
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                capture_port = listener.getsockname()[1]
            try:
                started = requests.post(
                    f"http://127.0.0.1:{port}/api/user-agent/start",
                    json={"host": "127.0.0.1", "port": capture_port}, timeout=2)
                self.assertEqual(started.status_code, 200)
                captured = requests.get(f"http://127.0.0.1:{capture_port}/",
                                        headers={"User-Agent": "web-test"}, timeout=2)
                self.assertEqual(captured.status_code, 200)
                running = requests.get(f"http://127.0.0.1:{port}/api/user-agent", timeout=2)
                self.assertTrue(running.json()["running"])
                self.assertEqual(running.json()["events"][0]["user_agent"], "web-test")
                stopped = requests.post(
                    f"http://127.0.0.1:{port}/api/user-agent/stop", json={}, timeout=2)
                self.assertEqual(stopped.status_code, 200)
                self.assertFalse(stopped.json()["running"])
                self.assertIn("web-test", (Path(directory) / "agents.log").read_text())
            finally:
                server.shutdown()
                server.server_close()

    @patch("enum_tool._run_headers_check", return_value=0)
    def test_headers_command_is_available_from_terminal(self, check):
        result = CliRunner().invoke(app, ["headers", "https://example.com"])
        self.assertEqual(result.exit_code, 0, result.stdout)
        check.assert_called_once_with("https://example.com", False)

    @patch("enum_tool._run_headers_check", return_value=0)
    @patch("enum_tool.inquirer.text")
    @patch("enum_tool._ask_task", return_value="headers")
    def test_interactive_menu_exposes_header_check(self, _task, text, check):
        text.return_value.execute.return_value = "https://example.com"
        result = CliRunner().invoke(app, ["--interactive"])
        self.assertEqual(result.exit_code, 0, result.stdout)
        check.assert_called_once_with("https://example.com")


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

    def test_rustscan_execution_timeout_is_separate_and_bounded(self):
        self.assertEqual(validate_module_options()["rustscan_timeout"],
                         DEFAULT_EXECUTION_TIMEOUT)
        for timeout in (9, 301, "60", True):
            with self.subTest(timeout=timeout), self.assertRaises(ScanError):
                validate_module_options({"rustscan_timeout": timeout})

    def test_rustscan_batch_is_bounded(self):
        self.assertEqual(validate_module_options()["rustscan_batch"], DEFAULT_BATCH)
        self.assertEqual(validate_module_options({"rustscan_batch": 200})["rustscan_batch"], 200)
        for batch in (5, 4501, "500", True):
            with self.subTest(batch=batch), self.assertRaises(ScanError):
                validate_module_options({"rustscan_batch": batch})

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
        self.assertEqual(client.session.get_adapter("https://").max_retries.total, 0)

    def test_site_dns_failure_is_not_retried_for_fallback_or_later_paths(self):
        client = HttpClient(timeout=7)
        error = requests.exceptions.ConnectionError(
            "failed DNS lookup", socket.gaierror(-3, "Temporary failure"))
        with patch.object(client, "get", side_effect=error) as get:
            with self.assertRaises(requests.exceptions.ConnectionError):
                client.get_site("example.invalid", "/robots.txt")
            with self.assertRaises(requests.exceptions.ConnectionError):
                client.get_site("example.invalid", "/sitemap.xml")
        self.assertEqual(get.call_count, 1)
        self.assertEqual(get.call_args.args[0], "https://example.invalid/robots.txt")

    def test_site_keeps_http_fallback_for_non_dns_connection_errors(self):
        client = HttpClient(timeout=7)
        response = FakeResponse()
        with patch.object(client, "get", side_effect=[
                requests.exceptions.ConnectionError("connection refused"), response]) as get:
            self.assertIs(client.get_site("example.com"), response)
        self.assertEqual([call.args[0] for call in get.call_args_list],
                         ["https://example.com/", "http://example.com/"])

    def test_site_does_not_downgrade_after_tls_error(self):
        client = HttpClient(timeout=7)
        with patch.object(client, "get",
                          side_effect=requests.exceptions.SSLError("certificate error")) as get:
            with self.assertRaises(requests.exceptions.SSLError):
                client.get_site("example.com")
        get.assert_called_once()

    @patch("osint.service.run_all", return_value=[])
    def test_report_records_effective_agent_and_header_names_only(self, _):
        report = run_scan("example.com", only=["dorks"], user_agent="practice-agent",
                          headers=["X-Engagement: private-value"])
        self.assertEqual(report.environment["user_agent"], "practice-agent")
        self.assertEqual(report.environment["custom_header_names"], ["X-Engagement"])
        self.assertNotIn("private-value", str(report.environment))
        self.assertEqual(report.environment["module_options"], {})
        self.assertEqual(DEFAULT_UA, HttpClient().session.headers["User-Agent"])


class TargetValidationTests(unittest.TestCase):
    def test_valid_targets_are_normalized(self):
        cases = {"Example.COM.": "example.com", "192.0.2.4": "192.0.2.4",
                 "münchen.de": "xn--mnchen-3ya.de"}
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(normalize_target(value), expected)

    def test_invalid_targets_are_rejected(self):
        for value in ("999.999.999.999", "1.2.3.4.5", "-oA.com", "example",
                      "a..com", "", "exa mple.com"):
            with self.subTest(value=value), self.assertRaises(ScanError):
                normalize_target(value)


class RustScanHelperTests(unittest.TestCase):
    def test_parse_open_ports_supports_greppable_and_legacy_output(self):
        self.assertEqual(parse_open_ports("192.0.2.4 -> [443,22,80]\n"), [22, 80, 443])
        self.assertEqual(parse_open_ports("Open 192.0.2.4:8080"), [8080])
        self.assertEqual(parse_open_ports("nothing useful"), [])

    def test_target_and_ports_are_validated(self):
        self.assertEqual(validate_target("example.com"), "example.com")
        for target in ("-oA", "a b", "x;y", "a..b"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                validate_target(target)
        self.assertEqual(normalize_ports("22, 80"), "22,80")
        with self.assertRaises(ValueError):
            normalize_ports("80,abc")

    @patch("osint.active.rustscan.subprocess.run")
    @patch("osint.active.rustscan.shutil.which", return_value="/usr/bin/rustscan")
    def test_command_is_greppable_and_uses_configured_batch(self, _, run):
        run.return_value = subprocess.CompletedProcess([], 0, "192.0.2.4 -> [22,80]\n", "")
        context = type("Context", (), {"options": {"rustscan_ports": "22,80",
                                                    "rustscan_batch": 200},
                                       "results": []})()
        result = RustScan(context).run("192.0.2.4")
        command = run.call_args.args[0]
        self.assertEqual([tuple(row) for row in result.rows], [(22, "open"), (80, "open")])
        self.assertIn("-g", command)
        self.assertEqual(command[command.index("--batch-size") + 1], "200")

    @patch("osint.active.rustscan.subprocess.run",
           side_effect=subprocess.TimeoutExpired("rustscan", 1))
    @patch("osint.active.rustscan.shutil.which", return_value="/usr/bin/rustscan")
    def test_timeout_is_reported(self, _, __):
        context = type("Context", (), {"options": {}, "results": []})()
        with self.assertRaisesRegex(RuntimeError, "execution limit"):
            RustScan(context).run("example.com")


class StubModule:
    def __init__(self, outcome):
        self.outcome = outcome

    def run(self, _target):
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def stub_spec(spec_id, outcome=None, **kwargs):
    outcome = outcome if outcome is not None else ModuleResult(spec_id, "passive", "ok")
    return ModuleSpec(spec_id, spec_id.upper(), "passive", "source", "finding", "High",
                      lambda _context: StubModule(outcome), **kwargs)


class RunnerTests(unittest.TestCase):
    def test_dependencies_run_first_and_order_is_otherwise_stable(self):
        specs = [stub_spec("late", requires=("early",)), stub_spec("early"), stub_spec("free")]
        self.assertEqual([s.id for s in order_by_dependencies(specs)],
                         ["early", "late", "free"])
        plain = [stub_spec("a"), stub_spec("b"), stub_spec("c")]
        self.assertEqual([s.id for s in order_by_dependencies(plain)], ["a", "b", "c"])

    def test_unselected_dependency_is_ignored_and_cycles_are_rejected(self):
        alone = [stub_spec("x", requires=("missing",))]
        self.assertEqual([s.id for s in order_by_dependencies(alone)], ["x"])
        cycle = [stub_spec("a", requires=("b",)), stub_spec("b", requires=("a",))]
        with self.assertRaisesRegex(ScanError, "circular"):
            order_by_dependencies(cycle)

    def test_invalid_and_failing_modules_become_failed_results(self):
        specs = [stub_spec("ok"), stub_spec("none", outcome=StubModule(None)),
                 stub_spec("boom", outcome=ValueError("boom"))]
        specs[1] = ModuleSpec("none", "NONE", "passive", "s", "finding", "High",
                              lambda _c: StubModule(None))
        results = run_all(specs, None, "example.com", module_options={})
        self.assertEqual([r.status for r in results], ["ok", "failed", "failed"])
        self.assertIn("TypeError", results[1].error)
        self.assertEqual(results[2].error, "ValueError: boom")
        self.assertEqual((results[0].confidence, results[2].confidence), ("High", "n/a"))

    def test_callback_errors_do_not_abort_the_scan(self):
        def broken(*_):
            raise RuntimeError("ui died")

        results = run_all([stub_spec("a"), stub_spec("b")], None, "example.com",
                          on_start=broken, on_result=broken, module_options={})
        self.assertEqual([r.status for r in results], ["ok", "ok"])

    def test_keyboard_interrupt_keeps_partial_results(self):
        specs = [stub_spec("a"), stub_spec("b", outcome=KeyboardInterrupt()), stub_spec("c")]
        results = run_all(specs, None, "example.com", module_options={})
        self.assertEqual([r.id for r in results], ["a", "b"])
        self.assertEqual(results[1].error, INTERRUPTED)


class OptionalToolTests(unittest.TestCase):
    class Context:
        options = {"rustscan_ports": "22,80", "exploit_query": "Apache 2.4"}

    def test_optional_tools_are_not_selected_implicitly(self):
        self.assertNotIn("searchsploit", [spec.id for spec in select("passive")])
        with patch("osint.registry.shutil.which", return_value="/usr/bin/searchsploit"):
            self.assertIn("searchsploit", [spec.id for spec in select("all")])
            self.assertIn("searchsploit", [spec.id for spec in select("active")])
            self.assertNotIn("searchsploit",
                             [spec.id for spec in select("all", exclude=["fingerprint"])])
        with patch("osint.registry.shutil.which", return_value=None):
            self.assertNotIn("searchsploit", [spec.id for spec in select("all")])
        self.assertNotIn("rustscan", [spec.id for spec in select("all")])
        self.assertEqual(["rustscan"], [spec.id for spec in select("all", ["rustscan"])])
        self.assertEqual(["searchsploit"],
                         [spec.id for spec in select("all", ["searchsploit"])])

    def test_select_rejects_invalid_arguments(self):
        for args in (("pasive",), ("all", ["nope"]), ("all", ["dns"], ["dns"])):
            with self.subTest(args=args), self.assertRaises(ScanError):
                select(*args)

    @patch("osint.service.run_all", return_value=[])
    @patch("osint.registry.shutil.which", return_value="/usr/bin/searchsploit")
    def test_active_profile_includes_searchsploit_without_query_input(self, _, run_all_mock):
        report = run_scan("example.com", mode="active", authorised=True)
        selected = run_all_mock.call_args.args[0]
        self.assertIn("searchsploit", [spec.id for spec in selected])
        self.assertEqual(report.environment["module_options"], {})

    def test_module_options_are_bounded_and_validate_required_search(self):
        options = validate_module_options({"rustscan_ports": "22,443",
                                           "rustscan_timeout": 90,
                                           "exploit_query": "Apache 2.4"})
        self.assertEqual(options["rustscan_ports"], "22,443")
        self.assertEqual(options["rustscan_timeout"], 90)
        self.assertEqual(options["exploit_query"], "Apache 2.4")
        self.assertEqual(validate_module_options()["rustscan_ports"], DEFAULT_PORTS)
        for ports in ("0", "22,22", "1-100", "22," * 65):
            with self.subTest(ports=ports), self.assertRaises(ScanError):
                validate_module_options({"rustscan_ports": ports})
        with self.assertRaises(ScanError):
            validate_module_options({"rustscan_ports": "022,22"})
        with self.assertRaises(ScanError):
            validate_module_options({"exploit_query": "--help"})

    def test_ipv4_target_and_active_authorization(self):
        target, specs = prepare("192.0.2.4", "all", ["rustscan"], None, True)
        self.assertEqual(target, "192.0.2.4")
        self.assertEqual([spec.id for spec in specs], ["rustscan"])
        with self.assertRaises(ScanError):
            prepare("192.0.2.4", "all", ["rustscan"], None, False)
        with self.assertRaises(ScanError):
            prepare("bad-.example.com", "passive", None, None, False)

    @patch("enum_tool.inquirer.checkbox")
    @patch("enum_tool.inquirer.confirm")
    @patch("enum_tool.inquirer.select")
    @patch("enum_tool.inquirer.text")
    def test_guided_wizard_collects_passive_profile(
            self, text, select_prompt, confirm, checkbox):
        text.return_value.execute.return_value = "example.com"
        select_prompt.return_value.execute.return_value = "passive"
        confirm.return_value.execute.side_effect = [False]
        checkbox.return_value.execute.side_effect = [["dorks"], ["html"]]
        args = ScanArgs(
            domain=None, mode="passive", only=None, exclude=None, authorised=False,
            timeout=10, user_agent=DEFAULT_UA, headers=[], rustscan_ports=None,
            rustscan_timeout=DEFAULT_EXECUTION_TIMEOUT, rustscan_batch=500,
            exploit_query="", operator="", note="", json=True, html=True, quiet=False)
        choices = run_wizard(args)
        self.assertEqual(choices.domain, "example.com")
        self.assertEqual(choices.only, "dorks")
        self.assertFalse(choices.json)
        self.assertTrue(choices.html)
        self.assertIsNone(choices.exclude)
        self.assertFalse(choices.quiet)

    @patch("enum_tool.inquirer.checkbox")
    @patch("enum_tool.inquirer.confirm")
    @patch("enum_tool.inquirer.select")
    @patch("enum_tool.inquirer.text")
    def test_guided_wizard_cancels_active_scan_without_authorization(
            self, text, select_prompt, confirm, checkbox):
        text.return_value.execute.return_value = "192.0.2.4"
        select_prompt.return_value.execute.return_value = "active"
        confirm.return_value.execute.return_value = False
        checkbox.return_value.execute.return_value = ["dns"]
        with self.assertRaisesRegex(ScanError, "explicit authorisation"):
            run_wizard(ScanArgs(
                domain=None, mode="active", only=None, exclude=None, authorised=False,
                timeout=10, user_agent=DEFAULT_UA, headers=[], rustscan_ports=None,
                rustscan_timeout=DEFAULT_EXECUTION_TIMEOUT, rustscan_batch=500,
                exploit_query="", operator="", note="", json=False, html=False,
                quiet=False))

    @patch("enum_tool._ask_task", return_value="scan")
    @patch("enum_tool.run_wizard", side_effect=ScanError("scan cancelled"))
    def test_cli_reports_wizard_cancellation(self, _, __):
        result = CliRunner().invoke(app, ["--interactive"])
        self.assertEqual(result.exit_code, 130)
        self.assertIn("scan cancelled", result.stdout)

    def test_typer_cli_keeps_legacy_flags_and_module_listing(self):
        runner = CliRunner()
        help_result = runner.invoke(app, ["--help"])
        self.assertEqual(help_result.exit_code, 0)
        self.assertIn("--domain", help_result.stdout)
        self.assertIn("--i-have-permission", help_result.stdout)
        modules_result = runner.invoke(app, ["modules"])
        self.assertEqual(modules_result.exit_code, 0)
        self.assertIn("rustscan", modules_result.stdout)

    @patch("enum_tool.run_scan")
    def test_typer_cli_runs_with_existing_scan_flags(self, scan_mock):
        scan_mock.return_value = Report(
            "osint-enum", "1.1", "abc", "example.com", "passive", "", "", False,
            "t0", "t1", 0.1, 10, ["dorks"], {}, [],
        )
        result = CliRunner().invoke(app, ["-d", "example.com", "--only", "dorks", "--quiet"])
        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertEqual(scan_mock.call_args.args[:3], ("example.com", "all", ["dorks"]))

    @patch("enum_tool.run_scan")
    @patch("enum_tool.run_wizard")
    @patch("enum_tool._ask_task", return_value="scan")
    def test_interactive_cli_passes_complete_options_to_scan(self, _task, wizard, scan_mock):
        wizard.side_effect = lambda defaults: replace(
            defaults, domain="example.com", mode="passive", only="dorks",
            exclude=None, authorised=False, json=False, html=False)
        scan_mock.return_value = Report(
            "osint-enum", "1.1", "abc", "example.com", "passive", "", "", False,
            "t0", "t1", 0.1, 10, ["dorks"], {}, [],
        )
        result = CliRunner().invoke(app, ["--interactive", "--quiet"])
        self.assertEqual(result.exit_code, 0, result.stdout)
        self.assertEqual(scan_mock.call_args.args[0], "example.com")
        self.assertEqual(scan_mock.call_args.args[3], None)

    @patch("osint.active.rustscan.subprocess.run")
    @patch("osint.active.rustscan.shutil.which", return_value="/usr/bin/rustscan")
    def test_rustscan_parses_open_ports_without_shell(self, _, run):
        run.return_value = type("Result", (), {
            "returncode": 0, "stdout": "Open 192.0.2.4:80\nOpen 192.0.2.4:22\n",
            "stderr": "",
        })()
        context = self.Context()
        context.options = {**context.options, "rustscan_timeout": 90}
        result = RustScan(context).run("192.0.2.4")
        self.assertEqual(result.rows, [(22, "open"), (80, "open")])
        command = run.call_args.args[0]
        self.assertEqual(command[0], "/usr/bin/rustscan")
        self.assertIn("22,80", command)
        self.assertIn("1500", command)
        self.assertEqual(run.call_args.kwargs["timeout"], 90)
        self.assertFalse(run.call_args.kwargs.get("shell", False))

    @patch("osint.passive.searchsploit.subprocess.run")
    @patch("osint.passive.searchsploit.shutil.which", return_value="/usr/bin/searchsploit")
    def test_searchsploit_returns_references_only(self, _, run):
        run.return_value = type("Result", (), {
            "returncode": 0,
            "stdout": json.dumps({"RESULTS_EXPLOIT": [{
                "Title": "Apache issue", "EDB-ID": "12345", "Path": "exploits/linux/remote/12345.py"
            }]}),
            "stderr": "",
        })()
        context = self.Context()
        context.options = dict(context.options)
        context.options["exploit_query"] = "Apache 2.4"
        result = SearchSploit(context).run("example.com")
        self.assertEqual(result.rows[0][0:3], ("Apache 2.4", "Apache issue", "12345"))
        self.assertIn("--json", run.call_args.args[0])
        self.assertIn("--", run.call_args.args[0])

    def test_searchsploit_derives_queries_from_fingerprint_results(self):
        result = ModuleResult(
            "Technology fingerprint", "active", id="fingerprint",
            headers=["SIGNAL", "VALUE"],
            rows=[("server", "Netlify"),
                  ("server", "Apache/2.4.49 (Unix)"),
                  ("x-powered-by", "PHP/8.1.2")],
        )
        self.assertEqual(inferred_queries([result]), ["Apache 2.4.49", "PHP 8.1.2"])

    def test_searchsploit_ignores_unversioned_server_platform_names(self):
        result = ModuleResult(
            "Technology fingerprint", "active", id="fingerprint",
            headers=["SIGNAL", "VALUE"], rows=[("server", "Netlify")],
        )
        self.assertEqual(inferred_queries([result]), [])

    @patch("osint.passive.searchsploit.subprocess.run")
    @patch("osint.passive.searchsploit.shutil.which", return_value="/usr/bin/searchsploit")
    def test_runner_executes_automatic_exploit_lookup_after_fingerprinting(self, _, run):
        run.return_value = type("Result", (), {
            "returncode": 0, "stdout": json.dumps({"RESULTS_EXPLOIT": [{
                "Title": "Apache issue", "EDB-ID": "12345",
            }]}), "stderr": "",
        })()

        class FingerprintStub:
            def __init__(self, _context):
                pass

            def run(self, _target):
                return ModuleResult("Technology fingerprint", "active",
                                    rows=[("server", "Apache/2.4.49")])

        specs = [
            ModuleSpec("searchsploit", "SearchSploit", "passive", "local", "finding",
                       "Moderate", SearchSploit, executable="searchsploit",
                       requires=("fingerprint",)),
            ModuleSpec("fingerprint", "Fingerprint", "active", "target", "finding",
                       "High", FingerprintStub),
        ]
        results = run_all(specs, None, "example.com", module_options={"exploit_query": ""})
        self.assertEqual([item.id for item in results], ["fingerprint", "searchsploit"])
        self.assertEqual(results[1].rows[0][:2], ("Apache 2.4.49", "Apache issue"))

    @patch("osint.passive.searchsploit.subprocess.run")
    @patch("osint.passive.searchsploit.shutil.which", return_value="/usr/bin/searchsploit")
    def test_searchsploit_skips_when_fingerprint_has_no_software(self, _, run):
        context = self.Context()
        context.options = dict(context.options)
        context.options["exploit_query"] = ""
        context.results = [ModuleResult("Technology fingerprint", "active",
                                        id="fingerprint", rows=[("status", "HTTP 200")])]
        result = SearchSploit(context).run("example.com")
        self.assertEqual(result.status, "skipped")
        self.assertIn("no software or version indicators", result.error)
        run.assert_not_called()

    @patch("osint.passive.searchsploit.subprocess.run")
    @patch("osint.passive.searchsploit.shutil.which", return_value="/usr/bin/searchsploit")
    def test_searchsploit_searches_detected_software_automatically(self, _, run):
        run.return_value = type("Result", (), {
            "returncode": 0, "stdout": json.dumps({"RESULTS_EXPLOIT": [{
                "Title": "Apache issue", "EDB-ID": "12345",
            }]}), "stderr": "",
        })()
        context = self.Context()
        context.options = dict(context.options)
        context.options["exploit_query"] = ""
        context.results = [ModuleResult(
            "Technology fingerprint", "active", id="fingerprint",
            rows=[("server", "Apache/2.4.49")],
        )]
        result = SearchSploit(context).run("example.com")
        self.assertEqual(result.rows[0][:3], ("Apache 2.4.49", "Apache issue", "12345"))
        self.assertEqual(run.call_args.args[0][-2:], ["Apache", "2.4.49"])

    @patch("osint.active.rustscan.shutil.which", return_value=None)
    def test_missing_rustscan_is_reported(self, _):
        with self.assertRaisesRegex(RuntimeError, "rustscan is not installed"):
            RustScan(self.Context()).run("192.0.2.4")

    @patch("osint.service.run_all", return_value=[])
    def test_report_records_only_selected_optional_tool_options(self, _):
        report = run_scan("example.com", only=["searchsploit"],
                          module_options={"exploit_query": "Apache 2.4"})
        self.assertEqual(report.environment["module_options"],
                         {"exploit_query": "Apache 2.4"})

    @patch("osint.service.run_all", return_value=[])
    def test_report_records_rustscan_execution_timeout(self, _):
        report = run_scan("192.0.2.4", mode="all", only=["rustscan"],
                          authorised=True, module_options={"rustscan_timeout": 90})
        self.assertEqual(report.environment["module_options"],
                         {"rustscan_ports": DEFAULT_PORTS, "rustscan_timeout": 90,
                          "rustscan_batch": DEFAULT_BATCH})


class SearchSploitResilienceTests(unittest.TestCase):
    SAMPLE = json.dumps({"RESULTS_EXPLOIT": [{"Title": "Apache issue", "EDB-ID": "12345"}]})

    def context(self, query=""):
        fingerprint = ModuleResult(
            "Technology fingerprint", "active", id="fingerprint",
            rows=[("server", "Apache/2.4.49"), ("x-powered-by", "PHP/7.4.3")])
        return type("Context", (), {"options": {"exploit_query": query},
                                    "results": [fingerprint]})()

    @patch("osint.passive.searchsploit.subprocess.run")
    @patch("osint.passive.searchsploit.shutil.which", return_value="/usr/bin/searchsploit")
    def test_one_failed_query_is_reported_without_losing_other_results(self, _, run):
        run.side_effect = [subprocess.TimeoutExpired("searchsploit", 1),
                           subprocess.CompletedProcess([], 0, self.SAMPLE, "")]
        result = SearchSploit(self.context()).run("example.com")
        titles = [row[1] for row in result.rows]
        self.assertTrue(any(title.startswith("Query failed") for title in titles))
        self.assertIn("Apache issue", titles)

    @patch("osint.passive.searchsploit.subprocess.run",
           side_effect=subprocess.TimeoutExpired("searchsploit", 1))
    @patch("osint.passive.searchsploit.shutil.which", return_value="/usr/bin/searchsploit")
    def test_all_queries_failing_raises(self, _, __):
        with self.assertRaises(RuntimeError):
            SearchSploit(self.context("apache")).run("example.com")

    @patch("osint.passive.searchsploit.subprocess.run")
    @patch("osint.passive.searchsploit.shutil.which", return_value="/usr/bin/searchsploit")
    def test_duplicate_entries_are_removed(self, _, run):
        run.return_value = subprocess.CompletedProcess([], 0, self.SAMPLE, "")
        result = SearchSploit(self.context()).run("example.com")
        self.assertEqual([row[2] for row in result.rows].count("12345"), 1)


if __name__ == "__main__":
    unittest.main()