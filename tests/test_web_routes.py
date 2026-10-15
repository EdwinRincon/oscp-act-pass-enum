# tests/test_web_routes.py
import socket
import threading
import unittest
from unittest.mock import patch

import requests

from osint.web.app import make_server


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class WebRouteTests(unittest.TestCase):
    def setUp(self):
        self.server = make_server("127.0.0.1", 0)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def post(self, path, **kwargs):
        return requests.post(f"{self.base}{path}", timeout=3, **kwargs)

    def test_network_failures_in_header_check_return_502(self):
        error = requests.exceptions.ConnectionError("boom")
        with patch("osint.web.app.check_security_headers", side_effect=error):
            response = self.post("/api/headers", json={
                "url": "example.com", "authorised": True})
        self.assertEqual(response.status_code, 502)
        self.assertIn("ConnectionError", response.json()["error"])

    def test_unexpected_errors_return_json_500(self):
        with patch("osint.web.app.check_security_headers", side_effect=KeyError("x")), \
                self.assertLogs("osint.web.app", level="ERROR"):
            response = self.post("/api/headers", json={
                "url": "example.com", "authorised": True})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["error"], "internal error")

    def test_header_check_requires_explicit_authorisation(self):
        with patch("osint.web.app.check_security_headers") as checker:
            response = self.post("/api/headers", json={"url": "example.com"})
        self.assertEqual(response.status_code, 400)
        checker.assert_not_called()

    def test_overlong_domain_is_rejected_instead_of_truncated(self):
        response = self.post("/api/scan", json={"domain": "a" * 254, "modules": ["dorks"]})
        self.assertEqual(response.status_code, 400)
        self.assertIn("too long", response.json()["error"])

    def test_empty_body_is_a_bad_request(self):
        response = self.post("/api/user-agent/stop", data=b"",
                             headers={"Content-Type": "application/json"})
        self.assertEqual(response.status_code, 400)

    def test_unknown_route_and_foreign_host_are_rejected(self):
        self.assertEqual(self.post("/api/nope", json={}).status_code, 404)
        response = requests.get(f"{self.base}/api/modules", timeout=3,
                                headers={"Host": "evil.example"})
        self.assertEqual(response.status_code, 403)

    def test_responses_carry_cross_origin_hardening_headers(self):
        response = requests.get(f"{self.base}/api/modules", timeout=3)
        self.assertEqual(response.headers["Cross-Origin-Resource-Policy"], "same-origin")

    def test_capture_start_twice_conflicts_and_bind_failure_is_400(self):
        port = free_port()
        body = {"host": "127.0.0.1", "port": port}
        self.assertEqual(self.post("/api/user-agent/start", json=body).status_code, 200)
        self.assertEqual(self.post("/api/user-agent/start", json=body).status_code, 409)
        self.assertEqual(self.post("/api/user-agent/stop", json={}).status_code, 200)

        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            busy = {"host": "127.0.0.1", "port": occupied.getsockname()[1]}
            response = self.post("/api/user-agent/start", json=busy)
        self.assertEqual(response.status_code, 400)


class ServerLifecycleTests(unittest.TestCase):
    def test_non_loopback_bind_requires_allow_remote(self):
        with self.assertRaises(ValueError):
            make_server("0.0.0.0", 0)
        server = make_server("0.0.0.0", 0, allow_remote=True)
        server.server_close()

    def test_closing_the_server_stops_the_capture_listener(self):
        server = make_server("127.0.0.1", 0)
        server.user_agent_capture.start(port=0)
        self.assertTrue(server.user_agent_capture.running)
        server.server_close()
        self.assertFalse(server.user_agent_capture.running)


if __name__ == "__main__":
    unittest.main()