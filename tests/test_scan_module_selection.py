import socket
import unittest
from unittest.mock import patch

import app as app_module


def _public_dns():
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            0,
            "",
            ("93.184.216.34", 80),
        )
    ]


def _recording_module(name, calls):
    def _run(_url):
        calls.append(name)
        return [{
            "type": "pass",
            "title": f"{name} ok",
            "detail": "ok",
        }]

    return _run


class ScanModuleSelectionTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        app_module._LAST_SCAN_BY_CLIENT.clear()
        self.client = app_module.app.test_client()

    def test_scan_runs_only_requested_modules(self):
        calls = []
        module_results = [
            ("headers", _recording_module("headers", calls)),
            ("cors", _recording_module("cors", calls)),
            ("xss", _recording_module("xss", calls)),
        ]

        with patch("socket.getaddrinfo", return_value=_public_dns()), patch.object(
            app_module,
            "SCAN_MODULES",
            module_results,
        ):
            response = self.client.post(
                "/api/scan",
                json={"url": "example.com", "modules": ["headers", "xss"]},
            )

        self.assertEqual(200, response.status_code)
        payload = response.get_json()
        self.assertEqual(["headers", "xss"], calls)
        self.assertEqual(["headers", "xss"], list(payload["results"].keys()))
        self.assertEqual(["headers", "xss"], payload["scan_metadata"]["selected_modules"])

    def test_scan_rejects_unknown_modules(self):
        with patch("socket.getaddrinfo", return_value=_public_dns()), patch.object(
            app_module,
            "SCAN_MODULES",
            [("headers", lambda _url: [])],
        ):
            response = self.client.post(
                "/api/scan",
                json={"url": "example.com", "modules": ["unknown-module"]},
            )

        self.assertEqual(400, response.status_code)
        self.assertIn("Unknown scan modules", response.get_json()["error"])


if __name__ == "__main__":
    unittest.main()
