import socket
import unittest
from unittest.mock import patch

import app as app_module


class ResultSchemaTests(unittest.TestCase):
    def setUp(self):
        app_module.app.config["TESTING"] = True
        app_module._LAST_SCAN_BY_CLIENT.clear()
        self.client = app_module.app.test_client()

    def test_normalize_findings_adds_defaults_and_preserves_legacy_fields(self):
        findings = [
            {
                "type": "medium",
                "title": "Missing header",
                "detail": "CSP is missing",
            },
            {
                "type": "pass",
                "title": "Healthy",
                "detail": "No issue found",
            },
        ]

        normalized = app_module.normalize_findings("headers", findings)

        self.assertEqual(2, len(normalized))

        medium_finding = normalized[0]
        self.assertEqual("medium", medium_finding["type"])
        self.assertEqual("Missing header", medium_finding["title"])
        self.assertEqual("CSP is missing", medium_finding["detail"])
        self.assertEqual("medium", medium_finding["severity"])
        self.assertEqual("open", medium_finding["status"])
        self.assertIsNone(medium_finding["confidence"])
        self.assertEqual([], medium_finding["evidence"])
        self.assertEqual([], medium_finding["remediation"])
        self.assertEqual("headers", medium_finding["module"])

        pass_finding = normalized[1]
        self.assertEqual("pass", pass_finding["severity"])
        self.assertEqual("pass", pass_finding["status"])
        self.assertIsNone(pass_finding["confidence"])
        self.assertEqual([], pass_finding["evidence"])
        self.assertEqual([], pass_finding["remediation"])
        self.assertEqual("headers", pass_finding["module"])

    def test_normalize_findings_tolerates_null_and_malformed_optional_fields(self):
        findings = [
            {
                "type": "high",
                "title": "Broken shape",
                "detail": "Optional fields are malformed",
                "severity": None,
                "status": None,
                "evidence": None,
                "remediation": "rotate keys",
            },
            {
                "type": "low",
                "title": "Explicit strings",
                "detail": "Optional fields are strings",
                "evidence": "header:value",
                "remediation": "apply fix",
            },
        ]

        normalized = app_module.normalize_findings("headers", findings)

        self.assertEqual(2, len(normalized))
        self.assertEqual("high", normalized[0]["severity"])
        self.assertEqual("open", normalized[0]["status"])
        self.assertEqual([], normalized[0]["evidence"])
        self.assertEqual(["rotate keys"], normalized[0]["remediation"])
        self.assertEqual(["header:value"], normalized[1]["evidence"])
        self.assertEqual(["apply fix"], normalized[1]["remediation"])

    def test_scan_response_includes_metadata_and_normalized_results(self):
        module_results = [
            (
                "headers",
                lambda _url: [
                    {
                        "type": "medium",
                        "title": "Missing CSP",
                        "detail": "No CSP header was returned",
                    }
                ],
            ),
            (
                "info",
                lambda _url: [
                    {
                        "type": "info",
                        "title": "Server banner",
                        "detail": "Apache detected",
                    }
                ],
            ),
        ]

        with patch(
            "socket.getaddrinfo",
            return_value=[
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("93.184.216.34", 80),
                )
            ],
        ), patch.object(app_module, "SCAN_MODULES", module_results):
            response = self.client.post("/api/scan", json={"url": "example.com"})

        self.assertEqual(200, response.status_code)
        payload = response.get_json()

        self.assertEqual("http://example.com", payload["url"])
        self.assertIn("results", payload)
        self.assertIn("summary", payload)
        self.assertIn("scan_metadata", payload)

        finding = payload["results"]["headers"][0]
        self.assertEqual("medium", finding["type"])
        self.assertEqual("medium", finding["severity"])
        self.assertEqual("open", finding["status"])
        self.assertIsNone(finding["confidence"])
        self.assertEqual([], finding["evidence"])
        self.assertEqual([], finding["remediation"])
        self.assertEqual("headers", finding["module"])

        self.assertEqual({"high": 0, "medium": 1, "low": 0}, payload["summary"])

        metadata = payload["scan_metadata"]
        self.assertTrue(metadata["started_at"])
        self.assertTrue(metadata["finished_at"])
        self.assertGreaterEqual(metadata["duration_ms"], 0)
        self.assertEqual(app_module.SCAN_REQUEST_LIMIT, metadata["request_budget_limit"])
        self.assertFalse(metadata["request_budget_exhausted"])
        self.assertEqual(["headers", "info"], metadata["modules_run"])
        self.assertEqual([], metadata["modules_skipped"])

    def test_scan_summary_uses_canonical_severity_instead_of_type(self):
        module_results = [
            (
                "headers",
                lambda _url: [
                    {
                        "type": "info",
                        "severity": "high",
                        "title": "Canonical severity wins",
                        "detail": "Stored type differs from severity",
                    }
                ],
            ),
        ]

        with patch(
            "socket.getaddrinfo",
            return_value=[
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("93.184.216.34", 80),
                )
            ],
        ), patch.object(app_module, "SCAN_MODULES", module_results):
            response = self.client.post("/api/scan", json={"url": "example.com"})

        self.assertEqual(200, response.status_code)
        payload = response.get_json()
        self.assertEqual({"high": 1, "medium": 0, "low": 0}, payload["summary"])

    def test_scan_metadata_preserves_budget_exhaustion_and_skipped_modules(self):
        module_results = [
            ("headers", lambda _url: []),
            ("info", lambda _url: []),
            ("cors", lambda _url: []),
        ]

        with patch(
            "socket.getaddrinfo",
            return_value=[
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("93.184.216.34", 80),
                )
            ],
        ), patch.object(
            app_module,
            "SCAN_MODULES",
            module_results,
        ), patch(
            "app.budget_exhausted",
            side_effect=[True, False],
        ):
            response = self.client.post("/api/scan", json={"url": "example.com"})

        self.assertEqual(200, response.status_code)
        payload = response.get_json()

        self.assertTrue(payload["scan_metadata"]["request_budget_exhausted"])
        self.assertEqual(["headers"], payload["scan_metadata"]["modules_run"])
        self.assertEqual(["info", "cors"], payload["scan_metadata"]["modules_skipped"])

        exhaustion_finding = payload["results"]["headers"][-1]
        self.assertEqual("error", exhaustion_finding["type"])
        self.assertEqual("error", exhaustion_finding["severity"])
        self.assertEqual("error", exhaustion_finding["status"])


if __name__ == "__main__":
    unittest.main()
