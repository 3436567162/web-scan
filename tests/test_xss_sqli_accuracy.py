import unittest
from unittest.mock import patch

from scanner import sqli_scanner, xss_scanner


class FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


class XssAccuracyTighteningTests(unittest.TestCase):
    @patch("scanner.xss_scanner.time.sleep", return_value=None)
    @patch("scanner.xss_scanner.fetch")
    @patch("scanner.xss_scanner.inject_param")
    @patch("scanner.xss_scanner.extract_params")
    def test_comment_reflection_is_not_reported_high(
        self,
        mock_extract_params,
        mock_inject_param,
        mock_fetch,
        _mock_sleep,
    ):
        payload = xss_scanner.XSS_PAYLOADS[0]
        mock_extract_params.return_value = {"q": ["test"]}
        mock_inject_param.side_effect = lambda url, param, value: f"{url}&{param}=injected"
        mock_fetch.return_value = FakeResponse(text=f"<html><!-- {payload} --></html>")

        results = xss_scanner._check_url_params("https://example.test/search?q=test")

        self.assertFalse(any(item["type"] == "high" for item in results))

    @patch("scanner.xss_scanner.time.sleep", return_value=None)
    @patch("scanner.xss_scanner.fetch")
    @patch("scanner.xss_scanner.inject_param")
    @patch("scanner.xss_scanner.extract_params")
    def test_inert_reflection_with_unrelated_executable_pattern_is_not_high(
        self,
        mock_extract_params,
        mock_inject_param,
        mock_fetch,
        _mock_sleep,
    ):
        payload = xss_scanner.XSS_PAYLOADS[0]
        mock_extract_params.return_value = {"q": ["test"]}
        mock_inject_param.side_effect = lambda url, param, value: f"{url}&{param}=injected"
        mock_fetch.return_value = FakeResponse(
            text=(
                f"<html><!-- reflected {payload} --><script>alert(1)</script>"
                "<p>Static site bootstrap</p></html>"
            )
        )

        results = xss_scanner._check_url_params("https://example.test/search?q=test")

        self.assertFalse(any(item["type"] == "high" for item in results))

    @patch("scanner.xss_scanner.time.sleep", return_value=None)
    @patch("scanner.xss_scanner.fetch")
    @patch("scanner.xss_scanner.inject_param")
    @patch("scanner.xss_scanner.extract_params")
    def test_raw_script_reflection_stays_high_and_includes_evidence(
        self,
        mock_extract_params,
        mock_inject_param,
        mock_fetch,
        _mock_sleep,
    ):
        payload = xss_scanner.XSS_PAYLOADS[0]
        mock_extract_params.return_value = {"q": ["test"]}
        mock_inject_param.side_effect = lambda url, param, value: f"{url}&{param}=injected"
        mock_fetch.return_value = FakeResponse(text=f"<html><body>{payload}</body></html>")

        results = xss_scanner._check_url_params("https://example.test/search?q=test")

        finding = next(item for item in results if item["type"] == "high")
        self.assertIsInstance(finding.get("evidence"), list)
        self.assertTrue(finding["evidence"])
        self.assertEqual(finding["evidence"][0]["payload"], payload)
        self.assertTrue(finding["evidence"][0]["response_snippet"])
        self.assertIsInstance(finding.get("remediation"), list)
        self.assertTrue(finding["remediation"])


class SqliAccuracyTighteningTests(unittest.TestCase):
    @patch("scanner.sqli_scanner.time.sleep", return_value=None)
    @patch("scanner.sqli_scanner.fetch")
    @patch("scanner.sqli_scanner.inject_param")
    @patch("scanner.sqli_scanner.extract_params")
    def test_generic_syntax_error_without_db_context_is_not_reported(
        self,
        mock_extract_params,
        mock_inject_param,
        mock_fetch,
        _mock_sleep,
    ):
        mock_extract_params.return_value = {"q": ["test"]}
        mock_inject_param.side_effect = lambda url, param, value: f"{url}&{param}=injected"

        def fake_fetch(url, method="GET", data=None, params=None):
            if url == "https://example.test/search?q=test":
                return FakeResponse(text="Search page")
            return FakeResponse(text="Template parser says syntax error near token")

        mock_fetch.side_effect = fake_fetch

        results = sqli_scanner._check_url_params("https://example.test/search?q=test")

        self.assertFalse(any(item["type"] == "high" for item in results))

    @patch("scanner.sqli_scanner.time.sleep", return_value=None)
    @patch("scanner.sqli_scanner.fetch")
    @patch("scanner.sqli_scanner.extract_forms")
    @patch("scanner.sqli_scanner.extract_params")
    def test_form_path_uses_baseline_comparison(
        self,
        mock_extract_params,
        mock_extract_forms,
        mock_fetch,
        _mock_sleep,
    ):
        mock_extract_params.return_value = {}
        mock_extract_forms.return_value = [
            {
                "action": "https://example.test/login",
                "method": "POST",
                "inputs": [{"name": "username", "type": "text", "value": ""}],
            }
        ]

        def fake_fetch(url, method="GET", data=None, params=None):
            if method == "POST" and data == {"username": "test"}:
                return FakeResponse(text="Support article headline: syntax error troubleshooting")
            if method == "POST":
                return FakeResponse(text="Support article headline: syntax error troubleshooting")
            return FakeResponse(text="<form></form>")

        mock_fetch.side_effect = fake_fetch

        results = sqli_scanner.check_sqli("https://example.test/login")

        self.assertFalse(any(item["type"] == "high" for item in results))

    @patch("scanner.sqli_scanner.time.sleep", return_value=None)
    @patch("scanner.sqli_scanner.fetch")
    @patch("scanner.sqli_scanner.inject_param")
    @patch("scanner.sqli_scanner.extract_params")
    def test_db_specific_error_still_reports_high(
        self,
        mock_extract_params,
        mock_inject_param,
        mock_fetch,
        _mock_sleep,
    ):
        mock_extract_params.return_value = {"id": ["1"]}
        mock_inject_param.side_effect = lambda url, param, value: f"{url}&{param}=injected"

        def fake_fetch(url, method="GET", data=None, params=None):
            if url == "https://example.test/item?id=1":
                return FakeResponse(text="Normal product page")
            return FakeResponse(text="You have an error in your SQL syntax near '' at line 1")

        mock_fetch.side_effect = fake_fetch

        results = sqli_scanner._check_url_params("https://example.test/item?id=1")

        finding = next(item for item in results if item["type"] == "high")
        self.assertEqual(finding.get("confidence"), "high")
        self.assertIsInstance(finding.get("evidence"), list)
        self.assertTrue(finding["evidence"])
        self.assertIn("sql syntax", finding["evidence"][0]["matched_text"].lower())
        self.assertIsInstance(finding.get("remediation"), list)
        self.assertTrue(finding["remediation"])


if __name__ == "__main__":
    unittest.main()
