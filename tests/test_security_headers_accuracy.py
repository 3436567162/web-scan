import unittest
from unittest.mock import patch

from scanner import security_headers


class FakeResponse:
    def __init__(self, status_code=200, headers=None):
        self.status_code = status_code
        self.headers = headers or {}


class SecurityHeadersAccuracyTests(unittest.TestCase):
    @patch("scanner.security_headers.fetch")
    def test_missing_x_xss_protection_is_not_medium(self, mock_fetch):
        mock_fetch.return_value = FakeResponse(
            headers={
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
            }
        )

        results = security_headers.check_security_headers("https://example.test")

        finding = next(item for item in results if "X-XSS-Protection" in item["title"])
        self.assertIn(finding["type"], {"info", "low"})
        self.assertNotEqual("medium", finding["type"])

    @patch("scanner.security_headers.fetch")
    def test_https_target_missing_hsts_is_reported(self, mock_fetch):
        mock_fetch.return_value = FakeResponse(
            headers={
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'self'",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
            }
        )

        results = security_headers.check_security_headers("https://example.test")

        finding = next(
            item for item in results if "Strict-Transport-Security" in item["title"]
        )
        self.assertEqual("medium", finding["type"])

    @patch("scanner.security_headers.fetch")
    def test_http_redirect_to_https_is_not_reported_as_missing(self, mock_fetch):
        def fake_fetch(url, *args, **kwargs):
            if url.startswith("http://"):
                if kwargs.get("allow_redirects", True) is False:
                    return FakeResponse(
                        status_code=301,
                        headers={"Location": "https://example.test/login"},
                    )
                return FakeResponse(
                    headers={
                        "X-Frame-Options": "DENY",
                        "X-Content-Type-Options": "nosniff",
                        "Content-Security-Policy": "default-src 'self'",
                        "X-XSS-Protection": "1; mode=block",
                        "Referrer-Policy": "strict-origin-when-cross-origin",
                        "Permissions-Policy": "geolocation=()",
                    }
                )
            return None

        mock_fetch.side_effect = fake_fetch

        results = security_headers.check_security_headers("http://example.test/login")

        self.assertFalse(any("HTTPS" in item["title"] for item in results))
        self.assertFalse(
            any("Strict-Transport-Security" in item["title"] for item in results)
        )

    @patch("scanner.security_headers.fetch")
    def test_http_redirect_to_https_is_not_reported_missing_when_followed_https_is_unavailable(self, mock_fetch):
        def fake_fetch(url, *args, **kwargs):
            if url.startswith("http://"):
                if kwargs.get("allow_redirects", True) is False:
                    return FakeResponse(
                        status_code=301,
                        headers={"Location": "https://example.test/login"},
                    )
                return None
            return None

        mock_fetch.side_effect = fake_fetch

        results = security_headers.check_security_headers("http://example.test/login")

        self.assertFalse(any("HTTPS" in item["title"] for item in results))
        self.assertTrue(
            any(
                call.args[0] == "http://example.test/login"
                and call.kwargs.get("allow_redirects") is False
                for call in mock_fetch.call_args_list
            )
        )

    @patch("scanner.security_headers.fetch")
    def test_http_redirect_to_external_https_still_reports_enforcement_gap(self, mock_fetch):
        def fake_fetch(url, *args, **kwargs):
            if url.startswith("http://"):
                if kwargs.get("allow_redirects", True) is False:
                    return FakeResponse(
                        status_code=302,
                        headers={"Location": "https://evil.com/login"},
                    )
                return FakeResponse(
                    headers={
                        "X-Frame-Options": "DENY",
                        "X-Content-Type-Options": "nosniff",
                        "Content-Security-Policy": "default-src 'self'",
                        "X-XSS-Protection": "1; mode=block",
                        "Referrer-Policy": "strict-origin-when-cross-origin",
                        "Permissions-Policy": "geolocation=()",
                    }
                )
            return None

        mock_fetch.side_effect = fake_fetch

        results = security_headers.check_security_headers("http://example.test/login")

        https_redirect_findings = [item for item in results if "HTTPS" in item["title"]]
        self.assertEqual(1, len(https_redirect_findings))
        self.assertTrue(https_redirect_findings[0].get("evidence"))

    @patch("scanner.security_headers.fetch")
    def test_http_target_without_redirect_reports_only_https_enforcement_gap(self, mock_fetch):
        def fake_fetch(url, *args, **kwargs):
            if url.startswith("http://") and kwargs.get("allow_redirects", True) is False:
                return FakeResponse(status_code=200, headers={})
            return FakeResponse(headers={})

        mock_fetch.side_effect = fake_fetch

        results = security_headers.check_security_headers("http://example.test")

        https_redirect_findings = [item for item in results if "HTTPS" in item["title"]]
        self.assertEqual(1, len(https_redirect_findings))
        self.assertTrue(https_redirect_findings[0].get("evidence"))
        self.assertFalse(
            any("Strict-Transport-Security" in item["title"] for item in results)
        )

    @patch("scanner.security_headers.fetch")
    def test_multiple_secure_cookies_do_not_raise_cookie_findings(self, mock_fetch):
        mock_fetch.return_value = FakeResponse(
            headers={
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=()",
                "Set-Cookie": (
                    "session=abc; HttpOnly; Secure, "
                    "prefs=light; HttpOnly; Secure"
                ),
            }
        )

        results = security_headers.check_security_headers("https://example.test")

        self.assertFalse(any("Cookie" in item["title"] for item in results))


if __name__ == "__main__":
    unittest.main()
