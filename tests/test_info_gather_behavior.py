import unittest
from unittest.mock import patch

from scanner import info_gather


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class InfoGatherBehaviorTests(unittest.TestCase):
    @patch("requests.options", side_effect=AssertionError("raw requests.options should not be used"))
    @patch("scanner.info_gather.fetch")
    def test_gather_info_uses_fetch_for_options_probe(self, mock_fetch, _mock_options):
        def fake_fetch(url, method="GET", headers=None, **kwargs):
            del headers, kwargs
            if method == "OPTIONS":
                return FakeResponse(
                    status_code=200,
                    headers={"Allow": "GET, POST, OPTIONS"},
                )
            if url.endswith(("/admin", "/administrator", "/wp-admin", "/phpmyadmin", "/manager")):
                return None
            return FakeResponse(
                status_code=200,
                text="<html><body>Welcome</body></html>",
                headers={"Server": "nginx"},
            )

        mock_fetch.side_effect = fake_fetch

        results = info_gather.gather_info("https://example.test")

        self.assertTrue(any(item["title"] == "Allowed HTTP methods" for item in results))
        self.assertTrue(
            any(call.kwargs.get("method") == "OPTIONS" for call in mock_fetch.call_args_list)
        )

    @patch("scanner.info_gather.fetch")
    def test_gather_info_returns_readable_labels(self, mock_fetch):
        def fake_fetch(url, method="GET", headers=None, **kwargs):
            del headers, kwargs
            if method == "OPTIONS":
                return FakeResponse(
                    status_code=200,
                    headers={"Allow": "GET, POST, TRACE"},
                )
            if url.endswith("/admin"):
                return FakeResponse(
                    status_code=200,
                    text="A" * 150,
                    headers={"Server": "nginx"},
                )
            if url.endswith(("/administrator", "/wp-admin", "/phpmyadmin", "/manager")):
                return None
            return FakeResponse(
                status_code=200,
                text="<html><body>flask app</body></html>",
                headers={"Server": "nginx", "X-Powered-By": "Express"},
            )

        mock_fetch.side_effect = fake_fetch

        results = info_gather.gather_info("https://example.test")
        titles = {item["title"] for item in results}

        self.assertIn("Server fingerprint", titles)
        self.assertIn("Technology stack detected", titles)
        self.assertIn("Allowed HTTP methods", titles)
        self.assertIn("Dangerous HTTP methods enabled", titles)
        self.assertIn("Administrative path exposed", titles)


if __name__ == "__main__":
    unittest.main()
