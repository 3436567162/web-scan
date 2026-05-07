import unittest
from unittest.mock import patch

from scanner import dir_traversal, open_redirect


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class OpenRedirectAccuracyTests(unittest.TestCase):
    @patch("time.sleep", return_value=None)
    @patch("scanner.open_redirect.fetch")
    def test_same_origin_redirect_with_evil_text_in_path_is_not_high(self, mock_fetch, _mock_sleep):
        mock_fetch.return_value = FakeResponse(
            status_code=302,
            headers={"Location": "https://example.test/evil.com/profile?next=evil.com"},
        )

        results = open_redirect.check_open_redirect("https://example.test/login?next=/home")

        self.assertEqual([item["type"] for item in results], ["pass"])

    @patch("time.sleep", return_value=None)
    @patch("scanner.open_redirect.fetch")
    def test_protocol_relative_redirect_to_external_origin_is_high(self, mock_fetch, _mock_sleep):
        mock_fetch.return_value = FakeResponse(
            status_code=302,
            headers={"Location": "//evil.com/callback"},
        )

        results = open_redirect.check_open_redirect("https://example.test/login?next=/home")

        finding = next(item for item in results if item["type"] == "high")
        self.assertIn("evil.com", finding["detail"])

    @patch("time.sleep", return_value=None)
    @patch("scanner.open_redirect.fetch")
    def test_high_redirect_includes_payload_and_target_evidence(self, mock_fetch, _mock_sleep):
        mock_fetch.return_value = FakeResponse(
            status_code=302,
            headers={"Location": "https://evil.com/callback"},
        )

        results = open_redirect.check_open_redirect("https://example.test/login?next=/home")

        finding = next(item for item in results if item["type"] == "high")
        self.assertIn("Payload:", finding["detail"])
        self.assertIn("Redirect", finding["detail"])
        self.assertIn("https://evil.com/callback", finding["detail"])


class SensitivePathAccuracyTests(unittest.TestCase):
    @patch("time.sleep", return_value=None)
    @patch("scanner.dir_traversal.fetch")
    def test_generic_html_fallback_does_not_count_as_env_or_sql_hit(self, mock_fetch, _mock_sleep):
        html = "<html><head><title>Welcome</title></head><body>This page is available for every path.</body></html>"

        def fake_fetch(url):
            if url.endswith("/.env") or url.endswith("/backup.sql"):
                return FakeResponse(status_code=200, text=html)
            return FakeResponse(status_code=404, text="404 not found")

        mock_fetch.side_effect = fake_fetch

        results = dir_traversal._check_sensitive_files("https://example.test")

        self.assertFalse(any("/.env" in item["detail"] for item in results))
        self.assertFalse(any("/backup.sql" in item["detail"] for item in results))
        self.assertEqual([item["type"] for item in results], ["pass"])

    @patch("time.sleep", return_value=None)
    @patch("scanner.dir_traversal.fetch")
    def test_generic_html_fallback_does_not_count_as_binary_high_value_hit(self, mock_fetch, _mock_sleep):
        html = "<html><head><title>Download</title></head><body>Archive unavailable.</body></html>"

        def fake_fetch(url):
            if url.endswith("/backup.zip") or url.endswith("/.DS_Store"):
                return FakeResponse(status_code=200, text=html)
            return FakeResponse(status_code=404, text="404 not found")

        mock_fetch.side_effect = fake_fetch

        results = dir_traversal._check_sensitive_files("https://example.test")

        self.assertFalse(any("/backup.zip" in item["detail"] for item in results))
        self.assertFalse(any("/.DS_Store" in item["detail"] for item in results))
        self.assertEqual([item["type"] for item in results], ["pass"])

    @patch("time.sleep", return_value=None)
    @patch("scanner.dir_traversal.fetch")
    def test_zip_signature_confirms_high_value_hit(self, mock_fetch, _mock_sleep):
        zip_like = "PK\x03\x04\x14\x00\x00\x00archive payload"

        def fake_fetch(url):
            if url.endswith("/backup.zip"):
                return FakeResponse(status_code=200, text=zip_like)
            return FakeResponse(status_code=404, text="404 not found")

        mock_fetch.side_effect = fake_fetch

        results = dir_traversal._check_sensitive_files("https://example.test")

        finding = next(item for item in results if "/backup.zip" in item["detail"])
        self.assertEqual(finding["type"], "high")
        self.assertIn("marker=PK", finding["evidence"])

    @patch("time.sleep", return_value=None)
    @patch("scanner.dir_traversal.fetch")
    def test_ds_store_marker_confirms_high_value_hit_without_length_heuristic(self, mock_fetch, _mock_sleep):
        ds_store_like = "\x00\x00\x00\x01Bud1\x00\x00\x00\x00binary metadata"

        def fake_fetch(url):
            if url.endswith("/.DS_Store"):
                return FakeResponse(status_code=200, text=ds_store_like)
            return FakeResponse(status_code=404, text="404 not found")

        mock_fetch.side_effect = fake_fetch

        results = dir_traversal._check_sensitive_files("https://example.test")

        finding = next(item for item in results if "/.DS_Store" in item["detail"])
        self.assertEqual(finding["type"], "high")
        self.assertIn("marker=Bud1", finding["evidence"])

    @patch("time.sleep", return_value=None)
    @patch("scanner.dir_traversal.fetch")
    def test_true_sql_dump_marker_reports_high_value_hit(self, mock_fetch, _mock_sleep):
        sql_dump = "\n".join(
            [
                "-- MySQL dump",
                "CREATE TABLE users (id int, password varchar(255));",
                "INSERT INTO users VALUES (1, 'hash');",
            ]
        )

        def fake_fetch(url):
            if url.endswith("/backup.sql"):
                return FakeResponse(status_code=200, text=sql_dump)
            return FakeResponse(status_code=404, text="404 not found")

        mock_fetch.side_effect = fake_fetch

        results = dir_traversal._check_sensitive_files("https://example.test")

        finding = next(item for item in results if "/backup.sql" in item["detail"])
        self.assertIn(finding["type"], {"medium", "high"})
        self.assertIn("/backup.sql", finding["detail"])

    @patch("time.sleep", return_value=None)
    @patch("scanner.dir_traversal.fetch")
    def test_public_metadata_paths_keep_structured_severities(self, mock_fetch, _mock_sleep):
        def fake_fetch(url):
            if url.endswith("/robots.txt"):
                return FakeResponse(status_code=200, text="User-agent: *\nDisallow: /private\n")
            if url.endswith("/sitemap.xml"):
                return FakeResponse(status_code=200, text="<urlset><url><loc>https://example.test/</loc></url></urlset>")
            if url.endswith("/.well-known/security.txt"):
                return FakeResponse(status_code=200, text="Contact: mailto:security@example.test\nExpires: 2027-01-01T00:00:00.000Z\n")
            return FakeResponse(status_code=404, text="404 not found")

        mock_fetch.side_effect = fake_fetch

        results = dir_traversal._check_sensitive_files("https://example.test")
        metadata = {
            "/robots.txt": "info",
            "/sitemap.xml": "info",
            "/.well-known/security.txt": "info",
        }

        for path, severity in metadata.items():
            finding = next(item for item in results if path in item["detail"])
            self.assertEqual(finding["type"], severity)


if __name__ == "__main__":
    unittest.main()
