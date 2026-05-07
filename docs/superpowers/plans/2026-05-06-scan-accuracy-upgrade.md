# Scan Accuracy Upgrade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve scan accuracy and finding quality without breaking the current `/api/scan` result shape or rewriting the current Flask UI.

**Architecture:** Keep the existing `results[module] = [finding, ...]` contract, add a normalization layer in `app.py`, and tighten the highest-noise scanners with focused heuristics and structured evidence. Front-end changes stay additive so richer fields render when present and legacy findings still display correctly.

**Tech Stack:** Python 3, Flask, requests, BeautifulSoup, unittest, vanilla HTML/CSS/JS

---

**Repository note:** No `.git` repository is initialized in this workspace. Replace normal commit steps with verification checkpoints that record touched files and rerun the relevant test commands. If the project is later moved into git, convert each checkpoint step into a normal commit.

## File Structure

### Files to modify

- `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\app.py`
- `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\scanner\xss_scanner.py`
- `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\scanner\sqli_scanner.py`
- `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\scanner\open_redirect.py`
- `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\scanner\dir_traversal.py`
- `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\scanner\security_headers.py`
- `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\templates\index.html`
- `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\static\style.css`

### Files to create

- `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\tests\test_result_schema.py`
- `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\tests\test_xss_sqli_accuracy.py`
- `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\tests\test_redirect_traversal_accuracy.py`
- `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\tests\test_security_headers_accuracy.py`

### File responsibilities

- `app.py`: normalize legacy findings, attach scan metadata, and compute compatible summary counts.
- `scanner/xss_scanner.py`: classify reflected XSS by executable context and produce evidence.
- `scanner/sqli_scanner.py`: baseline-aware SQLi detection for URL and form cases with narrower error signatures.
- `scanner/open_redirect.py`: report only genuine cross-origin redirects and record redirect evidence.
- `scanner/dir_traversal.py`: validate sensitive files with stronger content fingerprints and fallback suppression.
- `scanner/security_headers.py`: normalize severity policy and improve HTTPS redirect and cookie checks.
- `templates/index.html` and `static/style.css`: render optional confidence, status, evidence, remediation, and scan metadata fields without changing the page layout.
- new test files: isolate task-specific regression coverage so multiple workers can run in parallel without editing the same test module.

### Task 1: Result Normalization and Scan Metadata

**Files:**
- Modify: `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\app.py`
- Create: `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\tests\test_result_schema.py`
- Modify: `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\tests\test_app_security.py`

- [ ] **Step 1: Write the failing normalization tests**

```python
import socket
import unittest
from unittest.mock import patch

import app as app_module


class ScanResponseNormalizationTests(unittest.TestCase):
    def test_normalize_finding_preserves_legacy_fields_and_adds_defaults(self):
        finding = {"type": "high", "title": "Example", "detail": "Detail"}

        normalized = app_module.normalize_finding("XSS", finding)

        self.assertEqual("high", normalized["type"])
        self.assertEqual("high", normalized["severity"])
        self.assertEqual("open", normalized["status"])
        self.assertEqual([], normalized["evidence"])
        self.assertEqual([], normalized["remediation"])
        self.assertEqual("XSS", normalized["module"])

    def test_scan_response_includes_scan_metadata(self):
        app_module.app.config["TESTING"] = True
        client = app_module.app.test_client()

        with patch(
            "socket.getaddrinfo",
            return_value=[(
                socket.AF_INET,
                socket.SOCK_STREAM,
                0,
                "",
                ("93.184.216.34", 80),
            )],
        ), patch.object(
            app_module,
            "SCAN_MODULES",
            [("sentinel", lambda _url: [{
                "type": "pass",
                "title": "ok",
                "detail": "ok",
            }])],
        ):
            response = client.post("/api/scan", json={"url": "http://example.com"})
            payload = response.get_json()

        self.assertIn("scan_metadata", payload)
        self.assertIn("duration_ms", payload["scan_metadata"])
        self.assertIn("modules_run", payload["scan_metadata"])
```

- [ ] **Step 2: Run the focused tests and verify they fail for the expected reason**

Run: `python -B -m unittest discover -s tests -p "test_result_schema.py" -v`

Expected: FAIL because `normalize_finding` and scan metadata fields do not exist yet.

- [ ] **Step 3: Implement the normalization helpers and metadata assembly in `app.py`**

```python
from datetime import datetime, timezone


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def normalize_finding(module_name, finding):
    normalized = dict(finding)
    severity = normalized.get("severity", normalized.get("type", "info"))
    status = normalized.get("status")
    if status is None:
        if severity == "pass":
            status = "pass"
        elif severity == "info":
            status = "info"
        elif severity == "error":
            status = "error"
        else:
            status = "open"

    normalized["severity"] = severity
    normalized["status"] = status
    normalized.setdefault("confidence", None)
    normalized.setdefault("evidence", [])
    normalized.setdefault("remediation", [])
    normalized.setdefault("module", module_name)
    return normalized


def normalize_module_results(module_name, findings):
    return [normalize_finding(module_name, finding) for finding in findings]


def build_scan_metadata(started_at, finished_at, duration_ms, modules_run, modules_skipped):
    return {
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_ms": max(0, int(duration_ms)),
        "request_budget_limit": SCAN_REQUEST_LIMIT,
        "request_budget_exhausted": budget_exhausted(),
        "modules_run": modules_run,
        "modules_skipped": modules_skipped,
    }
```

Implementation notes:

- capture monotonic start and end timestamps inside `scan()`
- normalize each module result before storing it in `results`
- preserve `type`, `title`, and `detail`
- update the summary loop to count canonical `severity`
- keep the current response keys and add `scan_metadata`

- [ ] **Step 4: Run the focused normalization tests and existing app security tests**

Run: `python -B -m unittest discover -s tests -p "test_result_schema.py" -v`

Expected: PASS

Run: `python -B -m unittest discover -s tests -p "test_app_security.py" -v`

Expected: PASS

- [ ] **Step 5: Checkpoint the task**

Run: `python -B -m py_compile app.py tests\\test_result_schema.py tests\\test_app_security.py`

Expected: exit code `0`

Touched files to record:

- `app.py`
- `tests/test_result_schema.py`
- `tests/test_app_security.py`

### Task 2: XSS and SQLi Accuracy Tightening

**Files:**
- Modify: `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\scanner\xss_scanner.py`
- Modify: `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\scanner\sqli_scanner.py`
- Create: `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\tests\test_xss_sqli_accuracy.py`

- [ ] **Step 1: Write the failing XSS and SQLi regression tests**

```python
import unittest
from unittest.mock import patch

from scanner import sqli_scanner, xss_scanner


class FakeResponse:
    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code
        self.headers = {}


class XssAccuracyTests(unittest.TestCase):
    @patch("scanner.xss_scanner.extract_forms", return_value=[])
    @patch("scanner.xss_scanner.extract_params", return_value={"q": ["test"]})
    @patch("scanner.xss_scanner.inject_param", side_effect=lambda url, param, payload: f"{url}&{param}=x")
    @patch("scanner.xss_scanner.fetch")
    def test_comment_reflection_is_not_high(self, mock_fetch, *_mocks):
        mock_fetch.return_value = FakeResponse("<!-- <script>alert(1)</script> -->")
        results = xss_scanner.check_xss("https://example.test/search?q=test")
        self.assertFalse(any(item["type"] == "high" for item in results))

    @patch("scanner.xss_scanner.extract_forms", return_value=[])
    @patch("scanner.xss_scanner.extract_params", return_value={"q": ["test"]})
    @patch("scanner.xss_scanner.inject_param", side_effect=lambda url, param, payload: f"{url}&{param}=x")
    @patch("scanner.xss_scanner.fetch")
    def test_script_context_reflection_is_high_with_evidence(self, mock_fetch, *_mocks):
        mock_fetch.return_value = FakeResponse("<html><script>alert(1)</script></html>")
        results = xss_scanner.check_xss("https://example.test/search?q=test")
        finding = next(item for item in results if item["type"] == "high")
        self.assertTrue(finding["evidence"])


class SqliAccuracyTests(unittest.TestCase):
    @patch("scanner.sqli_scanner.extract_forms", return_value=[])
    @patch("scanner.sqli_scanner.extract_params", return_value={"id": ["1"]})
    @patch("scanner.sqli_scanner.inject_param", side_effect=lambda url, param, payload: f"{url}&{param}=x")
    @patch("scanner.sqli_scanner.fetch")
    def test_existing_error_page_is_not_reported(self, mock_fetch, *_mocks):
        mock_fetch.side_effect = [
            FakeResponse("syntax error"),
            FakeResponse("syntax error"),
        ]
        results = sqli_scanner.check_sqli("https://example.test/item?id=1")
        self.assertEqual([], results)
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run: `python -B -m unittest discover -s tests -p "test_xss_sqli_accuracy.py" -v`

Expected: FAIL because current XSS logic treats raw payload reflection as high risk and SQLi lacks baseline-aware suppression for the new cases.

- [ ] **Step 3: Implement context-aware XSS and baseline-aware SQLi**

```python
import re


def _make_evidence(kind, label, value):
    return {"kind": kind, "label": label, "value": value}


def _snippet(text, needle, radius=100):
    index = text.find(needle)
    if index < 0:
        return ""
    start = max(0, index - radius)
    end = min(len(text), index + len(needle) + radius)
    return text[start:end]


def _classify_xss_reflection(body, payload):
    if not body:
        return None
    if "<!--" in body and payload in body:
        return None
    if payload in body and "<script" in body.lower():
        return {
            "severity": "high",
            "rule_id": "xss.reflected.script",
            "context": "script-tag",
        }
    for pattern in DANGEROUS_HTML_PATTERNS:
        if pattern.search(body):
            return {
                "severity": "high",
                "rule_id": "xss.reflected.executable-html",
                "context": "html-executable",
            }
    return None
```

```python
SQL_ERROR_PATTERNS = [
    re.compile(r"mysql.*syntax", re.IGNORECASE),
    re.compile(r"postgresql.*error", re.IGNORECASE),
    re.compile(r"sqlite.*error", re.IGNORECASE),
    re.compile(r"sqlstate\\[[^\\]]+\\]", re.IGNORECASE),
]


def _match_new_sql_error(baseline_text, injected_text):
    baseline_hits = {pattern.pattern for pattern in SQL_ERROR_PATTERNS if pattern.search(baseline_text)}
    for pattern in SQL_ERROR_PATTERNS:
        if pattern.search(injected_text) and pattern.pattern not in baseline_hits:
            return pattern.pattern
    return None
```

Implementation notes:

- add evidence to high-confidence XSS findings: payload, matched context, snippet
- do not emit `high` for comments, plain text, or inert reflections
- compute a baseline response for form submissions as well as URL parameters
- carry `confidence`, `category`, `rule_id`, `location`, and `remediation` on new findings

- [ ] **Step 4: Run the focused test file and existing scan accuracy tests**

Run: `python -B -m unittest discover -s tests -p "test_xss_sqli_accuracy.py" -v`

Expected: PASS

Run: `python -B -m unittest discover -s tests -p "test_scan_accuracy.py" -v`

Expected: PASS

- [ ] **Step 5: Checkpoint the task**

Run: `python -B -m py_compile scanner\\xss_scanner.py scanner\\sqli_scanner.py tests\\test_xss_sqli_accuracy.py`

Expected: exit code `0`

Touched files to record:

- `scanner/xss_scanner.py`
- `scanner/sqli_scanner.py`
- `tests/test_xss_sqli_accuracy.py`

### Task 3: Open Redirect and Sensitive File Accuracy Tightening

**Files:**
- Modify: `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\scanner\open_redirect.py`
- Modify: `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\scanner\dir_traversal.py`
- Create: `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\tests\test_redirect_traversal_accuracy.py`

- [ ] **Step 1: Write the failing redirect and traversal tests**

```python
import unittest
from unittest.mock import patch

from scanner import dir_traversal, open_redirect


class FakeResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class OpenRedirectAccuracyTests(unittest.TestCase):
    @patch("scanner.open_redirect.fetch")
    @patch("time.sleep", return_value=None)
    def test_same_origin_location_containing_payload_text_is_not_high(self, _sleep, mock_fetch):
        mock_fetch.return_value = FakeResponse(
            status_code=302,
            headers={"Location": "https://example.test/redirect/evil.com"},
        )
        results = open_redirect.check_open_redirect("https://example.test/login?next=/home")
        self.assertFalse(any(item["type"] == "high" for item in results))


class TraversalAccuracyTests(unittest.TestCase):
    @patch("scanner.dir_traversal.fetch")
    @patch("time.sleep", return_value=None)
    def test_html_fallback_page_is_not_sensitive_file_hit(self, _sleep, mock_fetch):
        mock_fetch.return_value = FakeResponse(
            status_code=200,
            text="<html><title>App</title><div>Not found</div></html>",
        )
        results = dir_traversal._check_sensitive_files("https://example.test")
        self.assertTrue(all("/backup.sql" not in item["detail"] for item in results if item["type"] != "pass"))
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run: `python -B -m unittest discover -s tests -p "test_redirect_traversal_accuracy.py" -v`

Expected: FAIL because open redirect uses substring matching and sensitive-file checks still accept weak `200` pages.

- [ ] **Step 3: Implement cross-origin redirect validation and stronger sensitive-file fingerprints**

```python
from urllib.parse import urljoin, urlparse


def _redirect_leaves_origin(base_url, location):
    resolved = urljoin(base_url, location)
    base = urlparse(base_url)
    target = urlparse(resolved)
    return (target.scheme, target.netloc) != (base.scheme, base.netloc), resolved


def _build_redirect_evidence(payload, location, resolved_target):
    return [
        {"kind": "payload", "label": "Payload", "value": payload},
        {"kind": "redirect-target", "label": "Location", "value": location},
        {"kind": "redirect-target", "label": "Resolved target", "value": resolved_target},
    ]
```

```python
def _looks_like_sql_dump(body):
    body_lower = body.lower()
    return "create table" in body_lower or "insert into" in body_lower


def _looks_like_env_file(body):
    if "<html" in body.lower():
        return False
    lines = [line for line in body.splitlines() if "=" in line]
    return len(lines) >= 2


def _is_not_found_like(body, baseline_body):
    if not body or not baseline_body:
        return False
    return body.strip() == baseline_body.strip()
```

Implementation notes:

- parse and compare redirect origins instead of substring matching
- keep same-origin payload echoes below high severity or omit them
- fingerprint `.sql`, `.env`, `.zip`, `.DS_Store`, and `web.config` more strictly
- add evidence showing which content marker caused a traversal or sensitive-file finding

- [ ] **Step 4: Run the focused tests and the existing redirect and scan-accuracy tests**

Run: `python -B -m unittest discover -s tests -p "test_redirect_traversal_accuracy.py" -v`

Expected: PASS

Run: `python -B -m unittest discover -s tests -p "test_crawler_redirect.py" -v`

Expected: PASS

Run: `python -B -m unittest discover -s tests -p "test_scan_accuracy.py" -v`

Expected: PASS

- [ ] **Step 5: Checkpoint the task**

Run: `python -B -m py_compile scanner\\open_redirect.py scanner\\dir_traversal.py tests\\test_redirect_traversal_accuracy.py`

Expected: exit code `0`

Touched files to record:

- `scanner/open_redirect.py`
- `scanner/dir_traversal.py`
- `tests/test_redirect_traversal_accuracy.py`

### Task 4: Security Header Severity Normalization and Richer UI Rendering

**Files:**
- Modify: `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\scanner\security_headers.py`
- Modify: `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\templates\index.html`
- Modify: `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\static\style.css`
- Create: `C:\Users\hongke\OneDrive\Desktop\测试\web-scan-main\web-scan-main\tests\test_security_headers_accuracy.py`

- [ ] **Step 1: Write the failing security-header tests**

```python
import unittest
from unittest.mock import patch

from scanner import security_headers


class FakeResponse:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


class SecurityHeaderAccuracyTests(unittest.TestCase):
    @patch("scanner.security_headers.fetch")
    def test_missing_x_xss_protection_is_not_medium(self, mock_fetch):
        mock_fetch.return_value = FakeResponse(headers={})
        results = security_headers.check_security_headers("https://example.test")
        finding = next(item for item in results if "X-XSS-Protection" in item["title"])
        self.assertIn(finding["type"], {"info", "low"})

    @patch("scanner.security_headers.fetch")
    def test_http_redirect_to_https_is_not_reported_as_missing(self, mock_fetch):
        mock_fetch.side_effect = [
            FakeResponse(status_code=200, headers={}),
            FakeResponse(status_code=301, headers={"Location": "https://example.test/"}),
        ]
        results = security_headers.check_security_headers("http://example.test")
        self.assertFalse(any("HTTPS" in item["title"] and item["type"] == "medium" for item in results))
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run: `python -B -m unittest discover -s tests -p "test_security_headers_accuracy.py" -v`

Expected: FAIL because the current severity table and HTTPS redirect logic are too rigid.

- [ ] **Step 3: Implement the severity policy updates and additive UI rendering**

```python
REQUIRED_HEADERS = {
    "X-Frame-Options": {"severity": "medium", "desc": "..."},
    "Content-Security-Policy": {"severity": "medium", "desc": "..."},
    "X-Content-Type-Options": {"severity": "low", "desc": "..."},
    "X-XSS-Protection": {"severity": "info", "desc": "..."},
}


def _should_check_hsts(url):
    return url.startswith("https://")
```

```html
<div class="result-meta">
  ${item.confidence != null ? `<span class="pill">Confidence ${Math.round(item.confidence * 100)}%</span>` : ""}
  ${item.status ? `<span class="pill pill-status">${escapeHtml(item.status)}</span>` : ""}
</div>
${renderList("Evidence", item.evidence)}
${renderList("Remediation", item.remediation)}
```

```css
.result-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 8px;
}

.pill {
    padding: 2px 8px;
    border-radius: 999px;
    border: 1px solid #2a3a4a;
    color: #ccddee;
    font-size: 0.75rem;
}
```

Implementation notes:

- only evaluate HSTS for HTTPS targets
- when the input URL is HTTP, test whether it redirects to HTTPS rather than requiring a live HTTPS `200`
- keep front-end rendering tolerant of missing optional fields
- show scan metadata in one compact line above the detailed results

- [ ] **Step 4: Run the focused tests and the full suite**

Run: `python -B -m unittest discover -s tests -p "test_security_headers_accuracy.py" -v`

Expected: PASS

Run: `python -B -m unittest discover -s tests -v`

Expected: PASS

- [ ] **Step 5: Checkpoint the task**

Run: `python -B -m py_compile scanner\\security_headers.py`

Expected: exit code `0`

Touched files to record:

- `scanner/security_headers.py`
- `templates/index.html`
- `static/style.css`
- `tests/test_security_headers_accuracy.py`

## Self-Review

### Spec coverage

- XSS, SQLi, open redirect, directory traversal, security headers, result normalization, scan metadata, and front-end additive rendering are all covered by Tasks 1-4.
- Parallel write ownership matches the approved design.

### Placeholder scan

- No `TBD`, `TODO`, or deferred implementation placeholders remain in the plan.
- The only intentional environment deviation is replacing commit steps with checkpoints because no git repository exists.

### Type consistency

- The plan uses `severity`, `status`, `confidence`, `evidence`, `remediation`, `category`, `location`, `rule_id`, and `module` consistently.
- `type` remains the legacy field and must stay present after normalization.
