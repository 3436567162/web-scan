"""Web Vulnerability Scanner - Flask Application."""

import os
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import urllib3
from flask import Flask, jsonify, render_template, request

from scanner.crawler import budget_exhausted, request_budget
from scanner.cors_check import check_cors
from scanner.dir_traversal import check_dir_traversal
from scanner.info_gather import gather_info
from scanner.open_redirect import check_open_redirect
from scanner.security_headers import check_security_headers
from scanner.sqli_scanner import check_sqli
from scanner.url_safety import validate_public_http_url
from scanner.xss_scanner import check_xss

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
SCAN_REQUEST_LIMIT = 60
CLIENT_SCAN_COOLDOWN_SECONDS = 5.0
_LAST_SCAN_BY_CLIENT = {}


def _timestamp_utc():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _default_status_for_type(finding_type):
    if finding_type == "pass":
        return "pass"
    if finding_type == "info":
        return "info"
    if finding_type == "error":
        return "error"
    return "open"


def _coalesce_optional(value, default):
    if value is None:
        return default
    return value


def _normalize_optional_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        return [value]
    return []


def normalize_findings(module_name, findings):
    normalized = []
    for finding in findings or []:
        finding_type = finding.get("type")
        normalized.append({
            **finding,
            "severity": _coalesce_optional(finding.get("severity"), finding_type),
            "status": _coalesce_optional(
                finding.get("status"),
                _default_status_for_type(finding_type),
            ),
            "confidence": finding.get("confidence"),
            "evidence": _normalize_optional_list(finding.get("evidence")),
            "remediation": _normalize_optional_list(finding.get("remediation")),
            "module": finding.get("module", module_name),
        })
    return normalized


def summarize_results(results):
    total_high = 0
    total_medium = 0
    total_low = 0

    for module_results in results.values():
        for finding in module_results:
            severity = finding.get("severity", finding.get("type"))
            if severity == "high":
                total_high += 1
            elif severity == "medium":
                total_medium += 1
            elif severity == "low":
                total_low += 1

    return {
        "high": total_high,
        "medium": total_medium,
        "low": total_low,
    }


def normalize_url(url):
    """Ensure URL has an allowed scheme."""
    if not isinstance(url, str):
        raise ValueError("Invalid URL")

    url = url.strip()
    if not url:
        raise ValueError("URL is required")

    parsed = urlparse(url)
    if parsed.scheme:
        if parsed.scheme.lower() in {"http", "https"}:
            return url

        if "://" not in url:
            prefix, _, suffix = url.partition(":")
            port_text = suffix.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
            if prefix and port_text.isdigit():
                return "http://" + url

        raise ValueError("Only http and https URLs are allowed")

    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def validate_scan_url(url):
    validate_public_http_url(url)


def get_client_id():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.remote_addr or "unknown"


def is_rate_limited(client_id):
    now = time.monotonic()
    last_seen = _LAST_SCAN_BY_CLIENT.get(client_id)
    if last_seen is not None and now - last_seen < CLIENT_SCAN_COOLDOWN_SECONDS:
        return True

    _LAST_SCAN_BY_CLIENT[client_id] = now
    return False


def parse_debug_env(value):
    return value.strip().lower() in {"1", "true", "yes", "on"}


def get_run_config():
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    debug = parse_debug_env(os.environ.get("FLASK_DEBUG", ""))
    return host, port, debug


SCAN_MODULES = [
    ("info_gather", gather_info),
    ("security_headers", check_security_headers),
    ("sqli", check_sqli),
    ("xss", check_xss),
    ("dir_traversal", check_dir_traversal),
    ("open_redirect", check_open_redirect),
    ("cors", check_cors),
]


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    started_monotonic = time.monotonic()
    started_at = _timestamp_utc()

    data = request.get_json()
    if not data or not data.get("url"):
        return jsonify({"error": "Target URL is required"}), 400

    try:
        url = normalize_url(data["url"])
        validate_scan_url(url)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    client_id = get_client_id()
    if is_rate_limited(client_id):
        return jsonify({"error": "Too many scan requests. Please retry later."}), 429

    results = {}
    modules_run = []
    modules_skipped = []
    request_budget_exhausted = False

    with request_budget(SCAN_REQUEST_LIMIT):
        for index, (module_name, scan_func) in enumerate(SCAN_MODULES):
            try:
                module_results = scan_func(url)
                results[module_name] = normalize_findings(module_name, module_results)
            except Exception as e:
                results[module_name] = normalize_findings(module_name, [{
                    "type": "error",
                    "title": f"{module_name} scan failed",
                    "detail": str(e),
                }])

            modules_run.append(module_name)

            if budget_exhausted():
                request_budget_exhausted = True
                results.setdefault(module_name, []).append({
                    "type": "error",
                    "title": "Request budget exhausted",
                    "detail": (
                        "The per-scan outgoing request limit was reached and "
                        "the remaining modules were skipped."
                    ),
                })
                results[module_name] = normalize_findings(module_name, results[module_name])
                modules_skipped = [name for name, _ in SCAN_MODULES[index + 1:]]
                break

    finished_at = _timestamp_utc()
    duration_ms = int((time.monotonic() - started_monotonic) * 1000)

    return jsonify({
        "url": url,
        "results": results,
        "summary": summarize_results(results),
        "scan_metadata": {
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_ms": duration_ms,
            "request_budget_limit": SCAN_REQUEST_LIMIT,
            "request_budget_exhausted": request_budget_exhausted,
            "modules_run": modules_run,
            "modules_skipped": modules_skipped,
        },
    })


if __name__ == "__main__":
    run_host, run_port, run_debug = get_run_config()
    app.run(debug=run_debug, host=run_host, port=run_port)
