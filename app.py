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
TRUSTED_PROXIES_ENV = "TRUSTED_PROXIES"
SCAN_MODULE_LABELS = {
    "info_gather": "Information Gathering",
    "security_headers": "Security Headers",
    "sqli": "SQL Injection",
    "xss": "XSS",
    "dir_traversal": "Sensitive Paths",
    "open_redirect": "Open Redirect",
    "cors": "CORS",
}


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


def _parse_csv_env(value):
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


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


def get_trusted_proxies():
    return set(_parse_csv_env(os.environ.get(TRUSTED_PROXIES_ENV, "")))


def get_client_id():
    remote_addr = request.remote_addr or "unknown"
    if remote_addr not in get_trusted_proxies():
        return remote_addr

    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if not forwarded_for:
        return remote_addr

    client_ip = forwarded_for.split(",", 1)[0].strip()
    if client_ip:
        return client_ip
    return remote_addr


def prune_rate_limit_cache(now=None):
    if now is None:
        now = time.monotonic()

    stale_before = now - CLIENT_SCAN_COOLDOWN_SECONDS
    stale_clients = [
        client_id
        for client_id, last_seen in _LAST_SCAN_BY_CLIENT.items()
        if last_seen <= stale_before
    ]
    for client_id in stale_clients:
        del _LAST_SCAN_BY_CLIENT[client_id]


def is_rate_limited(client_id):
    now = time.monotonic()
    prune_rate_limit_cache(now)
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


def _default_module_label(module_name):
    return SCAN_MODULE_LABELS.get(module_name, module_name.replace("_", " ").title())


def get_scan_module_definitions():
    definitions = []
    for entry in SCAN_MODULES:
        if isinstance(entry, dict):
            module_name = entry["id"]
            scan_func = entry["func"]
            label = entry.get("label") or _default_module_label(module_name)
        else:
            module_name = entry[0]
            scan_func = entry[1]
            label = entry[2] if len(entry) > 2 else _default_module_label(module_name)

        definitions.append({
            "id": module_name,
            "label": label,
            "func": scan_func,
        })
    return definitions


def resolve_scan_modules(requested_modules):
    definitions = get_scan_module_definitions()
    registry = {definition["id"]: definition for definition in definitions}

    if requested_modules is None:
        return definitions
    if not isinstance(requested_modules, list) or not requested_modules:
        raise ValueError("`modules` must be a non-empty list of module ids")

    selected = []
    seen = set()
    unknown = []

    for module_name in requested_modules:
        if not isinstance(module_name, str):
            raise ValueError("`modules` must contain only string module ids")
        if module_name in seen:
            continue
        seen.add(module_name)

        definition = registry.get(module_name)
        if definition is None:
            unknown.append(module_name)
            continue

        selected.append(definition)

    if unknown:
        unknown_text = ", ".join(sorted(unknown))
        raise ValueError(f"Unknown scan modules: {unknown_text}")

    return selected


@app.route("/")
def index():
    return render_template(
        "index.html",
        scan_modules=[
            {
                "id": definition["id"],
                "label": definition["label"],
            }
            for definition in get_scan_module_definitions()
        ],
    )


@app.route("/api/scan", methods=["POST"])
def scan():
    started_monotonic = time.monotonic()
    started_at = _timestamp_utc()

    data = request.get_json(silent=True)
    if not data or not data.get("url"):
        return jsonify({"error": "Target URL is required"}), 400

    try:
        url = normalize_url(data["url"])
        validate_scan_url(url)
        selected_modules = resolve_scan_modules(data.get("modules"))
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
        for index, definition in enumerate(selected_modules):
            module_name = definition["id"]
            scan_func = definition["func"]
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
                modules_skipped = [
                    item["id"] for item in selected_modules[index + 1:]
                ]
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
            "selected_modules": [item["id"] for item in selected_modules],
        },
    })


if __name__ == "__main__":
    run_host, run_port, run_debug = get_run_config()
    app.run(debug=run_debug, host=run_host, port=run_port)
