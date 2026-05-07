"""SQL Injection detection based on error-based injection."""

import re
import time

from .crawler import extract_forms, extract_params, fetch, inject_param

SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "1' AND '1'='1", "1 AND 1=1--"]

SQL_ERROR_RULES = [
    ("sqli.mysql.syntax", re.compile(r"you have an error in your sql syntax", re.IGNORECASE)),
    ("sqli.mysql.warning", re.compile(r"warning:\s*mysql", re.IGNORECASE)),
    ("sqli.mssql.unclosed-quote", re.compile(r"unclosed quotation mark", re.IGNORECASE)),
    (
        "sqli.mssql.ole-db",
        re.compile(r"microsoft ole db provider for (?:odbc drivers|sql server)", re.IGNORECASE),
    ),
    ("sqli.sqlstate", re.compile(r"sqlstate(?:\[[^\]]+\])?", re.IGNORECASE)),
    ("sqli.postgres.pg-query", re.compile(r"\bpg_(?:query|exec)\b", re.IGNORECASE)),
    ("sqli.sqlite.sqlite3", re.compile(r"\bsqlite3\b", re.IGNORECASE)),
    ("sqli.oracle.command-ended", re.compile(r"sql command not properly ended", re.IGNORECASE)),
    ("sqli.oracle.quoted-string", re.compile(r"quoted string not properly terminated", re.IGNORECASE)),
    ("sqli.mysql.api-call", re.compile(r"\bmysql_(?:fetch|num_rows)\b", re.IGNORECASE)),
    ("sqli.oracle.ora-code", re.compile(r"\bora-\d{4,}\b", re.IGNORECASE)),
    ("sqli.postgres.name", re.compile(r"\bpostgresql\b", re.IGNORECASE)),
    ("sqli.sqlite.sqlite-error", re.compile(r"\bsqlite_error\b", re.IGNORECASE)),
    ("sqli.db2.error", re.compile(r"\bdb2 sql error\b", re.IGNORECASE)),
]


def check_sqli(url):
    """Check URL parameters and forms for SQL injection vulnerabilities."""
    results = []
    results.extend(_check_url_params(url))
    results.extend(_check_forms(url))
    return results


def _check_url_params(url):
    """Test URL query parameters for SQL injection."""
    results = []
    params = extract_params(url)
    if not params:
        return results

    original_resp = fetch(url)
    if original_resp is None:
        return results

    baseline_signals = _find_sql_error_signals(original_resp.text)

    for param_name in params:
        for payload in SQLI_PAYLOADS:
            test_url = inject_param(url, param_name, payload)
            resp = fetch(test_url)
            if resp is None:
                continue

            time.sleep(0.2)

            evidence = _build_sqli_evidence(resp.text, payload, baseline_signals)
            if evidence:
                results.append(
                    {
                        "type": "high",
                        "title": "SQL injection (query parameter)",
                        "detail": (
                            f"Parameter '{param_name}' introduced a database-specific error.\n"
                            f"Payload: {payload}\n"
                            f"Matched signal: {evidence[0]['matched_text']}"
                        ),
                        "url": test_url,
                        "confidence": "high",
                        "evidence": evidence,
                        "remediation": [
                            "Use parameterized queries for all database access.",
                            "Do not concatenate untrusted input into SQL statements.",
                        ],
                        "category": "injection",
                        "rule_id": evidence[0]["rule_id"],
                        "location": f"query.{param_name}",
                    }
                )
                break

    return results


def _check_forms(url):
    """Test form inputs for SQL injection."""
    results = []
    forms = extract_forms(url)
    if not forms:
        return results

    for form in forms:
        for inp in form["inputs"]:
            if inp["type"] in ("submit", "button", "hidden", "file", "checkbox", "radio"):
                continue

            baseline_data = _build_form_data(form, inp["name"], "test")
            try:
                baseline_resp = _submit_form(form, baseline_data)
            except Exception:
                continue

            if baseline_resp is None:
                continue

            baseline_signals = _find_sql_error_signals(baseline_resp.text)

            for payload in SQLI_PAYLOADS:
                data = _build_form_data(form, inp["name"], payload)
                try:
                    resp = _submit_form(form, data)
                except Exception:
                    continue

                if resp is None:
                    continue

                time.sleep(0.2)

                evidence = _build_sqli_evidence(resp.text, payload, baseline_signals)
                if evidence:
                    results.append(
                        {
                            "type": "high",
                            "title": "SQL injection (form input)",
                            "detail": (
                                f"Form field '{inp['name']}' introduced a database-specific error.\n"
                                f"Action: {form['action']}\n"
                                f"Method: {form['method']}\n"
                                f"Payload: {payload}\n"
                                f"Matched signal: {evidence[0]['matched_text']}"
                            ),
                            "confidence": "high",
                            "evidence": evidence,
                            "remediation": [
                                "Use parameterized queries for all database access.",
                                "Do not concatenate untrusted input into SQL statements.",
                            ],
                            "category": "injection",
                            "rule_id": evidence[0]["rule_id"],
                            "location": f"form.{inp['name']}",
                        }
                    )
                    break

    return results


def _submit_form(form, data):
    """Submit a form using its declared method."""
    if form["method"] == "POST":
        return fetch(form["action"], method="POST", data=data)
    return fetch(form["action"], params=data)


def _build_form_data(form, target_name, target_value):
    """Build a form submission payload with one targeted field value."""
    data = {}
    for field in form["inputs"]:
        if field["type"] in ("submit", "button"):
            continue
        if field["name"] == target_name:
            data[field["name"]] = target_value
        else:
            data[field["name"]] = field.get("value", "test") or "test"
    return data


def _build_sqli_evidence(body, payload, baseline_signals):
    """Return evidence only when the injected response adds a stronger DB signal."""
    response_signals = _find_sql_error_signals(body)
    baseline_rule_ids = {signal["rule_id"] for signal in baseline_signals}

    for signal in response_signals:
        if signal["rule_id"] not in baseline_rule_ids:
            return [
                {
                    "payload": payload,
                    "matched_text": signal["matched_text"],
                    "response_snippet": signal["matched_text"],
                    "rule_id": signal["rule_id"],
                    "baseline_signals": [item["rule_id"] for item in baseline_signals],
                }
            ]

    return []


def _find_sql_error_signals(text):
    """Extract strong, database-specific error signals from a response body."""
    if not text:
        return []

    signals = []
    for rule_id, pattern in SQL_ERROR_RULES:
        match = pattern.search(text)
        if match:
            signals.append({"rule_id": rule_id, "matched_text": match.group(0)[:200]})
    return signals
