"""XSS (Cross-Site Scripting) detection for reflected XSS."""

import re
import time

from .crawler import extract_forms, extract_params, fetch, inject_param

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
]

XSS_RULES = [
    (
        "xss.reflected.script-tag",
        re.compile(
            r"<\s*script\b[^>]*>.*?alert\s*\(\s*1\s*\).*?<\s*/\s*script\s*>",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "xss.reflected.event-handler",
        re.compile(r"<[^>]+\s+on(?:error|load)\s*=\s*['\"]?alert\s*\(\s*1\s*\)", re.IGNORECASE),
    ),
    (
        "xss.reflected.javascript-uri",
        re.compile(
            r"<[^>]+\s+(?:href|src)\s*=\s*['\"]?javascript\s*:\s*alert\s*\(\s*1\s*\)",
            re.IGNORECASE,
        ),
    ),
]


def check_xss(url):
    """Check URL parameters and forms for XSS vulnerabilities."""
    results = []
    results.extend(_check_url_params(url))
    results.extend(_check_forms(url))
    return results


def _check_url_params(url):
    """Test URL query parameters for reflected XSS."""
    results = []
    params = extract_params(url)
    if not params:
        return results

    for param_name in params:
        for payload in XSS_PAYLOADS:
            test_url = inject_param(url, param_name, payload)
            resp = fetch(test_url)
            if resp is None:
                continue

            time.sleep(0.2)

            evidence = _extract_xss_evidence(resp.text, payload)
            if evidence:
                results.append(
                    {
                        "type": "high",
                        "title": "Reflected XSS (query parameter)",
                        "detail": (
                            f"Parameter '{param_name}' reflects executable HTML.\n"
                            f"Payload: {payload}\n"
                            f"Matched snippet: {evidence[0]['response_snippet']}"
                        ),
                        "url": test_url,
                        "confidence": "high",
                        "evidence": evidence,
                        "remediation": [
                            "HTML-encode untrusted input before rendering it in HTML.",
                            "Do not place untrusted input into script blocks, event handlers, or javascript: URLs.",
                        ],
                        "category": "injection",
                        "rule_id": evidence[0]["rule_id"],
                        "location": f"query.{param_name}",
                    }
                )
                break

    return results


def _check_forms(url):
    """Test form inputs for reflected XSS."""
    results = []
    forms = extract_forms(url)
    if not forms:
        return results

    for form in forms:
        for inp in form["inputs"]:
            if inp["type"] in ("submit", "button", "hidden", "file", "checkbox", "radio"):
                continue

            for payload in XSS_PAYLOADS:
                data = {}
                for field in form["inputs"]:
                    if field["name"] == inp["name"]:
                        data[field["name"]] = payload
                    elif field["type"] not in ("submit", "button"):
                        data[field["name"]] = field.get("value", "test")

                try:
                    if form["method"] == "POST":
                        resp = fetch(form["action"], method="POST", data=data)
                    else:
                        resp = fetch(form["action"], params=data)
                except Exception:
                    continue

                if resp is None:
                    continue

                time.sleep(0.2)

                evidence = _extract_xss_evidence(resp.text, payload)
                if evidence:
                    results.append(
                        {
                            "type": "high",
                            "title": "Reflected XSS (form input)",
                            "detail": (
                                f"Form field '{inp['name']}' reflects executable HTML.\n"
                                f"Action: {form['action']}\n"
                                f"Method: {form['method']}\n"
                                f"Payload: {payload}"
                            ),
                            "confidence": "high",
                            "evidence": evidence,
                            "remediation": [
                                "HTML-encode untrusted input before rendering it in HTML.",
                                "Do not place untrusted input into script blocks, event handlers, or javascript: URLs.",
                            ],
                            "category": "injection",
                            "rule_id": evidence[0]["rule_id"],
                            "location": f"form.{inp['name']}",
                        }
                    )
                    break

    return results


def _has_unencoded_xss_reflection(body, payload):
    """Return True only for executable or clearly unsafe reflection."""
    return _match_xss_rule(body, payload) is not None


def _extract_xss_evidence(body, payload):
    """Return finding evidence for an executable reflection."""
    match = _match_xss_rule(body, payload)
    if match is None:
        return []

    rule_id, matched_text = match
    return [
        {
            "payload": payload,
            "response_snippet": matched_text,
            "matched_response_snippet": matched_text,
            "rule_id": rule_id,
        }
    ]


def _match_xss_rule(body, payload):
    """Return the matched rule id and snippet when reflection is executable."""
    if not body or payload not in body:
        return None

    comment_matches = list(re.finditer(r"<!--.*?-->", body, flags=re.DOTALL))
    if any(payload in match.group(0) for match in comment_matches):
        # Ambiguous reflection: the payload is definitely inert somewhere in the
        # response, so do not upgrade severity based on another matching pattern.
        return None

    body_without_comments = re.sub(r"<!--.*?-->", "", body, flags=re.DOTALL)
    for rule_id, pattern in XSS_RULES:
        match = pattern.search(body_without_comments)
        if match and payload in match.group(0):
            return rule_id, match.group(0)[:200]

    return None
