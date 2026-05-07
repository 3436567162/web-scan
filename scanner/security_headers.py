"""Check for missing or misconfigured HTTP security headers."""

from urllib.parse import urljoin, urlparse

from .crawler import fetch


REQUIRED_HEADERS = (
    (
        "X-Frame-Options",
        {
            "severity": "medium",
            "desc": "Prevent clickjacking by returning DENY or SAMEORIGIN.",
            "remediation": ["Set `X-Frame-Options` to `DENY` or `SAMEORIGIN`."],
        },
    ),
    (
        "X-Content-Type-Options",
        {
            "severity": "low",
            "desc": "Prevent MIME sniffing by returning `nosniff`.",
            "remediation": ["Set `X-Content-Type-Options` to `nosniff`."],
        },
    ),
    (
        "Content-Security-Policy",
        {
            "severity": "medium",
            "desc": "Reduce script injection risk with a restrictive CSP.",
            "remediation": ["Define a `Content-Security-Policy` for script, style, and frame sources."],
        },
    ),
    (
        "Strict-Transport-Security",
        {
            "severity": "medium",
            "desc": "Force repeat visitors to use HTTPS.",
            "remediation": [
                "Serve the site over HTTPS and return `Strict-Transport-Security: max-age=31536000; includeSubDomains`."
            ],
            "https_only": True,
        },
    ),
    (
        "X-XSS-Protection",
        {
            "severity": "info",
            "desc": "Legacy browser XSS filter header is absent.",
            "remediation": ["Prefer a strong Content Security Policy over relying on `X-XSS-Protection`."],
        },
    ),
    (
        "Referrer-Policy",
        {
            "severity": "low",
            "desc": "Limit referrer data exposure across origins.",
            "remediation": ["Set `Referrer-Policy` to `strict-origin-when-cross-origin` or stricter."],
        },
    ),
    (
        "Permissions-Policy",
        {
            "severity": "low",
            "desc": "Restrict access to powerful browser features.",
            "remediation": ["Return a `Permissions-Policy` that disables unused features."],
        },
    ),
)


def _make_finding(severity, title, detail, evidence=None, remediation=None):
    finding = {
        "type": severity,
        "title": title,
        "detail": detail,
    }
    if evidence:
        finding["evidence"] = evidence
    if remediation:
        finding["remediation"] = remediation
    return finding


def _is_https_target(url):
    return urlparse(url).scheme.lower() == "https"


def _normalized_port(parsed_url):
    if parsed_url.port is not None:
        return parsed_url.port
    if parsed_url.scheme.lower() == "https":
        return 443
    if parsed_url.scheme.lower() == "http":
        return 80
    return None


def _is_equivalent_https_redirect(source_url, redirect_url):
    source = urlparse(source_url)
    target = urlparse(redirect_url)
    return (
        target.scheme.lower() == "https"
        and bool(target.hostname)
        and source.hostname == target.hostname
        and _normalized_port(target) == 443
    )


def _redirects_to_https(url):
    response = fetch(url, allow_redirects=False)
    if response is None:
        return False, [{"url": url, "observed_status": None, "location": None}]

    location = response.headers.get("Location", "")
    redirected_url = urljoin(url, location) if location else ""
    redirects = response.status_code in {301, 302, 307, 308}
    is_https = bool(redirected_url) and _is_equivalent_https_redirect(url, redirected_url)

    evidence = [{
        "url": url,
        "observed_status": response.status_code,
        "location": location or None,
    }]
    return redirects and is_https, evidence


def check_security_headers(url):
    """Check for missing and misconfigured security headers."""
    results = []
    parsed_url = urlparse(url)
    is_http_target = parsed_url.scheme.lower() == "http"
    redirects_to_https = None
    redirect_evidence = None

    if is_http_target:
        redirects_to_https, redirect_evidence = _redirects_to_https(url)

    response = fetch(url)
    if response is None:
        if is_http_target and not redirects_to_https:
            results.append(
                _make_finding(
                    "medium",
                    "HTTP does not enforce HTTPS",
                    "The HTTP endpoint did not immediately redirect to an HTTPS URL.",
                    evidence=redirect_evidence,
                    remediation=["Redirect all HTTP requests to the equivalent HTTPS URL."],
                )
            )
        return results

    headers = response.headers
    is_https_target = _is_https_target(url)

    for header_name, info in REQUIRED_HEADERS:
        if info.get("https_only") and not is_https_target:
            continue

        value = headers.get(header_name)
        if value:
            continue

        evidence = [{"header": header_name, "observed": None, "url": url}]
        results.append(
            _make_finding(
                info["severity"],
                f"Missing security header: {header_name}",
                info["desc"],
                evidence=evidence,
                remediation=info.get("remediation"),
            )
        )

    acao = headers.get("Access-Control-Allow-Origin", "")
    if acao == "*":
        results.append(
            _make_finding(
                "medium",
                "CORS misconfiguration: Access-Control-Allow-Origin is wildcard",
                "Any origin can read the response, which can expose sensitive data.",
                evidence=[{"header": "Access-Control-Allow-Origin", "observed": acao}],
                remediation=["Return a specific allowlist origin instead of `*` for sensitive responses."],
            )
        )

    hsts = headers.get("Strict-Transport-Security", "")
    if is_https_target and hsts and "max-age" in hsts:
        try:
            max_age = int(hsts.split("max-age=")[1].split(";")[0].strip())
        except (ValueError, IndexError):
            max_age = None

        if max_age is not None and max_age < 31536000:
            results.append(
                _make_finding(
                    "low",
                    "HSTS max-age is shorter than recommended",
                    f"Observed max-age={max_age}; at least 31536000 seconds is recommended.",
                    evidence=[{"header": "Strict-Transport-Security", "observed": hsts}],
                    remediation=["Increase HSTS max-age to at least 31536000 seconds."],
                )
            )

    xfo = headers.get("X-Frame-Options", "").upper()
    if xfo and xfo not in ("DENY", "SAMEORIGIN"):
        results.append(
            _make_finding(
                "low",
                "X-Frame-Options value is weak",
                f"Observed `{xfo}`; `DENY` or `SAMEORIGIN` is recommended.",
                evidence=[{"header": "X-Frame-Options", "observed": xfo}],
                remediation=["Set `X-Frame-Options` to `DENY` or `SAMEORIGIN`."],
            )
        )

    cookies = headers.get("Set-Cookie", "")
    if cookies:
        lowered = cookies.lower()
        if "httponly" not in lowered:
            results.append(
                _make_finding(
                    "low",
                    "Cookie is missing HttpOnly",
                    "Cookies without HttpOnly can be exposed to client-side scripts.",
                    evidence=[{"header": "Set-Cookie", "observed": cookies}],
                    remediation=["Add the `HttpOnly` attribute to session and sensitive cookies."],
                )
            )
        if "secure" not in lowered:
            results.append(
                _make_finding(
                    "low",
                    "Cookie is missing Secure",
                    "Cookies without Secure can be transmitted over plaintext HTTP.",
                    evidence=[{"header": "Set-Cookie", "observed": cookies}],
                    remediation=["Add the `Secure` attribute to session and sensitive cookies."],
                )
            )

    if is_http_target and not is_https_target:
        if not redirects_to_https:
            results.append(
                _make_finding(
                    "medium",
                    "HTTP does not enforce HTTPS",
                    "The HTTP endpoint did not immediately redirect to an HTTPS URL.",
                    evidence=redirect_evidence,
                    remediation=["Redirect all HTTP requests to the equivalent HTTPS URL."],
                )
            )

    if not results:
        results.append(
            {
                "type": "pass",
                "title": "Security headers check passed",
                "detail": "Key response headers are present and no obvious misconfiguration was detected.",
                "evidence": [{"url": url, "checked_headers": [name for name, _info in REQUIRED_HEADERS]}],
            }
        )

    return results
