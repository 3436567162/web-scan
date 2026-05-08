"""Information gathering: server fingerprint, tech stack, CMS detection."""

from urllib.parse import urlparse

from .crawler import fetch


ADMIN_PATHS = ["/admin", "/administrator", "/wp-admin", "/phpmyadmin", "/manager"]
DANGEROUS_HTTP_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT"]


def gather_info(url):
    """Gather basic information about the target."""
    results = []
    response = fetch(url)
    if response is None:
        return [{
            "type": "info",
            "title": "Connection failed",
            "detail": f"Could not reach target: {url}",
        }]

    headers = response.headers
    server = headers.get("Server", "Unknown")
    powered_by = headers.get("X-Powered-By", "Unknown")
    status = response.status_code

    results.append({
        "type": "info",
        "title": "Server fingerprint",
        "detail": f"Server: {server} | X-Powered-By: {powered_by} | Status code: {status}",
    })

    tech = _detect_tech(headers, response.text)
    if tech:
        results.append({
            "type": "info",
            "title": "Technology stack detected",
            "detail": ", ".join(tech),
        })

    cms = _detect_cms(response.text, headers)
    if cms:
        results.append({
            "type": "info",
            "title": "CMS detected",
            "detail": cms,
        })

    options_response = fetch(url, method="OPTIONS", allow_redirects=False)
    allow = options_response.headers.get("Allow", "") if options_response is not None else ""
    if allow:
        results.append({
            "type": "info",
            "title": "Allowed HTTP methods",
            "detail": allow,
        })

        dangerous_methods = [
            method for method in DANGEROUS_HTTP_METHODS if method in allow.upper()
        ]
        if dangerous_methods:
            results.append({
                "type": "low",
                "title": "Dangerous HTTP methods enabled",
                "detail": (
                    "Server allows potentially dangerous methods: "
                    + ", ".join(dangerous_methods)
                ),
            })

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    for path in ADMIN_PATHS:
        admin_response = fetch(base + path)
        if admin_response is None:
            continue
        if admin_response.status_code == 200 and len(admin_response.text) > 100:
            results.append({
                "type": "low",
                "title": "Administrative path exposed",
                "detail": (
                    f"Discovered likely administrative path: {base + path} "
                    f"(status code: {admin_response.status_code})"
                ),
            })
            break

    return results


def _detect_tech(headers, body):
    """Detect technology stack from headers and body content."""
    tech = []
    powered = headers.get("X-Powered-By", "").lower()
    server = headers.get("Server", "").lower()
    cookie_header = headers.get("Set-Cookie", "")

    if "php" in powered or "php" in server:
        tech.append("PHP")
    if "asp.net" in powered or "asp.net" in server:
        tech.append("ASP.NET")
    if "express" in powered:
        tech.append("Node.js/Express")
    if "django" in body.lower() or "csrfmiddlewaretoken" in body:
        tech.append("Django")
    if "flask" in body.lower():
        tech.append("Flask")
    if "laravel" in body.lower() or "laravel_session" in cookie_header:
        tech.append("Laravel")
    if "spring" in powered or "jsessionid" in cookie_header.lower():
        tech.append("Java/Spring")
    if "nginx" in server:
        tech.append("Nginx")
    if "apache" in server:
        tech.append("Apache")
    if "iis" in server:
        tech.append("IIS")

    return tech


def _detect_cms(body, headers):
    """Detect common CMS platforms."""
    body_lower = body.lower()
    cookies = headers.get("Set-Cookie", "").lower()

    if "wp-content" in body_lower or "wp-includes" in body_lower or "wordpress" in cookies:
        return "WordPress"
    if "joomla" in body_lower or "joomla" in cookies:
        return "Joomla"
    if "drupal" in body_lower or "drupal" in cookies:
        return "Drupal"
    if "shopify" in body_lower:
        return "Shopify"
    if "wix.com" in body_lower:
        return "Wix"

    return None
