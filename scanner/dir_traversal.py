"""Directory traversal and sensitive file detection."""

import re
from urllib.parse import urlparse

from .crawler import fetch


def _path_rule(path, description, severity):
    return {"path": path, "description": description, "severity": severity}


SENSITIVE_PATHS = [
    _path_rule("/robots.txt", "robots.txt file", "info"),
    _path_rule("/.git/config", "Git config disclosure", "high"),
    _path_rule("/.git/HEAD", "Git repository disclosure", "high"),
    _path_rule("/.env", "Environment file disclosure", "high"),
    _path_rule("/.htaccess", "Apache config disclosure", "high"),
    _path_rule("/web.config", "IIS config disclosure", "high"),
    _path_rule("/phpinfo.php", "PHP info page", "medium"),
    _path_rule("/info.php", "PHP info page", "medium"),
    _path_rule("/server-status", "Apache server-status page", "medium"),
    _path_rule("/server-info", "Apache server-info page", "medium"),
    _path_rule("/.DS_Store", "macOS metadata disclosure", "high"),
    _path_rule("/backup.sql", "Database backup file", "high"),
    _path_rule("/backup.zip", "Backup archive", "high"),
    _path_rule("/db.sql", "Database backup file", "high"),
    _path_rule("/dump.sql", "Database dump file", "high"),
    _path_rule("/wp-config.php.bak", "WordPress config backup", "high"),
    _path_rule("/config.php.bak", "PHP config backup", "high"),
    _path_rule("/.svn/entries", "SVN repository disclosure", "high"),
    _path_rule("/.hg/dirstate", "Mercurial repository disclosure", "high"),
    _path_rule("/crossdomain.xml", "Cross-domain policy file", "low"),
    _path_rule("/sitemap.xml", "Sitemap", "info"),
    _path_rule("/.well-known/security.txt", "Security contact file", "info"),
    _path_rule("/admin/", "Admin directory", "medium"),
    _path_rule("/wp-admin/", "WordPress admin directory", "medium"),
    _path_rule("/api/", "API endpoint", "medium"),
    _path_rule("/debug/", "Debug page", "medium"),
    _path_rule("/test/", "Test page", "medium"),
    _path_rule("/console", "Console page", "medium"),
]

TRAVERSAL_PAYLOADS = [
    ("../../../etc/passwd", "Linux password file", "root:"),
    ("..\\..\\..\\windows\\win.ini", "Windows config file", "[fonts]"),
    ("....//....//....//etc/passwd", "double-encoding bypass", "root:"),
    ("%2e%2e/%2e%2e/%2e%2e/etc/passwd", "URL-encoded bypass", "root:"),
]

DIRECTORY_LISTING_MARKERS = [
    "index of /",
    "directory listing for",
    "<title>directory listing",
    "parent directory",
]

HTML_MARKERS = ("<html", "<!doctype html", "<body", "<head", "<title")
ENV_LINE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=\s*.+$", re.MULTILINE)
ZIP_MARKERS = ("PK\x03\x04", "PK\x05\x06", "PK\x07\x08")
DS_STORE_MARKERS = ("Bud1", "DSDB")


def check_dir_traversal(url):
    """Check for sensitive files, directory listing, and path traversal."""
    results = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    results.extend(_check_sensitive_files(base))
    results.extend(_check_directory_listing(base))
    results.extend(_check_path_traversal(url))

    return results


def _check_sensitive_files(base):
    """Probe for common sensitive files."""
    results = []
    found = []

    for rule in SENSITIVE_PATHS:
        path = rule["path"]
        test_url = base + path
        resp = fetch(test_url)
        if resp is None:
            continue

        body = resp.text or ""
        if resp.status_code == 200 and len(body) > 10:
            evidence = _build_sensitive_file_evidence(body, path)
            if evidence:
                found.append({
                    "severity": rule["severity"],
                    "detail": f"{rule['description']}: {test_url}",
                    "evidence": evidence,
                })

        import time
        time.sleep(0.1)

    if found:
        for item in found:
            results.append({
                "type": item["severity"],
                "title": "Sensitive file/path exposure",
                "detail": item["detail"],
                "evidence": item["evidence"],
            })
    else:
        results.append({
            "type": "pass",
            "title": "Sensitive file scan passed",
            "detail": "No common sensitive files were confirmed.",
        })

    return results


def _check_directory_listing(base):
    """Check if directory listing is enabled."""
    results = []
    test_paths = ["/", "/images/", "/uploads/", "/files/", "/assets/", "/static/"]

    for path in test_paths:
        resp = fetch(base + path)
        if resp is None:
            continue

        resp_lower = (resp.text or "").lower()
        for marker in DIRECTORY_LISTING_MARKERS:
            if marker in resp_lower:
                results.append({
                    "type": "medium",
                    "title": "Directory listing enabled",
                    "detail": f"Path {base + path} exposes a directory listing",
                })
                break

        import time
        time.sleep(0.1)

    return results


def _check_path_traversal(url):
    """Test for path traversal vulnerabilities."""
    results = []
    parsed = urlparse(url)
    path = parsed.path
    if not path or path == "/":
        return results

    segments = path.strip("/").split("/")
    if len(segments) < 1:
        return results

    for payload, desc, marker in TRAVERSAL_PAYLOADS:
        new_path = "/" + "/".join(segments[:-1]) + "/" + payload
        test_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
        if parsed.query:
            test_url += f"?{parsed.query}"

        resp = fetch(test_url)
        if resp is None:
            continue

        if marker in (resp.text or ""):
            results.append({
                "type": "high",
                "title": "Path traversal vulnerability",
                "detail": f"Traversal content found in path ({desc})\nTest URL: {test_url}",
            })
            break

        import time
        time.sleep(0.2)

    return results


def _looks_like_html(body_lower):
    return any(marker in body_lower for marker in HTML_MARKERS)


def _build_sensitive_file_evidence(body, path):
    """Return evidence markers when content looks like a real hit."""
    body_lower = body.lower()

    error_indicators = ["404 not found", "page not found", "error 404", "not found"]
    if any(indicator in body_lower for indicator in error_indicators) and len(body) < 2000:
        return None

    if path.endswith(("/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/crossdomain.xml")):
        return _metadata_evidence(body_lower, path)

    if _looks_like_html(body_lower):
        return None

    if path.endswith(".git/config"):
        return _marker_evidence(body, ("[core]", "repositoryformatversion"))
    if path.endswith(".git/HEAD"):
        return _marker_evidence(body, ("ref:",))
    if path.endswith(".env"):
        match = ENV_LINE_RE.search(body)
        return [f"env_line={match.group(0).strip()}"] if match else None
    if path.endswith((".sql", "/backup.sql", "/db.sql", "/dump.sql")):
        return _marker_evidence(body, (
            "-- MySQL dump",
            "CREATE TABLE",
            "INSERT INTO",
            "DROP TABLE",
            "LOCK TABLES",
        ))
    if path.endswith(".htaccess"):
        return _marker_evidence(body, ("RewriteEngine", "AuthType", "Deny from", "Require all"))
    if path.endswith("web.config"):
        return _marker_evidence(body, ("<configuration", "<appsettings", "<connectionstrings"))
    if path.endswith(".php.bak"):
        return _marker_evidence(body, ("<?php", "$", "define("))
    if path.endswith(".svn/entries"):
        return _marker_evidence(body, ("svn", "dir", "file"))
    if path.endswith(".hg/dirstate"):
        if "\x00" in body and len(body) > 40:
            return [f"binary_length={len(body)}", "marker=NUL"]
        return None
    if path.endswith(".DS_Store"):
        return _marker_evidence(body, DS_STORE_MARKERS)
    if path.endswith(".zip"):
        return _binary_prefix_evidence(body, ZIP_MARKERS)
    if path.endswith("/phpinfo.php") or path.endswith("/info.php"):
        return _marker_evidence(body, ("phpinfo()", "PHP Version", "<title>phpinfo"))
    if path.endswith("/server-status"):
        return _marker_evidence(body, ("apache server status", "server version", "current time"))
    if path.endswith("/server-info"):
        return _marker_evidence(body, ("server information", "apache server information"))
    if path.endswith(("/admin/", "/wp-admin/", "/api/", "/debug/", "/test/", "/console")):
        return [f"content_length={len(body)}"] if len(body) > 50 else None

    return [f"content_length={len(body)}"] if len(body) > 50 else None


def _metadata_evidence(body_lower, path):
    if path.endswith("/robots.txt"):
        return _marker_evidence(body_lower, ("user-agent", "disallow", "allow"))
    if path.endswith("/sitemap.xml"):
        return _marker_evidence(body_lower, ("<urlset", "<sitemapindex", "<url>", "<loc>"))
    if path.endswith("/.well-known/security.txt"):
        return _marker_evidence(body_lower, (
            "contact:",
            "expires:",
            "encryption:",
            "policy:",
            "acknowledgments:",
            "hiring:",
        ))
    if path.endswith("/crossdomain.xml"):
        return _marker_evidence(body_lower, ("<cross-domain-policy",))
    return None


def _marker_evidence(body, markers):
    body_lower = body.lower()
    for marker in markers:
        if marker.lower() in body_lower:
            return [f"marker={marker}"]
    return None


def _binary_prefix_evidence(body, markers):
    for marker in markers:
        if body.startswith(marker):
            return [f"marker={marker[:2]}"]
    return None
