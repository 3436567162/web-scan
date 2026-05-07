"""Open redirect vulnerability detection."""

from urllib.parse import urlencode, urljoin, urlparse

from .crawler import extract_params, fetch

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com%00.example.com",
    "/\\evil.com",
    "https://evil.com/",
    "////evil.com",
]

REDIRECT_PARAM_NAMES = [
    "url", "redirect", "next", "return", "returnto", "return_to",
    "redirect_uri", "redirect_url", "go", "out", "view", "to",
    "continue", "dest", "destination", "redir", "redirect_to",
    "checkout_url", "return_url", "rurl", "forward",
]


def _effective_port(parsed):
    if parsed.port is not None:
        return parsed.port
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    return None


def _origin_tuple(parsed):
    return (
        (parsed.scheme or "").lower(),
        (parsed.hostname or "").lower(),
        _effective_port(parsed),
    )


def _normalize_redirect_target(base_url, location):
    location = (location or "").strip()
    if not location:
        return ""

    normalized = location.replace("\\", "/")
    if normalized.startswith("/"):
        slash_count = len(normalized) - len(normalized.lstrip("/"))
        if slash_count >= 2:
            normalized = "//" + normalized.lstrip("/")

    return urljoin(base_url, normalized)


def _is_external_redirect(base_url, location):
    redirect_target = _normalize_redirect_target(base_url, location)
    if not redirect_target:
        return False, redirect_target

    return _origin_tuple(urlparse(base_url)) != _origin_tuple(urlparse(redirect_target)), redirect_target


def _build_redirect_finding(title, detail_lines, evidence):
    return {
        "type": "high",
        "title": title,
        "detail": "\n".join(detail_lines),
        "evidence": evidence,
    }


def check_open_redirect(url):
    """Check for open redirect vulnerabilities in URL parameters."""
    results = []
    params = extract_params(url)

    redirect_params = list(params.keys())
    parsed = urlparse(url)

    for param_name in REDIRECT_PARAM_NAMES:
        if param_name in redirect_params:
            redirect_params.remove(param_name)
            redirect_params.insert(0, param_name)

    tested = set()
    for param_name in redirect_params:
        if param_name in tested:
            continue
        tested.add(param_name)

        for payload in REDIRECT_PAYLOADS:
            test_params = dict(params)
            test_params[param_name] = [payload]
            test_url = parsed._replace(
                query=urlencode(test_params, doseq=True)
            ).geturl()

            resp = fetch(test_url, allow_redirects=False)
            if resp is None:
                continue

            import time
            time.sleep(0.2)

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                is_external, redirect_target = _is_external_redirect(test_url, location)
                if is_external:
                    results.append(_build_redirect_finding(
                        "寮€鏀鹃噸瀹氬悜婕忔礊",
                        [
                            f"鍙傛暟 '{param_name}' 瀛樺湪寮€鏀鹃噸瀹氬悜",
                            f"Payload: {payload}",
                            f"Redirect target: {redirect_target}",
                        ],
                        [
                            f"parameter={param_name}",
                            f"payload={payload}",
                            f"location={location}",
                            f"redirect_target={redirect_target}",
                        ],
                    ))
                    break

    path_payloads = ["/evil.com", "/\\/evil.com"]
    for payload in path_payloads:
        test_url = f"{parsed.scheme}://{parsed.netloc}{payload}"
        resp = fetch(test_url, allow_redirects=False)
        if resp is None:
            continue

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            is_external, redirect_target = _is_external_redirect(test_url, location)
            if is_external:
                results.append(_build_redirect_finding(
                    "寮€鏀鹃噸瀹氬悜婕忔礊 (璺緞)",
                    [
                        "璺緞绾ч噸瀹氬悜鍒板閮ㄥ煙",
                        f"Payload: {payload}",
                        f"Redirect target: {redirect_target}",
                    ],
                    [
                        f"payload={payload}",
                        f"location={location}",
                        f"redirect_target={redirect_target}",
                    ],
                ))
                break

        import time
        time.sleep(0.2)

    if not results:
        results.append({
            "type": "pass",
            "title": "寮€鏀鹃噸瀹氬悜妫€鏌ラ€氳繃",
            "detail": "鏈彂鐜板紑鏀鹃噸瀹氬悜婕忔礊",
        })

    return results
