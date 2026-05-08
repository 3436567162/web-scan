"""Simple page crawler to extract forms and links from target pages."""

from contextlib import contextmanager
from contextvars import ContextVar
import ipaddress
import os
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import requests
from bs4 import BeautifulSoup

from .url_safety import (
    is_blocked_ip,
    resolve_target_ips,
    validate_public_http_url,
    validate_redirect_target,
)


HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}
TIMEOUT = 10
MAX_RESPONSE_BYTES = 1024 * 1024
VERIFY_TLS_ENV = "SCANNER_VERIFY_TLS"
_REQUEST_BUDGET = ContextVar("scan_request_budget", default=None)


@contextmanager
def request_budget(limit):
    """Apply a per-scan outgoing request budget."""
    token = _REQUEST_BUDGET.set({
        "remaining": int(limit),
        "exhausted": False,
    })
    try:
        yield
    finally:
        _REQUEST_BUDGET.reset(token)


def budget_exhausted():
    """Return True when the active budget has been exceeded."""
    state = _REQUEST_BUDGET.get()
    return bool(state and state["exhausted"])


def _consume_request_budget():
    state = _REQUEST_BUDGET.get()
    if state is None:
        return True
    if state["remaining"] <= 0:
        state["exhausted"] = True
        return False
    state["remaining"] -= 1
    return True


def _redirect_guard(response, *_args, **_kwargs):
    location = response.headers.get("Location")
    if response.is_redirect and location:
        validate_redirect_target(response.url, location)
    return response


def _merge_response_hooks(existing_hooks):
    hooks = {}
    if existing_hooks:
        hooks.update(existing_hooks)

    response_hooks = hooks.get("response", [])
    if callable(response_hooks):
        response_hooks = [response_hooks]
    else:
        response_hooks = list(response_hooks)

    response_hooks.append(_redirect_guard)
    hooks["response"] = response_hooks
    return hooks


def _safe_close(response):
    try:
        response.close()
    except AttributeError:
        pass


def _parse_bool_env(name, default=True):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _should_verify_tls():
    return _parse_bool_env(VERIFY_TLS_ENV, default=True)


def _extract_peer_ip(response):
    raw = getattr(response, "raw", None)
    if raw is None:
        return None

    socket_candidates = [
        getattr(getattr(raw, "_connection", None), "sock", None),
        getattr(
            getattr(getattr(getattr(raw, "_fp", None), "fp", None), "raw", None),
            "_sock",
            None,
        ),
    ]

    for sock in socket_candidates:
        if sock is None:
            continue

        try:
            peer_name = sock.getpeername()
        except (AttributeError, OSError, TypeError):
            continue

        if isinstance(peer_name, tuple):
            peer_name = peer_name[0]

        try:
            return ipaddress.ip_address(peer_name)
        except ValueError:
            continue

    return None


def _validate_response_peer(response):
    peer_ip = _extract_peer_ip(response)
    if peer_ip is None:
        return
    if is_blocked_ip(peer_ip):
        raise ValueError("Response peer address is not allowed")

    hostname = urlparse(response.url).hostname
    if not hostname:
        raise ValueError("Response URL hostname is required")

    expected_ips = resolve_target_ips(hostname)
    if any(is_blocked_ip(ip) for ip in expected_ips):
        raise ValueError("Response URL resolved to a blocked address")
    if peer_ip not in expected_ips:
        raise ValueError("Response peer address did not match the validated target")


def _validate_response_peer_chain(response):
    history = list(getattr(response, "history", []) or [])
    for item in history + [response]:
        _validate_response_peer(item)


def _read_bounded_response(response):
    if getattr(response, "raw", None) is None and hasattr(response, "_content"):
        content = getattr(response, "_content", b"") or b""
        if len(content) > MAX_RESPONSE_BYTES:
            _safe_close(response)
            return None
        response._content = content
        _safe_close(response)
        return response

    chunks = []
    total = 0

    try:
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                _safe_close(response)
                return None
            chunks.append(chunk)
    except requests.RequestException:
        _safe_close(response)
        return None

    response._content = b"".join(chunks)
    _safe_close(response)
    return response


def fetch(url, method="GET", headers=None, **kwargs):
    """Fetch a URL with default headers and timeout."""
    merged_headers = dict(HEADERS)
    if headers:
        merged_headers.update(headers)
    allow_redirects = kwargs.pop("allow_redirects", True)
    hooks = kwargs.pop("hooks", None)

    try:
        validate_public_http_url(url)
        if not _consume_request_budget():
            return None

        request_kwargs = dict(kwargs)
        if allow_redirects:
            request_kwargs["hooks"] = _merge_response_hooks(hooks)
        elif hooks is not None:
            request_kwargs["hooks"] = hooks

        request_method = method.upper()
        if request_method == "POST":
            resp = requests.post(url, headers=merged_headers, timeout=TIMEOUT,
                                 verify=_should_verify_tls(), allow_redirects=allow_redirects,
                                 stream=True, **request_kwargs)
        elif request_method == "GET":
            resp = requests.get(url, headers=merged_headers, timeout=TIMEOUT,
                                verify=_should_verify_tls(), allow_redirects=allow_redirects,
                                stream=True, **request_kwargs)
        else:
            resp = requests.request(request_method, url, headers=merged_headers, timeout=TIMEOUT,
                                    verify=_should_verify_tls(), allow_redirects=allow_redirects,
                                    stream=True, **request_kwargs)
        _validate_response_peer_chain(resp)
        return _read_bounded_response(resp)
    except (requests.RequestException, ValueError):
        return None


def extract_forms(url):
    """Extract all forms from a page, returning form details."""
    resp = fetch(url)
    if resp is None:
        return []

    soup = BeautifulSoup(resp.text, "html.parser")
    forms = []

    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        form_action = urljoin(url, action) if action else url

        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            inputs.append({
                "name": name,
                "type": inp.get("type", "text"),
                "value": inp.get("value", ""),
            })

        forms.append({
            "action": form_action,
            "method": method,
            "inputs": inputs,
        })

    return forms


def extract_links(url, max_links=50):
    """Extract links from a page that belong to the same domain."""
    resp = fetch(url)
    if resp is None:
        return []

    soup = BeautifulSoup(resp.text, "html.parser")
    parsed_base = urlparse(url)
    links = set()

    for a in soup.find_all("a", href=True):
        href = urljoin(url, a["href"])
        parsed = urlparse(href)
        if parsed.netloc == parsed_base.netloc and parsed.scheme in ("http", "https"):
            links.add(href.split("#")[0])
        if len(links) >= max_links:
            break

    return list(links)


def extract_params(url):
    """Extract query parameters from a URL as a dict."""
    parsed = urlparse(url)
    return parse_qs(parsed.query)


def inject_param(url, param_name, payload):
    """Replace a single query parameter value with a payload."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param_name] = [payload]
    new_query = urlencode(params, doseq=True)
    return parsed._replace(query=new_query).geturl()
