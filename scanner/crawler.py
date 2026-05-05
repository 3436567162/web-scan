"""Simple page crawler to extract forms and links from target pages."""

import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import requests
from bs4 import BeautifulSoup


HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}
TIMEOUT = 10


def fetch(url, method="GET", headers=None, **kwargs):
    """Fetch a URL with default headers and timeout."""
    merged_headers = dict(HEADERS)
    if headers:
        merged_headers.update(headers)
    try:
        if method.upper() == "POST":
            resp = requests.post(url, headers=merged_headers, timeout=TIMEOUT,
                                 verify=False, allow_redirects=True, **kwargs)
        else:
            resp = requests.get(url, headers=merged_headers, timeout=TIMEOUT,
                                verify=False, allow_redirects=True, **kwargs)
        return resp
    except requests.RequestException:
        return None


def extract_forms(url):
    """Extract all forms from a page, returning form details."""
    resp = fetch(url)
    if not resp:
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
    if not resp:
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
