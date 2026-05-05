"""Web Vulnerability Scanner - Flask Application."""

import urllib3
from flask import Flask, render_template, request, jsonify

from scanner.info_gather import gather_info
from scanner.security_headers import check_security_headers
from scanner.sqli_scanner import check_sqli
from scanner.xss_scanner import check_xss
from scanner.dir_traversal import check_dir_traversal
from scanner.open_redirect import check_open_redirect
from scanner.cors_check import check_cors

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)


def normalize_url(url):
    """Ensure URL has a scheme."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


SCAN_MODULES = [
    ("信息收集", gather_info),
    ("安全响应头", check_security_headers),
    ("SQL注入", check_sqli),
    ("XSS跨站脚本", check_xss),
    ("目录遍历与敏感文件", check_dir_traversal),
    ("开放重定向", check_open_redirect),
    ("CORS配置", check_cors),
]


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json()
    if not data or not data.get("url"):
        return jsonify({"error": "请输入目标URL"}), 400

    url = normalize_url(data["url"])
    results = {}

    for module_name, scan_func in SCAN_MODULES:
        try:
            module_results = scan_func(url)
            results[module_name] = module_results
        except Exception as e:
            results[module_name] = [{
                "type": "error",
                "title": f"{module_name} 扫描出错",
                "detail": str(e),
            }]

    # Summary
    total_high = 0
    total_medium = 0
    total_low = 0
    for module_results in results.values():
        for r in module_results:
            if r.get("type") == "high":
                total_high += 1
            elif r.get("type") == "medium":
                total_medium += 1
            elif r.get("type") == "low":
                total_low += 1

    return jsonify({
        "url": url,
        "results": results,
        "summary": {
            "high": total_high,
            "medium": total_medium,
            "low": total_low,
        },
    })


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
