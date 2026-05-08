# Web Vulnerability Scanner

一个基于 Python + Flask 的轻量级 Web 漏洞扫描器，提供浏览器界面和 JSON API，可对目标站点执行基础信息收集与常见 Web 安全检查。

## 功能概览

- 信息收集：服务指纹、技术栈识别、CMS 识别、管理路径探测
- 安全响应头：缺失或弱配置的安全头检查
- SQL 注入：基于参数和表单的基础探测
- XSS：基于参数和表单的反射型 XSS 探测
- 敏感路径：常见敏感文件、目录列表与路径穿越探测
- 开放重定向：参数型和部分路径型重定向检查
- CORS：跨域资源共享配置问题检查
- 模块选择：前端和 API 都支持按模块选择扫描范围

## 项目结构

```text
app.py
requirements.txt
scanner/
  crawler.py
  url_safety.py
  info_gather.py
  security_headers.py
  sqli_scanner.py
  xss_scanner.py
  dir_traversal.py
  open_redirect.py
  cors_check.py
templates/
  index.html
static/
  style.css
tests/
```

## 环境要求

- Python 3.8+

## 安装与运行

```bash
pip install -r requirements.txt
python app.py
```

默认监听地址为 `127.0.0.1:5000`。启动后在浏览器访问：

```text
http://127.0.0.1:5000
```

## 可选环境变量

- `FLASK_HOST`：服务监听地址
- `FLASK_PORT`：服务监听端口
- `FLASK_DEBUG`：是否开启 Flask debug 模式，支持 `1/true/yes/on`
- `TRUSTED_PROXIES`：受信代理 IP 列表，逗号分隔；只有来自这些代理的请求才会信任 `X-Forwarded-For`
- `SCANNER_VERIFY_TLS`：是否校验证书，默认开启；显式设为 `0/false/no/off` 时关闭

示例：

```bash
FLASK_HOST=0.0.0.0
FLASK_PORT=8080
FLASK_DEBUG=true
TRUSTED_PROXIES=127.0.0.1,10.0.0.10
SCANNER_VERIFY_TLS=true
```

## Web 界面

- 输入目标 URL 后可直接发起扫描
- 支持勾选扫描模块，缩小扫描范围
- 展示高、中、低风险与通过项汇总
- 展示扫描元数据，包括耗时、请求预算和实际执行模块

## API

### `POST /api/scan`

请求体：

```json
{
  "url": "https://example.com",
  "modules": ["info_gather", "security_headers", "cors"]
}
```

说明：

- `url` 必填
- `modules` 选填；省略时执行全部模块
- 若 `modules` 中包含未知模块，接口会返回 `400`

响应示例：

```json
{
  "url": "https://example.com",
  "results": {
    "info_gather": [
      {
        "type": "info",
        "title": "Server fingerprint",
        "detail": "Server: nginx | X-Powered-By: Unknown | Status code: 200"
      }
    ]
  },
  "summary": {
    "high": 0,
    "medium": 1,
    "low": 2
  },
  "scan_metadata": {
    "started_at": "2026-05-08T12:00:00Z",
    "finished_at": "2026-05-08T12:00:01Z",
    "duration_ms": 812,
    "request_budget_limit": 60,
    "request_budget_exhausted": false,
    "modules_run": ["info_gather", "security_headers"],
    "modules_skipped": [],
    "selected_modules": ["info_gather", "security_headers", "cors"]
  }
}
```

## 安全控制

- 仅允许扫描公网 `http/https` 目标
- 默认校验 TLS 证书
- 会校验重定向目标是否合法
- 会校验实际连接到的对端 IP，拒绝异常或受限地址
- 单次扫描带有出站请求预算限制
- 同一客户端存在短时间冷却限制

## 测试

运行全部测试：

```bash
python -m pytest -q
```

## 使用边界

- 仅应在你拥有授权的目标上使用
- 本项目用于教学、研究和本地实验环境验证，不应作为高强度生产扫描器直接投入外网批量使用

## License

[MIT](LICENSE)
