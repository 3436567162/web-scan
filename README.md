# Web Vulnerability Scanner

一个基于 Python + Flask 的 Web 漏洞扫描器，通过 Web 界面输入目标 URL，自动检测 OWASP Top 10 常见基础漏洞。

## 功能特性

| 模块 | 检测内容 |
|------|----------|
| **信息收集** | 服务器指纹、技术栈识别、CMS检测、管理后台路径探测 |
| **安全响应头** | X-Frame-Options、CSP、HSTS、Cookie安全标志等 |
| **SQL注入** | 基于错误的注入检测（GET参数 + 表单字段） |
| **XSS跨站脚本** | 反射型XSS检测（GET参数 + 表单字段） |
| **目录遍历** | 敏感文件探测、目录列表检测、路径穿越测试 |
| **开放重定向** | URL参数未验证重定向检测 |
| **CORS配置** | 跨域资源共享配置错误检测 |

## 截图

![扫描结果](screenshots/result.png)

## 快速开始

### 环境要求

- Python 3.8+

### 安装

```bash
# 克隆项目
git clone https://github.com/yourusername/web-vuln-scanner.git
cd web-vuln-scanner

# 安装依赖
pip install -r requirements.txt
```

### 运行

```bash
python app.py
```

浏览器访问 http://localhost:5000，输入目标 URL 即可开始扫描。

## 项目结构

```
├── app.py                  # Flask 主应用
├── requirements.txt        # Python 依赖
├── scanner/
│   ├── __init__.py
│   ├── crawler.py          # 页面爬虫（表单、链接提取）
│   ├── info_gather.py      # 信息收集模块
│   ├── security_headers.py # 安全响应头检查
│   ├── sqli_scanner.py     # SQL 注入检测
│   ├── xss_scanner.py      # XSS 跨站脚本检测
│   ├── dir_traversal.py    # 目录遍历与敏感文件探测
│   ├── open_redirect.py    # 开放重定向检测
│   └── cors_check.py       # CORS 配置检查
├── templates/
│   └── index.html          # Web 界面
└── static/
    └── style.css           # 样式文件
```

## API

### POST /api/scan

发起扫描请求。

**请求体：**
```json
{
  "url": "http://example.com"
}
```

**响应：**
```json
{
  "url": "http://example.com",
  "results": {
    "信息收集": [...],
    "安全响应头": [...],
    "SQL注入": [...],
    ...
  },
  "summary": {
    "high": 2,
    "medium": 5,
    "low": 3
  }
}
```

## 注意事项

- 仅用于**授权的安全测试**，请勿用于非法用途
- 扫描请求自带速率限制，避免对目标造成压力
- 建议在本地测试环境或授权的目标上使用

## License

[MIT](LICENSE)
