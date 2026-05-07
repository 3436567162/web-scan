# Scan Accuracy Upgrade Design

**Date:** 2026-05-06

**Goal**

Improve scan accuracy and result quality for the current Flask-based web scanner without breaking the existing `/api/scan` response shape or requiring a front-end rewrite.

**Problem Statement**

The current scanner has three linked problems:

1. Several detectors over-report high-risk findings based on weak signals.
2. Findings carry too little evidence to explain why they were reported.
3. Result items are inconsistent across modules and do not carry confidence, remediation, or scan metadata.

Adding more payloads before fixing these issues would increase output volume while making trust in the results worse.

## Scope

This design covers:

- XSS accuracy improvements
- SQLi accuracy improvements
- Open redirect accuracy improvements
- Directory traversal and sensitive file accuracy improvements
- Security header severity normalization
- A backward-compatible result normalization layer
- Minimal front-end rendering updates for richer findings

This design does not cover:

- Async scan jobs
- Persistence or scan history
- New scan modules
- A full API schema rewrite
- Authentication or multi-user workflow changes

## Constraints

- Preserve the current top-level `results[module] = [finding, ...]` shape for this iteration.
- Existing tests that depend on `type`, `title`, and `detail` must remain valid.
- New result fields must be optional and additive.
- Changes should be decomposed so multiple workers can implement in parallel with minimal file overlap.

## Chosen Approach

Use a compatibility-first upgrade:

1. Keep the existing module result array structure.
2. Add a normalization layer in `app.py` that enriches legacy findings with optional standard fields.
3. Tighten the highest-noise detectors first, focusing on XSS, SQLi, open redirect, and sensitive file detection.
4. Normalize severity logic in security header findings.
5. Add lightweight UI support for the new fields instead of redesigning the page.

This approach gives immediate accuracy gains while creating a stable foundation for future rule growth.

## Target Result Model

Each module may still return legacy findings, but the API response should normalize each item into a compatible richer structure.

### Required legacy fields

- `type`
- `title`
- `detail`

### New optional fields

- `severity`: canonical severity, defaulting to `type`
- `status`: one of `open`, `pass`, `info`, `error`, `needs-review`
- `confidence`: float from `0.0` to `1.0`
- `evidence`: list of structured evidence records
- `remediation`: list of concise remediation steps
- `category`: scanner category such as `xss`, `sqli`, `open_redirect`
- `location`: structured location metadata such as URL, parameter, method, or path
- `rule_id`: stable rule identifier for the finding

### Evidence record shape

Each evidence record should use this additive structure:

```json
{
  "kind": "response-snippet",
  "label": "Matched response fragment",
  "value": "<script>alert(1)</script>"
}
```

Allowed initial `kind` values:

- `payload`
- `response-snippet`
- `header`
- `status-code`
- `redirect-target`
- `content-marker`

### Top-level response additions

The response should keep the existing `url`, `results`, and `summary` keys, and add:

```json
{
  "scan_metadata": {
    "started_at": "ISO-8601 timestamp",
    "finished_at": "ISO-8601 timestamp",
    "duration_ms": 1234,
    "request_budget_limit": 60,
    "request_budget_exhausted": false,
    "modules_run": ["XSS", "SQLi", "CORS"],
    "modules_skipped": []
  }
}
```

This preserves compatibility while making the response useful for richer rendering and follow-on reporting features.

## Module Design

### XSS

Current issue:

- High severity is reported when raw payload text appears anywhere in the body.
- Plain reflection in comments, JSON, or inert text can be marked high risk.
- No context evidence is returned.

New rule:

- Only report `high` when reflection appears in an executable or clearly unsafe HTML context.
- Acceptable high-confidence contexts in this iteration:
  - `<script>...</script>`
  - event handler attributes such as `onload=` or `onerror=`
  - `javascript:` URL sinks
  - clearly unescaped HTML tag injection
- Plain reflected text without an executable context should be downgraded to `low` or omitted.

Evidence requirements:

- tested parameter or form field
- payload used
- matched context type
- response snippet around the match

Result metadata:

- `category = "xss"`
- `rule_id` per context type
- `confidence` higher for executable contexts and lower for weak reflections

### SQLi

Current issue:

- GET checks compare against a baseline, but form checks do not.
- Error terms such as `syntax error`, `jdbc`, or `odbc` are too broad and can cause false positives.

New rule:

- Use a baseline response for both URL and form injection paths.
- Only report when the injected response introduces a stronger database error signal than the baseline.
- Replace broad string matching with tighter patterns or combined indicators that imply actual database error output.

Evidence requirements:

- parameter or form field
- payload used
- matched database error pattern
- baseline vs injected status code or response-length delta when useful
- matched response snippet

Result metadata:

- `category = "sqli"`
- `confidence` based on strength of the matched error signature

### Open Redirect

Current issue:

- Detection checks whether `Location` merely contains `evil.com`.
- Same-origin URLs that contain the payload text may be misreported as high risk.

New rule:

- Parse the redirect target with `urljoin` and `urlparse`.
- Report `high` only when the redirect target resolves to a different origin from the tested origin.
- Same-origin reflection or path-only payload echo should not be high severity.
- Optional low-cost enhancement: probe a small set of common redirect parameter names on likely redirect endpoints.

Evidence requirements:

- tested parameter
- payload used
- raw `Location` header
- normalized redirect origin

Result metadata:

- `category = "open_redirect"`
- `rule_id` distinguishing parameter-based and path-based findings

### Directory Traversal and Sensitive Files

Current issue:

- Many sensitive path findings rely on `200` plus content length.
- Login pages, SPA fallbacks, or custom error templates may look like valid hits.

New rule:

- Use stronger content fingerprints for high-value files:
  - SQL dumps: `CREATE TABLE`, `INSERT INTO`, or similar markers
  - ZIP backups: ZIP magic or relevant content-type
  - `.env`: multiple key-value lines and non-HTML content
  - `web.config`: XML markers
  - `.DS_Store`: binary signature or content markers
- Compare against a not-found baseline page to suppress generic application templates.
- Keep public metadata files such as `robots.txt` and `sitemap.xml` at low-risk or informational severities.

Evidence requirements:

- matched path
- marker that caused the match
- response snippet or content marker

Result metadata:

- `category = "dir_traversal"`
- `rule_id` for `sensitive_file`, `directory_listing`, or `path_traversal`

### Security Headers

Current issue:

- Static severity mapping does not reflect current browser reality.
- HSTS is evaluated even when the target is not meaningfully in an HTTPS context.
- HTTP to HTTPS redirect logic is too loose.

New rule:

- Normalize severities with a small policy matrix:
  - missing `Content-Security-Policy`: `medium`
  - missing `X-Frame-Options`: `medium`
  - missing `X-Content-Type-Options`: `low`
  - missing `Referrer-Policy`: `low`
  - missing `Permissions-Policy`: `low`
  - missing `X-XSS-Protection`: `info` or `low`
- Evaluate HSTS only for HTTPS targets.
- Evaluate HTTP to HTTPS redirect by requesting the HTTP URL and verifying redirect behavior rather than requiring an HTTPS `200`.
- Parse cookie flags more carefully so cookie findings reflect actual missing protections.

Evidence requirements:

- header name
- observed header value when present
- redirect target for HTTPS redirect findings

Result metadata:

- `category = "security_headers"`
- `confidence` generally high because these are deterministic header observations

## Result Normalization Layer

`app.py` should own response normalization rather than requiring every module to emit the full richer structure immediately.

Responsibilities:

- take module findings and fill default fields
- map `type` to `severity` when `severity` is absent
- derive `status` defaults:
  - `pass -> pass`
  - `info -> info`
  - `error -> error`
  - vulnerability severities -> `open`
- ensure `evidence` and `remediation` default to empty lists
- attach `scan_metadata`
- compute summary counts from canonical severity while remaining compatible with existing summary cards

This keeps module changes incremental and avoids blocking detector work on a large API rewrite.

## Front-End Changes

The front end should remain structurally the same.

Changes to `templates/index.html`:

- continue iterating over `results[module]`
- render optional pills for `confidence` and `status`
- render optional evidence and remediation blocks under the existing detail area
- add a compact scan metadata line for duration, modules run, and budget exhaustion

Changes to `static/style.css`:

- add styles for metadata pills
- add styles for evidence and remediation lists
- preserve the current layout and color model

No new pages are required.

## Data Flow

1. User submits target URL to `/api/scan`.
2. `app.py` validates target, rate-limits, and applies the request budget.
3. Each module produces findings, some legacy and some richer.
4. `app.py` normalizes module findings into the additive schema.
5. `app.py` computes summary counts and attaches `scan_metadata`.
6. Front end renders the existing summary plus optional richer finding details.

## Error Handling

- Module exceptions remain isolated to the module that failed.
- Normalization must tolerate missing optional fields.
- Evidence extraction must never crash a module if snippet extraction fails.
- New heuristics should fail closed toward lower confidence or no finding rather than reporting high severity on weak signals.

## Testing Strategy

Testing remains focused and module-specific.

### XSS tests

- inert text reflection does not report `high`
- raw executable contexts still report `high`
- evidence includes snippet and payload

### SQLi tests

- generic terms without a stronger database signature do not report
- baseline pages that already contain error-like text do not report
- injected database errors still report
- form branch mirrors URL branch behavior

### Open redirect tests

- same-origin URLs containing payload text do not report `high`
- cross-origin redirects do report `high`
- protocol-relative redirects are handled correctly

### Directory traversal tests

- generic HTML fallback pages do not count as sensitive file hits
- real SQL dump markers still count
- public metadata paths stay informational or low risk

### Security header tests

- HSTS only applies to HTTPS targets
- HTTP to HTTPS redirect is evaluated correctly
- outdated `X-XSS-Protection` handling does not inflate severity

### Response normalization tests

- legacy findings are enriched without breaking `type/title/detail`
- `scan_metadata` exists on successful scans
- summary remains compatible with current UI expectations

## Parallel Implementation Boundaries

The work should be split into these ownership areas:

### Worker 1

- `app.py`
- result normalization helpers
- `scan_metadata`
- summary logic
- tests for normalized API output

### Worker 2

- `scanner/xss_scanner.py`
- `scanner/sqli_scanner.py`
- accuracy tests for XSS and SQLi

### Worker 3

- `scanner/open_redirect.py`
- `scanner/dir_traversal.py`
- related accuracy tests

### Worker 4

- `scanner/security_headers.py`
- `templates/index.html`
- `static/style.css`
- tests that cover display-facing richer fields and header severity logic

These write scopes minimize overlap and fit a multi-agent execution model.

## Risks

- Existing files contain visible text encoding issues; new UI text should avoid making that problem worse and may require a dedicated maintenance task.
- Response normalization can create hidden coupling if modules start depending on fields that only exist after normalization.
- Overly aggressive suppression may reduce recall; tests must preserve genuine positives for each detector.

## Success Criteria

This iteration is successful when:

- high-severity findings require materially stronger evidence than before
- the main false-positive classes described above are covered by tests
- `/api/scan` remains backward-compatible for existing consumers
- each finding can optionally explain why it was reported and how to fix it
- the work can be split cleanly across multiple workers for implementation
