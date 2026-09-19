# CampusConnect — Dynamic Application Security Testing (DAST)

**SIT738 Secure Coding — Task 2, Phase 3**

This document records the Dynamic Application Security Testing (DAST) assessment performed against the deliberately vulnerable `vulnerable-webapp` using **OWASP ZAP 2.17.0**.

The testing process followed:

**ZAP configured → authenticated application explored → spider executed → active scan performed → alerts reviewed → findings mapped against known vulnerabilities → DAST limitations documented.**

---

## Table of Contents

- [Tool & Scan Configuration](#tool--scan-configuration)
- [DAST Scan Results](#dast-scan-results)
- [T2-07 — Persistent XSS](#t2-07--persistent-xss-detected)
- [T2-08 — Reflected XSS](#t2-08--reflected-xss-detected)
- [T2-09 — SQL Injection](#t2-09--sql-injection-detected)
- [T2-10 — CSRF](#t2-10--csrf-detected)
- [T2-11 — Data Aggregation / IDOR](#t2-11--data-aggregation--idor-not-automatically-detected)
- [T2-12 — Unrestricted File Upload](#t2-12--unrestricted-file-upload-not-detected)
- [T2-13 — SSRF](#t2-13--ssrf-not-detected)
- [Additional DAST Findings](#additional-dast-findings)
- [DAST Tooling Limitations](#dast-tooling-limitations)
- [SAST vs DAST Comparison](#sast-vs-dast-comparison)
- [Evidence Checklist](#evidence-checklist--task-2-phase-3)
- [Conclusion](#conclusion)

---

# Tool & Scan Configuration

| | |
|---|---|
| **Tool** | OWASP ZAP 2.17.0 |
| **Testing type** | Dynamic Application Security Testing (DAST) |
| **Target** | `http://localhost:8080/vulnerable-webapp/` |
| **Application** | CampusConnect vulnerable web application |
| **Authentication** | Authenticated browser session through ZAP Manual Explore |
| **Spidering** | Completed successfully |
| **Active scanning** | Completed |
| **Report** | ZAP HTML scanning report |
| **Scan scope** | `http://localhost:8080` |
| **Alert types** | 17 |
| **Primary testing areas** | Login, Noticeboard, Members, Profiles, Study Points, Upload, Link Preview |

### Evidence

| Screenshot | Description |
|---|---|
| `T2-12_tomcat-server-running.png` | CampusConnect successfully responding with HTTP 200 |
| `T2-13_zap-quickstart-target-set.png` | ZAP configured with the CampusConnect target |
| `T2-14_zap-sites-tree-authenticated.png` | Authenticated application endpoints discovered |
| `T2-15_zap-spider-results.png` | Spider completed successfully |
| `T2-16_zap-active-scan-running.png` | Active Scan in progress |
| `T2-17_zap-alerts-summary.png` | Completed Active Scan / alert summary |
| `T2-24_zap-report-summary.png` | Generated ZAP HTML report |

---

# DAST Scan Results

The ZAP scan identified several security issues, including the major vulnerabilities intentionally introduced into CampusConnect.

## High-risk findings

| Finding | ZAP Result |
|---|---|
| Persistent XSS | **Detected** |
| Reflected XSS | **Detected** |
| SQL Injection | **Detected** |

## Medium-risk findings

| Finding | ZAP Result |
|---|---|
| Missing Anti-CSRF Tokens | **Detected** |
| Buffer Overflow | **Detected** |
| CSP Header Not Set | **Detected** |
| Missing Anti-clickjacking Header | **Detected** |
| Session ID in URL Rewrite | **Detected** |

## Lower-risk / informational findings

ZAP also identified:

- Application Error Disclosure
- Cookie without SameSite Attribute
- Information Disclosure / Debug Error Messages
- X-Content-Type-Options Header Missing
- Sensitive Information in URL
- Suspicious Comments
- Session Management Responses Identified
- User Agent Fuzzer
- Potential XSS in HTML Attribute

---

# T2-07 — Persistent XSS (Detected)

## Objective

Determine whether ZAP can identify the Stored/Persistent Cross-Site Scripting vulnerability implemented in the CampusConnect Noticeboard.

## Location

| | |
|---|---|
| **Endpoint** | `/vulnerable-webapp/noticeboard` |
| **Method** | `GET` / `POST` |
| **Risk** | High |
| **ZAP alert** | Cross Site Scripting (Persistent) |
| **CWE** | CWE-79 |

## Finding

ZAP identified persistent XSS on the Noticeboard.

The application accepts attacker-controlled content and subsequently renders the stored content in the Noticeboard response.

The ZAP report identifies the Noticeboard endpoint as an affected location. The response contains attacker-controlled markup that had been stored and subsequently returned by the application, providing evidence of the persistent behaviour.

## Result

**Detected by DAST.**

This demonstrates the advantage of DAST for vulnerabilities where malicious input must travel through the running application and become observable in the HTTP response.

## Evidence

`T2-19_zap-xss-alerts.png`

The ZAP browser alert panel displays:

- Cross Site Scripting (Persistent)
- Cross Site Scripting (Reflected)

---

# T2-08 — Reflected XSS (Detected)

## Objective

Determine whether ZAP can identify reflected Cross-Site Scripting caused by user-controlled request data being returned in an HTTP response.

## Result

**Detected by DAST.**

ZAP reported:

```text
Cross Site Scripting (Reflected)
Risk: High
CWE: 79
```

## Why DAST detected it

ZAP was able to:

1. inject test payloads into HTTP parameters;
2. send the modified request to the running application;
3. inspect the resulting response;
4. determine that attacker-controlled content was reflected.

This is a runtime behaviour that is well suited to DAST.

## Evidence

`T2-19_zap-xss-alerts.png`

The ZAP Page Alerts panel shows the Reflected XSS alert alongside the Persistent XSS alert.

---

# T2-09 — SQL Injection (Detected)

## Objective

Determine whether ZAP can identify the SQL Injection vulnerability intentionally implemented in the Member Search functionality.

## Location

```text
/vulnerable-webapp/members/results?username=...
```

## Result

**Detected by DAST.**

ZAP reported:

```text
SQL Injection
Risk: High
CWE: 89
```

The scan identified the vulnerable Member Search endpoint.

The attack used a manipulated `username` parameter and produced a server-side error response, which ZAP used as evidence of SQL injection behaviour.

## Evidence

`T2-18_zap-sql-injection.png`

The screenshot shows:

```text
URL:
http://localhost:8080/vulnerable-webapp/members/results?username=%27

Risk:
High

Confidence:
Low

Parameter:
Attack

Evidence:
HTTP/1.1 500

CWE:
89
```

## Result

**SQL Injection was detected by both SAST and DAST.**

This makes SQL Injection a useful example of the overlap between the two testing approaches:

```text
SAST
 ↓
Detects dangerous SQL construction in source code

DAST
 ↓
Sends malicious input to running application

Both identify SQL Injection
```

---

# T2-10 — CSRF (Detected)

## Objective

Determine whether the running application contains state-changing requests without appropriate anti-CSRF protection.

## Result

**Detected by DAST.**

ZAP reported:

```text
Absence of Anti-CSRF Tokens
Risk: Medium
CWE: 352
```

The report identified multiple affected endpoints.

## Evidence

`T2-20_zap-csrf-alert.png`

The ZAP Page Alerts panel displays:

```text
Absence of Anti-CSRF Tokens
```

under the Medium-risk findings.

## Important interpretation

This finding means that ZAP observed state-changing forms/requests without recognised anti-CSRF tokens.

It should therefore be documented as:

> **DAST identified the absence of anti-CSRF protection.**

rather than claiming that ZAP automatically demonstrated every possible CSRF attack scenario.

---

# T2-11 — Data Aggregation / IDOR (Not Automatically Detected)

## Objective

Determine whether ZAP's automated scan identifies the intentionally vulnerable profile-access behaviour.

## Result

**Not automatically detected as an IDOR/Data Aggregation vulnerability.**

The application contains profile access through an identifier such as:

```text
/vulnerable-webapp/profile?id=1
```

The vulnerability depends on whether the authenticated user is authorised to access the requested profile.

This is fundamentally an **access-control/business-logic question**.

## Why automated DAST may miss it

An automated scanner can discover:

```text
/profile?id=1
/profile?id=2
/profile?id=3
```

but it does not automatically know:

```text
User A owns profile 1
User B owns profile 2
User A must NOT access profile 2
```

That requires an understanding of the application's authorization model.

Therefore, IDOR requires **authenticated manual testing**.

## Result

**Not detected automatically by ZAP.**

This does **not** mean that the application is secure against IDOR.

It means that the automated DAST scan did not establish the authorization violation.

## Evidence

Use:

```text
T2-21_idor-before.png
T2-22_idor-after.png
```

These screenshots should demonstrate:

```text
Authenticated User
       ↓
Request profile?id=another-user
       ↓
Another user's information returned
       ↓
Authorization bypass
```

---

# T2-12 — Unrestricted File Upload (Not Detected)

## Objective

Determine whether ZAP's automated scan identifies the unrestricted file-upload vulnerability implemented in CampusConnect.

## Endpoint

```text
/vulnerable-webapp/upload
```

## Result

**The unrestricted file-upload vulnerability was not automatically identified as an unrestricted upload finding.**

However, ZAP did identify several problems associated with the upload endpoint.

For example, the report contains:

```text
POST /vulnerable-webapp/upload
```

with an application error response:

```text
HTTP/1.1 500
```

and:

```json
{
  "status":500,
  "error":"Internal Server Error",
  "path":"/vulnerable-webapp/upload"
}
```

ZAP consequently reported **Application Error Disclosure** and **Debug Error Messages** associated with this endpoint.

## Why ZAP did not establish unrestricted upload

An unrestricted upload vulnerability requires demonstrating that an attacker can upload an inappropriate or dangerous file type and that the application accepts, stores or serves it in an unsafe manner.

A generic automated scan result on `/upload` does not by itself establish this.

Therefore:

> **The unrestricted file-upload vulnerability requires manual validation.**

## Evidence

```text
T2-23_file-upload.png
```

The evidence should show the controlled test file being uploaded and the resulting application behaviour.

---

# T2-13 — SSRF (Not Detected)

## Objective

Determine whether ZAP automatically identifies the Server-Side Request Forgery vulnerability implemented in the Link Preview functionality.

## Endpoint

```text
/vulnerable-webapp/link-preview
```

The application exposes a URL-fetching feature.

## Result

**SSRF was not reported as a dedicated ZAP alert in the generated report.**

This should not be interpreted as proof that the feature is secure.

SSRF often requires demonstrating that:

```text
Attacker-controlled URL
        ↓
Application server
        ↓
Server makes outbound request
        ↓
Internal / restricted resource accessed
```

An automated scanner cannot necessarily establish the security impact of arbitrary server-side URL fetching without an appropriate target and controlled verification.

## Result

**Not detected automatically by ZAP.**

The SSRF vulnerability should therefore be demonstrated separately through controlled manual testing of the Link Preview functionality.

---

# Additional DAST Findings

## 1. Content Security Policy Header Not Set

**Risk:** Medium

ZAP identified missing CSP headers.

CSP provides browser-side restrictions on permitted content sources and can reduce the impact of certain XSS and injection attacks.

---

## 2. Missing Anti-clickjacking Header

**Risk:** Medium

ZAP identified missing anti-clickjacking protection.

This is commonly addressed using an appropriate `X-Frame-Options` header and/or a CSP `frame-ancestors` policy.

---

## 3. Session ID in URL Rewrite

**Risk:** Medium

ZAP identified session identifiers being included in URLs.

Example pattern:

```text
/login;jsessionid=...
```

Session identifiers in URLs can create additional exposure through browser history, logs, referrer information and copied links.

---

## 4. Cookie without SameSite Attribute

**Risk:** Low

ZAP identified cookies without an appropriate `SameSite` attribute.

This is particularly relevant to session-cookie protection and CSRF risk reduction.

---

## 5. X-Content-Type-Options Header Missing

**Risk:** Low

ZAP identified missing:

```http
X-Content-Type-Options: nosniff
```

This header helps prevent browsers from MIME-sniffing responses in ways that can create additional security risks.

---

## 6. Application Error Disclosure

**Risk:** Low

ZAP identified application error information associated with the upload endpoint.

The endpoint returned an HTTP 500 response during testing.

---

## 7. Debug Error Messages

**Risk:** Low

ZAP also identified debug/error information associated with the upload endpoint.

Debugging information should not be exposed to users in a production deployment.

---

# DAST Tooling Limitations

The results demonstrate an important distinction between automated DAST findings and manual security testing.

| Vulnerability | DAST Result |
|---|---|
| Stored XSS | **Detected** |
| Reflected XSS | **Detected** |
| SQL Injection | **Detected** |
| CSRF | **Detected through absence of anti-CSRF tokens** |
| Data Aggregation / IDOR | **Not automatically detected** |
| Unrestricted File Upload | **Not automatically detected** |
| SSRF | **Not automatically detected** |

The important point is that a vulnerability not appearing in the ZAP alert list should **not** be described as secure.

Instead:

> **Not detected by automated DAST; manual validation required.**

This is particularly important for authorization and business-logic vulnerabilities such as IDOR.

---

# SAST vs DAST Comparison

| Vulnerability | SAST | DAST | Explanation |
|---|---|---|---|
| SQL Injection | Detected | **Detected** | Recognisable unsafe SQL construction and exploitable runtime behaviour |
| Stored XSS | Not detected | **Detected** | Runtime injection/storage/output behaviour exposed by ZAP |
| CSRF | Not detected | **Detected** | ZAP identified missing anti-CSRF tokens |
| IDOR | Not detected | Not automatically detected | Requires understanding user/data ownership |
| File Upload | Not detected | Not automatically detected | Requires controlled upload and validation testing |
| SSRF | Not detected | Not automatically detected | Requires controlled server-side request verification |
| Hardcoded DB credentials | **Detected** | Not applicable | Source-code secret is primarily a SAST finding |
| Missing security headers | Not applicable | **Detected** | Headers can be observed directly in HTTP responses |
| Session ID in URL | Not applicable | **Detected** | Runtime HTTP behaviour |

This illustrates why the assignment uses both SAST and DAST rather than relying on a single security-testing technique.

---

# Evidence Checklist — Task 2 Phase 3

| ID | Item | Result | Evidence |
|---|---|---|---|
| T2-12 | Application reachable | Complete | `T2-12_tomcat-server-running.png` |
| T2-13 | ZAP target configured | Complete | `T2-13_zap-quickstart-target-set.png` |
| T2-14 | Authenticated application explored | Complete | `T2-14_zap-sites-tree-authenticated.png` |
| T2-15 | Spider completed | Complete | `T2-15_zap-spider-results.png` |
| T2-16 | Active Scan running | Complete | `T2-16_zap-active-scan-running.png` |
| T2-17 | Active Scan completed/results | Complete | `T2-17_zap-alerts-summary.png` |
| T2-18 | SQL Injection | Detected | `T2-18_zap-sql-injection.png` |
| T2-19 | XSS | Detected | `T2-19_zap-xss-alerts.png` |
| T2-20 | CSRF | Detected | `T2-20_zap-csrf-alert.png` |
| T2-21 | IDOR before | Manual test | `T2-21_idor-before.png` |
| T2-22 | IDOR after | Manual test | `T2-22_idor-after.png` |
| T2-23 | File upload | Manual test | `T2-23_file-upload.png` |
| T2-24 | ZAP report | Complete | `T2-24_zap-report-summary.png` |

---

# Conclusion

The OWASP ZAP assessment successfully demonstrated that dynamic testing can identify several of the vulnerabilities present in CampusConnect.

The most significant automated findings were **Persistent XSS, Reflected XSS and SQL Injection**, all reported as High-risk findings. ZAP also identified the **absence of anti-CSRF tokens** and several security-configuration and information-disclosure issues.

At the same time, the assessment demonstrated the limitations of automated DAST. **Data Aggregation/IDOR, unrestricted file upload and SSRF cannot be considered resolved merely because ZAP did not generate dedicated alerts for them.** These vulnerabilities depend on application-specific authorization, validation and server-side behaviour and therefore require controlled manual testing.

The combined SAST and DAST results therefore provide broader coverage:

```text
                 CampusConnect
                       │
             ┌─────────┴─────────┐
             │                   │
            SAST                DAST
             │                   │
       Source-code           Running app
        analysis              analysis
             │                   │
       SQL Injection        XSS
       Hardcoded secrets    SQL Injection
                           CSRF
                           Headers
                           Session issues
             │                   │
             └─────────┬─────────┘
                       │
                Manual Testing
                       │
                IDOR / Upload
                     / SSRF
```

**Task 2 Phase 3 establishes the baseline security state of the vulnerable application before prevention mechanisms are implemented.**
