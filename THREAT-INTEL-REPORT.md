# Threat-Informed Vulnerability Assessment — `fixpoint-demo`

**Date:** 2026-07-27
**Scope:** Static review of `app.py`, `config.py`, `views.py`
**Intelligence source:** Anomali ThreatStream (actors, campaigns, TIP reports, CVEs, MITRE ATT&CK)
**Classification:** TLP:CLEAR — demo repository

> **Caveat:** This repo ships *intentionally* vulnerable code to exercise the Fixpoint auto-fixer. The findings below are real vulnerability classes, but the AWS keys in `config.py` are AWS's published *documentation example* keys (`AKIAIOSFODNN7EXAMPLE`), not live credentials. The point of this report is to show what these bug classes look like *when they escape into a production repo* and which real adversaries hunt them.

---

## 1. Vulnerability inventory

| # | File / sink | Class | CWE | Where |
|---|-------------|-------|-----|-------|
| V1 | `app.py:24` `get_user_by_email` — f-string in `execute()` | SQL injection | CWE-89 | user-controlled `email` |
| V2 | `app.py:38` `get_user_by_id` — string concatenation | SQL injection | CWE-89 | `str(user_id)` |
| V3 | `app.py:52` `search_users` — `.format()` inside a `LIKE` clause | SQL injection (blind-friendly) | CWE-89 | `search_term` |
| V4 | `app.py:66` `get_orders_by_status` — `%` formatting | SQL injection | CWE-89 | `status` |
| V5 | `config.py:13-31` — 12 hardcoded secrets (API keys, Postgres DSN `admin:secretpass123`, AWS `AKIA…`, `JWT_SECRET`, `ENCRYPTION_KEY`) | Hardcoded credentials | CWE-798 | committed to VCS |
| V6 | `views.py:21,30,38,46,54,59` — `mark_safe()` / `SafeString()` on caller input | Stored/Reflected XSS | CWE-79 | Django template autoescape bypass |

The parameterized `get_user_safe()` (`app.py:73`), the `os.environ.get()` block (`config.py:61`), and the `escape()`/static-`mark_safe` functions (`views.py:66-89`) are the correct patterns and are **not** findings.

---

## 2. SQL injection (V1–V4) → cross-referenced intel

The four sinks are the canonical "textbook four" — f-string, concat, `.format()`, `%`. The `LIKE '%{}%'` sink in `search_users` is the highest-value one to an attacker: it sits in a search endpoint (high call volume, low authorization) and the wildcard context makes **time-based blind** extraction trivial.

### Adversary: `ByteToBreach` (ThreatStream `actor-1099092`, SOCRadar, active since Jun 2025)

This is the most direct real-world analog in the dataset. ByteToBreach is a financially-motivated **access broker / data-leak trader** (35+ known victims across banking, telecom, airlines) whose signature move is exactly V3:

> *"A vulnerable GLPI version exposed an **SQL injection path**. Data extraction utilized slow, **time-based SQL queries**, with approximately **20 rented VPS servers** in several European countries to parallelize requests and retrieve roughly **10,000 password hashes** and related secrets over about ten days."* — Eurofiber breach, Nov 2025

**Mapped ATT&CK TTPs (from the actor profile):**
- **T1583.003** Acquire Infrastructure: Virtual Private Server — the ~20-node VPS fleet used to parallelize blind-SQLi extraction and dodge per-IP rate limits.
- **T1190** Exploit Public-Facing Application — SQLi against internet-facing enterprise apps (GLPI, ITSM).
- **T1059** Command & Scripting Interpreter — "reverse shell access" advertised post-exploitation.
- **T1213** Data from Information Repositories — bulk theft of structured DBs, then monetization on DarkForums + the "Pentesting Ltd" shaming site.

### Campaign: `Operation Cleaver` (ThreatStream `tipreport-27814778`)

The tradecraft escalation reference. Cleaver operators used **double-encoded SQLi payloads to bypass WAF filters**, then pivoted from injection to OS command execution:

> *"The attackers would enable `xp_cmdshell` … then connect outbound via anonymous FTP."*

This is the SQLi→RCE bridge: once V1–V4 reach a SQL Server / stacked-query backend, injection stops being "just" a data breach and becomes a foothold. (This repo uses `sqlite3`, which lacks `xp_cmdshell` — but the code pattern is backend-agnostic and would carry straight into a Postgres/MSSQL port.)

### Corroboration: Cisco Talos IR Trends Q1 2023 (`tipreport-6908955`, FIN13/Chrysene)

Talos observed **exploitation of public-facing apps jump from 15% → 45% of IR engagements quarter-over-quarter**, with web-shell drops following injection/exploitation of internet-exposed web servers. Establishes T1190 as a *volume* vector, not a boutique one.

---

## 3. Hardcoded secrets (V5) → cross-referenced intel

`config.py` commits a Postgres DSN, an AWS key pair, a JWT signing secret, and an AES key straight into version control. The threat here is **automated and fast** — this is not a "someday" risk.

### Campaign: `EleKtra-Leak` / "CloudKeys in the Air" (Unit 42, ThreatStream `tipreport-27691346`)

The defining case for V5. Unit 42's honeycloud research measured the reaction time to a leaked `AKIA…` key:

> *"The actor was able to detect and use the exposed IAM credentials **within five minutes** of their initial exposure on GitHub … used to create multiple AWS EC2 instances for … **long-lasting cryptojacking**."*

**Mapped TTPs:** T1552.001 Unsecured Credentials: Credentials In Files → T1078.004 Valid Accounts: Cloud Accounts → T1580 Cloud Infrastructure Discovery → **T1496 Resource Hijacking** (cryptojacking). The five-minute window means rotation-after-commit is not a mitigation; the key is burned the moment it lands on a public remote.

### Campaign: `UAT-10608` — automated credential harvesting (ThreatStream `tipreport-32321014`)

Shows what a foothold does with `config.py`-style secrets. This operation runs staged harvesters (`aws_full.txt`, `cloud_meta.txt`, `k8s.txt`, `docker.txt`) that:
- query **IMDS / cloud metadata** for instance-role creds,
- read the **Kubernetes service-account token** at `/var/run/secrets/kubernetes.io/serviceaccount/token`,
- dump **container env vars** (where committed secrets like these most often re-surface at runtime),
- scrape **shell history** for `mysql -u root -p …` invocations.

A `DATABASE_PASSWORD`/`DB_CONNECTION_STRING` pair like V5 is exactly the "secondary credential" this operation pivots on for lateral movement.

### Trend: "Attackers Ramp Up Efforts Targeting Developer Secrets" (`tipreport-24455628`)

Quantifies the scanning pressure: **~4,800 unique IPs** in a single month, sourced from cloud providers in Singapore and the US, sweeping for `.env` and `.git` config files. V5 assumes an attacker has to read your source — this report shows they're mass-scanning for it continuously.

### Escalation: "The Vercel Breach — OAuth Supply Chain" (`tipreport-33282641`)

The supply-chain endgame. When secrets live in platform env vars / repos rather than a runtime secret manager, a single upstream compromise cascades: *"credentials are the universal target and trust relationships are the universal attack surface."* Relevant because this repo's whole premise is a CI action (`.github/workflows/fixpoint.yml`) operating on the code — a `WEBHOOK_SECRET`/`AUTH_TOKEN` in-repo widens the CI blast radius.

---

## 4. Cross-site scripting (V6) → cross-referenced intel

`views.py` deliberately defeats Django's single best XSS defense — template autoescaping — by wrapping caller input in `mark_safe()`/`SafeString()`. `render_profile_bio` (`views.py:30`) is the nastiest: it interpolates `bio_text` into an HTML string *and then* marks the whole thing safe, so a stored bio becomes **persistent stored XSS** served to every profile viewer.

### CVE cluster: Django autoescape-bypass lineage (ThreatStream)

ThreatStream tracks a long tail of CWE-79 issues in Django itself — `CVE-2010-3082` (csrf cookie), `CVE-2011-0697` (upload filename), `CVE-2021-32052` (Django 3.2.1), `CVE-2022-22818` (Django 4.0.1, `{% debug %}`). The lesson: even *framework* code that forgets to escape ships as an XSS CVE. Hand-rolled `mark_safe()` on user data (V6) is the same defect with none of the framework's review. Recent commodity entries `CVE-2025-60280` and `CVE-2026-3862` show the class is still weaponized:

> `CVE-2025-60280`: *"attacker-controlled input rendered directly in the browser … an attacker can **steal session** [tokens]."*

### Attack pattern: XSS→XSRF credential-theft chain (ThreatStream `attackpattern-29315`)

Establishes the modern impact profile — not `alert(1)`, but:

> *"Stealing user cookies … stealing saved browser credentials … starting a keylogger … silently adding sensitive user information … We won't use the `<script>` tag at all,"* chained with **CSRF** to perform authenticated actions as the victim.

**Mapped TTPs:** T1059.007 Command & Scripting Interpreter: JavaScript → **T1539 Steal Web Session Cookie** → T1185 Browser Session Hijacking. Given V6 sits in a comment/bio renderer, the realistic outcome is **session-token theft of any admin who views the malicious content** → account takeover.

---

## 5. Contextualized attack scenarios

### Scenario A — "The Eurofiber Playbook" (V3 + V5 chained)
A ByteToBreach-style broker fingerprints the search endpoint backed by `search_users()` (V3). Because the sink is a `LIKE '%{}%'` clause, they run **time-based blind SQLi** — no error output needed. Mirroring the real Eurofiber op, they stand up a **~20-node VPS fleet (T1583.003)** to parallelize the boolean/timing oracle and stay under per-IP throttles, exfiltrating the `users` table over days (T1190 → T1213). The dump includes password hashes — but it also includes the **`config.py` secrets if this DB stores app config**, or the attacker simply reads `config.py` from a linked repo. Now they hold `DB_CONNECTION_STRING` (`admin:secretpass123`) and pivot to *direct* Postgres access, and `JWT_SECRET` to **forge valid session tokens (T1078)** — turning a read-only injection into full authenticated access. Data is listed on a DarkForums thread; the victim is named on a "Pentesting Ltd"-style shaming page (T1583.006).

### Scenario B — "Five-Minute Burn" (V5, EleKtra-Leak model)
A contributor forks this demo, adds a feature, and force-pushes a branch that still carries `config.py`. The instant the `AKIA…` pattern hits a public remote, EleKtra-Leak-class automation detects it **within five minutes (T1552.001)**, assumes the role (T1078.004), enumerates the account (T1580), and spins up EC2 for **cryptojacking (T1496)**. Meanwhile a UAT-10608-style harvester that already has any container foothold reads the same secrets out of **env vars and IMDS**, grabs the K8s service-account token, and pivots laterally. Rotation-after-the-fact does not help — detection beat the CI pipeline.

### Scenario C — "Stored Bio, Stolen Admin" (V6, XSS→XSRF chain)
An attacker submits a profile bio containing a non-`<script>` payload (SVG/event-handler based, per `attackpattern-29315`). `render_profile_bio()` (V6) interpolates it and `mark_safe()`s the result → **persistent stored XSS**. When a moderator opens the profile, the payload executes in the admin origin, exfiltrates the session cookie (**T1539**), and rides an existing session via **CSRF** to escalate privileges or add a backdoor admin (T1185). No credential phishing required — the vulnerable renderer delivers the admin's session to the attacker.

---

## 6. Prioritized remediation

| Priority | Finding | Fix (also what Fixpoint applies) |
|----------|---------|----------------------------------|
| **P0** | V5 secrets | Purge from history (`git filter-repo`), **rotate every value**, move to `os.environ` / a runtime secret manager. Assume already-scanned. |
| **P0** | V1–V4 SQLi | Parameterized queries only (`cursor.execute(sql, params)`), as in `get_user_safe()`. Never format user data into SQL text. |
| **P1** | V6 XSS | Delete `mark_safe`/`SafeString` on dynamic data; rely on Django autoescape or `escape()`, as in `render_safe_*`. |
| **P2** | Detection | Alert on the ByteToBreach fingerprint: **long-running low-bandwidth connections + repeated SQL errors + time-based query patterns**; alert on IMDS access from app containers; alert on new `AKIA` keys in commits (push protection). |

---

### Appendix — ThreatStream references
- Actor: `actor-1099092` ByteToBreach (SOCRadar)
- Campaigns/TIP: `tipreport-27814778` Operation Cleaver · `tipreport-6908955` Talos IR Q1 2023 (FIN13/Chrysene) · `tipreport-27691346` CloudKeys/EleKtra-Leak · `tipreport-32321014` UAT-10608 · `tipreport-24455628` Developer Secrets · `tipreport-33282641` Vercel OAuth
- CVEs: `CVE-2010-3082`, `CVE-2011-0697`, `CVE-2021-32052`, `CVE-2022-22818`, `CVE-2025-60280`, `CVE-2026-3862`
- Patterns: `attackpattern-29315` XSS→XSRF chain · `attackpattern-20831` AWS lateral movement
- ATT&CK: T1190, T1213, T1059, T1059.007, T1583.003, T1583.006, T1552.001, T1078, T1078.004, T1580, T1496, T1539, T1185
