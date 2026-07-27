# Sigma Detection Rules — `fixpoint-demo`

Threat-informed detections for the three vulnerability classes in this repo, derived from the
ThreatStream cross-reference in [`../../THREAT-INTEL-REPORT.md`](../../THREAT-INTEL-REPORT.md).
Each rule is anchored to a real adversary, campaign, or attack pattern — not a generic signature.

## Coverage matrix

| Rule | Vuln | Detects | Intel anchor | ATT&CK |
|------|------|---------|--------------|--------|
| `sqli_time_based_blind_bytetobreach.yml` | V1–V4 | Time-delay SQLi primitives (`SLEEP`, `pg_sleep`, `WAITFOR DELAY`, `BENCHMARK`) | ByteToBreach (`actor-1099092`) | T1190, T1213 |
| `sqli_waf_bypass_double_encoding_cleaver.yml` | V1–V4 | Double-encoded payloads + `xp_cmdshell`/`sp_configure` SQLi→RCE | Operation Cleaver (`tipreport-27814778`) | T1190, T1059, T1027 |
| `sqli_distributed_extraction_correlation.yml` | V3 | ≥8 distinct source IPs running SQLi/error-oracle against one host in 10 min | ByteToBreach VPS fleet | T1190, T1583.003 |
| `aws_exposed_iam_key_abuse_elektra_leak.yml` | V5 | Long-lived `AKIA` key doing recon → `RunInstances` (cryptojacking) | EleKtra-Leak / CloudKeys (`tipreport-27691346`) | T1552.001, T1078.004, T1496 |
| `cloud_imds_credential_harvest_uat10608.yml` | V5 | Shell reaching IMDS `169.254.169.254` / reading K8s SA token | UAT-10608 (`tipreport-32321014`) | T1552.001, T1552.005, T1580 |
| `xss_session_cookie_theft.yml` | V6 | Cookie/credential-theft XSS incl. non-`<script>` vectors | XSS→XSRF chain (`attackpattern-29315`) | T1059.007, T1539, T1185 |

## Log sources required

- **webserver** — access logs with query string (`cs-uri-query`), URI (`c-uri`), status (`sc-status`), host (`cs-host`). SQLi + XSS rules.
- **aws / cloudtrail** — management-event trail. EleKtra-Leak rule.
- **process_creation** — EDR / auditd / Sysmon-for-Linux on the app hosts. IMDS/K8s harvesting rule.

## Mapping to the ThreatStream `eventlog` schema

If you hunt directly in ThreatStream's analyst store (the `eventlog` table) rather than a SIEM,
translate the standard Sigma taxonomy fields as follows:

| Sigma field | ThreatStream `eventlog` column |
|-------------|-------------------------------|
| `cs-uri-query`, `c-uri` | `url`, `query` |
| `c-ip` / `sourceIPAddress` | `src_ip`, `public_src_ip` |
| `cs-host` | `host`, `dest` |
| `sc-status` / `return_code` | `return_code`, `status` |
| `cs-user-agent` | `user_agent` |
| `cs-referer` | `http_referrer` |
| `Image` / `CommandLine` | `image`, `command_line` |
| `ParentImage` | `parent_image` |
| `eventName` (CloudTrail) | `event_name` |
| `userIdentity.arn` | `user_role_arn`, `account_id` |

## Validation

These are hand-authored to the Sigma spec; validate/convert before deployment:

```bash
pip install sigma-cli pysigma-backend-splunk pysigma-backend-elasticsearch
sigma check detections/sigma/
# Example conversions:
sigma convert -t splunk       -p sysmon detections/sigma/cloud_imds_credential_harvest_uat10608.yml
sigma convert -t esql          detections/sigma/sqli_time_based_blind_bytetobreach.yml
```

The correlation rule (`sqli_distributed_extraction_correlation.yml`) uses the Sigma **correlation**
schema (`value_count`) and needs a backend that supports it (pySigma ≥ 0.10 / recent sigma-cli).

## Tuning notes

- Populate the `falsepositives` allowlists (scanner source ranges, authorized automation ARNs,
  known IMDS-calling agents) **before** promoting any rule from `experimental` to `stable`.
- The EleKtra-Leak rule keys on `AKIA` (long-term keys). Once you migrate off long-lived keys to
  IAM roles (see report §6), it becomes near-zero-noise — any surviving `AKIA` use is suspicious.
- Pair the SQLi rules with ByteToBreach's exfil tell from the actor profile: **long-running,
  low-bandwidth outbound connections** concurrent with **repeated SQL errors**.
