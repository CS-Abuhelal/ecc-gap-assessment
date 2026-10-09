# ECC Gap Assessment: Design

**Date:** 2026-10-08
**Author:** Ahmed Helal
**Status:** Approved in brainstorming, waiting for spec review

## 1. Goal

A GRC portfolio project: assess a small fictional Saudi company against the NCA
Essential Cybersecurity Controls (ECC-2:2024), using real scan evidence from my Wazuh
home lab. The result is the kind of deliverable a Big Four cyber team would hand a
client: a control-by-control gap workbook, a risk register, a remediation roadmap and a
written report, plus a measured before/after improvement on a real machine.

It sits beside SENTINEL (SOC) on the CV and replaces the Phishing Email Analyzer entry.
A threat-intelligence project follows it.

## 2. The framework

ECC-2:2024, published by the National Cybersecurity Authority (NCA). Source: the official
English PDF, classified Public / TLP: White.

- 4 domains, 28 subdomains, 108 main controls, plus subcontrols.
- Main control IDs look like `2-2-3`; subcontrol IDs look like `2.2.3.1`.
- Domains: 1 Cybersecurity Governance (1-1 to 1-10), 2 Cybersecurity Defense (2-1 to
  2-15), 3 Cybersecurity Resilience (3-1), 4 Third-Party and Cloud Computing
  Cybersecurity (4-1, 4-2).
- ECC applies to government agencies, their affiliated companies and private owners or
  operators of critical national infrastructure. The NCA encourages all other entities to
  use it.
- Most subdomains follow one pattern: `X-Y-1` requirements are documented and approved,
  `X-Y-2` they are implemented, `X-Y-3` they include a stated minimum, `X-Y-4` they are
  periodically reviewed. The status rules below lean on this.

The assessment works at main-control level (108 rows). Subcontrols appear as notes where
the evidence is specific, for example 2.12.3.5 (keep event logs for at least 12 months).

## 3. Scope

- **Organization:** a ~30-person IT services company in Jeddah, fictional. It wants
  government contracts, so it adopts ECC voluntarily. Its name is chosen during the build,
  checked so it is not a real Saudi company, and always written with "(fictional)".
- **In scope:** one Windows 11 workstation (my PC, always called `WS-01`) and the Wazuh
  SIEM that monitors it.
- **Everything else** (email, network devices, servers, cloud, backups, physical sites) is
  described in a one-page company profile and marked out of scope or not applicable, each
  with a reason. This is the Statement of Applicability.
- **Statuses:** Implemented, Partially implemented, Not implemented, Not applicable.
- **Evidence kinds:** technical (measured by Wazuh on WS-01) and documentary (policies and
  a roles chart written for the fictional company).
- **Honesty rule:** the README and report say plainly that technical results are measured,
  while governance ratings are judged against documents I wrote.

## 4. Architecture

```
Wazuh (live) --collect--> snapshot (allowlisted, committed) --assess--> results --report--> xlsx / html / pdf
                                        ^
        catalog, mapping, evidence, applicability, risks   (hand-written YAML, reviewed)
```

Only `collect` talks to Wazuh. Everything after it runs from committed snapshots, so
anyone can rebuild the report, and CI rebuilds it without Wazuh.

Python 3.11+, same tooling as SENTINEL (ruff, pytest). Libraries: httpx, PyYAML, pydantic,
openpyxl, Jinja2.

### 4.1 Repository layout

```
ecc/                 package: models.py, load.py, mapping.py, facts.py, assess.py,
                     validate.py, risk.py, privacy.py, collect.py, excel.py, html.py, cli.py
tools/               one-off generators: extract_catalog.py, gen_cis_checks.py
ecc/templates/       Jinja2 templates for the web page and the PDF
data/                catalog.yaml, cis_checks.yaml, mapping.yaml, evidence.yaml,
                     applicability.yaml, risks.yaml
snapshots/           dated snapshots, e.g. 2026-10-baseline.json, 2026-10-after.json
docs/company-profile.md
docs/policies/       the six policy documents
remediation/         fixes.yaml, apply.ps1, undo.ps1 (backups/ is git-ignored)
tests/
.github/workflows/   ci.yml (tests), pages.yml (build + deploy)
```

### 4.2 Commands

- `python -m ecc collect --label baseline`: read Wazuh, write `snapshots/<yyyy-mm>-<label>.json`.
- `python -m ecc check`: validate all data files and snapshots; print every problem.
- `python -m ecc build [--before baseline --after after]`: assess and write the workbook,
  web page and PDF to `build/` (git-ignored).

## 5. Data files

### 5.1 `catalog.yaml`
The 108 main controls: id, domain, subdomain id and title, control text. Transcribed from
the NCA PDF once (a one-off extraction script, then checked by hand). A test asserts 108
controls, 28 subdomains, 4 domains.

### 5.2 `cis_checks.yaml`
All 482 checks of the Wazuh policy `cis_win11_enterprise` (CIS Microsoft Windows 11
Enterprise Benchmark v3.0.0): Wazuh check id, CIS section id (e.g. `1.1.1`), title.
Generated from the policy file that ships with the Wazuh agent.

### 5.3 `mapping.yaml`
Links CIS checks and named facts to ECC controls. Every entry has a one-line `why`.

```yaml
rules:               # matched on the CIS id; the longest match wins
  - cis: "1.1"       # Password Policy
    ecc: ["2-2-3"]
    why: "Password rules are part of ECC's minimum IAM requirements (2.2.3.1)."
  - cis: "9"         # Windows Firewall
    ecc: ["2-5-3"]
    why: "Host firewall settings protect the network boundary of the workstation."
  - cis: "17"        # Advanced Audit Policy
    ecc: ["2-12-3"]
    why: "Audit policy turns on the event logs ECC requires (2.12.3.1, 2.12.3.2)."
  - cis: "18.10.42"  # Microsoft Defender Antivirus
    ecc: ["2-3-3"]
    why: "Malware protection on workstations (2.3.3.1)."
  - cis: "18.10.7.1" # one check: Disallow Autoplay for non-volume devices
    ecc: ["2-3-3"]
    why: "Restricting external media (2.3.3.2)."
facts:               # named rules computed in code (section 6.2)
  - fact: vulnerabilities
    ecc: ["2-10-3"]
  - fact: log_retention
    ecc: ["2-12-3"]
```

Matching works on whole dot-separated parts, so `1.1` matches `1.1.3` but not `1.10.1`.
A rule can name a full CIS id to target a single check, so no separate override list is
needed.

Validation: every one of the 482 checks maps to at least one control, and every target
control exists in the catalog.

### 5.4 `evidence.yaml`
Documentary evidence, per control: status, the document(s) that prove it, and a short note.
Controls the fictional company has not addressed are recorded as gaps, e.g. `1-6-3` (no
secure-development requirements yet). Validation: every referenced document exists.

### 5.5 `applicability.yaml`
The Statement of Applicability: each control that is Not applicable, with a reason (for
example 4-2: the company uses no cloud hosting). Validation: every N/A has a reason.

### 5.6 `risks.yaml`
One or more risks per gap: id, linked control(s), risk statement, likelihood 1-5,
impact 1-5, treatment (mitigate / accept / transfer / avoid), owner (a role from the roles
document), due date. Score = likelihood x impact. Rating bands, defined in the risk method
policy: 1-4 Low, 5-9 Medium, 10-16 High, 20-25 Critical.

## 6. Assessment logic

### 6.1 Snapshot (what `collect` stores)

```json
{
  "schema": 1,
  "label": "baseline",
  "taken_at": "2026-10-12T18:00:00Z",
  "host": "WS-01",
  "policy": {"id": "cis_win11_enterprise", "checks_total": 482},
  "checks": [{"id": 26000, "result": "failed"}],
  "vulnerabilities": {"critical": 0, "high": 0, "medium": 0, "low": 0},
  "logging": {"oldest_alert": "2026-09-28T00:00:00Z", "agent_active": true}
}
```

`result` is `passed`, `failed`, `not applicable` (from Wazuh) or `not scanned` (in the
policy but no result in the indexer). Check results come from the latest SCA check alert
per check (`rule.groups: sca`, `data.sca.type: check`, newest first), the same approach as
SENTINEL's `latest_checks`. Vulnerability counts come from `wazuh-states-vulnerabilities-*`.
`oldest_alert` is the earliest alert from the agent in `wazuh-alerts-*`; `agent_active`
means the agent sent at least one alert in the last 24 hours.
Connection settings use SENTINEL's variable names: `WAZUH_INDEXER_URL`,
`WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD`, `WAZUH_CA_CERT`. Because the indexer's
certificate is issued to `wazuh.indexer` while `collect` runs on the host against
`127.0.0.1`, `WAZUH_TLS_SERVER_NAME=wazuh.indexer` sets the TLS server name; certificate
checking stays on.

### 6.2 Named facts
- `vulnerabilities`: no critical and no high open → Implemented; no critical → Partially;
  otherwise Not implemented.
- `log_retention`: oldest stored alert at least 365 days old → Implemented; agent active
  and logs collected but under 365 days → Partially; otherwise Not implemented.

### 6.3 Control status
1. If the control is in `applicability.yaml`, it is Not applicable and is not scored.
2. **Technical rating** (if the control has mapped checks or facts):
   - Checks rating: ignore checks that are `not applicable` or `not scanned`; all remaining
     pass → Implemented; some pass → Partially; none pass → Not implemented.
   - The technical rating is the weakest of the checks rating and each mapped fact's rating.
   - If no usable check and no fact remains, there is no technical rating, and the control
     must have an `evidence.yaml` entry.
3. **Documentary rating** comes from `evidence.yaml`.
4. If both exist, the control gets the weaker one
   (Not implemented < Partially < Implemented).
5. Every applicable control must end up with a rating; otherwise `check` fails.

### 6.4 Scores
Compliance % = (Implemented + 0.5 x Partially) / applicable controls x 100, overall and per
domain. In compare mode, the report lists controls whose status changed and the score
change.

### 6.5 Risks
Every control rated Partially or Not implemented must be covered by at least one risk.
A risk whose controls are all Implemented in the latest snapshot is shown as closed.

## 7. Outputs

- **Excel workbook:** Summary (scores overall and by domain, before vs after), Controls
  (108 rows: status, evidence, gap note), Technical evidence (482 checks, their result and
  mapped controls), Risk register, Roadmap (gaps grouped into 30 / 60 / 90 days and later,
  ordered by risk score). Status cells colour-coded.
- **Web page** (GitHub Pages): score tiles, domain heatmap, before/after, a filterable
  controls table, a 5x5 risk heatmap, links to download the workbook and PDF.
- **PDF report** (~10-15 pages), printed from the same HTML with a print stylesheet and
  headless Chrome: executive summary, scope and Statement of Applicability, method,
  results by domain, top risks, roadmap, appendix with the mapping.
- **Policy pack** in `docs/policies/`, each one to two pages: cybersecurity policy (1-3),
  roles and responsibilities (1-4), risk method (1-5), access control (2-2), vulnerability
  management (2-10), logging and monitoring (2-12). Claude drafts; Ahmed edits until he
  owns them and can explain them in an interview.

## 8. Remediation (before/after)

- `remediation/fixes.yaml` lists 10-20 failed checks to fix. Each fix must be reversible,
  need no reboot, and not change how Ahmed signs in or break his apps. Mechanisms limited
  to `auditpol`, `net accounts`, `Set-NetFirewallProfile` and registry values under policy
  keys.
- Account lockout is decided with Ahmed separately: it would lock him out during the
  failed-logon bursts he runs for SENTINEL tests.
- `apply.ps1` requires an admin PowerShell, saves every current value to
  `remediation/backups/<timestamp>.json` before changing anything, and supports `-WhatIf`.
  `undo.ps1` restores from a backup file.
- Ahmed reviews and runs both scripts himself; Claude does not change system settings.
- The PC runs Windows 11 Home while the CIS policy targets Enterprise, so some checks
  cannot be fixed on Home. The report states this as a limitation.
- After the fixes: restart the Wazuh agent to trigger an SCA scan, then
  `collect --label after`.

## 9. Privacy

- Allowlist, not cleanup: a snapshot holds only the fields in 6.1 (check ids and results,
  counts, two dates). Check titles live in `cis_checks.yaml`, generated from the public
  policy file. No raw alert text is ever stored.
- The agent's real name is replaced with `WS-01` before anything is written.
- Before writing, `collect` scans the snapshot for forbidden terms: `$env:USERNAME`,
  `$env:COMPUTERNAME` and anything in `ECC_FORBIDDEN_TERMS` (Ahmed's names, passed only at
  run time, never written to a file). Any hit stops the write.
- Ahmed reviews the first snapshot before it is committed.
- Accepted: the public snapshot shows which Windows settings are weak on WS-01. Low risk
  for a home PC behind a router; the siem-homelab repo already publishes the failed-check
  count.

## 10. Errors

- `collect` stops with a plain message when Wazuh is unreachable ("Start Docker and Wazuh,
  then retry"), when there is no agent or more than one (asks for `--agent`), or when the
  indexer returns a cut-off result.
- `check` and `build` collect all validation problems and print them together, then exit
  non-zero.

## 11. Testing

- Privacy: forbidden terms stop the write; the snapshot contains only allowlisted fields.
- Mapping: all 482 checks mapped; all targets exist; longest match wins; `1.1` does not
  match `1.10.1`.
- Status rules: each case in 6.2 and 6.3, including weaker-of-two and no-usable-input.
- Scores: overall and per domain, N/A excluded, compare mode.
- Validation: missing evidence, missing N/A reason, gap without a risk, missing document.
- Outputs: the workbook has the five sheets and 108 control rows; the web page renders.
- Tests use a small synthetic snapshot, never the real one.
- CI: `ci.yml` runs ruff and pytest on every push and PR. `pages.yml` builds from the
  committed snapshots (Chrome is on GitHub's Ubuntu runners for the PDF) and deploys on
  pushes to main.

## 12. Build order

1. Repo skeleton, `catalog.yaml` (108 controls) and `cis_checks.yaml` (482 checks).
2. Mapping, facts and assessment engine on a synthetic snapshot, with tests.
3. `collect` and the privacy guard; baseline snapshot from live Wazuh (Ahmed starts Docker
   and Wazuh, then reviews the snapshot).
4. Company profile (name chosen and checked), applicability, evidence, policy pack, risks.
5. Outputs: workbook, web page, PDF; CI and Pages.
6. Remediation scripts; Ahmed runs them; after snapshot; before/after view.
7. README with results, public GitHub repo (only after Ahmed confirms), CV line.

## 13. Out of scope for v1

SAMA Cyber Security Framework mapping, other NCA frameworks (CCC, DCC, OTCC), more than one
endpoint, an Arabic version, AI features, a live dashboard.

## 14. Addendum (2026-10-09): SAMA Cyber Security Framework view

Ahmed asked for a second mapping, to the Saudi Central Bank's Cyber Security Framework (SAMA
CSF), because bank co-ops are a priority. Rimal Byte (fictional) is not regulated by SAMA, so the
view is indicative: it shows how the company would look to a bank client that expects SAMA
alignment from its suppliers.

- `data/sama_csf.yaml`: SAMA CSF's 4 domains, 32 subdomains and maturity levels 0-5, as published
  in the SAMA Rulebook.
- `data/sama_mapping.yaml`: each SAMA subdomain links to the ECC controls covering the same
  requirements, with a reason, or is marked not applicable with a reason (3.2.3 is excluded for
  non-banks; payment systems, e-banking and outsourcing do not apply). A link may override the
  derived score with its own rating and a note when the ECC control only partly matches (used
  for 3.3.11 Secure Disposal).
- Score: the ECC compliance of the linked controls. Indicative maturity: Level 3 when every
  linked control is Implemented, 2 at 50% or more with at least one Implemented, 1 above 0%, 0
  otherwise. The levels show how much of the mapped ECC controls is in place, not SAMA's own
  level criteria, so they are an upper bound. Levels 4 and 5 need measured control effectiveness
  and are not derived. SAMA expects at least Level 3.
- Outputs: a "SAMA CSF view (indicative)" workbook sheet, which also gives each link's reason,
  and a report section, both labelled indicative.
- Final review (2026-10-09): Level 2 originally needed only 50%, which put subdomains resting on
  one Partially implemented control (3.1.7 Training, 3.2.2 Regulatory Compliance) at "Repeatable
  but informal" against their own evidence; the rule now also needs an Implemented control. ECC
  1-5-3 (risk assessment triggers) was added to 3.1.5, 3.3.7 and 3.4.1.
- Plan: `docs/superpowers/plans/2026-10-09-ecc-plan-2b-sama.md`.
