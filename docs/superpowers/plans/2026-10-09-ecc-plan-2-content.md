# ECC Gap Assessment, Plan 2: The Assessment Content

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the pipeline into a finished baseline assessment of the fictional company Rimal Byte: company profile, Statement of Applicability, six policies, evidence for every control, a risk register and the report narrative, so `python -m ecc check` passes and `python -m ecc build` produces the full report (26.0% compliant at baseline).

**Architecture:** Mostly data and documents on top of plan 1's pipeline. One code task adds the report narrative (`data/report.yaml`: company, executive summary, key findings, limitations) to the web page, PDF and workbook, makes `check` list every problem, and makes `check` say what it skipped when there are no snapshots. Every data file below was drafted and validated against the real code and the real baseline snapshot before this plan was written.

**Tech Stack:** As plan 1 (Python 3.11+, pydantic, PyYAML, openpyxl, Jinja2, pytest, ruff 0.16.4).

**Spec:** `docs/superpowers/specs/2026-10-08-ecc-gap-assessment-design.md` (sections 3, 5, 7). **Plan 1:** `docs/superpowers/plans/2026-10-08-ecc-plan-1-pipeline.md` (complete; its later fix rounds are recorded in git history).

**This is plan 2 of 3.** Plan 3 covers the Windows fixes and "after" snapshot, the README, the GitHub Pages workflow and publishing (moved from plan 2 because it can only be tested once the public repository exists).

## Global Constraints

- Work in the repository root `ecc-gap-assessment/`. Every path below is relative to it.
- Run everything through `.venv/Scripts/python` (Windows virtualenv, Git Bash).
- Lint with `ruff==0.16.4`, rules `E, F, I, UP, B`, line length 100. Run `.venv/Scripts/python -m ruff check .` before every commit; it must print `All checks passed!`.
- Privacy: never write the Windows user name, the computer name, any `C:\Users\...` path or the Wazuh agent's real name into a committed file. Tests use made-up names only.
- Rimal Byte is fictional. Every document about it says so. Never name, imitate or describe a real company or person.
- People are named only by role: General Manager, Cybersecurity Lead, IT Manager, HR Officer, Project Manager, staff.
- Fixed facts used everywhere: about 30 staff, Jeddah, policies approved on 5 October 2026, next review October 2027, baseline snapshot of 8 October 2026.
- Copy data files exactly as given. They were validated against the code; a changed character can break `check` or the 26.0% result.
- Commit with `git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "..."`. Do not push, add a remote or create a GitHub repository.

## File Structure

| File | Responsibility |
|---|---|
| `ecc/models.py`, `ecc/load.py` | New `ReportText` model; `Dataset.report` read from `data/report.yaml` |
| `ecc/html.py`, `ecc/templates/report.html.j2` | Company name, executive summary, key findings, limitations on the page and PDF |
| `ecc/excel.py` | "Company" row on the Summary sheet |
| `ecc/validate.py` | `listed()` shows every item |
| `ecc/cli.py` | `check` says what it skipped when there are no snapshots |
| `data/report.yaml` | The report narrative |
| `docs/company-profile.md` | The fictional company: people, technology, facilities, suppliers, scope |
| `data/applicability.yaml` | Statement of Applicability: 6 controls not applicable, with reasons |
| `docs/policies/*.md` | Six policies (cybersecurity, roles, risk method, access control, vulnerability management, logging and monitoring) |
| `data/evidence.yaml` | Documentary rating for the 94 applicable controls that have no technical rating |
| `data/risks.yaml` | 26 risks covering all 96 gaps |
| `tests/test_policies.py`, `tests/test_real_data.py` | Checks on the policy documents and on the committed assessment |

---

### Task 1: Report narrative, full problem lists, clearer `check`

**Files:**
- Modify: `ecc/models.py`, `ecc/load.py`, `ecc/validate.py`, `ecc/cli.py`, `ecc/html.py`, `ecc/templates/report.html.j2`, `ecc/excel.py`, `tests/fixtures.py`
- Create: `data/report.yaml`
- Test: `tests/test_load.py`, `tests/test_validate.py`, `tests/test_cli.py`, `tests/test_html.py`, `tests/test_excel.py`

**Interfaces:**
- Produces: `Paragraph` type (non-blank string); `ReportText(company: Paragraph, executive_summary: tuple[Paragraph, ...] (at least one), key_findings: tuple[Paragraph, ...] = (), limitations: tuple[Paragraph, ...] = ())`; `Dataset.report: ReportText` loaded from `data/report.yaml`; `listed(label, items)` now shows every item; template context key `report`.

- [ ] **Step 1: Write the failing tests**

In `tests/test_validate.py`, replace the test `test_long_lists_are_shortened` with:

```python
def test_lists_show_every_item():
    items = [str(n) for n in range(20)]
    assert listed("things", items) == "things (20): " + ", ".join(items)
```

Append to `tests/test_load.py`:

```python
def test_dataset_reads_the_report_text(dataset):
    assert dataset.report.company == "Example Co (fictional)"
    summary = ("Example Co is a made-up company used by the tests.",)
    assert dataset.report.executive_summary == summary


def test_the_report_text_needs_a_company_and_a_summary(root: Path):
    rewrite(root, "report.yaml", {"company": "  ", "executive_summary": []})
    with pytest.raises(DataError, match="report.yaml"):
        load_dataset(root)
```

Append to `tests/test_cli.py`:

```python
def test_check_without_snapshots_says_what_it_skipped(root, capsys):
    for path in (root / "snapshots").glob("*.json"):
        path.unlink()
    assert run("check", "--root", str(root)) == 0
    out = capsys.readouterr().out
    assert "0 snapshot(s)." in out
    assert "checked once a snapshot exists" in out
```

Append to `tests/test_html.py`:

```python
def test_the_report_shows_the_company_summary_and_limitations(dataset, baseline):
    report = dataset.report.model_copy(update={"key_findings": ("<i>Passwords</i> need work.",)})
    changed = dataclasses.replace(dataset, report=report)
    html = render_html(changed, assess(changed, baseline))
    assert '<p class="company">Example Co (fictional)</p>' in html
    assert "<p>Example Co is a made-up company used by the tests.</p>" in html
    assert "<li>&lt;i&gt;Passwords&lt;/i&gt; need work.</li>" in html
    assert "<li>All data here is made up.</li>" in html
```

Append to `tests/test_excel.py`:

```python
def test_the_summary_names_the_company(tmp_path, dataset, after):
    rows = list(workbook(tmp_path, dataset, after)["Summary"].iter_rows(values_only=True))
    assert ("Company", "Example Co (fictional)") in [row[:2] for row in rows]
```

In `tests/fixtures.py`, add this constant directly above `DATA_FILES = {`:

```python
REPORT = {
    "company": "Example Co (fictional)",
    "executive_summary": ["Example Co is a made-up company used by the tests."],
    "key_findings": ["Password rules need work."],
    "limitations": ["All data here is made up."],
}

```

and add `"report.yaml": REPORT,` as the last entry of `DATA_FILES`.

- [ ] **Step 2: Run the tests to make sure they fail**

Run: `.venv/Scripts/python -m pytest -q`
Expected: failures in the new tests (`ReportText`/`report` missing, `listed` still shortening, no "checked once a snapshot exists"), and fixture loading errors (`report.yaml` is an unknown file), because the code does not know about the report yet.

- [ ] **Step 3: Implement**

`ecc/models.py`: directly after the `RiskRegister` class, add:

```python
Paragraph = Annotated[str, Field(min_length=1, pattern=NOT_BLANK)]


class ReportText(Strict):
    """The report's words: who was assessed, the summary, key findings and limitations."""

    company: Paragraph
    executive_summary: tuple[Paragraph, ...] = Field(min_length=1)
    key_findings: tuple[Paragraph, ...] = ()
    limitations: tuple[Paragraph, ...] = ()
```

`ecc/load.py`:
- add `ReportText,` to the `from ecc.models import (...)` list, between `Mapping,` and `RiskRegister,`;
- add the field `report: ReportText` as the last field of `Dataset`;
- in `load_dataset`, change the docstring to `"""Read all seven data files; if any are broken, report every one of them together."""` and add the reader `"report": lambda: load_model(ReportText, data / "report.yaml"),` as the last entry of `readers`.

`ecc/validate.py`: delete the `SHOWN = 15` line and replace the `listed` function with (keep two blank lines after the imports):

```python
def listed(label: str, items: Sequence[str]) -> str:
    return f"{label} ({len(items)}): {', '.join(items)}"
```

`ecc/cli.py`: in `run_check`, replace the final `print(...)` call and `return 0` with:

```python
    message = (
        f"OK: {len(dataset.catalog)} controls, {len(dataset.policy.checks)} checks, "
        f"{len(snapshots)} snapshot(s)."
    )
    if not snapshots:
        message += " Control ratings and risks are checked once a snapshot exists."
    print(message)
    return 0
```

`ecc/html.py`: in `report_context`, add `"report": dataset.report,` as the last entry of the returned dict.

`ecc/templates/report.html.j2`:
- after the CSS line `h3 { font-size: 16px; margin: 16px 0 6px; }` add `.company { font-size: 18px; font-weight: 600; margin: 0 0 4px; }`;
- after `  <h1>NCA ECC-2:2024 Gap Assessment</h1>` add `  <p class="company">{{ report.company }}</p>`;
- between the closing `</section>` of the tiles and `<h2>Results by domain</h2>`, insert:

```jinja
<h2>Executive summary</h2>
{% for paragraph in report.executive_summary %}
<p>{{ paragraph }}</p>
{% endfor %}
{% if report.key_findings %}
<h3>Key findings</h3>
<ul>
{% for finding in report.key_findings %}
<li>{{ finding }}</li>
{% endfor %}
</ul>
{% endif %}

```

- in the "Scope and applicability" section, directly after the paragraph that ends `governance ratings are judged against the company's own documents.</p>`, insert:

```jinja
{% if report.limitations %}
<h3>Limitations</h3>
<ul>
{% for item in report.limitations %}
<li>{{ item }}</li>
{% endfor %}
</ul>
{% endif %}
```

`ecc/excel.py`: in `write_summary`, directly after the `sheet.append([])` that precedes the `"As of"` row, add `sheet.append(["Company", dataset.report.company])`.

Create `data/report.yaml`:

```yaml
# The report's words. Figures describe the baseline snapshot of 8 October 2026; update them when
# a new snapshot is reported.
company: Rimal Byte (fictional)
executive_summary:
  - >-
    Rimal Byte (fictional) is a 30-person IT services company in Jeddah that is aligning with the
    National Cybersecurity Authority's Essential Cybersecurity Controls (ECC-2:2024) to compete for
    government contracts. This baseline assessment rates all 108 ECC controls. 102 apply, and the
    company meets 26.0% of them, counting Partially implemented controls as half.
  - >-
    Governance has a starting point: six policies, a Cybersecurity Lead role and a supervisory
    committee were approved in October 2026. Most of what those policies require is still being
    rolled out, and there is no cybersecurity strategy, awareness program, incident response plan
    or business continuity plan yet.
  - >-
    The largest gap is technical. Only 122 of the 473 applicable CIS benchmark checks pass on the
    representative workstation (WS-01), and every technically measured control is a gap. The 26
    risks in the register are led by insecure software delivery, phishing without awareness
    training and weak workstation hardening. The roadmap starts with email authentication and the
    five open high-severity vulnerabilities.
key_findings:
  - >-
    Six policies are approved, but there is no cybersecurity strategy and the only cybersecurity
    role is part-time (1-1, 1-2).
  - >-
    Only 122 of 473 applicable CIS checks pass on WS-01. Encryption scores 0 of 47 because Windows
    11 Home has no full BitLocker (2-3, 2-8).
  - Security logs go back about 10 days; ECC asks for 12 months (2.12.3.5).
  - No critical vulnerabilities are open, but 5 high-severity ones are (2-10-3).
  - >-
    There is no awareness program, incident response plan, penetration testing or business
    continuity plan (1-10, 2-11, 2-13, 3-1).
limitations:
  - >-
    Rimal Byte is fictional. Its profile, policies and governance ratings were written for this
    assessment and have not been independently audited.
  - >-
    Technical evidence comes from one Windows 11 Home workstation (WS-01) that stands in for the
    company's laptops.
  - >-
    The CIS benchmark is written for Windows 11 Enterprise; some of its settings cannot be applied
    on the Home edition.
  - Results describe one point in time, the baseline snapshot of 8 October 2026.
```

- [ ] **Step 4: Run the tests to make sure they pass**

Run: `.venv/Scripts/python -m pytest -q -W error`
Expected: all pass (200 tests), no warnings.

Run: `.venv/Scripts/python -m ecc check`
Expected: exit 1 listing the full set of unrated controls (all 100 ids, no "and N more") and the 8 gaps without risks. That is expected until Task 5.

- [ ] **Step 5: Lint and commit**

```bash
.venv/Scripts/python -m ruff check .
git add ecc/ tests/ data/report.yaml
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Add the report narrative; list every problem; explain checks skipped without snapshots"
```

---

### Task 2: Company profile and Statement of Applicability

**Files:**
- Create: `docs/company-profile.md`, replace `data/applicability.yaml`

These facts are the single source for every policy, evidence note and risk later in this plan.

- [ ] **Step 1: Write the company profile**

Create `docs/company-profile.md`:

```markdown
# Rimal Byte (fictional): Company Profile

> Rimal Byte is a fictional company created for a portfolio GRC project. It does not describe
> any real company. Its technical evidence comes from a real Windows 11 workstation in a home
> lab, labelled WS-01.

## The company

- An IT services company in Jeddah, Saudi Arabia, with about 30 staff.
- Services: managed IT support for small and medium businesses, and small custom software
  projects for clients.
- Why ECC: Rimal Byte is bidding for government contracts. ECC-2:2024 is mandatory for government
  agencies, their affiliated companies and critical infrastructure operators; the National
  Cybersecurity Authority (NCA) encourages every other entity to adopt it, and government clients
  expect their suppliers to show alignment. Rimal Byte has adopted it voluntarily.
- Authorized Official: the General Manager.

## People and roles

| Role | Who | Notes |
|---|---|---|
| General Manager | Authorized Official | Approves policies and accepts High and Critical risks |
| Cybersecurity Lead | A systems engineer, part-time (about 40% of their time) | Reports to the General Manager; separate from the IT Manager |
| IT Manager | Runs laptops, accounts, Microsoft 365 and the office network | |
| HR Officer | Hiring, contracts, leavers | |
| Project Manager | Client software projects | |
| Supervisory committee | General Manager, Cybersecurity Lead, IT Manager | Meets quarterly; first meeting planned |

## Technology

- **Laptops:** one Windows 11 laptop per employee. WS-01 represents them and is the only device
  with technical evidence in this assessment. It runs Windows 11 Home; the company plans to move
  its laptops to Windows 11 Pro or Enterprise.
- **Microsoft 365 Business:** email, Teams, OneDrive and SharePoint. Multi-factor authentication
  is enforced for every account, and there are two named administrators.
- **Wazuh SIEM:** a single-node Wazuh server in the office collects security events and
  vulnerability data from the laptops.
- **Office network:** the internet provider's router with its built-in firewall, and a separate
  guest Wi-Fi. There are no servers in the office apart from the Wazuh server.
- **Phones:** staff use their personal phones for email and Teams. There is no mobile device
  management.
- **Website:** a static brochure page at a web hosting provider, with no logins or forms.
- **Backups:** files in OneDrive and SharePoint are covered by Microsoft 365 retention. Laptops are
  not backed up, and no restore has ever been tested.
- **Software projects:** delivered into client environments through an informal process, with no
  secure coding standard or security testing.

## Facilities

The office is in a shared building in Jeddah. The landlord runs badge access to the building and
CCTV in the lobby; the office door uses a key. There is no secure disposal service for old devices
or paper.

## Suppliers and clients

- Suppliers: Microsoft (cloud services, assessed under ECC 4-2), the internet provider and the
  web hosting provider, all on their standard terms.
- Client contracts include non-disclosure clauses.
- Rimal Byte does not outsource IT or cybersecurity operations.

## People practices

- Employment contracts include a confidentiality clause. There is no background screening.
- When someone leaves, the IT Manager disables their accounts, with no checklist or record.
- There is no awareness program. The Cybersecurity Lead has done some self-paced training.

## Assets and data

The IT Manager keeps a spreadsheet of laptops and accounts, which is incomplete and not updated on
a schedule. Information is not classified or labelled.

## Assessment scope

- **Framework:** NCA Essential Cybersecurity Controls ECC-2:2024, all 108 main controls. Six do
  not apply; the reasons are in `data/applicability.yaml`.
- **Technical evidence:** WS-01, measured by Wazuh: the CIS Microsoft Windows 11 Enterprise
  Benchmark v3.0.0 checks, open vulnerabilities and log retention.
- **Documentary evidence:** the six policies in `docs/policies/`, approved on 5 October 2026.
- **Baseline:** the snapshot of 8 October 2026.
```

- [ ] **Step 2: Write the Statement of Applicability**

Replace `data/applicability.yaml` with:

```yaml
# Statement of Applicability for Rimal Byte (fictional): controls that do not apply, with reasons.
# Every other ECC-2:2024 control applies and is rated.
not_applicable:
  - control: 1-7-1
    reason: >-
      Rimal Byte is a small private company and is not party to any nationally approved
      international agreement or commitment that carries cybersecurity requirements.
  - control: 2-15-1
    reason: >-
      Rimal Byte runs no external web applications. Its public website is a static brochure
      page with no logins or forms, hosted by a third party and covered under 4-1 and 4-2.
  - control: 2-15-2
    reason: Rimal Byte runs no external web applications (see 2-15-1).
  - control: 2-15-3
    reason: Rimal Byte runs no external web applications (see 2-15-1).
  - control: 2-15-4
    reason: Rimal Byte runs no external web applications (see 2-15-1).
  - control: 4-1-3
    reason: >-
      Rimal Byte does not outsource IT or cybersecurity operations or managed services; its
      cloud service (Microsoft 365) is assessed under 4-2.
```

- [ ] **Step 3: Verify**

Run: `.venv/Scripts/python -m pytest -q -W error`
Expected: all pass (the real-data tests from plan 1 do not touch applicability).

Run: `.venv/Scripts/python -m ecc check`
Expected: exit 1; the unrated list now has 94 controls (the 6 not-applicable ones are gone).

- [ ] **Step 4: Commit**

```bash
git add docs/company-profile.md data/applicability.yaml
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Add the Rimal Byte company profile and Statement of Applicability"
```

---

### Task 3: The policy pack

**Files:**
- Create: `docs/policies/cybersecurity-policy.md`, `docs/policies/roles-and-responsibilities.md`, `docs/policies/risk-management-method.md`, `docs/policies/access-control-policy.md`, `docs/policies/vulnerability-management-policy.md`, `docs/policies/logging-and-monitoring-policy.md`
- Test: `tests/test_policies.py`

Write six short, plain-English policies for Rimal Byte (fictional), 400 to 900 words each. They must be consistent with `docs/company-profile.md` and with the evidence notes in Task 5 (which quote what these policies say). Write like a real small-company policy: clear "must" statements, no filler, no legal boilerplate, no marketing tone.

- [ ] **Step 1: Write the failing test**

Create `tests/test_policies.py`:

```python
from pathlib import Path

import pytest

POLICIES = Path(__file__).resolve().parents[1] / "docs" / "policies"
EXPECTED = {
    "cybersecurity-policy.md": ["1-3-1", "1-3-3", "1-3-4", "1-9-4", "2-3-1"],
    "roles-and-responsibilities.md": ["1-2-1", "1-2-3", "1-4-1", "1-4-2"],
    "risk-management-method.md": ["1-5-1", "1-5-2", "1-5-3", "1-5-4"],
    "access-control-policy.md": ["2-2-1", "2-2-2", "2-2-3", "2-2-4"],
    "vulnerability-management-policy.md": ["2-10-1", "2-10-2", "2-10-3", "2-10-4"],
    "logging-and-monitoring-policy.md": ["2-12-1", "2-12-2", "2-12-3", "2-12-4"],
}
HEADER = ("Rimal Byte (fictional)", "Approved by", "5 October 2026", "October 2027")


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_each_policy_has_its_header_and_controls(name):
    text = (POLICIES / name).read_text(encoding="utf-8")
    for required in HEADER:
        assert required in text, f"{name} lacks {required!r}"
    for control in EXPECTED[name]:
        assert control in text, f"{name} does not cite ECC {control}"
    words = len(text.split())
    assert 400 <= words <= 900, f"{name} has {words} words"


def test_the_risk_method_matches_the_code():
    text = (POLICIES / "risk-management-method.md").read_text(encoding="utf-8")
    for band in ("1-4", "5-9", "10-16", "20-25", "Low", "Medium", "High", "Critical"):
        assert band in text


def test_the_vulnerability_deadlines_are_stated():
    text = (POLICIES / "vulnerability-management-policy.md").read_text(encoding="utf-8")
    for deadline in ("7 days", "30 days", "90 days"):
        assert deadline in text
```

Run: `.venv/Scripts/python -m pytest tests/test_policies.py -q`
Expected: 8 failed (files do not exist).

- [ ] **Step 2: Write the six policies**

Every policy starts with this header (fill in the title and the ECC controls line), followed by the disclaimer:

```markdown
# Rimal Byte (fictional): <Title>

| | |
|---|---|
| Version | 1.0 |
| Owner | Cybersecurity Lead |
| Approved by | General Manager (Authorized Official) |
| Approved on | 5 October 2026 |
| Next review | October 2027 |
| ECC-2:2024 controls | <the control ids listed below for this policy> |

> Rimal Byte is a fictional company. This policy was written for a portfolio GRC project.
```

Then these sections, in order: **Purpose**, **Scope**, **Policy** (numbered "must" statements, each ending with the ECC control or subcontrol it supports in brackets, e.g. "[2.2.3.2]"), **Roles**, **Exceptions** (requested from the Cybersecurity Lead, assessed with the risk management method, approved by the General Manager, time-limited to at most 12 months), **Compliance** (breaches handled under HR disciplinary rules), **Review** (annually in October, or sooner if the law or the business changes significantly).

Required content per policy (each item must appear; wording is yours):

1. `cybersecurity-policy.md`. Controls: 1-3-1, 1-3-2, 1-3-3, 1-3-4, 1-9-4, 2-3-1.
   - The General Manager commits to a cybersecurity program aligned with ECC-2:2024.
   - Scope: all staff and contractors, company laptops, Microsoft 365, the office network and client data.
   - Lists the five topic policies and says they carry the detailed requirements.
   - The CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 (Level 1) is the security baseline for every company laptop; deviations are recorded as exceptions [1-3-3, 2-3-1].
   - Policies are shared with staff; staff must read and acknowledge them when they join and after each update, and must follow them [1-3-1, 1-9-4].
   - The Cybersecurity Lead checks compliance and reports to the supervisory committee [1-3-2].
2. `roles-and-responsibilities.md`. Controls: 1-2-1, 1-2-2, 1-2-3, 1-4-1, 1-4-2.
   - General Manager: Authorized Official; approves policies; accepts High and Critical risks.
   - Cybersecurity Lead: part-time role (about 40% of one systems engineer's time), reports directly to the General Manager and is independent of the IT Manager; owns the policies, risk register, monitoring and incident coordination [1-2-1].
   - States the target to make the cybersecurity role full-time and filled by a qualified Saudi professional by the end of 2027 [1-2-2].
   - IT Manager, HR Officer, Project Manager and all staff, each with concrete duties.
   - Supervisory committee: General Manager (chair), Cybersecurity Lead, IT Manager; meets quarterly; reviews program progress, the risk register and assessment results; keeps minutes [1-2-3].
   - A RACI table (Responsible, Accountable, Consulted, Informed) for: approving policies, maintaining the risk register, managing accounts, patching, reviewing alerts, onboarding and offboarding, responding to incidents.
3. `risk-management-method.md`. Controls: 1-5-1, 1-5-2, 1-5-3, 1-5-4.
   - Likelihood scale 1 to 5 (Rare, Unlikely, Possible, Likely, Almost certain) and impact scale 1 to 5 (Minimal, Minor, Moderate, Major, Severe), each level with a one-line definition.
   - Score = likelihood x impact. Bands exactly: 1-4 Low, 5-9 Medium, 10-16 High, 20-25 Critical.
   - Treatments: mitigate, accept, transfer, avoid. Low and Medium risks may be accepted by the Cybersecurity Lead; High and Critical only by the General Manager.
   - The risk register records, per risk: id, linked ECC controls, statement, likelihood, impact, treatment, owner and due date.
   - A risk assessment is required: at the early stage of technology projects; before major changes to technology infrastructure; when planning to use a third-party service; before releasing new technology services or products [1-5-3].
   - A full assessment against ECC each year, and the method itself reviewed each year [1-5-4].
4. `access-control-policy.md`. Controls: 2-2-1, 2-2-2, 2-2-3, 2-2-4.
   - One named account per person; no shared accounts.
   - Multi-factor authentication for Microsoft 365 and any remote access [2.2.3.2].
   - Password and lockout rules follow the CIS baseline: at least 14 characters, history of 24, and account lockout after repeated failed attempts [2.2.3.1].
   - Least privilege; administrator rights only for IT staff, using separate administrator accounts [2.2.3.3, 2.2.3.4].
   - Access is granted on an HR request and removed on the person's last day.
   - The IT Manager reviews all accounts and rights every quarter and reports the results to the Cybersecurity Lead [2.2.3.5, 2-2-4].
5. `vulnerability-management-policy.md`. Controls: 2-10-1, 2-10-2, 2-10-3, 2-10-4.
   - Wazuh vulnerability detection runs on every laptop; the Cybersecurity Lead reviews the results at least weekly [2.10.3.1].
   - Severity follows the CVSS rating: Critical, High, Medium, Low [2.10.3.2].
   - Fix deadlines from detection: Critical 7 days, High 30 days, Medium 90 days, Low at the next monthly update [2.10.3.3].
   - Windows updates install automatically; other applications are updated at least monthly [2.10.3.4].
   - Exceptions follow the risk management method and are tracked; the Cybersecurity Lead follows NCA and vendor security advisories [2.10.3.5].
6. `logging-and-monitoring-policy.md`. Controls: 2-12-1, 2-12-2, 2-12-3, 2-12-4.
   - Every laptop has security event logging turned on as the CIS audit policy requires, including events for privileged accounts and remote access [2.12.3.1, 2.12.3.2].
   - Logs are collected centrally in the Wazuh SIEM [2.12.3.3].
   - The Cybersecurity Lead reviews Wazuh alerts every working day [2.12.3.4].
   - Logs are kept for at least 12 months [2.12.3.5].
   - Clocks are synchronised with a trusted time source, and only the Cybersecurity Lead and IT Manager can access the logs.

- [ ] **Step 3: Run the tests to make sure they pass**

Run: `.venv/Scripts/python -m pytest tests/test_policies.py -q`
Expected: 8 passed.

Run: `.venv/Scripts/python -m pytest -q -W error` and `.venv/Scripts/python -m ruff check .`
Expected: all pass; `All checks passed!`.

- [ ] **Step 4: Commit**

```bash
git add docs/policies tests/test_policies.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Add Rimal Byte's six cybersecurity policies"
```

---

### Task 4: Ahmed reviews the profile and policies (checkpoint)

This task is for Ahmed, not a subagent. The controller shows him `docs/company-profile.md` and the six policies and asks him to read them and change anything he would not be able to explain in an interview. Edits he asks for are made by the controller (or a small fix subagent) and committed with the message "Edit the profile and policies after review"; `tests/test_policies.py` must still pass. If an edit changes a fact that an evidence note in Task 5 depends on, update that note in Task 5 to match before committing it.

- [ ] **Step 1:** Ahmed has read all seven documents and either approved them or listed changes.
- [ ] **Step 2:** Requested changes are made, tests pass, and the change is committed.

---

### Task 5: Evidence and the risk register

**Files:**
- Replace: `data/evidence.yaml`, `data/risks.yaml`
- Test: `tests/test_real_data.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_real_data.py`:

```python
from collections import Counter
from pathlib import Path

from ecc.assess import assess, compliance, domain_scores
from ecc.load import load_dataset, load_snapshots
from ecc.validate import validate

ROOT = Path(__file__).resolve().parents[1]


def baseline_assessment():
    dataset = load_dataset(ROOT)
    snapshots = load_snapshots(ROOT / "snapshots")
    baseline = next(snapshot for snapshot in snapshots if snapshot.label == "baseline")
    return dataset, snapshots, assess(dataset, baseline)


def test_the_committed_assessment_is_complete():
    dataset, snapshots, _ = baseline_assessment()
    assert validate(dataset, snapshots) == []


def test_the_baseline_results():
    _, _, assessment = baseline_assessment()
    assert compliance(assessment.results) == 26.0
    assert domain_scores(assessment) == {1: 30.9, 2: 25.4, 3: 0.0, 4: 21.4}
    statuses = Counter(result.status.value for result in assessment.results)
    assert statuses == {
        "Implemented": 6,
        "Partially implemented": 41,
        "Not implemented": 55,
        "Not applicable": 6,
    }
```

Run: `.venv/Scripts/python -m pytest tests/test_real_data.py -q`
Expected: 2 failed (unrated controls and gaps without risks).

- [ ] **Step 2: Write the evidence**

Replace `data/evidence.yaml` with:

```yaml
# Documentary evidence for Rimal Byte (fictional). One entry per applicable control that has no
# technical rating. Facts come from docs/company-profile.md; documents are in docs/policies/.
# Rubric: a topic policy makes its "documented and approved" control Implemented, its
# "implemented" control Partially implemented (rollout started) and its "periodically reviewed"
# control Partially implemented (review cycle set, first review due October 2027). Controls no
# policy covers are Not implemented unless a stated fact shows a partial measure.
entries:
  # 1-1 Cybersecurity Strategy
  - {control: 1-1-1, status: Not implemented, note: "No cybersecurity strategy has been written or approved yet."}
  - {control: 1-1-2, status: Not implemented, note: "No strategy action plan, because there is no strategy yet."}
  - {control: 1-1-3, status: Not implemented, note: "No strategy to review."}

  # 1-2 Cybersecurity Management
  - control: 1-2-1
    status: Partially implemented
    documents: [docs/policies/roles-and-responsibilities.md]
    note: >-
      A part-time Cybersecurity Lead, separate from the IT Manager, reports to the General
      Manager; there is no dedicated cybersecurity department.
  - control: 1-2-2
    status: Not implemented
    documents: [docs/policies/roles-and-responsibilities.md]
    note: The only cybersecurity role is part-time; no position is filled full-time.
  - control: 1-2-3
    status: Partially implemented
    documents: [docs/policies/roles-and-responsibilities.md]
    note: >-
      A supervisory committee (General Manager, Cybersecurity Lead, IT Manager) is defined and
      approved; it has not met yet.

  # 1-3 Cybersecurity Policies and Procedures
  - control: 1-3-1
    status: Implemented
    documents: [docs/policies/cybersecurity-policy.md]
    note: >-
      The cybersecurity policy and five topic policies are documented, approved by the General
      Manager and shared with staff.
  - control: 1-3-2
    status: Partially implemented
    documents: [docs/policies/cybersecurity-policy.md]
    note: The policies were approved recently; rollout has started but is not complete.
  - control: 1-3-3
    status: Partially implemented
    documents: [docs/policies/cybersecurity-policy.md]
    note: >-
      The CIS Microsoft Windows 11 benchmark is adopted as the workstation standard; there are
      no standards yet for network devices or cloud services.
  - control: 1-3-4
    status: Partially implemented
    documents: [docs/policies/cybersecurity-policy.md]
    note: Annual review cycle set; first review due October 2027.

  # 1-4 Cybersecurity Roles and Responsibilities
  - control: 1-4-1
    status: Implemented
    documents: [docs/policies/roles-and-responsibilities.md]
    note: Governance structure, roles and responsibilities documented and approved by the General Manager.
  - control: 1-4-2
    status: Partially implemented
    documents: [docs/policies/roles-and-responsibilities.md]
    note: Annual review cycle set; first review due October 2027.

  # 1-5 Cybersecurity Risk Management
  - control: 1-5-1
    status: Implemented
    documents: [docs/policies/risk-management-method.md]
    note: >-
      Risk management method (1-5 likelihood and impact scales, rating bands, treatment options)
      documented and approved.
  - control: 1-5-2
    status: Partially implemented
    documents: [docs/policies/risk-management-method.md]
    note: This gap assessment is the first use of the method; risk management is not yet routine.
  - control: 1-5-3
    status: Partially implemented
    documents: [docs/policies/risk-management-method.md]
    note: The method names the four triggers for a risk assessment; none has been run on a real project yet.
  - control: 1-5-4
    status: Partially implemented
    documents: [docs/policies/risk-management-method.md]
    note: Annual review cycle set; first review due October 2027.

  # 1-6 Cybersecurity in Information and Technology Project Management
  - {control: 1-6-1, status: Not implemented, note: "Project and change procedures do not include cybersecurity requirements."}
  - {control: 1-6-2, status: Not implemented, note: "No vulnerability assessment or hardening review before changes go live."}
  - {control: 1-6-3, status: Not implemented, note: "Software projects have no secure coding standard or security testing step."}
  - {control: 1-6-4, status: Not implemented, note: "No project security requirements to review."}

  # 1-8 Periodical Cybersecurity Review and Audit
  - {control: 1-8-1, status: Partially implemented, note: "This gap assessment is the first internal review of the controls; there is no regular review schedule yet."}
  - {control: 1-8-2, status: Not implemented, note: "No independent review or audit has been done."}
  - {control: 1-8-3, status: Partially implemented, note: "This assessment's results go to the General Manager; the supervisory committee has not met to receive them."}

  # 1-9 Cybersecurity in Human Resources
  - {control: 1-9-1, status: Not implemented, note: "No documented cybersecurity requirements for staff before, during or after employment."}
  - {control: 1-9-2, status: Not implemented, note: "No personnel security requirements to implement."}
  - {control: 1-9-3, status: Partially implemented, note: "Employment contracts include a confidentiality clause; there is no screening or vetting."}
  - control: 1-9-4
    status: Partially implemented
    documents: [docs/policies/cybersecurity-policy.md]
    note: Staff must acknowledge and follow the new policies, but there is no awareness training.
  - {control: 1-9-5, status: Partially implemented, note: "The IT Manager disables leavers' accounts, but there is no checklist or record."}
  - {control: 1-9-6, status: Not implemented, note: "No personnel security requirements to review."}

  # 1-10 Cybersecurity Awareness and Training Program
  - {control: 1-10-1, status: Not implemented, note: "No awareness program."}
  - {control: 1-10-2, status: Not implemented, note: "No awareness program to implement."}
  - {control: 1-10-3, status: Not implemented, note: "No awareness content on email, mobile devices, browsing or social media."}
  - {control: 1-10-4, status: Partially implemented, note: "The Cybersecurity Lead has done some self-paced training; developers and managers have none."}
  - {control: 1-10-5, status: Not implemented, note: "No awareness program to review."}

  # 2-1 Asset Management
  - {control: 2-1-1, status: Not implemented, note: "No documented asset management requirements."}
  - {control: 2-1-2, status: Partially implemented, note: "The IT Manager keeps a spreadsheet of laptops and accounts, but it is incomplete and not updated on a schedule."}
  - {control: 2-1-3, status: Not implemented, note: "No acceptable use policy."}
  - {control: 2-1-4, status: Not implemented, note: "No acceptable use policy to implement."}
  - {control: 2-1-5, status: Not implemented, note: "Information is not classified or labelled."}
  - {control: 2-1-6, status: Not implemented, note: "No asset management requirements to review."}

  # 2-2 Identity and Access Management (2-2-3 is rated from CIS checks)
  - control: 2-2-1
    status: Implemented
    documents: [docs/policies/access-control-policy.md]
    note: Access control policy documented and approved.
  - control: 2-2-2
    status: Partially implemented
    documents: [docs/policies/access-control-policy.md]
    note: >-
      Microsoft 365 enforces MFA and every account is personal; least privilege and access
      reviews are not yet in place.
  - control: 2-2-4
    status: Partially implemented
    documents: [docs/policies/access-control-policy.md]
    note: Quarterly access review and annual policy review set; none done yet.

  # 2-3 Information System and Processing Facilities Protection (2-3-2, 2-3-3 from CIS checks)
  - control: 2-3-1
    status: Partially implemented
    documents: [docs/policies/cybersecurity-policy.md]
    note: >-
      The cybersecurity policy commits to the CIS workstation baseline, but there is no detailed
      protection standard.
  - {control: 2-3-4, status: Partially implemented, note: "This gap assessment is the first review of workstation protection; there is no regular schedule yet."}

  # 2-4 Email Protection
  - {control: 2-4-1, status: Not implemented, note: "No documented email security requirements."}
  - {control: 2-4-2, status: Partially implemented, note: "Microsoft 365 default spam and malware filtering is on, but nothing is set to a documented standard."}
  - control: 2-4-3
    status: Partially implemented
    note: >-
      Filtering and MFA are in place; there is no archiving, no protection beyond the defaults
      against advanced threats, and only SPF is set (no DKIM or DMARC).
  - {control: 2-4-4, status: Not implemented, note: "No email security requirements to review."}

  # 2-5 Networks Security Management (2-5-3 from CIS checks)
  - {control: 2-5-1, status: Not implemented, note: "No documented network security requirements."}
  - {control: 2-5-2, status: Partially implemented, note: "The office router's firewall is on and guest Wi-Fi is separate; there is no IPS and no documented rule set."}
  - {control: 2-5-4, status: Not implemented, note: "No network security requirements to review."}

  # 2-6 Mobile Devices Security
  - {control: 2-6-1, status: Not implemented, note: "No mobile device or BYOD requirements; staff use personal phones for email and Teams."}
  - {control: 2-6-2, status: Not implemented, note: "No mobile device controls in place."}
  - {control: 2-6-3, status: Not implemented, note: "Company data on personal phones is not separated, encrypted or remotely wipeable."}
  - {control: 2-6-4, status: Not implemented, note: "No mobile device requirements to review."}

  # 2-7 Data and Information Protection (2-7-2 from CIS checks)
  - {control: 2-7-1, status: Not implemented, note: "No documented data protection requirements or classification scheme."}
  - {control: 2-7-3, status: Not implemented, note: "No data protection requirements to review."}

  # 2-8 Cryptography (2-8-3 from CIS checks)
  - {control: 2-8-1, status: Not implemented, note: "No documented cryptography requirements."}
  - {control: 2-8-2, status: Partially implemented, note: "Microsoft 365 encrypts data in transit and at rest; laptops are not encrypted."}
  - {control: 2-8-4, status: Not implemented, note: "No cryptography requirements to review."}

  # 2-9 Backup and Recovery Management
  - {control: 2-9-1, status: Not implemented, note: "No documented backup requirements."}
  - {control: 2-9-2, status: Partially implemented, note: "Files in OneDrive and SharePoint have Microsoft 365 retention; laptops are not backed up."}
  - {control: 2-9-3, status: Partially implemented, note: "Backups cover cloud files only, and recovery has never been tested."}
  - {control: 2-9-4, status: Not implemented, note: "No backup requirements to review."}

  # 2-10 Vulnerabilities Management (2-10-3 from open-vulnerability counts)
  - control: 2-10-1
    status: Implemented
    documents: [docs/policies/vulnerability-management-policy.md]
    note: Vulnerability management policy documented and approved.
  - control: 2-10-2
    status: Partially implemented
    documents: [docs/policies/vulnerability-management-policy.md]
    note: >-
      Wazuh vulnerability detection runs on workstations; fixes are not yet tracked against the
      policy's deadlines.
  - control: 2-10-4
    status: Partially implemented
    documents: [docs/policies/vulnerability-management-policy.md]
    note: Annual review cycle set; first review due October 2027.

  # 2-11 Penetration Testing
  - {control: 2-11-1, status: Not implemented, note: "No penetration testing requirements."}
  - {control: 2-11-2, status: Not implemented, note: "No penetration test has been done."}
  - {control: 2-11-3, status: Not implemented, note: "No penetration testing scope or schedule."}
  - {control: 2-11-4, status: Not implemented, note: "No penetration testing requirements to review."}

  # 2-12 Cybersecurity Event Logs and Monitoring Management (2-12-3 from CIS checks and retention)
  - control: 2-12-1
    status: Implemented
    documents: [docs/policies/logging-and-monitoring-policy.md]
    note: Logging and monitoring policy documented and approved.
  - control: 2-12-2
    status: Partially implemented
    documents: [docs/policies/logging-and-monitoring-policy.md]
    note: >-
      Wazuh collects workstation security events; not every system sends logs, and alerts are
      not reviewed on a schedule.
  - control: 2-12-4
    status: Partially implemented
    documents: [docs/policies/logging-and-monitoring-policy.md]
    note: Annual review cycle set; first review due October 2027.

  # 2-13 Cybersecurity Incident and Threat Management
  - {control: 2-13-1, status: Not implemented, note: "No documented incident and threat management requirements."}
  - {control: 2-13-2, status: Not implemented, note: "No incident response process in place."}
  - {control: 2-13-3, status: Not implemented, note: "Wazuh raises alerts, but there is no response plan, incident classification, NCA reporting or threat intelligence feed."}
  - {control: 2-13-4, status: Not implemented, note: "No incident management requirements to review."}

  # 2-14 Physical Security
  - {control: 2-14-1, status: Not implemented, note: "No documented physical security requirements."}
  - {control: 2-14-2, status: Partially implemented, note: "The shared office building has badge access and lobby CCTV run by the landlord; the office itself uses a key."}
  - {control: 2-14-3, status: Partially implemented, note: "Building access control and CCTV exist but are not under Rimal Byte's control; old devices and paper are not securely destroyed."}
  - {control: 2-14-4, status: Not implemented, note: "No physical security requirements to review."}

  # 3-1 Cybersecurity Resilience Aspects of Business Continuity Management
  - {control: 3-1-1, status: Not implemented, note: "No business continuity requirements."}
  - {control: 3-1-2, status: Not implemented, note: "No business continuity requirements to implement."}
  - {control: 3-1-3, status: Not implemented, note: "No continuity, cyber incident response or disaster recovery plans."}
  - {control: 3-1-4, status: Not implemented, note: "No business continuity requirements to review."}

  # 4-1 Third-Party Cybersecurity (4-1-3 not applicable)
  - {control: 4-1-1, status: Not implemented, note: "No documented cybersecurity requirements for third-party contracts."}
  - control: 4-1-2
    status: Partially implemented
    note: >-
      Client contracts include non-disclosure clauses; supplier contracts (internet provider, web
      hosting) use the suppliers' standard terms, without incident or data-removal clauses.
  - {control: 4-1-4, status: Not implemented, note: "No third-party requirements to review."}

  # 4-2 Cloud Computing and Hosting Cybersecurity
  - {control: 4-2-1, status: Not implemented, note: "No documented cloud security requirements."}
  - {control: 4-2-2, status: Partially implemented, note: "Microsoft 365 enforces MFA and has two named administrators; no other cloud requirements are applied."}
  - control: 4-2-3
    status: Partially implemented
    note: >-
      Microsoft's standard terms cover data protection, data return and tenant separation; where
      the data is stored has not been checked against its classification.
  - {control: 4-2-4, status: Not implemented, note: "No cloud security requirements to review."}
```

- [ ] **Step 3: Write the risk register**

Replace `data/risks.yaml` with:

```yaml
# Risk register for Rimal Byte (fictional). Scales and bands are defined in
# docs/policies/risk-management-method.md: likelihood and impact 1-5, score = likelihood x impact,
# 1-4 Low, 5-9 Medium, 10-16 High, 20-25 Critical. Every gap in the assessment is covered.
risks:
  - id: R-01
    controls: [1-1-1, 1-1-2, 1-1-3]
    statement: >-
      Without a cybersecurity strategy, security work is not prioritised or funded against
      business goals, so known gaps stay open.
    likelihood: 3
    impact: 3
    treatment: mitigate
    owner: General Manager
    due: 2027-03-31
  - id: R-02
    controls: [1-2-1, 1-2-2, 1-2-3]
    statement: >-
      The only cybersecurity role is part-time, so incidents and compliance work go unhandled
      when the Cybersecurity Lead is busy with engineering work.
    likelihood: 4
    impact: 3
    treatment: mitigate
    owner: General Manager
    due: 2027-01-31
  - id: R-03
    controls: [1-3-2, 1-3-3, 1-3-4]
    statement: >-
      The new policies are not yet fully rolled out or backed by technical standards, so staff
      and systems do not follow them consistently.
    likelihood: 3
    impact: 3
    treatment: mitigate
    owner: Cybersecurity Lead
    due: 2026-12-31
  - id: R-04
    controls: [1-4-2]
    statement: >-
      Roles and responsibilities are not yet reviewed, so they may drift out of date as staff
      change.
    likelihood: 2
    impact: 2
    treatment: accept
    owner: General Manager
    due: 2027-10-31
  - id: R-05
    controls: [1-5-2, 1-5-3, 1-5-4]
    statement: >-
      Risk management is not yet routine, so new risks from projects, changes and suppliers can
      be missed.
    likelihood: 3
    impact: 3
    treatment: mitigate
    owner: Cybersecurity Lead
    due: 2027-01-31
  - id: R-06
    controls: [1-6-1, 1-6-2, 1-6-3, 1-6-4]
    statement: >-
      Software delivered to clients is built without secure coding standards or security
      testing, which could lead to a client data breach and lost contracts.
    likelihood: 4
    impact: 4
    treatment: mitigate
    owner: Project Manager
    due: 2027-01-31
  - id: R-07
    controls: [1-8-1, 1-8-2, 1-8-3]
    statement: >-
      Without regular and independent reviews, control weaknesses go unnoticed and compliance
      claims in government tenders cannot be backed up.
    likelihood: 3
    impact: 3
    treatment: mitigate
    owner: General Manager
    due: 2027-06-30
  - id: R-08
    controls: [1-9-1, 1-9-2, 1-9-3, 1-9-4, 1-9-5, 1-9-6]
    statement: >-
      New staff are not vetted and leavers are offboarded informally, so an untrusted person
      could gain or keep access to client data.
    likelihood: 3
    impact: 4
    treatment: mitigate
    owner: HR Officer
    due: 2026-12-31
  - id: R-09
    controls: [1-10-1, 1-10-2, 1-10-3, 1-10-4, 1-10-5]
    statement: >-
      Staff have no security awareness training, so a phishing email is likely to lead to a
      compromised Microsoft 365 account.
    likelihood: 4
    impact: 4
    treatment: mitigate
    owner: Cybersecurity Lead
    due: 2026-12-15
  - id: R-10
    controls: [2-1-1, 2-1-2, 2-1-3, 2-1-4, 2-1-5, 2-1-6]
    statement: >-
      The asset list is incomplete and information is not classified, so unknown devices go
      unpatched and sensitive data is handled like any other data.
    likelihood: 3
    impact: 3
    treatment: mitigate
    owner: IT Manager
    due: 2026-12-31
  - id: R-11
    controls: [2-2-2, 2-2-3, 2-2-4]
    statement: >-
      Weak workstation sign-in settings and no access reviews make account takeover easier and
      let excess privileges build up.
    likelihood: 3
    impact: 4
    treatment: mitigate
    owner: IT Manager
    due: 2026-11-30
  - id: R-12
    controls: [2-3-1, 2-3-2, 2-3-3, 2-3-4]
    statement: >-
      Workstations fall well short of the CIS baseline, so malware and misuse are more likely to
      succeed.
    likelihood: 4
    impact: 4
    treatment: mitigate
    owner: IT Manager
    due: 2026-11-30
  - id: R-13
    controls: [2-4-1, 2-4-2, 2-4-3, 2-4-4]
    statement: >-
      Without DKIM, DMARC or protection beyond the defaults, attackers can spoof the company's
      email domain and phishing is more likely to reach staff.
    likelihood: 4
    impact: 3
    treatment: mitigate
    owner: IT Manager
    due: 2026-11-05
  - id: R-14
    controls: [2-5-1, 2-5-2, 2-5-3, 2-5-4]
    statement: >-
      A flat office network behind a consumer-grade firewall, with unneeded services running on
      workstations, lets an attacker move from one device to others.
    likelihood: 3
    impact: 3
    treatment: mitigate
    owner: IT Manager
    due: 2027-01-31
  - id: R-15
    controls: [2-6-1, 2-6-2, 2-6-3, 2-6-4]
    statement: >-
      Company email and files on unmanaged personal phones are exposed when a phone is lost and
      stay with staff after they leave.
    likelihood: 3
    impact: 3
    treatment: mitigate
    owner: IT Manager
    due: 2027-02-28
  - id: R-16
    controls: [2-7-1, 2-7-2, 2-7-3]
    statement: >-
      Without data protection rules, client data can leak through unmanaged cloud storage and
      diagnostic data sent to vendors.
    likelihood: 3
    impact: 3
    treatment: mitigate
    owner: Cybersecurity Lead
    due: 2027-02-28
  - id: R-17
    controls: [2-8-1, 2-8-2, 2-8-3, 2-8-4]
    statement: >-
      Laptops are not encrypted (Windows 11 Home has no full BitLocker), so a lost or stolen
      laptop exposes client data.
    likelihood: 3
    impact: 4
    treatment: mitigate
    owner: IT Manager
    due: 2026-12-31
  - id: R-18
    controls: [2-9-1, 2-9-2, 2-9-3, 2-9-4]
    statement: >-
      Laptops are not backed up and recovery has never been tested, so ransomware or a disk
      failure can destroy work.
    likelihood: 3
    impact: 4
    treatment: mitigate
    owner: IT Manager
    due: 2026-12-31
  - id: R-19
    controls: [2-10-2, 2-10-3, 2-10-4]
    statement: >-
      High-severity vulnerabilities stay open without tracked deadlines, leaving known ways in
      for attackers.
    likelihood: 3
    impact: 4
    treatment: mitigate
    owner: IT Manager
    due: 2026-11-05
  - id: R-20
    controls: [2-11-1, 2-11-2, 2-11-3, 2-11-4]
    statement: >-
      Without penetration testing, exploitable weaknesses are more likely to be found by
      attackers first.
    likelihood: 2
    impact: 3
    treatment: mitigate
    owner: Cybersecurity Lead
    due: 2027-06-30
  - id: R-21
    controls: [2-12-2, 2-12-3, 2-12-4]
    statement: >-
      Missing audit settings and only about 10 days of stored logs (ECC asks for 12 months) mean
      an incident could not be investigated.
    likelihood: 3
    impact: 3
    treatment: mitigate
    owner: Cybersecurity Lead
    due: 2026-12-31
  - id: R-22
    controls: [2-13-1, 2-13-2, 2-13-3, 2-13-4]
    statement: >-
      Without an incident response plan, an attack would be handled slowly and inconsistently,
      and required reporting to the NCA could be missed.
    likelihood: 3
    impact: 4
    treatment: mitigate
    owner: Cybersecurity Lead
    due: 2026-12-31
  - id: R-23
    controls: [2-14-1, 2-14-2, 2-14-3, 2-14-4]
    statement: >-
      Devices could be stolen from the shared office, and old devices and paper are not securely
      destroyed.
    likelihood: 2
    impact: 3
    treatment: mitigate
    owner: IT Manager
    due: 2027-03-31
  - id: R-24
    controls: [3-1-1, 3-1-2, 3-1-3, 3-1-4]
    statement: >-
      With no continuity or disaster recovery plan, a ransomware attack could stop client
      services for days.
    likelihood: 2
    impact: 5
    treatment: mitigate
    owner: General Manager
    due: 2027-03-31
  - id: R-25
    controls: [4-1-1, 4-1-2, 4-1-4]
    statement: >-
      Supplier contracts have no security or incident clauses, so a supplier breach could expose
      company data with no agreed response.
    likelihood: 2
    impact: 3
    treatment: mitigate
    owner: General Manager
    due: 2027-03-31
  - id: R-26
    controls: [4-2-1, 4-2-2, 4-2-3, 4-2-4]
    statement: >-
      Microsoft 365 settings and data location are not governed by documented requirements, so
      a misconfiguration could expose client data.
    likelihood: 2
    impact: 4
    treatment: mitigate
    owner: IT Manager
    due: 2027-01-31
```

- [ ] **Step 4: Verify**

Run: `.venv/Scripts/python -m pytest -q -W error`
Expected: all pass, including the 2 real-data tests.

Run: `.venv/Scripts/python -m ecc check`
Expected: `OK: 108 controls, 482 checks, 1 snapshot(s).`

- [ ] **Step 5: Lint and commit**

```bash
.venv/Scripts/python -m ruff check .
git add data/evidence.yaml data/risks.yaml tests/test_real_data.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Rate every control and add the risk register"
```

---

### Task 6: Build the report and review it with Ahmed (checkpoint)

- [ ] **Step 1: Build**

Run: `.venv/Scripts/python -m ecc build`
Expected: `Built build/ecc-gap-assessment.xlsx, build/index.html, build/ecc-gap-assessment.pdf: 26.0% compliant (baseline).` (`build/` is git-ignored.)

- [ ] **Step 2: Review**

The controller opens `build/index.html` in the browser pane and checks it at desktop and phone widths: the company name and executive summary at the top, no "No rating" anywhere, 26 risks in the register, the roadmap starting with "30 days" (R-13 and R-19). Then Ahmed reads the PDF and opens the workbook. Any wording change he asks for goes into `data/report.yaml` or the relevant data file, followed by `check`, the full test suite and a rebuild, and is committed with the message "Edit the report after review".

- [ ] **Step 3:** Ahmed approves the report. Plan 2 is complete.

## After this plan

- Plan 3: Windows fixes (`remediation/`), the "after" snapshot and before/after report, README with results, LICENSE and attribution (Wazuh SCA policy is GPLv2; ECC text is NCA's), GitHub Pages workflow, publishing the public repository, and the CV line.
- Open judgment calls to raise with Ahmed in plan 3: routing of WDigest, Credential Guard and Print Spooler checks (2-3-2 versus 2-2-3 or 2-5-3), and noting in the report that the CIS catch-all rule sends about a quarter of the checks to 2-3-2.
