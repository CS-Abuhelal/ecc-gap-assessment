# ECC Gap Assessment, Plan 2b: SAMA Cyber Security Framework View

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an indicative SAMA Cyber Security Framework view to the assessment: map SAMA's 32 subdomains to the ECC controls, reuse the ECC ratings, derive an indicative maturity level per subdomain, and show it in the workbook and the report.

**Architecture:** Two new data files (`data/sama_csf.yaml`: SAMA's domains, subdomains and maturity levels; `data/sama_mapping.yaml`: SAMA subdomain → ECC controls with a reason, plus not-applicable subdomains), loaded into `Dataset` and validated. A small module `ecc/sama.py` turns an ECC `Assessment` into a SAMA view: score = the ECC compliance of the linked controls (or an explicit override), indicative level = 3 when all are Implemented, 2 at 50% or more, 1 above 0%, 0 otherwise. Levels 4 and 5 are not derived. The view is labelled indicative everywhere, because Rimal Byte (fictional) is not regulated by SAMA.

**Tech Stack:** As before (Python 3.11+, pydantic, PyYAML, openpyxl, Jinja2, pytest, ruff 0.16.4).

**Sources:** SAMA Cyber Security Framework as published in the SAMA Rulebook (https://rulebook.sama.gov.sa/en/node/3868): 4 domains, 32 subdomains; maturity model levels 0-5 (Non-existent, Ad-hoc, Repeatable but informal, Structured and formalized, Managed and measurable, Adaptive); SAMA expects at least Level 3. Subdomain 3.2.3 is excluded for non-bank member organisations; 3.2.4 Cyber Security Review includes annual penetration tests of internet-facing services. **Spec:** `docs/superpowers/specs/2026-10-08-ecc-gap-assessment-design.md` section 14 (added with this plan).

Every code block and data file below was applied to a copy of the repository and verified before this plan was written: 228 tests pass, ruff is clean, `check` passes and `build` reports 26.0%. The real SAMA view gives 0 of 28 applicable subdomains at Level 3 (8 at Level 2, 10 at Level 1, 10 at Level 0).

## Global Constraints

- Work in the repository root `ecc-gap-assessment/`; run everything through `.venv/Scripts/python`.
- Lint with `ruff==0.16.4`, rules `E, F, I, UP, B`, line length 100; `ruff check .` must print `All checks passed!` before every commit.
- Privacy: never write the Windows user name, the computer name, any `C:\Users\...` path or the Wazuh agent's real name into a committed file.
- The SAMA view is always called indicative, and the report states that Rimal Byte (fictional) is not regulated by SAMA.
- Copy code and data exactly as given; they were verified against the real baseline.
- Commit with `git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "..."`. Do not push, add a remote or create a GitHub repository.

---

### Task 1: SAMA models, data files, loading and validation

**Files:** Modify `ecc/models.py`, `ecc/load.py`, `ecc/validate.py`, `tests/fixtures.py`, `tests/test_validate.py`; create `data/sama_csf.yaml`, `data/sama_mapping.yaml`.

**Interfaces produced:** `SamaId`, `SamaSubdomain(id, title)`, `SamaDomain(id, title, subdomains)`, `SamaLevel(level, name, meaning)`, `SamaFramework(framework, source, domains, levels)`, `SamaLink(subdomain, ecc, why, rating=None, rating_note=None)` (rating and rating_note go together; rating may not be Not applicable), `SamaExclusion(subdomain, reason)`, `SamaMapping(links, not_applicable)`; `Dataset.sama`, `Dataset.sama_mapping`; validation of SAMA links. Test fixtures `SAMA_CSF`, `SAMA_MAPPING`.

- [ ] **Step 1: Write the failing tests and fixtures**

In `tests/fixtures.py`, replace:

```python
DATA_FILES = {
```

with:

```python
SAMA_CSF = {
    "framework": "SAMA Cyber Security Framework",
    "source": "https://example.test/sama",
    "domains": [
        {
            "id": "3.1",
            "title": "Cyber Security Leadership and Governance",
            "subdomains": [
                {"id": "3.1.3", "title": "Cyber Security Policy"},
                {"id": "3.1.4", "title": "Cyber Security Roles and Responsibilities"},
            ],
        },
        {
            "id": "3.3",
            "title": "Cyber Security Operations and Technology",
            "subdomains": [
                {"id": "3.3.5", "title": "Identity and Access Management"},
                {"id": "3.3.12", "title": "Payment Systems"},
                {"id": "3.3.14", "title": "Cyber Security Event Management"},
            ],
        },
        {
            "id": "3.4",
            "title": "Third Party Cyber Security",
            "subdomains": [{"id": "3.4.3", "title": "Cloud Computing"}],
        },
    ],
    "levels": [
        {"level": n, "name": name, "meaning": f"Level {n}."}
        for n, name in enumerate(
            [
                "Non-existent",
                "Ad-hoc",
                "Repeatable but informal",
                "Structured and formalized",
                "Managed and measurable",
                "Adaptive",
            ]
        )
    ],
}

SAMA_MAPPING = {
    "links": [
        {"subdomain": "3.1.3", "ecc": ["1-3-1"], "why": "Policies."},
        {
            "subdomain": "3.1.4",
            "ecc": ["1-3-1"],
            "why": "Roles are part of the policy.",
            "rating": "Not implemented",
            "rating_note": "Roles are not written down.",
        },
        {"subdomain": "3.3.5", "ecc": ["2-2-1", "2-2-3"], "why": "Access management."},
        {"subdomain": "3.3.14", "ecc": ["2-12-3"], "why": "Event logs."},
        {"subdomain": "3.4.3", "ecc": ["4-2-1"], "why": "Cloud."},
    ],
    "not_applicable": [{"subdomain": "3.3.12", "reason": "Example Co runs no payment systems."}],
}

DATA_FILES = {
```

In `tests/fixtures.py`, replace:

```python
    "report.yaml": REPORT,
}
```

with:

```python
    "report.yaml": REPORT,
    "sama_csf.yaml": SAMA_CSF,
    "sama_mapping.yaml": SAMA_MAPPING,
}
```

In `tests/test_validate.py`, replace:

```python
    RISKS,
```

with:

```python
    RISKS,
    SAMA_MAPPING,
```

Append to `tests/test_validate.py`:

```python
def test_every_sama_subdomain_needs_a_link_or_a_reason(root):
    mapping = copy.deepcopy(SAMA_MAPPING)
    mapping["links"] = mapping["links"][1:]
    mapping["links"].append({"subdomain": "3.4.9", "ecc": ["1-3-9"], "why": "Unknown."})
    rewrite(root, "sama_mapping.yaml", mapping)
    found = problems(root)
    assert "sama_mapping.yaml: SAMA subdomains with no link or reason (1): 3.1.3" in found
    assert "sama_mapping.yaml: unknown SAMA subdomains (1): 3.4.9" in found
    assert "sama_mapping.yaml: unknown ECC controls (1): 1-3-9" in found


def test_a_sama_subdomain_cannot_be_linked_twice(root):
    mapping = copy.deepcopy(SAMA_MAPPING)
    mapping["not_applicable"].append({"subdomain": "3.1.3", "reason": "Twice."})
    rewrite(root, "sama_mapping.yaml", mapping)
    assert "sama_mapping.yaml: subdomains linked twice (1): 3.1.3" in problems(root)
```


Run: `.venv/Scripts/python -m pytest -q`
Expected: failures, because the code does not know about the SAMA files yet.

- [ ] **Step 2: Implement**

In `ecc/models.py`, replace:

```python
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator
```

with:

```python
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator
```

In `ecc/models.py`, replace:

```python
    key_findings: tuple[Paragraph, ...] = ()
    limitations: tuple[Paragraph, ...] = ()
```

with:

```python
    key_findings: tuple[Paragraph, ...] = ()
    limitations: tuple[Paragraph, ...] = ()


SamaId = Annotated[str, Field(pattern=r"^3\.[1-4]\.\d{1,2}$")]


class SamaSubdomain(Strict):
    id: SamaId
    title: Paragraph


class SamaDomain(Strict):
    id: str = Field(pattern=r"^3\.[1-4]$")
    title: Paragraph
    subdomains: tuple[SamaSubdomain, ...] = Field(min_length=1)


class SamaLevel(Strict):
    level: int = Field(ge=0, le=5)
    name: Paragraph
    meaning: Paragraph


class SamaFramework(Strict):
    """SAMA Cyber Security Framework structure: domains, subdomains and maturity levels."""

    framework: Paragraph
    source: Paragraph
    domains: tuple[SamaDomain, ...] = Field(min_length=1)
    levels: tuple[SamaLevel, ...] = Field(min_length=6, max_length=6)


class SamaLink(Strict):
    """A SAMA subdomain and the ECC controls whose ratings stand in for it.

    `rating` overrides the derived score when the linked ECC control only partly matches the
    subdomain; it must come with `rating_note` saying why.
    """

    subdomain: SamaId
    ecc: tuple[ControlId, ...] = Field(min_length=1)
    why: Paragraph
    rating: Status | None = None
    rating_note: Paragraph | None = None

    @model_validator(mode="after")
    def _override_is_explained(self) -> SamaLink:
        if self.rating is Status.NOT_APPLICABLE:
            raise ValueError("list subdomains that do not apply under not_applicable")
        if (self.rating is None) != (self.rating_note is None):
            raise ValueError("rating and rating_note must be given together")
        return self


class SamaExclusion(Strict):
    subdomain: SamaId
    reason: Paragraph


class SamaMapping(Strict):
    links: tuple[SamaLink, ...]
    not_applicable: tuple[SamaExclusion, ...] = ()
```

In `ecc/load.py`, replace:

```python
    ReportText,
    RiskRegister,
    Snapshot,
)
```

with:

```python
    ReportText,
    RiskRegister,
    SamaFramework,
    SamaMapping,
    Snapshot,
)
```

In `ecc/load.py`, replace:

```python
    report: ReportText
```

with:

```python
    report: ReportText
    sama: SamaFramework
    sama_mapping: SamaMapping
```

In `ecc/load.py`, replace:

```python
    """Read all seven data files; if any are broken, report every one of them together."""
```

with:

```python
    """Read all nine data files; if any are broken, report every one of them together."""
```

In `ecc/load.py`, replace:

```python
        "report": lambda: load_model(ReportText, data / "report.yaml"),
```

with:

```python
        "report": lambda: load_model(ReportText, data / "report.yaml"),
        "sama": lambda: load_model(SamaFramework, data / "sama_csf.yaml"),
        "sama_mapping": lambda: load_model(SamaMapping, data / "sama_mapping.yaml"),
```

In `ecc/validate.py`, replace:

```python
    report("snapshots: labels used twice", duplicates(s.label for s in snapshots))
```

with:

```python
    sama_ids = [s.id for d in dataset.sama.domains for s in d.subdomains]
    linked = [link.subdomain for link in dataset.sama_mapping.links]
    excluded = [item.subdomain for item in dataset.sama_mapping.not_applicable]
    report("sama_csf.yaml: subdomain ids used twice", duplicates(sama_ids))
    unknown_sama = sorted(set(linked + excluded) - set(sama_ids))
    report("sama_mapping.yaml: unknown SAMA subdomains", unknown_sama)
    report("sama_mapping.yaml: subdomains linked twice", duplicates(linked + excluded))
    report(
        "sama_mapping.yaml: SAMA subdomains with no link or reason",
        [s for s in sama_ids if s not in set(linked) | set(excluded)],
    )
    sama_targets = {c for link in dataset.sama_mapping.links for c in link.ecc}
    report("sama_mapping.yaml: unknown ECC controls", sorted(sama_targets - known))

    report("snapshots: labels used twice", duplicates(s.label for s in snapshots))
```


- [ ] **Step 3: Add the real SAMA data**

Create `data/sama_csf.yaml`:

```yaml
# SAMA Cyber Security Framework (Saudi Central Bank), structure only: domains, subdomains and the
# maturity model. Titles as published in the SAMA Rulebook (rulebook.sama.gov.sa).
framework: SAMA Cyber Security Framework
source: https://rulebook.sama.gov.sa/en/node/3868
domains:
  - id: "3.1"
    title: Cyber Security Leadership and Governance
    subdomains:
      - {id: "3.1.1", title: Cyber Security Governance}
      - {id: "3.1.2", title: Cyber Security Strategy}
      - {id: "3.1.3", title: Cyber Security Policy}
      - {id: "3.1.4", title: Cyber Security Roles and Responsibilities}
      - {id: "3.1.5", title: Cyber Security in Project Management}
      - {id: "3.1.6", title: Cyber Security Awareness}
      - {id: "3.1.7", title: Cyber Security Training}
  - id: "3.2"
    title: Cyber Security Risk Management and Compliance
    subdomains:
      - {id: "3.2.1", title: Cyber Security Risk Management}
      - {id: "3.2.2", title: Regulatory Compliance}
      - {id: "3.2.3", title: Compliance with (Inter)national Industry Standards}
      - {id: "3.2.4", title: Cyber Security Review}
      - {id: "3.2.5", title: Cyber Security Audits}
  - id: "3.3"
    title: Cyber Security Operations and Technology
    subdomains:
      - {id: "3.3.1", title: Human Resources}
      - {id: "3.3.2", title: Physical Security}
      - {id: "3.3.3", title: Asset Management}
      - {id: "3.3.4", title: Cyber Security Architecture}
      - {id: "3.3.5", title: Identity and Access Management}
      - {id: "3.3.6", title: Application Security}
      - {id: "3.3.7", title: Change Management}
      - {id: "3.3.8", title: Infrastructure Security}
      - {id: "3.3.9", title: Cryptography}
      - {id: "3.3.10", title: Bring Your Own Device (BYOD)}
      - {id: "3.3.11", title: Secure Disposal of Information Assets}
      - {id: "3.3.12", title: Payment Systems}
      - {id: "3.3.13", title: Electronic Banking Services}
      - {id: "3.3.14", title: Cyber Security Event Management}
      - {id: "3.3.15", title: Cyber Security Incident Management}
      - {id: "3.3.16", title: Threat Management}
      - {id: "3.3.17", title: Vulnerability Management}
  - id: "3.4"
    title: Third Party Cyber Security
    subdomains:
      - {id: "3.4.1", title: Contract and Vendor Management}
      - {id: "3.4.2", title: Outsourcing}
      - {id: "3.4.3", title: Cloud Computing}
levels:
  - {level: 0, name: Non-existent, meaning: "Controls are not in place and there is no documentation or awareness of them."}
  - {level: 1, name: Ad-hoc, meaning: "Controls are partly defined and performed inconsistently."}
  - {level: 2, name: Repeatable but informal, meaning: "Controls follow an unwritten but standard practice, without formally approved objectives."}
  - {level: 3, name: Structured and formalized, meaning: "Controls are defined, approved and implemented in a structured way. SAMA expects at least this level."}
  - {level: 4, name: Managed and measurable, meaning: "Control effectiveness is measured and evaluated periodically."}
  - {level: 5, name: Adaptive, meaning: "Controls are continuously improved and benchmarked against peers."}
```

Create `data/sama_mapping.yaml`:

```yaml
# Crosswalk from SAMA Cyber Security Framework subdomains to NCA ECC-2:2024 main controls. Each
# SAMA subdomain is either linked to the ECC controls that cover the same requirements or marked
# not applicable to Rimal Byte (fictional). The SAMA view reuses the ECC ratings; it is indicative,
# because Rimal Byte is not regulated by SAMA. ECC 3-1 (business continuity) has no SAMA CSF
# counterpart: SAMA covers continuity in a separate framework.
links:
  - subdomain: "3.1.1"
    ecc: [1-2-1, 1-2-2, 1-2-3]
    why: The cybersecurity function, its staffing and the supervisory committee (ECC 1-2) are the governance structure SAMA 3.1.1 requires.
  - subdomain: "3.1.2"
    ecc: [1-1-1, 1-1-2, 1-1-3]
    why: Both frameworks require a documented, approved and reviewed cybersecurity strategy (ECC 1-1).
  - subdomain: "3.1.3"
    ecc: [1-3-1, 1-3-2, 1-3-3, 1-3-4]
    why: Policies, their implementation, supporting standards and their review (ECC 1-3).
  - subdomain: "3.1.4"
    ecc: [1-4-1, 1-4-2]
    why: Documented and reviewed cybersecurity roles and responsibilities (ECC 1-4).
  - subdomain: "3.1.5"
    ecc: [1-6-1, 1-6-4]
    why: Cybersecurity requirements in project management and their review (ECC 1-6-1, 1-6-4).
  - subdomain: "3.1.6"
    ecc: [1-10-1, 1-10-2, 1-10-3, 1-10-5]
    why: An approved, implemented and reviewed awareness program (ECC 1-10, except specialised training).
  - subdomain: "3.1.7"
    ecc: [1-10-4]
    why: Specialised training for staff in cybersecurity-related roles (ECC 1-10-4).
  - subdomain: "3.2.1"
    ecc: [1-5-1, 1-5-2, 1-5-3, 1-5-4]
    why: A documented, applied and reviewed risk management methodology (ECC 1-5).
  - subdomain: "3.2.2"
    ecc: [1-3-4]
    why: >-
      SAMA asks for a process that updates policies when regulations change; ECC 1-3-4 requires
      policies to be reviewed when legislative and regulatory requirements change.
  - subdomain: "3.2.4"
    ecc: [1-8-1, 1-8-3, 2-11-1, 2-11-2, 2-11-3, 2-11-4]
    why: >-
      Periodic reviews with documented results reported to management (ECC 1-8-1, 1-8-3), and
      the annual penetration tests SAMA 3.2.4 includes (ECC 2-11).
  - subdomain: "3.2.5"
    ecc: [1-8-2]
    why: Audits by parties independent of the cybersecurity function (ECC 1-8-2).
  - subdomain: "3.3.1"
    ecc: [1-9-1, 1-9-2, 1-9-3, 1-9-4, 1-9-5, 1-9-6]
    why: Security requirements before, during and after employment (ECC 1-9).
  - subdomain: "3.3.2"
    ecc: [2-14-1, 2-14-2, 2-14-3, 2-14-4]
    why: Physical protection of information and technology assets (ECC 2-14).
  - subdomain: "3.3.3"
    ecc: [2-1-1, 2-1-2, 2-1-3, 2-1-4, 2-1-5, 2-1-6]
    why: Asset inventory, acceptable use and classification (ECC 2-1).
  - subdomain: "3.3.4"
    ecc: [2-3-1, 2-5-1]
    why: >-
      ECC has no architecture control; its documented protection and network security
      requirements (ECC 2-3-1, 2-5-1) are the closest match.
  - subdomain: "3.3.5"
    ecc: [2-2-1, 2-2-2, 2-2-3, 2-2-4]
    why: Identity and access management requirements, their minimums and review (ECC 2-2).
  - subdomain: "3.3.6"
    ecc: [1-6-3]
    why: Secure coding and security testing of software (ECC 1-6-3); ECC 2-15 does not apply to Rimal Byte.
  - subdomain: "3.3.7"
    ecc: [1-6-1, 1-6-2]
    why: Cybersecurity requirements in change management, including hardening and vulnerability checks before go-live (ECC 1-6-1, 1-6-2).
  - subdomain: "3.3.8"
    ecc: [2-3-1, 2-3-2, 2-3-3, 2-3-4, 2-4-1, 2-4-2, 2-4-3, 2-4-4, 2-5-1, 2-5-2, 2-5-3, 2-5-4, 2-7-1, 2-7-2, 2-7-3, 2-9-1, 2-9-2, 2-9-3, 2-9-4]
    why: >-
      SAMA's infrastructure standards span hardening and malware protection, email gateways,
      network segmentation, data protection and backup (ECC 2-3, 2-4, 2-5, 2-7, 2-9).
  - subdomain: "3.3.9"
    ecc: [2-8-1, 2-8-2, 2-8-3, 2-8-4]
    why: Cryptography requirements and their review (ECC 2-8).
  - subdomain: "3.3.10"
    ecc: [2-6-1, 2-6-2, 2-6-3, 2-6-4]
    why: Mobile device and BYOD security (ECC 2-6).
  - subdomain: "3.3.11"
    ecc: [2-14-3]
    why: Secure destruction and re-use of assets holding classified information (ECC 2.14.3.4).
    rating: Not implemented
    rating_note: >-
      ECC 2-14-3 is Partially implemented only for its access-control parts; old devices and
      paper are not securely destroyed, so this subdomain is rated on its own.
  - subdomain: "3.3.14"
    ecc: [2-12-1, 2-12-2, 2-12-3, 2-12-4]
    why: Event logging, collection, monitoring and retention (ECC 2-12).
  - subdomain: "3.3.15"
    ecc: [2-13-1, 2-13-2, 2-13-3, 2-13-4]
    why: Incident response plans, classification and reporting (ECC 2-13).
  - subdomain: "3.3.16"
    ecc: [2-13-3]
    why: Collecting and handling threat intelligence feeds (ECC 2.13.3.5).
  - subdomain: "3.3.17"
    ecc: [2-10-1, 2-10-2, 2-10-3, 2-10-4]
    why: Vulnerability scanning, classification, remediation deadlines and patching (ECC 2-10).
  - subdomain: "3.4.1"
    ecc: [4-1-1, 4-1-2, 4-1-4]
    why: Cybersecurity requirements in contracts with third parties (ECC 4-1).
  - subdomain: "3.4.3"
    ecc: [4-2-1, 4-2-2, 4-2-3, 4-2-4]
    why: Cloud computing and hosting requirements (ECC 4-2).
not_applicable:
  - subdomain: "3.2.3"
    reason: SAMA excludes this subdomain for member organisations that are not banks, and Rimal Byte is not a bank.
  - subdomain: "3.3.12"
    reason: Rimal Byte runs no payment systems.
  - subdomain: "3.3.13"
    reason: Rimal Byte offers no electronic banking services.
  - subdomain: "3.4.2"
    reason: Rimal Byte outsources no IT or cybersecurity services (ECC 4-1-3 does not apply).
```

- [ ] **Step 4: Verify and commit**

Run: `.venv/Scripts/python -m pytest -q -W error` (all pass), `.venv/Scripts/python -m ecc check` (`OK: 108 controls, 482 checks, 1 snapshot(s).`), `.venv/Scripts/python -m ruff check .`.

```bash
git add ecc/models.py ecc/load.py ecc/validate.py tests/fixtures.py tests/test_validate.py data/sama_csf.yaml data/sama_mapping.yaml
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Add the SAMA Cyber Security Framework and its crosswalk to ECC"
```

---

### Task 2: The SAMA view

**Files:** Create `ecc/sama.py`, `tests/test_sama.py`; modify `tests/test_real_data.py`.

**Interfaces produced:** `SamaResult(domain, subdomain, ecc, score, level, note)`; `maturity(score) -> int | None`; `sama_view(dataset, assessment) -> tuple[SamaResult, ...]` (one result per SAMA subdomain, in framework order; not-applicable subdomains have `level=None` and their reason as `note`; a subdomain whose linked ECC controls are all Not applicable also gets `level=None`); `level_counts(view) -> dict[int, int]` (levels 0-3).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_sama.py`:

```python
import pytest
from pydantic import ValidationError

from ecc.assess import assess
from ecc.models import SamaLink
from ecc.sama import level_counts, maturity, sama_view


@pytest.mark.parametrize(
    ("score", "level"),
    [(None, None), (0.0, 0), (0.1, 1), (49.9, 1), (50.0, 2), (99.9, 2), (100.0, 3)],
)
def test_maturity_levels(score, level):
    assert maturity(score) == level


def view_of(dataset, snapshot):
    return {item.subdomain.id: item for item in sama_view(dataset, assess(dataset, snapshot))}


def test_the_baseline_view(dataset, baseline):
    view = view_of(dataset, baseline)
    assert list(view) == ["3.1.3", "3.1.4", "3.3.5", "3.3.12", "3.3.14", "3.4.3"]
    assert (view["3.1.3"].score, view["3.1.3"].level) == (50.0, 2)
    assert (view["3.3.5"].score, view["3.3.5"].level) == (75.0, 2)
    assert (view["3.3.14"].score, view["3.3.14"].level) == (0.0, 0)


def test_after_fixes_a_subdomain_reaches_level_3(dataset, after):
    view = view_of(dataset, after)
    assert (view["3.3.5"].score, view["3.3.5"].level) == (100.0, 3)
    assert view["3.3.14"].level == 2


def test_an_override_replaces_the_derived_score(dataset, baseline):
    item = view_of(dataset, baseline)["3.1.4"]
    assert (item.score, item.level) == (0.0, 0)
    assert item.note == "Roles are not written down."


def test_not_applicable_subdomains_have_no_level(dataset, baseline):
    view = view_of(dataset, baseline)
    assert view["3.3.12"].level is None
    assert view["3.3.12"].note == "Example Co runs no payment systems."
    assert view["3.4.3"].level is None  # its only ECC control is Not applicable


def test_level_counts(dataset, baseline):
    view = sama_view(dataset, assess(dataset, baseline))
    assert level_counts(view) == {0: 2, 1: 0, 2: 2, 3: 0}


def test_an_override_needs_a_note():
    with pytest.raises(ValidationError):
        SamaLink(subdomain="3.1.4", ecc=["1-3-1"], why="Roles.", rating="Not implemented")
    with pytest.raises(ValidationError):
        SamaLink(
            subdomain="3.1.4",
            ecc=["1-3-1"],
            why="Roles.",
            rating="Not applicable",
            rating_note="Does not apply.",
        )
```


Append to `tests/test_real_data.py` (and add `from ecc.sama import level_counts, sama_view` to its imports, keeping them sorted):

```python
def test_the_sama_view():
    dataset, _, assessment = baseline_assessment()
    view = sama_view(dataset, assessment)
    assert len(view) == 32
    assert level_counts(view) == {0: 10, 1: 10, 2: 8, 3: 0}
```

Run: `.venv/Scripts/python -m pytest tests/test_sama.py tests/test_real_data.py -q`
Expected: collection error, `No module named 'ecc.sama'`.

- [ ] **Step 2: Implement**

Create `ecc/sama.py`:

```python
"""An indicative SAMA Cyber Security Framework view derived from the ECC ratings."""

from __future__ import annotations

from dataclasses import dataclass

from ecc.assess import POINTS, Assessment, compliance
from ecc.load import Dataset
from ecc.models import SamaDomain, SamaSubdomain


@dataclass(frozen=True)
class SamaResult:
    domain: SamaDomain
    subdomain: SamaSubdomain
    ecc: tuple[str, ...]
    score: float | None
    level: int | None
    note: str | None


def maturity(score: float | None) -> int | None:
    """Indicative SAMA maturity level from an ECC compliance score.

    Level 3 when every linked control is Implemented, 2 at 50% or more, 1 above 0%, otherwise 0.
    Levels 4 and 5 need measured control effectiveness, which the ECC ratings do not carry.
    """
    if score is None:
        return None
    if score >= 100.0:
        return 3
    if score >= 50.0:
        return 2
    if score > 0.0:
        return 1
    return 0


def sama_view(dataset: Dataset, assessment: Assessment) -> tuple[SamaResult, ...]:
    by_id = {result.control.id: result for result in assessment.results}
    links = {link.subdomain: link for link in dataset.sama_mapping.links}
    excluded = {item.subdomain: item.reason for item in dataset.sama_mapping.not_applicable}
    view: list[SamaResult] = []
    for domain in dataset.sama.domains:
        for subdomain in domain.subdomains:
            if subdomain.id in excluded:
                view.append(SamaResult(domain, subdomain, (), None, None, excluded[subdomain.id]))
                continue
            link = links.get(subdomain.id)
            if link is None:
                continue
            if link.rating is not None:
                score: float | None = 100 * POINTS[link.rating]
                note: str | None = link.rating_note
            else:
                score = compliance(by_id[c] for c in link.ecc if c in by_id)
                note = None
            view.append(SamaResult(domain, subdomain, link.ecc, score, maturity(score), note))
    return tuple(view)


def level_counts(view: tuple[SamaResult, ...]) -> dict[int, int]:
    """How many applicable subdomains sit at each indicative level, 0 to 3."""
    counts = dict.fromkeys(range(4), 0)
    for result in view:
        if result.level is not None:
            counts[result.level] += 1
    return counts
```


- [ ] **Step 3: Verify and commit**

Run: `.venv/Scripts/python -m pytest -q -W error` (all pass) and `.venv/Scripts/python -m ruff check .`.

```bash
git add ecc/sama.py tests/test_sama.py tests/test_real_data.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Derive an indicative SAMA maturity view from the ECC ratings"
```

---

### Task 3: SAMA view in the workbook and the report

**Files:** Modify `ecc/excel.py`, `ecc/html.py`, `ecc/templates/report.html.j2`, `tests/test_excel.py`, `tests/test_html.py`, `data/report.yaml`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_excel.py`:

```python
def test_the_sama_sheet(tmp_path, dataset, baseline):
    sheet = workbook(tmp_path, dataset, baseline)["SAMA CSF view"]
    rows = {row[0]: row for row in sheet.iter_rows(min_row=2, values_only=True)}
    assert rows["3.3.5"][4:6] == (75.0, "2 Repeatable but informal")
    assert rows["3.3.12"][4:7] == ("n/a", "n/a", "Example Co runs no payment systems.")
    assert rows["3.1.4"][6] == "Roles are not written down."
```

Append to `tests/test_html.py`:

```python
def test_the_report_shows_the_sama_view(dataset, after):
    html = render_html(dataset, assess(dataset, after))
    assert "SAMA Cyber Security Framework view (indicative)" in html
    assert "<b>1 of 4 applicable subdomains reach Level 3</b>" in html
    assert "<td>3 Structured and formalized</td>" in html
    assert "Example Co runs no payment systems." in html
```


Run: `.venv/Scripts/python -m pytest tests/test_excel.py tests/test_html.py -q`
Expected: the two new tests fail (no "SAMA CSF view" sheet, no SAMA section).

- [ ] **Step 2: Implement the workbook sheet**

In `ecc/excel.py`, replace:

```python
from ecc.risk import risk_rows, roadmap
```

with:

```python
from ecc.risk import risk_rows, roadmap
from ecc.sama import sama_view
```

In `ecc/excel.py`, replace:

```python
SHEETS = ("Summary", "Controls", "Technical evidence", "Risk register", "Roadmap")
```

with:

```python
SHEETS = (
    "Summary",
    "Controls",
    "Technical evidence",
    "Risk register",
    "Roadmap",
    "SAMA CSF view",
)
LEVEL_COLOURS = {0: "FFC7CE", 1: "FCE4D6", 2: "FFEB9C", 3: "C6EFCE"}
```

In `ecc/excel.py`, replace:

```python
def write_workbook(
```

with:

```python
def write_sama(sheet: Worksheet, dataset: Dataset, after: Assessment) -> None:
    names = {level.level: level.name for level in dataset.sama.levels}
    view = sama_view(dataset, after)
    rows = [
        [
            result.subdomain.id,
            result.subdomain.title,
            f"{result.domain.id} {result.domain.title}",
            ", ".join(result.ecc),
            score(result.score) if result.level is not None else "n/a",
            f"{result.level} {names[result.level]}" if result.level is not None else "n/a",
            result.note or "",
        ]
        for result in view
    ]
    header = ["SAMA subdomain", "Title", "SAMA domain", "ECC controls", "Compliance %",
              "Indicative maturity", "Note"]
    table(sheet, header, rows, [10, 34, 30, 30, 13, 26, 60], autofilter=True)
    for row_number, result in enumerate(view, start=2):
        if result.level is not None:
            sheet.cell(row=row_number, column=6).fill = fill(LEVEL_COLOURS[result.level])
            if isinstance(result.score, float):
                sheet.cell(row=row_number, column=5).number_format = "0.0"


def write_workbook(
```

In `ecc/excel.py`, replace:

```python
    write_risks(sheets[3], sheets[4], dataset, after)
```

with:

```python
    write_risks(sheets[3], sheets[4], dataset, after)
    write_sama(sheets[5], dataset, after)
```


- [ ] **Step 3: Implement the report section**

In `ecc/html.py`:
- add `from ecc.sama import level_counts, sama_view` directly after `from ecc.risk import BUCKET_ORDER, rating, risk_rows, roadmap`;
- in `report_context`, add `sama = sama_view(dataset, after)` directly before the line `rows = risk_rows(dataset.risks, after)`;
- add these three entries at the end of the returned dict, after `"report": dataset.report,`:

```python
        "sama": sama,
        "sama_counts": level_counts(sama),
        "sama_levels": {level.level: level.name for level in dataset.sama.levels},
```

In `ecc/templates/report.html.j2`, replace:

```jinja
<h2>Scope and applicability</h2>
```

with:

```jinja
<h2>SAMA Cyber Security Framework view (indicative)</h2>
<p class="note">SAMA's Cyber Security Framework applies to banks and other institutions regulated by the Saudi Central Bank; {{ report.company }} is not one. This view maps the ECC results onto SAMA's subdomains to show how the company would look to a bank client that expects SAMA alignment from its suppliers. Each subdomain's maturity comes from the ECC controls it maps to: Level 3 when all are Implemented, Level 2 at 50% or more, Level 1 above 0% and Level 0 otherwise. Levels 4 and 5 need measured control effectiveness and are not derived. SAMA expects at least Level 3.</p>
<p><b>{{ sama_counts[3] }} of {{ sama_counts.values()|sum }} applicable subdomains reach Level 3</b> ({{ sama_counts[2] }} at Level 2, {{ sama_counts[1] }} at Level 1, {{ sama_counts[0] }} at Level 0).</p>
<div class="table-wrap"><table>
<thead><tr><th>SAMA</th><th>Subdomain</th><th>ECC controls</th><th>Compliance</th><th>Indicative maturity</th></tr></thead>
<tbody>
{% for item in sama %}
<tr><td class="nowrap">{{ item.subdomain.id }}</td><td>{{ item.subdomain.title }}{% if item.note %}<br><span class="note">{{ item.note }}</span>{% endif %}</td><td>{{ item.ecc|join(", ") }}</td><td>{{ pct(item.score) if item.level is not none else "n/a" }}</td><td>{{ (item.level ~ " " ~ sama_levels[item.level]) if item.level is not none else "Not applicable" }}</td></tr>
{% endfor %}
</tbody></table></div>

<h2>Scope and applicability</h2>
```


- [ ] **Step 4: Add the SAMA finding and limitation to the narrative**

In `data/report.yaml`, append this item to the end of `key_findings`:

```yaml
  - >-
    Mapped onto SAMA's Cyber Security Framework, none of the 28 applicable subdomains reaches
    maturity Level 3, the minimum SAMA expects of the banks it regulates (indicative view).
```

and insert this item into `limitations` directly before the last item ("Results describe one point in time, ..."):

```yaml
  - >-
    The SAMA Cyber Security Framework view is indicative: Rimal Byte is not regulated by SAMA,
    and its maturity levels are derived from the ECC ratings by a stated rule rather than
    assessed separately.
```

- [ ] **Step 5: Verify, build and commit**

Run: `.venv/Scripts/python -m pytest -q -W error` (all pass), `.venv/Scripts/python -m ruff check .`, `.venv/Scripts/python -m ecc check`, `.venv/Scripts/python -m ecc build --no-pdf` (`26.0% compliant (baseline)`; the workbook has six sheets).

```bash
git add ecc/excel.py ecc/html.py ecc/templates/report.html.j2 tests/test_excel.py tests/test_html.py data/report.yaml
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Show the indicative SAMA view in the workbook and the report"
```
