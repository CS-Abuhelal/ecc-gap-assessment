# ECC Gap Assessment, Plan 1: Assessment Pipeline

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the tested Python pipeline that turns Wazuh CIS scan results into a control-by-control NCA ECC-2:2024 assessment (Excel workbook, web page, PDF), and capture the real baseline snapshot.

**Architecture:** Only `collect` talks to Wazuh; it saves an allowlisted JSON snapshot. Everything else (`assess`, `validate`, outputs) runs from committed snapshots plus hand-written YAML data files, so the report is reproducible without Wazuh. Statuses come from mapped CIS checks, two named facts and documentary evidence; a control gets the weaker of its technical and documentary ratings.

**Tech Stack:** Python 3.11+ (3.14 locally), pydantic 2, PyYAML, httpx, openpyxl, Jinja2, pytest, ruff 0.16.4. `pdftotext` (ships with Git for Windows) for the one-off catalog extraction; headless Chrome or Edge prints the PDF.

**Spec:** `docs/superpowers/specs/2026-10-08-ecc-gap-assessment-design.md`

**This is plan 1 of 3.** Plan 2 (company profile, applicability, evidence, policy pack, risks, GitHub Pages) and plan 3 (remediation scripts, after snapshot, README, publishing) are written after this plan's baseline snapshot exists, because their content depends on the real results.

## Global Constraints

- Work in the repository root `ecc-gap-assessment/` (a sibling of `SENTINEL/` and `wazuh-docker/`). Every path below is relative to it.
- `requires-python = ">=3.11"`. Run everything through the virtualenv: `.venv/Scripts/python` (Windows layout, Git Bash).
- Lint with `ruff==0.16.4`, rules `E, F, I, UP, B`, line length 100. Run `.venv/Scripts/python -m ruff check .` before every commit; it must print `All checks passed!`.
- Privacy: never write the Windows user name, the computer name, any `C:\Users\...` path or the Wazuh agent's real name into a committed file (code, tests, docs, this plan). Tests use made-up names only: `jdoe`, `Jane`, `Doe`, `DESKTOP-TEST1`, `lab-agent`.
- Snapshots hold only allowlisted fields, and `host` is always `WS-01`.
- Claude never changes system settings and never handles the Wazuh password. Ahmed runs `collect` himself (Task 16).
- Commit with `git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "..."` (this machine has no global git identity).
- Do not push, add a remote or create a GitHub repository in this plan.

## File Structure

| File | Responsibility |
|---|---|
| `pyproject.toml`, `requirements.txt`, `.gitignore` | Project config, dependencies, ignored paths |
| `ecc/models.py` | Pydantic models for every data file and the snapshot; `Status`, `weakest()` |
| `ecc/load.py` | Read YAML/JSON into models; `Dataset`; `DataError` |
| `ecc/mapping.py` | Longest-match CIS → ECC rules; unmapped/unused/duplicate rule checks |
| `ecc/facts.py` | Named facts: `vulnerabilities`, `log_retention` |
| `ecc/assess.py` | Per-control ratings, compliance %, domain scores, compare |
| `ecc/validate.py` | Cross-file checks that collect every problem |
| `ecc/risk.py` | Risk rating bands, roadmap buckets, risk rows |
| `ecc/privacy.py` | Forbidden terms, leak check, safe snapshot writing |
| `ecc/collect.py` | Wazuh indexer client and snapshot building |
| `ecc/excel.py` | The five-sheet workbook |
| `ecc/html.py`, `ecc/templates/report.html.j2` | Web page / PDF report rendering and printing |
| `ecc/cli.py`, `ecc/__main__.py` | `python -m ecc collect | check | build` |
| `tools/extract_catalog.py` | One-off: NCA PDF text → `data/catalog.yaml` |
| `tools/gen_cis_checks.py` | One-off: Wazuh SCA policy → `data/cis_checks.yaml` |
| `data/catalog.yaml` | 108 ECC main controls and 92 subcontrols |
| `data/cis_checks.yaml` | 482 CIS checks (id, CIS section, title) |
| `data/mapping.yaml` | CIS → ECC rules and fact links |
| `data/evidence.yaml`, `data/applicability.yaml`, `data/risks.yaml` | Empty stubs here; filled in plan 2 |
| `tests/fixtures.py`, `tests/conftest.py` | A tiny made-up repo used by the tests |
| `.github/workflows/ci.yml` | ruff + pytest on push and PR |

---

### Task 1: Project skeleton and data models

**Files:**
- Create: `pyproject.toml`, `requirements.txt`, `.gitignore`, `ecc/__init__.py`, `tests/__init__.py`, `ecc/models.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Produces: `Status` (StrEnum: `IMPLEMENTED="Implemented"`, `PARTIAL="Partially implemented"`, `NOT_IMPLEMENTED="Not implemented"`, `NOT_APPLICABLE="Not applicable"`), `RANKED`, `weakest(*statuses) -> Status`, `HOST_PLACEHOLDER = "WS-01"`, `LABEL_PATTERN`, type aliases `ControlId`, `FactName`, and models `Subcontrol`, `ControlEntry`, `SubdomainEntry`, `DomainEntry`, `CatalogFile`, `Control`, `CisCheck`, `CisPolicyInfo`, `CisPolicy`, `Rule`, `FactLink`, `Mapping`, `EvidenceEntry`, `Evidence`, `NotApplicable`, `Applicability`, `Risk` (with `.score`), `RiskRegister`, `CheckResult`, `SnapshotPolicy`, `VulnerabilityCounts`, `LoggingFacts`, `Snapshot` (field `format_version`, JSON key `schema`).

- [ ] **Step 1: Create the project files and virtualenv**

Create `pyproject.toml`:

```toml
[project]
name = "ecc-gap-assessment"
version = "0.1.0"
requires-python = ">=3.11"

[tool.ruff]
line-length = 100
target-version = "py311"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B"]

[tool.pytest.ini_options]
pythonpath = ["."]
testpaths = ["tests"]
```

Create `requirements.txt`:

```text
httpx>=0.28
jinja2>=3.1
openpyxl>=3.1
pydantic>=2.12
pyyaml>=6.0

pytest>=8.3

# Pinned exactly, as in SENTINEL: CI and a local checkout must agree on what "clean" means.
ruff==0.16.4
```

Create `.gitignore`:

```text
.venv/
__pycache__/
.pytest_cache/
.ruff_cache/
.cache/
build/
remediation/backups/
```

Create `ecc/__init__.py`:

```python
"""NCA ECC-2:2024 gap assessment built from Wazuh evidence."""
```

Create `tests/__init__.py`:

```python
```

Run:

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt
```

Expected: ends with `Successfully installed ...` (pydantic, httpx, openpyxl, jinja2, pyyaml, pytest, ruff).

- [ ] **Step 2: Write the failing tests**

Create `tests/test_models.py`:

```python
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from ecc.models import HOST_PLACEHOLDER, EvidenceEntry, Risk, Rule, Snapshot, Status, weakest

SNAPSHOT = {
    "schema": 1,
    "label": "baseline",
    "taken_at": "2026-10-12T18:00:00Z",
    "host": "WS-01",
    "policy": {"id": "cis_win11_enterprise", "checks_total": 1},
    "checks": [{"id": 26000, "result": "failed"}],
    "vulnerabilities": {"critical": 0, "high": 1, "medium": 2, "low": 3},
    "logging": {"oldest_alert": "2026-09-28T10:00:00Z", "agent_active": True},
}


def test_weakest_picks_the_lowest_rating():
    assert weakest(Status.IMPLEMENTED, Status.PARTIAL) is Status.PARTIAL
    assert weakest(Status.PARTIAL, Status.NOT_IMPLEMENTED) is Status.NOT_IMPLEMENTED
    assert weakest(Status.IMPLEMENTED) is Status.IMPLEMENTED


def test_weakest_refuses_not_applicable_and_empty_input():
    with pytest.raises(ValueError):
        weakest(Status.NOT_APPLICABLE)
    with pytest.raises(ValueError):
        weakest()


def test_evidence_cannot_claim_not_applicable():
    with pytest.raises(ValidationError):
        EvidenceEntry(control="1-3-1", status=Status.NOT_APPLICABLE, note="Not used.")


def test_snapshot_round_trip_keeps_the_schema_key():
    snapshot = Snapshot.model_validate(SNAPSHOT)
    assert snapshot.format_version == 1
    assert snapshot.taken_at == datetime(2026, 10, 12, 18, 0, tzinfo=UTC)
    dumped = snapshot.model_dump(by_alias=True, mode="json")
    assert dumped["schema"] == 1
    assert "format_version" not in dumped


def test_snapshot_rejects_extra_fields():
    with pytest.raises(ValidationError):
        Snapshot.model_validate({**SNAPSHOT, "raw_alert": {"full_log": "secret"}})


def test_snapshot_only_accepts_the_placeholder_host():
    assert HOST_PLACEHOLDER == "WS-01"
    with pytest.raises(ValidationError):
        Snapshot.model_validate({**SNAPSHOT, "host": "real-computer-name"})


def test_snapshot_needs_time_zones():
    with pytest.raises(ValidationError):
        Snapshot.model_validate({**SNAPSHOT, "taken_at": "2026-10-12T18:00:00"})


def test_risk_score_is_likelihood_times_impact():
    risk = Risk(
        id="R-01",
        controls=["2-2-3"],
        statement="Weak passwords allow account takeover.",
        likelihood=3,
        impact=4,
        treatment="mitigate",
        owner="IT Manager",
        due="2026-11-01",
    )
    assert risk.score == 12


def test_rule_needs_a_well_formed_target_control():
    with pytest.raises(ValidationError):
        Rule(cis="1.1", ecc=[], why="Password rules.")
    with pytest.raises(ValidationError):
        Rule(cis="1.1", ecc=["2.2.3"], why="Wrong id format.")
```

- [ ] **Step 3: Run the tests to make sure they fail**

Run: `.venv/Scripts/python -m pytest tests/test_models.py -v`
Expected: collection error, `ModuleNotFoundError: No module named 'ecc.models'`.

- [ ] **Step 4: Write the models**

Create `ecc/models.py`:

```python
"""Data models. Every model rejects unknown fields, so files cannot carry extra data."""

from __future__ import annotations

from datetime import date
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

CONTROL_PATTERN = r"^[1-4]-\d{1,2}-\d{1,2}$"
SUBDOMAIN_PATTERN = r"^[1-4]-\d{1,2}$"
SUBCONTROL_PATTERN = r"^[1-4]\.\d{1,2}\.\d{1,2}\.\d{1,2}$"
CIS_PATTERN = r"^\d+(\.\d+)*$"
LABEL_PATTERN = r"^[a-z0-9][a-z0-9-]*$"
HOST_PLACEHOLDER = "WS-01"

ControlId = Annotated[str, Field(pattern=CONTROL_PATTERN)]
FactName = Literal["vulnerabilities", "log_retention"]
CheckResultValue = Literal["passed", "failed", "not applicable", "not scanned"]
Treatment = Literal["mitigate", "accept", "transfer", "avoid"]


class Status(StrEnum):
    IMPLEMENTED = "Implemented"
    PARTIAL = "Partially implemented"
    NOT_IMPLEMENTED = "Not implemented"
    NOT_APPLICABLE = "Not applicable"


RANKED = (Status.NOT_IMPLEMENTED, Status.PARTIAL, Status.IMPLEMENTED)


def weakest(*statuses: Status) -> Status:
    """Return the weakest rating: Not implemented < Partially implemented < Implemented."""
    if not statuses:
        raise ValueError("weakest() needs at least one status")
    for status in statuses:
        if status not in RANKED:
            raise ValueError(f"{status} has no rank")
    return min(statuses, key=RANKED.index)


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Subcontrol(Strict):
    id: str = Field(pattern=SUBCONTROL_PATTERN)
    text: str = Field(min_length=1)


class ControlEntry(Strict):
    id: ControlId
    text: str = Field(min_length=1)
    subcontrols: tuple[Subcontrol, ...] = ()


class SubdomainEntry(Strict):
    id: str = Field(pattern=SUBDOMAIN_PATTERN)
    title: str = Field(min_length=1)
    controls: tuple[ControlEntry, ...]


class DomainEntry(Strict):
    id: int = Field(ge=1, le=4)
    title: str = Field(min_length=1)
    subdomains: tuple[SubdomainEntry, ...]


class CatalogFile(Strict):
    framework: str
    source: str
    domains: tuple[DomainEntry, ...]


class Control(Strict):
    """One ECC main control with its place in the framework."""

    id: ControlId
    domain: int
    domain_title: str
    subdomain: str
    subdomain_title: str
    text: str
    subcontrols: tuple[Subcontrol, ...] = ()


class CisCheck(Strict):
    id: int
    cis: str = Field(pattern=CIS_PATTERN)
    title: str = Field(min_length=1)


class CisPolicyInfo(Strict):
    id: str
    name: str


class CisPolicy(Strict):
    policy: CisPolicyInfo
    checks: tuple[CisCheck, ...]


class Rule(Strict):
    cis: str = Field(pattern=CIS_PATTERN)
    ecc: tuple[ControlId, ...] = Field(min_length=1)
    why: str = Field(min_length=1)


class FactLink(Strict):
    fact: FactName
    ecc: tuple[ControlId, ...] = Field(min_length=1)


class Mapping(Strict):
    rules: tuple[Rule, ...]
    facts: tuple[FactLink, ...] = ()


class EvidenceEntry(Strict):
    control: ControlId
    status: Status
    documents: tuple[str, ...] = ()
    note: str = Field(min_length=1)

    @field_validator("status")
    @classmethod
    def _rated(cls, value: Status) -> Status:
        if value is Status.NOT_APPLICABLE:
            raise ValueError("record Not applicable controls in applicability.yaml")
        return value


class Evidence(Strict):
    entries: tuple[EvidenceEntry, ...] = ()


class NotApplicable(Strict):
    control: ControlId
    reason: str = Field(min_length=1)


class Applicability(Strict):
    not_applicable: tuple[NotApplicable, ...] = ()


class Risk(Strict):
    id: str = Field(pattern=r"^R-\d{2,3}$")
    controls: tuple[ControlId, ...] = Field(min_length=1)
    statement: str = Field(min_length=1)
    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)
    treatment: Treatment
    owner: str = Field(min_length=1)
    due: date

    @property
    def score(self) -> int:
        return self.likelihood * self.impact


class RiskRegister(Strict):
    risks: tuple[Risk, ...] = ()


class CheckResult(Strict):
    id: int
    result: CheckResultValue


class SnapshotPolicy(Strict):
    id: str
    checks_total: int = Field(ge=1)


class VulnerabilityCounts(Strict):
    critical: int = Field(ge=0)
    high: int = Field(ge=0)
    medium: int = Field(ge=0)
    low: int = Field(ge=0)


class LoggingFacts(Strict):
    oldest_alert: AwareDatetime | None
    agent_active: bool


class Snapshot(Strict):
    """Everything collect stores. Nothing else may be written to a snapshot."""

    format_version: Literal[1] = Field(default=1, alias="schema")
    label: str = Field(pattern=LABEL_PATTERN)
    taken_at: AwareDatetime
    host: Literal["WS-01"]
    policy: SnapshotPolicy
    checks: tuple[CheckResult, ...]
    vulnerabilities: VulnerabilityCounts
    logging: LoggingFacts
```

- [ ] **Step 5: Run the tests to make sure they pass**

Run: `.venv/Scripts/python -m pytest tests/test_models.py -v`
Expected: 9 passed.

- [ ] **Step 6: Lint and commit**

```bash
.venv/Scripts/python -m ruff check .
git add pyproject.toml requirements.txt .gitignore ecc/__init__.py ecc/models.py tests/__init__.py tests/test_models.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Add project skeleton and data models"
```

---

### Task 2: Loading data files, and the test fixture repo

**Files:**
- Create: `ecc/load.py`, `tests/fixtures.py`, `tests/conftest.py`
- Test: `tests/test_load.py`

**Interfaces:**
- Consumes: models from Task 1.
- Produces: `DataError(Exception)`; `@dataclass(frozen=True) Dataset(root: Path, catalog: tuple[Control, ...], policy: CisPolicy, mapping: Mapping, evidence: Evidence, applicability: Applicability, risks: RiskRegister)`; `load_model(model, path)`; `load_catalog(path) -> tuple[Control, ...]`; `load_dataset(root) -> Dataset` (reads `root/data/*.yaml`); `load_snapshot(path) -> Snapshot`; `load_snapshots(directory) -> list[Snapshot]` (sorted by `taken_at`, `[]` if the folder is missing).
- Produces for tests: `tests.fixtures` constants `CATALOG, CIS_CHECKS, MAPPING, EVIDENCE, APPLICABILITY, RISKS, BASELINE, AFTER`, functions `write_root(root) -> Path`, `rewrite(root, name, content)`; pytest fixtures `root`, `dataset`, `baseline`, `after`.

The fixture repo has 5 controls and 4 checks. Its expected results, used by later tasks:

| Control | Baseline (2026-10-12) | After (2026-10-20) |
|---|---|---|
| 1-3-1 | Partially (documents) | Partially |
| 2-2-1 | Implemented (documents) | Implemented |
| 2-2-3 | Partially (1 of 2 checks) | Implemented |
| 2-12-3 | Not implemented (check failed; logs kept 10 days; policy approved) | Partially (checks pass; logs kept 18 days) |
| 4-2-1 | Not applicable | Not applicable |
| **Compliance** | **50.0%** | **75.0%** |

- [ ] **Step 1: Write the fixture repo**

Create `tests/fixtures.py`:

```python
"""A tiny, self-consistent repo used by the tests. Every name in it is made up."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

CATALOG = {
    "framework": "ECC-2:2024",
    "source": "https://example.test/ecc.pdf",
    "domains": [
        {
            "id": 1,
            "title": "Cybersecurity Governance",
            "subdomains": [
                {
                    "id": "1-3",
                    "title": "Cybersecurity Policies and Procedures",
                    "controls": [{"id": "1-3-1", "text": "Policies shall be documented."}],
                }
            ],
        },
        {
            "id": 2,
            "title": "Cybersecurity Defense",
            "subdomains": [
                {
                    "id": "2-2",
                    "title": "Identity and Access Management",
                    "controls": [
                        {"id": "2-2-1", "text": "IAM requirements shall be documented."},
                        {
                            "id": "2-2-3",
                            "text": "IAM requirements shall include the following as a minimum:",
                            "subcontrols": [
                                {"id": "2.2.3.1", "text": "Single-factor authentication."}
                            ],
                        },
                    ],
                },
                {
                    "id": "2-12",
                    "title": "Cybersecurity Event Logs and Monitoring Management",
                    "controls": [
                        {"id": "2-12-3", "text": "Logging shall include the following:"}
                    ],
                },
            ],
        },
        {
            "id": 4,
            "title": "Third-Party and Cloud Computing Cybersecurity",
            "subdomains": [
                {
                    "id": "4-2",
                    "title": "Cloud Computing and Hosting Cybersecurity",
                    "controls": [
                        {"id": "4-2-1", "text": "Cloud requirements shall be documented."}
                    ],
                }
            ],
        },
    ],
}

CIS_CHECKS = {
    "policy": {
        "id": "cis_win11_enterprise",
        "name": "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0",
    },
    "checks": [
        {"id": 26000, "cis": "1.1.1", "title": "Ensure 'Enforce password history' is set."},
        {"id": 26001, "cis": "1.1.2", "title": "Ensure 'Maximum password age' is set."},
        {"id": 26139, "cis": "17.1.1", "title": "Ensure 'Audit Credential Validation' is set."},
        {"id": 26140, "cis": "17.2.1", "title": "Ensure 'Audit Application Group Management'."},
    ],
}

MAPPING = {
    "rules": [
        {"cis": "1", "ecc": ["2-2-3"], "why": "Password rules protect sign-in."},
        {"cis": "17", "ecc": ["2-12-3"], "why": "Audit policy turns on event logs."},
    ],
    "facts": [{"fact": "log_retention", "ecc": ["2-12-3"]}],
}

EVIDENCE = {
    "entries": [
        {
            "control": "1-3-1",
            "status": "Partially implemented",
            "note": "Policy drafted, not yet approved.",
        },
        {
            "control": "2-2-1",
            "status": "Implemented",
            "documents": ["docs/policies/access-control.md"],
            "note": "Access control policy approved.",
        },
        {
            "control": "2-12-3",
            "status": "Implemented",
            "documents": ["docs/policies/logging.md"],
            "note": "Logging policy approved.",
        },
    ]
}

APPLICABILITY = {
    "not_applicable": [{"control": "4-2-1", "reason": "The company uses no cloud hosting."}]
}

RISKS = {
    "risks": [
        {
            "id": "R-01",
            "controls": ["2-2-3"],
            "statement": "Weak passwords allow account takeover.",
            "likelihood": 3,
            "impact": 4,
            "treatment": "mitigate",
            "owner": "IT Manager",
            "due": "2026-11-01",
        },
        {
            "id": "R-02",
            "controls": ["2-12-3"],
            "statement": "Missing logs hide attacks.",
            "likelihood": 4,
            "impact": 4,
            "treatment": "mitigate",
            "owner": "Cybersecurity Lead",
            "due": "2026-12-15",
        },
        {
            "id": "R-03",
            "controls": ["1-3-1"],
            "statement": "Unapproved policies are not followed.",
            "likelihood": 2,
            "impact": 2,
            "treatment": "accept",
            "owner": "General Manager",
            "due": "2027-03-01",
        },
    ]
}

BASELINE = {
    "schema": 1,
    "label": "baseline",
    "taken_at": "2026-10-12T18:00:00Z",
    "host": "WS-01",
    "policy": {"id": "cis_win11_enterprise", "checks_total": 4},
    "checks": [
        {"id": 26000, "result": "failed"},
        {"id": 26001, "result": "passed"},
        {"id": 26139, "result": "failed"},
        {"id": 26140, "result": "not applicable"},
    ],
    "vulnerabilities": {"critical": 1, "high": 3, "medium": 5, "low": 2},
    "logging": {"oldest_alert": "2026-10-02T18:00:00Z", "agent_active": True},
}

AFTER = {
    **BASELINE,
    "label": "after",
    "taken_at": "2026-10-20T18:00:00Z",
    "checks": [
        {"id": 26000, "result": "passed"},
        {"id": 26001, "result": "passed"},
        {"id": 26139, "result": "passed"},
        {"id": 26140, "result": "not applicable"},
    ],
    "vulnerabilities": {"critical": 0, "high": 1, "medium": 5, "low": 2},
}

DATA_FILES = {
    "catalog.yaml": CATALOG,
    "cis_checks.yaml": CIS_CHECKS,
    "mapping.yaml": MAPPING,
    "evidence.yaml": EVIDENCE,
    "applicability.yaml": APPLICABILITY,
    "risks.yaml": RISKS,
}


def rewrite(root: Path, name: str, content: object) -> None:
    (root / "data" / name).write_text(yaml.safe_dump(content, sort_keys=False), encoding="utf-8")


def write_root(root: Path) -> Path:
    (root / "data").mkdir(parents=True)
    for name, content in DATA_FILES.items():
        rewrite(root, name, content)
    policies = root / "docs" / "policies"
    policies.mkdir(parents=True)
    for document in ("access-control.md", "logging.md"):
        (policies / document).write_text("# Policy\n", encoding="utf-8")
    snapshots = root / "snapshots"
    snapshots.mkdir()
    for name, content in (("2026-10-baseline.json", BASELINE), ("2026-10-after.json", AFTER)):
        (snapshots / name).write_text(json.dumps(content, indent=2), encoding="utf-8")
    return root
```

Create `tests/conftest.py`:

```python
from pathlib import Path

import pytest

from ecc.load import Dataset, load_dataset, load_snapshots
from ecc.models import Snapshot
from tests.fixtures import write_root


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return write_root(tmp_path / "repo")


@pytest.fixture
def dataset(root: Path) -> Dataset:
    return load_dataset(root)


@pytest.fixture
def baseline(root: Path) -> Snapshot:
    return load_snapshots(root / "snapshots")[0]


@pytest.fixture
def after(root: Path) -> Snapshot:
    return load_snapshots(root / "snapshots")[1]
```

- [ ] **Step 2: Write the failing tests**

Create `tests/test_load.py`:

```python
from pathlib import Path

import pytest

from ecc.load import DataError, load_dataset, load_snapshots
from tests.fixtures import RISKS, rewrite


def test_dataset_flattens_the_catalog(dataset):
    assert [control.id for control in dataset.catalog] == [
        "1-3-1",
        "2-2-1",
        "2-2-3",
        "2-12-3",
        "4-2-1",
    ]
    control = dataset.catalog[2]
    assert (control.domain, control.subdomain) == (2, "2-2")
    assert control.domain_title == "Cybersecurity Defense"
    assert control.subdomain_title == "Identity and Access Management"
    assert control.subcontrols[0].id == "2.2.3.1"


def test_dataset_reads_every_file(dataset):
    assert len(dataset.policy.checks) == 4
    assert [rule.cis for rule in dataset.mapping.rules] == ["1", "17"]
    assert len(dataset.evidence.entries) == 3
    assert dataset.applicability.not_applicable[0].control == "4-2-1"
    assert [risk.id for risk in dataset.risks.risks] == ["R-01", "R-02", "R-03"]


def test_snapshots_are_sorted_by_time(root: Path):
    labels = [snapshot.label for snapshot in load_snapshots(root / "snapshots")]
    assert labels == ["baseline", "after"]


def test_a_missing_snapshot_folder_means_no_snapshots(tmp_path: Path):
    assert load_snapshots(tmp_path / "snapshots") == []


def test_a_missing_file_names_the_file(root: Path):
    (root / "data" / "risks.yaml").unlink()
    with pytest.raises(DataError, match="risks.yaml"):
        load_dataset(root)


def test_invalid_values_name_the_file(root: Path):
    rewrite(root, "risks.yaml", {"risks": [{**RISKS["risks"][0], "likelihood": 9}]})
    with pytest.raises(DataError, match="risks.yaml"):
        load_dataset(root)


def test_broken_yaml_names_the_file(root: Path):
    (root / "data" / "mapping.yaml").write_text("rules: [", encoding="utf-8")
    with pytest.raises(DataError, match="mapping.yaml: not valid YAML"):
        load_dataset(root)


def test_a_snapshot_with_extra_data_is_rejected(root: Path):
    path = root / "snapshots" / "2026-10-baseline.json"
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace('"host"', '"agent_ip": "10.0.0.5", "host"'), encoding="utf-8")
    with pytest.raises(DataError, match="2026-10-baseline.json"):
        load_snapshots(root / "snapshots")
```

- [ ] **Step 3: Run the tests to make sure they fail**

Run: `.venv/Scripts/python -m pytest tests/test_load.py -v`
Expected: errors, `ModuleNotFoundError: No module named 'ecc.load'` (raised while importing `tests/conftest.py`).

- [ ] **Step 4: Write the loader**

Create `ecc/load.py`:

```python
"""Read the YAML data files and JSON snapshots into models."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

import yaml
from pydantic import BaseModel, ValidationError

from ecc.models import (
    Applicability,
    CatalogFile,
    CisPolicy,
    Control,
    Evidence,
    Mapping,
    RiskRegister,
    Snapshot,
)

ModelT = TypeVar("ModelT", bound=BaseModel)


class DataError(Exception):
    """A data file is missing, unreadable or does not match its model."""


@dataclass(frozen=True)
class Dataset:
    root: Path
    catalog: tuple[Control, ...]
    policy: CisPolicy
    mapping: Mapping
    evidence: Evidence
    applicability: Applicability
    risks: RiskRegister


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise DataError(f"{path.name}: cannot read the file ({error.strerror}).") from error


def load_model(model: type[ModelT], path: Path) -> ModelT:
    try:
        data: Any = yaml.safe_load(read_text(path))
    except yaml.YAMLError as error:
        raise DataError(f"{path.name}: not valid YAML ({error}).") from error
    try:
        return model.model_validate(data)
    except ValidationError as error:
        raise DataError(f"{path.name}: {error}") from error


def load_catalog(path: Path) -> tuple[Control, ...]:
    catalog = load_model(CatalogFile, path)
    return tuple(
        Control(
            id=entry.id,
            domain=domain.id,
            domain_title=domain.title,
            subdomain=subdomain.id,
            subdomain_title=subdomain.title,
            text=entry.text,
            subcontrols=entry.subcontrols,
        )
        for domain in catalog.domains
        for subdomain in domain.subdomains
        for entry in subdomain.controls
    )


def load_dataset(root: Path) -> Dataset:
    data = root / "data"
    return Dataset(
        root=root,
        catalog=load_catalog(data / "catalog.yaml"),
        policy=load_model(CisPolicy, data / "cis_checks.yaml"),
        mapping=load_model(Mapping, data / "mapping.yaml"),
        evidence=load_model(Evidence, data / "evidence.yaml"),
        applicability=load_model(Applicability, data / "applicability.yaml"),
        risks=load_model(RiskRegister, data / "risks.yaml"),
    )


def load_snapshot(path: Path) -> Snapshot:
    try:
        return Snapshot.model_validate_json(read_text(path))
    except ValidationError as error:
        raise DataError(f"{path.name}: {error}") from error


def load_snapshots(directory: Path) -> list[Snapshot]:
    if not directory.is_dir():
        return []
    snapshots = [load_snapshot(path) for path in sorted(directory.glob("*.json"))]
    return sorted(snapshots, key=lambda snapshot: snapshot.taken_at)
```

- [ ] **Step 5: Run the tests to make sure they pass**

Run: `.venv/Scripts/python -m pytest tests -v`
Expected: 17 passed (9 from Task 1, 8 here).

- [ ] **Step 6: Lint and commit**

```bash
.venv/Scripts/python -m ruff check .
git add ecc/load.py tests/fixtures.py tests/conftest.py tests/test_load.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Load data files and snapshots; add the test fixture repo"
```

---

### Task 3: The ECC-2:2024 catalog

**Files:**
- Create: `tools/__init__.py`, `tools/extract_catalog.py`, `data/catalog.yaml` (generated)
- Test: `tests/test_catalog_data.py`

**Interfaces:**
- Consumes: `load_catalog` (Task 2).
- Produces: `data/catalog.yaml` with 4 domains, 28 subdomains, 108 main controls, 92 subcontrols.

- [ ] **Step 1: Download the NCA PDF and extract its text**

```bash
mkdir -p .cache
curl -L -o .cache/ecc-2-2024-en.pdf "https://cdn.nca.gov.sa/api/files/public/upload/86e09090-44e4-481f-bc28-355673607654_ECC--2024-EN.pdf"
pdftotext -raw -enc UTF-8 .cache/ecc-2-2024-en.pdf .cache/ecc-2-2024-en.txt
```

Expected: `.cache/ecc-2-2024-en.pdf` is about 1.2 MB. `pdftotext` prints many `Syntax Warning: Mismatch between font type and embedded font file` lines; they are harmless. `.cache/` is git-ignored, so the PDF is never committed.

- [ ] **Step 2: Write the failing tests**

Create `tests/test_catalog_data.py`:

```python
from collections import Counter
from pathlib import Path

from ecc.load import load_catalog

CATALOG = Path(__file__).resolve().parents[1] / "data" / "catalog.yaml"
EXPECTED = {
    "1-1": 3, "1-2": 3, "1-3": 4, "1-4": 2, "1-5": 4, "1-6": 4, "1-7": 1, "1-8": 3,
    "1-9": 6, "1-10": 5, "2-1": 6, "2-2": 4, "2-3": 4, "2-4": 4, "2-5": 4, "2-6": 4,
    "2-7": 3, "2-8": 4, "2-9": 4, "2-10": 4, "2-11": 4, "2-12": 4, "2-13": 4, "2-14": 4,
    "2-15": 4, "3-1": 4, "4-1": 4, "4-2": 4,
}
ALLOWED_NON_ASCII = set("\u2019\u201c\u201d")
FURNITURE = ("Essential Cybersecurity Controls", "Document classification", "Objective")


def test_108_controls_in_28_subdomains_and_4_domains():
    controls = load_catalog(CATALOG)
    assert len(controls) == 108
    assert dict(Counter(control.subdomain for control in controls)) == EXPECTED
    assert sorted({control.domain for control in controls}) == [1, 2, 3, 4]


def test_controls_are_numbered_in_order():
    controls = load_catalog(CATALOG)
    for subdomain, count in EXPECTED.items():
        ids = [control.id for control in controls if control.subdomain == subdomain]
        assert ids == [f"{subdomain}-{n}" for n in range(1, count + 1)]


def test_92_subcontrols_sit_under_their_parent():
    pairs = [(c.id, s.id) for c in load_catalog(CATALOG) for s in c.subcontrols]
    assert len(pairs) == 92
    for parent, child in pairs:
        assert child.replace(".", "-").startswith(parent + "-")


def test_known_texts():
    controls = {control.id: control for control in load_catalog(CATALOG)}
    assert controls["1-7-1"].subdomain_title == (
        "Compliance with Cybersecurity Standards, Laws and Regulations"
    )
    assert controls["3-1-1"].subdomain_title == (
        "Cybersecurity Resilience Aspects of Business Continuity Management (BCM)"
    )
    assert controls["2-2-1"].text == (
        "Cybersecurity requirements for identity and access management of the entity shall be "
        "identified, documented, and approved."
    )
    retention = {s.id: s.text for s in controls["2-12-3"].subcontrols}["2.12.3.5"]
    assert retention == (
        "Retention period of cybersecurity event logs (shall be at least 12 months)."
    )


def test_no_page_furniture_leaked_into_the_text():
    for control in load_catalog(CATALOG):
        for text in (control.text, *(sub.text for sub in control.subcontrols)):
            for marker in FURNITURE:
                assert marker not in text, control.id
            assert all(ord(ch) < 128 or ch in ALLOWED_NON_ASCII for ch in text), control.id
```

- [ ] **Step 3: Run the tests to make sure they fail**

Run: `.venv/Scripts/python -m pytest tests/test_catalog_data.py -v`
Expected: 5 failed with `DataError: catalog.yaml: cannot read the file (No such file or directory).`

- [ ] **Step 4: Write the extractor**

Create `tools/__init__.py`:

```python
```

Create `tools/extract_catalog.py`:

```python
"""Turn `pdftotext -raw -enc UTF-8` output of the NCA ECC-2:2024 PDF into data/catalog.yaml.

One-off helper: run it once, then review the YAML against the PDF. After that the YAML is
the source of truth.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

SOURCE = (
    "https://cdn.nca.gov.sa/api/files/public/upload/"
    "86e09090-44e4-481f-bc28-355673607654_ECC--2024-EN.pdf"
)
HEADER = (
    "# NCA Essential Cybersecurity Controls ECC-2:2024 (Document classification: Public,\n"
    "# TLP: White). Generated by tools/extract_catalog.py, then reviewed by hand.\n"
)
DOMAINS = {
    1: "Cybersecurity Governance",
    2: "Cybersecurity Defense",
    3: "Cybersecurity Resilience",
    4: "Third-Party and Cloud Computing Cybersecurity",
}
SUBDOMAIN = re.compile(r"^([1-4])[-.](\d{1,2})(?:\s+(\S.*))?$")
CONTROL = re.compile(r"^([1-4]-\d{1,2}-\d{1,2})(?:\s+(\S.*))?$")
SUBCONTROL = re.compile(r"^([1-4])[.-](\d{1,2})[.-](\d{1,2})[.-](\d{1,2})\s+(\S.*)$")
# Running headers, footers, page numbers and domain banners repeat on every page.
NOISE = re.compile(
    r"^(Document classification: Public.*|Essential Cybersecurity Controls|-|\d{1,3}|"
    + "|".join(re.escape(title) for title in DOMAINS.values())
    + r")$"
)
# Every page carries an Arabic watermark.
ARABIC = re.compile(r"[\u0600-\u06FF\uFB50-\uFDFF\uFE70-\uFEFF]")
END = "Appendices"


def clean_lines(text: str) -> list[str]:
    lines = [ARABIC.sub("", line).strip() for line in text.splitlines()]
    return [line for line in lines if line and not NOISE.match(line)]


def is_subdomain_header(lines: list[str], index: int) -> bool:
    if not SUBDOMAIN.match(lines[index]):
        return False
    return any(line.startswith("Objective") for line in lines[index + 1 : index + 5])


def join(parts: list[str]) -> str:
    text = ""
    for part in parts:
        if not text:
            text = part
        elif text.endswith("-"):
            text += part
        else:
            text += " " + part
    return re.sub(r"\s+", " ", text).strip()


def finish(domain: dict) -> dict:
    for subdomain in domain["subdomains"]:
        for control in subdomain["controls"]:
            control["text"] = join(control["text"])
            for sub in control["subcontrols"]:
                sub["text"] = join(sub["text"])
            if not control["subcontrols"]:
                del control["subcontrols"]
    return domain


def parse(lines: list[str]) -> list[dict]:
    start = next(i for i in range(len(lines)) if is_subdomain_header(lines, i))
    domains: dict[int, dict] = {}
    subdomain: dict = {}
    control: dict | None = None
    target: list[str] | None = None
    in_objective = False
    i = start
    while i < len(lines) and lines[i] != END:
        line = lines[i]
        if is_subdomain_header(lines, i):
            match = SUBDOMAIN.match(line)
            domain_id = int(match.group(1))
            title = [match.group(3)] if match.group(3) else []
            i += 1
            while not lines[i].startswith("Objective"):
                title.append(lines[i])
                i += 1
            domain = domains.setdefault(
                domain_id, {"id": domain_id, "title": DOMAINS[domain_id], "subdomains": []}
            )
            subdomain = {
                "id": f"{domain_id}-{int(match.group(2))}",
                "title": join(title),
                "controls": [],
            }
            domain["subdomains"].append(subdomain)
            control, target, in_objective = None, None, True
            i += 1
            continue
        i += 1
        if in_objective:
            in_objective = line != "Controls"
            continue
        control_match = CONTROL.match(line)
        if control_match:
            control = {"id": control_match.group(1), "text": [], "subcontrols": []}
            subdomain["controls"].append(control)
            target = control["text"]
            if control_match.group(2):
                target.append(control_match.group(2))
            continue
        sub_match = SUBCONTROL.match(line)
        if sub_match and control is not None:
            sub_id = ".".join(sub_match.group(n) for n in range(1, 5))
            sub = {"id": sub_id, "text": [sub_match.group(5)]}
            control["subcontrols"].append(sub)
            target = sub["text"]
            continue
        if target is not None:
            target.append(line)
    return [finish(domains[key]) for key in sorted(domains)]


def main(source: str, output: str) -> int:
    lines = clean_lines(Path(source).read_text(encoding="utf-8"))
    catalog = {"framework": "ECC-2:2024", "source": SOURCE, "domains": parse(lines)}
    body = yaml.safe_dump(catalog, sort_keys=False, allow_unicode=True, width=88)
    Path(output).write_text(HEADER + body, encoding="utf-8")
    total = sum(len(s["controls"]) for d in catalog["domains"] for s in d["subdomains"])
    print(f"Wrote {output}: {total} controls")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
```

- [ ] **Step 5: Generate the catalog**

Run: `.venv/Scripts/python tools/extract_catalog.py .cache/ecc-2-2024-en.txt data/catalog.yaml`
Expected: `Wrote data/catalog.yaml: 108 controls`

- [ ] **Step 6: Run the tests to make sure they pass**

Run: `.venv/Scripts/python -m pytest tests/test_catalog_data.py -v`
Expected: 5 passed.

- [ ] **Step 7: Review by hand**

Open `data/catalog.yaml` next to the PDF and compare subdomains 1-6, 2-2, 2-5, 2-8 and 2-12 word for word (these cross page breaks or have long subcontrol lists). If a text is wrong, fix it directly in `data/catalog.yaml`; the YAML is the source of truth from now on. Re-run the tests after any edit.

- [ ] **Step 8: Lint and commit**

```bash
.venv/Scripts/python -m ruff check .
git add tools/__init__.py tools/extract_catalog.py data/catalog.yaml tests/test_catalog_data.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Add the ECC-2:2024 catalog extracted from the NCA PDF"
```

---

### Task 4: The CIS check list

**Files:**
- Create: `tools/gen_cis_checks.py`, `data/cis_checks.yaml` (generated)
- Test: `tests/test_gen_cis_checks.py`, `tests/test_cis_data.py`

**Interfaces:**
- Consumes: `load_model`, `CisPolicy`.
- Produces: `tools.gen_cis_checks.cis_id(check) -> str`, `convert(policy) -> dict`; `data/cis_checks.yaml` with policy `cis_win11_enterprise` and 482 checks, ids 26000–26481. Note: two checks share CIS id `18.7.5`, so code must key checks by Wazuh check id, not by CIS id.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_gen_cis_checks.py`:

```python
import pytest

from tools.gen_cis_checks import cis_id, convert

TITLE = "Ensure 'Enforce password history' is set to '24 or more password(s)'."
POLICY = {
    "policy": {"id": "cis_win11_enterprise", "name": "CIS Benchmark", "file": "x.yml"},
    "checks": [
        {"id": 26000, "title": TITLE, "compliance": [{"cis": ["1.1.1"]}, {"cis_csc_v8": ["5.2"]}]}
    ],
}


def test_convert_keeps_id_cis_section_and_title():
    assert convert(POLICY) == {
        "policy": {"id": "cis_win11_enterprise", "name": "CIS Benchmark"},
        "checks": [{"id": 26000, "cis": "1.1.1", "title": TITLE}],
    }


def test_a_check_needs_exactly_one_cis_id():
    with pytest.raises(ValueError, match="no CIS id"):
        cis_id({"id": 1, "compliance": [{"pci_dss": ["2.2"]}]})
    with pytest.raises(ValueError, match="2 CIS ids"):
        cis_id({"id": 2, "compliance": [{"cis": ["1.1", "1.2"]}]})
```

Create `tests/test_cis_data.py`:

```python
from pathlib import Path

from ecc.load import load_model
from ecc.models import CisPolicy

POLICY_FILE = Path(__file__).resolve().parents[1] / "data" / "cis_checks.yaml"


def test_policy_is_the_cis_windows_11_enterprise_benchmark():
    policy = load_model(CisPolicy, POLICY_FILE)
    assert policy.policy.id == "cis_win11_enterprise"
    assert policy.policy.name == "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0"


def test_policy_has_482_checks_numbered_26000_to_26481():
    ids = [check.id for check in load_model(CisPolicy, POLICY_FILE).checks]
    assert ids == list(range(26000, 26482))


def test_spot_check_sections_and_titles():
    checks = {check.id: check for check in load_model(CisPolicy, POLICY_FILE).checks}
    assert checks[26005].cis == "1.2.1"
    assert checks[26403].cis == "18.10.42.17"
    assert "Turn off Microsoft Defender AntiVirus" in checks[26403].title
```

- [ ] **Step 2: Run the tests to make sure they fail**

Run: `.venv/Scripts/python -m pytest tests/test_gen_cis_checks.py tests/test_cis_data.py -v`
Expected: `ModuleNotFoundError: No module named 'tools.gen_cis_checks'`, and `DataError: cis_checks.yaml: cannot read the file`.

- [ ] **Step 3: Write the generator**

Create `tools/gen_cis_checks.py`:

```python
"""Write data/cis_checks.yaml from the Wazuh SCA policy that ships with the Windows agent."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

DEFAULT_POLICY = Path("C:/Program Files (x86)/ossec-agent/ruleset/sca/cis_win11_enterprise.yml")
DEFAULT_OUTPUT = Path("data/cis_checks.yaml")
HEADER = (
    "# Generated by tools/gen_cis_checks.py from the Wazuh SCA policy cis_win11_enterprise.yml\n"
    "# (Wazuh Inc., GPLv2), based on the CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0.\n"
    "# Do not edit by hand; regenerate instead.\n"
)


def cis_id(check: dict[str, Any]) -> str:
    for item in check.get("compliance", []):
        if "cis" in item:
            values = item["cis"]
            if len(values) != 1:
                raise ValueError(f"check {check['id']} has {len(values)} CIS ids")
            return str(values[0])
    raise ValueError(f"check {check['id']} has no CIS id")


def convert(policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "policy": {"id": policy["policy"]["id"], "name": policy["policy"]["name"]},
        "checks": [
            {"id": int(check["id"]), "cis": cis_id(check), "title": check["title"]}
            for check in policy["checks"]
        ],
    }


def main(argv: list[str]) -> int:
    source = Path(argv[1]) if len(argv) > 1 else DEFAULT_POLICY
    output = Path(argv[2]) if len(argv) > 2 else DEFAULT_OUTPUT
    data = convert(yaml.safe_load(source.read_text(encoding="utf-8")))
    body = yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100)
    output.write_text(HEADER + body, encoding="utf-8")
    print(f"Wrote {output}: {len(data['checks'])} checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

- [ ] **Step 4: Generate the check list**

Run: `.venv/Scripts/python tools/gen_cis_checks.py`
Expected: `Wrote data/cis_checks.yaml: 482 checks`

- [ ] **Step 5: Run the tests to make sure they pass**

Run: `.venv/Scripts/python -m pytest tests/test_gen_cis_checks.py tests/test_cis_data.py -v`
Expected: 5 passed.

- [ ] **Step 6: Lint and commit**

```bash
.venv/Scripts/python -m ruff check .
git add tools/gen_cis_checks.py data/cis_checks.yaml tests/test_gen_cis_checks.py tests/test_cis_data.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Add the 482 CIS checks from the Wazuh SCA policy"
```

---

### Task 5: Mapping engine

**Files:**
- Create: `ecc/mapping.py`
- Test: `tests/test_mapping.py`

**Interfaces:**
- Consumes: `CisCheck`, `CisPolicy`, `Mapping`, `Rule`, `FactName`.
- Produces: `rule_for(cis: str, rules) -> Rule | None` (longest whole-part prefix wins), `controls_for(check, mapping) -> tuple[str, ...]`, `checks_by_control(policy, mapping) -> dict[str, list[CisCheck]]`, `facts_by_control(mapping) -> dict[str, list[FactName]]`, `unmapped_checks(policy, mapping) -> list[CisCheck]`, `unused_rules(policy, mapping) -> list[Rule]` (rules that never win for any check), `duplicate_rules(mapping) -> list[str]`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_mapping.py`:

```python
from ecc.mapping import (
    checks_by_control,
    controls_for,
    duplicate_rules,
    facts_by_control,
    rule_for,
    unmapped_checks,
    unused_rules,
)
from ecc.models import CisCheck, CisPolicy, Mapping, Rule


def rule(cis: str, *ecc: str) -> Rule:
    return Rule(cis=cis, ecc=ecc or ("2-3-2",), why="Test rule.")


RULES = (rule("1", "2-2-3"), rule("1.1", "2-2-1"), rule("1.10", "2-5-3"), rule("17", "2-12-3"))


def test_the_longest_matching_rule_wins():
    assert rule_for("1.1.3", RULES).cis == "1.1"
    assert rule_for("1.2.1", RULES).cis == "1"


def test_matching_uses_whole_parts():
    assert rule_for("1.10.1", RULES).cis == "1.10"
    assert rule_for("11.1", RULES) is None


def test_a_full_cis_id_targets_one_check():
    rules = (*RULES, rule("1.1.3", "2-12-3"))
    assert rule_for("1.1.3", rules).cis == "1.1.3"
    assert rule_for("1.1.4", rules).cis == "1.1"


def test_checks_are_grouped_by_control(dataset):
    found = checks_by_control(dataset.policy, dataset.mapping)
    assert [check.id for check in found["2-2-3"]] == [26000, 26001]
    assert [check.id for check in found["2-12-3"]] == [26139, 26140]
    assert unmapped_checks(dataset.policy, dataset.mapping) == []


def test_controls_for_returns_the_rule_targets(dataset):
    assert controls_for(dataset.policy.checks[0], dataset.mapping) == ("2-2-3",)


def test_unmapped_checks_unused_and_duplicate_rules():
    policy = CisPolicy(
        policy={"id": "p", "name": "P"},
        checks=[CisCheck(id=1, cis="1.1.1", title="a"), CisCheck(id=2, cis="5.1", title="b")],
    )
    mapping = Mapping(rules=[rule("1"), rule("1.1"), rule("1.1"), rule("9")])
    assert [check.id for check in unmapped_checks(policy, mapping)] == [2]
    assert [r.cis for r in unused_rules(policy, mapping)] == ["1", "9"]
    assert duplicate_rules(mapping) == ["1.1"]


def test_facts_are_grouped_by_control(dataset):
    assert facts_by_control(dataset.mapping) == {"2-12-3": ["log_retention"]}
```

- [ ] **Step 2: Run the tests to make sure they fail**

Run: `.venv/Scripts/python -m pytest tests/test_mapping.py -v`
Expected: `ModuleNotFoundError: No module named 'ecc.mapping'`.

- [ ] **Step 3: Write the mapping engine**

Create `ecc/mapping.py`:

```python
"""Match CIS checks to ECC controls with the rules in mapping.yaml."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from ecc.models import CisCheck, CisPolicy, FactName, Mapping, Rule


def cis_parts(cis: str) -> tuple[str, ...]:
    return tuple(cis.split("."))


def rule_for(cis: str, rules: Iterable[Rule]) -> Rule | None:
    """The rule whose CIS id is the longest whole-part prefix of `cis`."""
    target = cis_parts(cis)
    best: Rule | None = None
    for rule in rules:
        prefix = cis_parts(rule.cis)
        if target[: len(prefix)] != prefix:
            continue
        if best is None or len(prefix) > len(cis_parts(best.cis)):
            best = rule
    return best


def controls_for(check: CisCheck, mapping: Mapping) -> tuple[str, ...]:
    rule = rule_for(check.cis, mapping.rules)
    return rule.ecc if rule is not None else ()


def checks_by_control(policy: CisPolicy, mapping: Mapping) -> dict[str, list[CisCheck]]:
    found: dict[str, list[CisCheck]] = {}
    for check in policy.checks:
        for control_id in controls_for(check, mapping):
            found.setdefault(control_id, []).append(check)
    return found


def facts_by_control(mapping: Mapping) -> dict[str, list[FactName]]:
    found: dict[str, list[FactName]] = {}
    for link in mapping.facts:
        for control_id in link.ecc:
            found.setdefault(control_id, []).append(link.fact)
    return found


def unmapped_checks(policy: CisPolicy, mapping: Mapping) -> list[CisCheck]:
    return [check for check in policy.checks if rule_for(check.cis, mapping.rules) is None]


def unused_rules(policy: CisPolicy, mapping: Mapping) -> list[Rule]:
    """Rules that are never the winning rule for any check (dead or shadowed)."""
    winners = set()
    for check in policy.checks:
        rule = rule_for(check.cis, mapping.rules)
        if rule is not None:
            winners.add(rule.cis)
    return [rule for rule in mapping.rules if rule.cis not in winners]


def duplicate_rules(mapping: Mapping) -> list[str]:
    counts = Counter(rule.cis for rule in mapping.rules)
    return sorted(cis for cis, count in counts.items() if count > 1)
```

- [ ] **Step 4: Run the tests to make sure they pass**

Run: `.venv/Scripts/python -m pytest tests/test_mapping.py -v`
Expected: 7 passed.

- [ ] **Step 5: Lint and commit**

```bash
.venv/Scripts/python -m ruff check .
git add ecc/mapping.py tests/test_mapping.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Add the longest-match CIS to ECC mapping engine"
```

---

### Task 6: The CIS → ECC mapping

**Files:**
- Create: `data/mapping.yaml`
- Test: `tests/test_mapping_data.py`

**Interfaces:**
- Consumes: Task 3 catalog, Task 4 checks, Task 5 engine.
- Produces: 65 rules covering all 482 checks, and two fact links. Technical evidence reaches 7 controls (2-2-3, 2-3-2, 2-3-3, 2-5-3, 2-7-2, 2-8-3, 2-12-3) plus 2-10-3 through the `vulnerabilities` fact.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_mapping_data.py`:

```python
from pathlib import Path

from ecc.load import load_catalog, load_model
from ecc.mapping import controls_for, duplicate_rules, unmapped_checks, unused_rules
from ecc.models import CisPolicy, Mapping

DATA = Path(__file__).resolve().parents[1] / "data"


def load() -> tuple[CisPolicy, Mapping]:
    policy = load_model(CisPolicy, DATA / "cis_checks.yaml")
    return policy, load_model(Mapping, DATA / "mapping.yaml")


def test_every_check_has_a_rule():
    policy, mapping = load()
    assert unmapped_checks(policy, mapping) == []


def test_every_rule_is_used_and_unique():
    policy, mapping = load()
    assert unused_rules(policy, mapping) == []
    assert duplicate_rules(mapping) == []


def test_every_target_is_a_real_control():
    _, mapping = load()
    known = {control.id for control in load_catalog(DATA / "catalog.yaml")}
    targets = {target for rule in mapping.rules for target in rule.ecc}
    targets |= {target for link in mapping.facts for target in link.ecc}
    assert targets <= known


def test_every_rule_explains_itself():
    _, mapping = load()
    assert all(len(rule.why) >= 20 for rule in mapping.rules)


def test_spot_checks():
    policy, mapping = load()
    checks = {check.id: check for check in policy.checks}
    assert controls_for(checks[26005], mapping) == ("2-2-3",)  # 1.2.1 lockout duration
    assert controls_for(checks[26138], mapping) == ("2-5-3", "2-12-3")  # 9.3.9 firewall log
    assert controls_for(checks[26139], mapping) == ("2-12-3",)  # 17.1.1 audit credentials
    assert controls_for(checks[26294], mapping) == ("2-3-3",)  # 18.9.51.1.1 NTP client
    assert controls_for(checks[26403], mapping) == ("2-3-3",)  # 18.10.42.17 Defender AV
    assert controls_for(checks[26474], mapping) == ("2-3-3",)  # 18.10.92.2.1 auto updates
```

- [ ] **Step 2: Run the tests to make sure they fail**

Run: `.venv/Scripts/python -m pytest tests/test_mapping_data.py -v`
Expected: 5 failed with `DataError: mapping.yaml: cannot read the file`.

- [ ] **Step 3: Write the mapping**

Create `data/mapping.yaml`:

```yaml
# CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 (Wazuh policy cis_win11_enterprise)
# mapped to NCA ECC-2:2024 main controls. The longest matching CIS id wins; matching
# works on whole dot-separated parts, so "1.1" matches "1.1.3" but not "1.10.1".
rules:
  # 1 Account Policies
  - cis: "1"
    ecc: ["2-2-3"]
    why: "Password and lockout rules protect username-and-password sign-in (2.2.3.1)."

  # 2 Local Policies: Security Options
  - cis: "2"
    ecc: ["2-3-2"]
    why: "Security options harden the workstation, part of implementing 2-3 protection requirements."
  - cis: "2.3.1"
    ecc: ["2-2-3"]
    why: "Account options (guest account, blank passwords, Microsoft accounts) govern who can sign in (2.2.3.1)."
  - cis: "2.3.2"
    ecc: ["2-12-3"]
    why: "Audit options make sure security events are actually logged (2.12.3.1)."
  - cis: "2.3.7"
    ecc: ["2-2-3"]
    why: "Interactive logon settings (screen lock, sign-in prompts) protect local sign-in (2.2.3.1)."
  - cis: "2.3.8"
    ecc: ["2-5-3"]
    why: "SMB client signing restricts how the workstation uses network protocols (2.5.3.5)."
  - cis: "2.3.9"
    ecc: ["2-5-3"]
    why: "SMB server settings restrict the network services the workstation offers (2.5.3.5)."
  - cis: "2.3.10"
    ecc: ["2-5-3"]
    why: "Network access rules block anonymous enumeration and share access (2.5.3.5)."
  - cis: "2.3.11"
    ecc: ["2-2-3"]
    why: "Network security settings choose the authentication protocols (NTLM, Kerberos) (2.2.3.1)."
  - cis: "2.3.17"
    ecc: ["2-2-3"]
    why: "User Account Control limits use of administrator rights (2.2.3.4 privileged access)."

  # 5 System Services
  - cis: "5"
    ecc: ["2-5-3"]
    why: "Disabling unneeded services reduces the network services and ports exposed (2.5.3.5)."

  # 9 Windows Defender Firewall
  - cis: "9"
    ecc: ["2-5-3"]
    why: "The host firewall controls inbound connections and network isolation (2.5.3.1, 2.5.3.5)."
  - {cis: "9.1.4", ecc: ["2-5-3", "2-12-3"], why: "Firewall log file (domain profile) is a security event log (2.12.3.1)."}
  - {cis: "9.1.5", ecc: ["2-5-3", "2-12-3"], why: "Firewall log size (domain profile) keeps enough history (2.12.3.1)."}
  - {cis: "9.1.6", ecc: ["2-5-3", "2-12-3"], why: "Logging dropped packets (domain profile) records blocked traffic (2.12.3.1)."}
  - {cis: "9.1.7", ecc: ["2-5-3", "2-12-3"], why: "Logging allowed connections (domain profile) records network activity (2.12.3.1)."}
  - {cis: "9.2.4", ecc: ["2-5-3", "2-12-3"], why: "Firewall log file (private profile) is a security event log (2.12.3.1)."}
  - {cis: "9.2.5", ecc: ["2-5-3", "2-12-3"], why: "Firewall log size (private profile) keeps enough history (2.12.3.1)."}
  - {cis: "9.2.6", ecc: ["2-5-3", "2-12-3"], why: "Logging dropped packets (private profile) records blocked traffic (2.12.3.1)."}
  - {cis: "9.2.7", ecc: ["2-5-3", "2-12-3"], why: "Logging allowed connections (private profile) records network activity (2.12.3.1)."}
  - {cis: "9.3.6", ecc: ["2-5-3", "2-12-3"], why: "Firewall log file (public profile) is a security event log (2.12.3.1)."}
  - {cis: "9.3.7", ecc: ["2-5-3", "2-12-3"], why: "Firewall log size (public profile) keeps enough history (2.12.3.1)."}
  - {cis: "9.3.8", ecc: ["2-5-3", "2-12-3"], why: "Logging dropped packets (public profile) records blocked traffic (2.12.3.1)."}
  - {cis: "9.3.9", ecc: ["2-5-3", "2-12-3"], why: "Logging allowed connections (public profile) records network activity (2.12.3.1)."}

  # 17 Advanced Audit Policy
  - cis: "17"
    ecc: ["2-12-3"]
    why: "Audit policy turns on the security event logs ECC requires (2.12.3.1, 2.12.3.2)."

  # 18 Administrative Templates (Computer)
  - cis: "18"
    ecc: ["2-3-2"]
    why: "Administrative template settings harden the workstation, part of implementing 2-3."
  - {cis: "18.4.3", ecc: ["2-5-3"], why: "Disabling the SMBv1 client removes an insecure network protocol (2.5.3.5)."}
  - {cis: "18.4.4", ecc: ["2-5-3"], why: "Disabling the SMBv1 server removes an insecure network protocol (2.5.3.5)."}
  - cis: "18.5"
    ecc: ["2-5-3"]
    why: "MSS settings harden the TCP/IP and NetBIOS network stack (2.5.3.5)."
  - {cis: "18.5.1", ecc: ["2-2-3"], why: "Automatic logon would bypass sign-in entirely (2.2.3.1)."}
  - {cis: "18.5.4", ecc: ["2-2-3"], why: "Saved dial-up passwords weaken password-based sign-in (2.2.3.1)."}
  - {cis: "18.5.9", ecc: ["2-3-2"], why: "Safe DLL search mode hardens how programs load code."}
  - {cis: "18.5.10", ecc: ["2-2-3"], why: "The screen saver grace period decides how fast a locked screen needs a password (2.2.3.1)."}
  - {cis: "18.5.13", ecc: ["2-12-3"], why: "A warning before the security log fills up protects event logs (2.12.3.1)."}
  - cis: "18.6"
    ecc: ["2-5-3"]
    why: "Network settings cover DNS over HTTPS, guest logons, bridges and wireless (2.5.3.4, 2.5.3.5, 2.5.3.7)."
  - cis: "18.9.3"
    ecc: ["2-12-3"]
    why: "Recording command lines in process creation events improves monitoring (2.12.3.1)."
  - cis: "18.9.4"
    ecc: ["2-2-3"]
    why: "Credential delegation settings protect credentials used for remote sign-in (2.2.3.2)."
  - cis: "18.9.7"
    ecc: ["2-3-3"]
    why: "Device installation restrictions limit what hardware, including external media, can be attached (2.3.3.2)."
  - cis: "18.9.13"
    ecc: ["2-3-3"]
    why: "Early Launch Antimalware protects the boot process from malicious drivers (2.3.3.1)."
  - cis: "18.9.25"
    ecc: ["2-2-3"]
    why: "LAPS manages the local administrator password (2.2.3.4 privileged access)."
  - cis: "18.9.26"
    ecc: ["2-2-3"]
    why: "Protecting LSASS keeps stored sign-in credentials from being stolen (2.2.3.1)."
  - cis: "18.9.28"
    ecc: ["2-2-3"]
    why: "Logon settings control which sign-in methods are allowed (2.2.3.1)."
  - cis: "18.9.33"
    ecc: ["2-2-3"]
    why: "Power settings require a password when the computer wakes (2.2.3.1)."
  - cis: "18.9.35"
    ecc: ["2-5-3"]
    why: "Remote Assistance is a remote access service that should be restricted (2.5.3.5)."
  - cis: "18.9.36"
    ecc: ["2-5-3"]
    why: "RPC settings restrict unauthenticated network RPC clients (2.5.3.5)."
  - cis: "18.9.51"
    ecc: ["2-3-3"]
    why: "The Windows NTP client keeps the clock synchronised with a trusted source (2.3.3.4)."
  - cis: "18.10.7"
    ecc: ["2-3-3"]
    why: "Turning off AutoPlay restricts external storage media (2.3.3.2)."
  - cis: "18.10.8"
    ecc: ["2-2-3"]
    why: "Anti-spoofing for facial recognition protects biometric sign-in (2.2.3.1)."
  - cis: "18.10.9"
    ecc: ["2-8-3"]
    why: "BitLocker encrypts data at rest (2.8.3.3)."
  - cis: "18.10.9.3"
    ecc: ["2-8-3", "2-3-3"]
    why: "BitLocker on removable drives encrypts data and restricts external media (2.8.3.3, 2.3.3.2)."
  - cis: "18.10.14"
    ecc: ["2-2-3"]
    why: "Credential UI settings stop passwords and admin accounts from being revealed (2.2.3.1)."
  - cis: "18.10.15"
    ecc: ["2-7-2"]
    why: "Limiting diagnostic data sent to the vendor protects the entity's data (2-7)."
  - cis: "18.10.25"
    ecc: ["2-12-3"]
    why: "Event log size and retention settings keep security events available (2.12.3.1, 2.12.3.5)."
  - cis: "18.10.41"
    ecc: ["2-2-3"]
    why: "Blocking consumer Microsoft account sign-in keeps identities under the entity's control (2.2.3.1)."
  - cis: "18.10.42"
    ecc: ["2-3-3"]
    why: "Microsoft Defender Antivirus protects the workstation from malware (2.3.3.1)."
  - cis: "18.10.43"
    ecc: ["2-3-3"]
    why: "Defender Application Guard isolates untrusted browsing from the system (2.3.3.1)."
  - cis: "18.10.50"
    ecc: ["2-7-2"]
    why: "Blocking OneDrive file storage stops data leaving to unmanaged cloud storage (2-7)."
  - cis: "18.10.56"
    ecc: ["2-5-3"]
    why: "Remote Desktop Services settings restrict and secure remote access (2.5.3.5)."
  - cis: "18.10.75"
    ecc: ["2-5-3"]
    why: "Phishing protection and SmartScreen secure web browsing (2.5.3.3, 2.5.3.8)."
  - cis: "18.10.81"
    ecc: ["2-2-3"]
    why: "Logon options stop automatic sign-in after a restart (2.2.3.1)."
  - cis: "18.10.86"
    ecc: ["2-12-3"]
    why: "PowerShell script block logging and transcription record script activity (2.12.3.1)."
  - cis: "18.10.88"
    ecc: ["2-5-3"]
    why: "WinRM settings block basic authentication and unencrypted remote management (2.5.3.5)."
  - cis: "18.10.89"
    ecc: ["2-5-3"]
    why: "Turning off Remote Shell restricts remote command execution (2.5.3.5)."
  - cis: "18.10.91"
    ecc: ["2-3-3"]
    why: "Stopping users from changing Windows Security settings keeps malware protection on (2.3.3.1)."
  - cis: "18.10.92"
    ecc: ["2-3-3"]
    why: "Windows Update settings keep the system patched (2.3.3.3)."

facts:
  - fact: vulnerabilities
    ecc: ["2-10-3"]
  - fact: log_retention
    ecc: ["2-12-3"]
```

- [ ] **Step 4: Run the tests to make sure they pass**

Run: `.venv/Scripts/python -m pytest tests/test_mapping_data.py -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add data/mapping.yaml tests/test_mapping_data.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Map all 482 CIS checks to ECC-2:2024 controls"
```

---

### Task 7: Named facts

**Files:**
- Create: `ecc/facts.py`
- Test: `tests/test_facts.py`

**Interfaces:**
- Consumes: `Snapshot`, `Status`, `FactName`.
- Produces: `RETENTION_DAYS = 365`; `@dataclass(frozen=True) FactResult(name: FactName, status: Status, detail: str)`; `rate_vulnerabilities(snapshot)`, `rate_log_retention(snapshot)`, `rate_fact(name, snapshot) -> FactResult`. `detail` strings carry no trailing full stop.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_facts.py`:

```python
from ecc.facts import rate_fact, rate_log_retention, rate_vulnerabilities
from ecc.models import Snapshot, Status
from tests.fixtures import BASELINE


def snapshot(**changes) -> Snapshot:
    return Snapshot.model_validate({**BASELINE, **changes})


def counts(critical: int = 0, high: int = 0) -> dict[str, int]:
    return {"critical": critical, "high": high, "medium": 4, "low": 1}


def test_no_critical_or_high_vulnerabilities_is_implemented():
    result = rate_vulnerabilities(snapshot(vulnerabilities=counts()))
    assert result.status is Status.IMPLEMENTED
    assert result.detail == "Open vulnerabilities: 0 critical, 0 high, 4 medium, 1 low"


def test_high_but_no_critical_is_partial():
    assert rate_vulnerabilities(snapshot(vulnerabilities=counts(high=2))).status is Status.PARTIAL


def test_any_critical_is_not_implemented():
    result = rate_vulnerabilities(snapshot(vulnerabilities=counts(critical=1)))
    assert result.status is Status.NOT_IMPLEMENTED


def test_a_year_of_logs_is_implemented():
    logging = {"oldest_alert": "2025-10-12T18:00:00Z", "agent_active": True}
    assert rate_log_retention(snapshot(logging=logging)).status is Status.IMPLEMENTED


def test_short_retention_with_an_active_agent_is_partial():
    result = rate_log_retention(snapshot())
    assert result.status is Status.PARTIAL
    assert result.detail == "Oldest stored alert is 10 days old; ECC asks for 365 (2.12.3.5)"


def test_short_retention_with_a_silent_agent_is_not_implemented():
    logging = {"oldest_alert": "2026-10-02T18:00:00Z", "agent_active": False}
    assert rate_log_retention(snapshot(logging=logging)).status is Status.NOT_IMPLEMENTED


def test_no_stored_alerts_is_not_implemented():
    logging = {"oldest_alert": None, "agent_active": True}
    assert rate_log_retention(snapshot(logging=logging)).status is Status.NOT_IMPLEMENTED


def test_rate_fact_dispatches_by_name():
    assert rate_fact("vulnerabilities", snapshot()).name == "vulnerabilities"
    assert rate_fact("log_retention", snapshot()).name == "log_retention"
```

- [ ] **Step 2: Run the tests to make sure they fail**

Run: `.venv/Scripts/python -m pytest tests/test_facts.py -v`
Expected: `ModuleNotFoundError: No module named 'ecc.facts'`.

- [ ] **Step 3: Write the facts**

Create `ecc/facts.py`:

```python
"""Named facts: ratings computed from snapshot data rather than from CIS checks."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ecc.models import FactName, Snapshot, Status

RETENTION_DAYS = 365


@dataclass(frozen=True)
class FactResult:
    name: FactName
    status: Status
    detail: str


def rate_vulnerabilities(snapshot: Snapshot) -> FactResult:
    counts = snapshot.vulnerabilities
    detail = (
        f"Open vulnerabilities: {counts.critical} critical, {counts.high} high, "
        f"{counts.medium} medium, {counts.low} low"
    )
    if counts.critical == 0 and counts.high == 0:
        status = Status.IMPLEMENTED
    elif counts.critical == 0:
        status = Status.PARTIAL
    else:
        status = Status.NOT_IMPLEMENTED
    return FactResult("vulnerabilities", status, detail)


def rate_log_retention(snapshot: Snapshot) -> FactResult:
    oldest = snapshot.logging.oldest_alert
    if oldest is None:
        return FactResult("log_retention", Status.NOT_IMPLEMENTED, "No stored alerts were found")
    days = (snapshot.taken_at - oldest).days
    detail = f"Oldest stored alert is {days} days old; ECC asks for {RETENTION_DAYS} (2.12.3.5)"
    if days >= RETENTION_DAYS:
        status = Status.IMPLEMENTED
    elif snapshot.logging.agent_active:
        status = Status.PARTIAL
    else:
        status = Status.NOT_IMPLEMENTED
    return FactResult("log_retention", status, detail)


RATERS: dict[str, Callable[[Snapshot], FactResult]] = {
    "vulnerabilities": rate_vulnerabilities,
    "log_retention": rate_log_retention,
}


def rate_fact(name: FactName, snapshot: Snapshot) -> FactResult:
    return RATERS[name](snapshot)
```

- [ ] **Step 4: Run the tests to make sure they pass**

Run: `.venv/Scripts/python -m pytest tests/test_facts.py -v`
Expected: 8 passed.

- [ ] **Step 5: Lint and commit**

```bash
.venv/Scripts/python -m ruff check .
git add ecc/facts.py tests/test_facts.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Rate vulnerabilities and log retention as named facts"
```

---

### Task 8: Assessment engine

**Files:**
- Create: `ecc/assess.py`
- Test: `tests/test_assess.py`

**Interfaces:**
- Consumes: `Dataset`; `checks_by_control`, `facts_by_control`; `rate_fact`, `FactResult`; `RANKED`, `Status`, `weakest`.
- Produces: `CheckOutcome(check: CisCheck, result: str)`; `ControlResult(control, status, technical, documentary, checks, facts, evidence, na_reason)` with `.is_gap` and `.summary`; `Assessment(snapshot, results)` with `.result(control_id)`; `Change(control, before, after)`; `rate_checks(results) -> Status | None`; `technical_rating(checks, facts)`; `assess(dataset, snapshot) -> Assessment`; `compliance(results) -> float | None` (one decimal); `domain_scores(assessment) -> dict[int, float | None]`; `compare(before, after) -> tuple[Change, ...]`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_assess.py`:

```python
import pytest

from ecc.assess import assess, compare, compliance, domain_scores, rate_checks
from ecc.models import Status


@pytest.mark.parametrize(
    ("results", "expected"),
    [
        (["passed", "passed"], Status.IMPLEMENTED),
        (["passed", "failed"], Status.PARTIAL),
        (["failed", "failed"], Status.NOT_IMPLEMENTED),
        (["passed", "not applicable", "not scanned"], Status.IMPLEMENTED),
        (["not applicable", "not scanned"], None),
        ([], None),
    ],
)
def test_rate_checks(results, expected):
    assert rate_checks(results) == expected


def statuses(assessment):
    return {result.control.id: result.status for result in assessment.results}


def test_baseline_statuses(dataset, baseline):
    assert statuses(assess(dataset, baseline)) == {
        "1-3-1": Status.PARTIAL,  # documents only
        "2-2-1": Status.IMPLEMENTED,  # documents only
        "2-2-3": Status.PARTIAL,  # one of two checks passed
        "2-12-3": Status.NOT_IMPLEMENTED,  # weaker of failed checks and approved policy
        "4-2-1": Status.NOT_APPLICABLE,
    }


def test_a_control_gets_the_weaker_of_technical_and_documentary(dataset, baseline):
    result = assess(dataset, baseline).result("2-12-3")
    assert result.technical is Status.NOT_IMPLEMENTED
    assert result.documentary is Status.IMPLEMENTED
    assert [fact.name for fact in result.facts] == ["log_retention"]
    assert [(o.check.id, o.result) for o in result.checks] == [
        (26139, "failed"),
        (26140, "not applicable"),
    ]


def test_after_statuses(dataset, after):
    found = statuses(assess(dataset, after))
    assert found["2-2-3"] is Status.IMPLEMENTED
    assert found["2-12-3"] is Status.PARTIAL  # checks pass, but logs are kept only 18 days


def test_missing_results_count_as_not_scanned(dataset, baseline):
    trimmed = baseline.model_copy(update={"checks": baseline.checks[:1]})
    result = assess(dataset, trimmed).result("2-2-3")
    assert [outcome.result for outcome in result.checks] == ["failed", "not scanned"]
    assert result.status is Status.NOT_IMPLEMENTED


def test_summary_lines(dataset, baseline):
    assessment = assess(dataset, baseline)
    assert assessment.result("2-2-3").summary == "1 of 2 CIS checks passed"
    assert assessment.result("2-2-1").summary == (
        "Access control policy approved. (docs/policies/access-control.md)"
    )
    assert assessment.result("4-2-1").summary == "The company uses no cloud hosting."


def test_compliance_and_domain_scores(dataset, baseline, after):
    before_assessment = assess(dataset, baseline)
    after_assessment = assess(dataset, after)
    assert compliance(before_assessment.results) == 50.0
    assert compliance(after_assessment.results) == 75.0
    assert domain_scores(before_assessment) == {1: 50.0, 2: 50.0, 4: None}
    assert domain_scores(after_assessment) == {1: 50.0, 2: 83.3, 4: None}


def test_compare_lists_changed_controls(dataset, baseline, after):
    changes = compare(assess(dataset, baseline), assess(dataset, after))
    assert [(c.control.id, c.before, c.after) for c in changes] == [
        ("2-2-3", Status.PARTIAL, Status.IMPLEMENTED),
        ("2-12-3", Status.NOT_IMPLEMENTED, Status.PARTIAL),
    ]
```

- [ ] **Step 2: Run the tests to make sure they fail**

Run: `.venv/Scripts/python -m pytest tests/test_assess.py -v`
Expected: `ModuleNotFoundError: No module named 'ecc.assess'`.

- [ ] **Step 3: Write the assessment engine**

Create `ecc/assess.py`:

```python
"""Rate every ECC control from check results, facts and documentary evidence."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ecc.facts import FactResult, rate_fact
from ecc.load import Dataset
from ecc.mapping import checks_by_control, facts_by_control
from ecc.models import RANKED, CisCheck, Control, EvidenceEntry, Snapshot, Status, weakest

USABLE = ("passed", "failed")
POINTS = {Status.IMPLEMENTED: 1.0, Status.PARTIAL: 0.5, Status.NOT_IMPLEMENTED: 0.0}


@dataclass(frozen=True)
class CheckOutcome:
    check: CisCheck
    result: str


@dataclass(frozen=True)
class ControlResult:
    control: Control
    status: Status | None
    technical: Status | None
    documentary: Status | None
    checks: tuple[CheckOutcome, ...]
    facts: tuple[FactResult, ...]
    evidence: EvidenceEntry | None
    na_reason: str | None

    @property
    def is_gap(self) -> bool:
        return self.status in (Status.PARTIAL, Status.NOT_IMPLEMENTED)

    @property
    def summary(self) -> str:
        """One line of evidence, shared by the workbook and the report."""
        parts: list[str] = []
        usable = [outcome for outcome in self.checks if outcome.result in USABLE]
        if usable:
            passed = sum(outcome.result == "passed" for outcome in usable)
            parts.append(f"{passed} of {len(usable)} CIS checks passed")
        elif self.checks:
            skipped = len(self.checks)
            parts.append(f"No usable CIS results ({skipped} not applicable or not scanned)")
        parts.extend(fact.detail for fact in self.facts)
        if self.evidence is not None:
            documents = ", ".join(self.evidence.documents)
            note = self.evidence.note
            parts.append(f"{note} ({documents})" if documents else note)
        if self.na_reason is not None:
            parts.append(self.na_reason)
        return "; ".join(parts)


@dataclass(frozen=True)
class Assessment:
    snapshot: Snapshot
    results: tuple[ControlResult, ...]

    def result(self, control_id: str) -> ControlResult:
        for result in self.results:
            if result.control.id == control_id:
                return result
        raise KeyError(control_id)


@dataclass(frozen=True)
class Change:
    control: Control
    before: Status | None
    after: Status | None


def rate_checks(results: Iterable[str]) -> Status | None:
    usable = [result for result in results if result in USABLE]
    if not usable:
        return None
    passed = usable.count("passed")
    if passed == len(usable):
        return Status.IMPLEMENTED
    if passed == 0:
        return Status.NOT_IMPLEMENTED
    return Status.PARTIAL


def technical_rating(
    checks: Iterable[CheckOutcome], facts: Iterable[FactResult]
) -> Status | None:
    """The weakest of the checks rating and every fact rating; None if there are none."""
    ratings = [fact.status for fact in facts]
    from_checks = rate_checks(outcome.result for outcome in checks)
    if from_checks is not None:
        ratings.append(from_checks)
    return weakest(*ratings) if ratings else None


def assess(dataset: Dataset, snapshot: Snapshot) -> Assessment:
    results = {check.id: check.result for check in snapshot.checks}
    checks = checks_by_control(dataset.policy, dataset.mapping)
    facts = facts_by_control(dataset.mapping)
    evidence = {entry.control: entry for entry in dataset.evidence.entries}
    not_applicable = {item.control: item.reason for item in dataset.applicability.not_applicable}
    rated: list[ControlResult] = []
    for control in dataset.catalog:
        outcomes = tuple(
            CheckOutcome(check, results.get(check.id, "not scanned"))
            for check in checks.get(control.id, [])
        )
        fact_results = tuple(rate_fact(name, snapshot) for name in facts.get(control.id, []))
        entry = evidence.get(control.id)
        reason = not_applicable.get(control.id)
        technical = technical_rating(outcomes, fact_results)
        documentary = entry.status if entry is not None else None
        status: Status | None
        if reason is not None:
            status = Status.NOT_APPLICABLE
        else:
            found = [rating for rating in (technical, documentary) if rating is not None]
            status = weakest(*found) if found else None
        rated.append(
            ControlResult(
                control=control,
                status=status,
                technical=technical,
                documentary=documentary,
                checks=outcomes,
                facts=fact_results,
                evidence=entry,
                na_reason=reason,
            )
        )
    return Assessment(snapshot, tuple(rated))


def compliance(results: Iterable[ControlResult]) -> float | None:
    """Percent of applicable controls met, counting Partially implemented as half."""
    statuses = [result.status for result in results if result.status in RANKED]
    if not statuses:
        return None
    return round(100 * sum(POINTS[status] for status in statuses) / len(statuses), 1)


def domain_scores(assessment: Assessment) -> dict[int, float | None]:
    domains = sorted({result.control.domain for result in assessment.results})
    return {
        domain: compliance(r for r in assessment.results if r.control.domain == domain)
        for domain in domains
    }


def compare(before: Assessment, after: Assessment) -> tuple[Change, ...]:
    old = {result.control.id: result.status for result in before.results}
    return tuple(
        Change(result.control, old.get(result.control.id), result.status)
        for result in after.results
        if old.get(result.control.id) != result.status
    )
```

- [ ] **Step 4: Run the tests to make sure they pass**

Run: `.venv/Scripts/python -m pytest tests/test_assess.py -v`
Expected: 13 passed.

- [ ] **Step 5: Lint and commit**

```bash
.venv/Scripts/python -m ruff check .
git add ecc/assess.py tests/test_assess.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Rate controls, score compliance and compare snapshots"
```

---

### Task 9: Validation

**Files:**
- Create: `ecc/validate.py`
- Test: `tests/test_validate.py`

**Interfaces:**
- Consumes: `Dataset`, `assess`, mapping checks.
- Produces: `listed(label, items) -> str` (shows 15 items then `, and N more`); `duplicates(values) -> list[str]`; `validate(dataset, snapshots) -> list[str]` (empty when everything is consistent).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_validate.py`:

```python
import json
from pathlib import Path

from ecc.load import load_dataset, load_snapshots
from ecc.validate import listed, validate
from tests.fixtures import EVIDENCE, MAPPING, RISKS, rewrite


def problems(root: Path) -> list[str]:
    return validate(load_dataset(root), load_snapshots(root / "snapshots"))


def test_the_fixture_is_valid(root):
    assert problems(root) == []


def test_long_lists_are_shortened():
    text = listed("things", [str(n) for n in range(20)])
    assert text.startswith("things (20): 0, 1, 2")
    assert text.endswith(", and 5 more")


def test_unmapped_checks_and_unused_rules(root):
    rules = [MAPPING["rules"][0], {"cis": "9", "ecc": ["2-12-3"], "why": "Firewall rules."}]
    rewrite(root, "mapping.yaml", {**MAPPING, "rules": rules})
    found = problems(root)
    assert "mapping.yaml: checks with no rule (2): 26139 (17.1.1), 26140 (17.2.1)" in found
    assert "mapping.yaml: rules that match no check (1): 9" in found


def test_unknown_target_controls(root):
    rules = [{**MAPPING["rules"][0], "ecc": ["2-2-9"]}, MAPPING["rules"][1]]
    rewrite(root, "mapping.yaml", {**MAPPING, "rules": rules})
    assert "mapping.yaml: unknown ECC controls (1): 2-2-9" in problems(root)


def test_missing_documents(root):
    (root / "docs" / "policies" / "logging.md").unlink()
    expected = "evidence.yaml: documents that do not exist (1): docs/policies/logging.md"
    assert expected in problems(root)


def test_evidence_for_a_not_applicable_control(root):
    entry = {"control": "4-2-1", "status": "Implemented", "note": "Cloud policy."}
    rewrite(root, "evidence.yaml", {"entries": [*EVIDENCE["entries"], entry]})
    assert "evidence.yaml: entries for Not applicable controls (1): 4-2-1" in problems(root)


def test_controls_without_any_rating(root):
    rewrite(root, "evidence.yaml", {"entries": EVIDENCE["entries"][1:]})
    found = problems(root)
    label = "controls with no rating (add them to evidence.yaml) (1): 1-3-1"
    assert f"snapshot 'baseline': {label}" in found
    assert f"snapshot 'after': {label}" in found


def test_gaps_without_a_risk(root):
    rewrite(root, "risks.yaml", {"risks": RISKS["risks"][1:]})
    found = problems(root)
    assert "snapshot 'baseline': gaps with no risk in risks.yaml (1): 2-2-3" in found
    assert not any(problem.startswith("snapshot 'after': gaps") for problem in found)


def test_a_snapshot_from_another_policy(root):
    path = root / "snapshots" / "2026-10-baseline.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["policy"]["id"] = "other_policy"
    path.write_text(json.dumps(data), encoding="utf-8")
    expected = (
        "snapshot 'baseline': policy other_policy does not match cis_checks.yaml "
        "(cis_win11_enterprise)"
    )
    assert expected in problems(root)


def test_duplicate_snapshot_labels(root):
    source = (root / "snapshots" / "2026-10-baseline.json").read_text(encoding="utf-8")
    (root / "snapshots" / "2026-11-baseline.json").write_text(source, encoding="utf-8")
    assert "snapshots: labels used twice (1): baseline" in problems(root)
```

- [ ] **Step 2: Run the tests to make sure they fail**

Run: `.venv/Scripts/python -m pytest tests/test_validate.py -v`
Expected: `ModuleNotFoundError: No module named 'ecc.validate'`.

- [ ] **Step 3: Write the validator**

Create `ecc/validate.py`:

```python
"""Cross-file checks. Every problem is collected, so one run shows them all."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence

from ecc.assess import assess
from ecc.load import Dataset
from ecc.mapping import duplicate_rules, unmapped_checks, unused_rules
from ecc.models import Snapshot

SHOWN = 15


def listed(label: str, items: Sequence[str]) -> str:
    shown = ", ".join(items[:SHOWN])
    more = len(items) - SHOWN
    return f"{label} ({len(items)}): {shown}" + (f", and {more} more" if more > 0 else "")


def duplicates(values: Iterable[str]) -> list[str]:
    return sorted(value for value, count in Counter(values).items() if count > 1)


def validate(dataset: Dataset, snapshots: Sequence[Snapshot]) -> list[str]:
    problems: list[str] = []

    def report(label: str, items: Sequence[str]) -> None:
        if items:
            problems.append(listed(label, items))

    known = {control.id for control in dataset.catalog}
    report("catalog.yaml: duplicate control ids", duplicates(c.id for c in dataset.catalog))

    mapping = dataset.mapping
    report("mapping.yaml: duplicate rules", duplicate_rules(mapping))
    unmapped = unmapped_checks(dataset.policy, mapping)
    report("mapping.yaml: checks with no rule", [f"{c.id} ({c.cis})" for c in unmapped])
    unused = unused_rules(dataset.policy, mapping)
    report("mapping.yaml: rules that match no check", [rule.cis for rule in unused])
    targets = {target for rule in mapping.rules for target in rule.ecc}
    targets |= {target for link in mapping.facts for target in link.ecc}
    report("mapping.yaml: unknown ECC controls", sorted(targets - known))

    not_applicable = [item.control for item in dataset.applicability.not_applicable]
    report("applicability.yaml: unknown ECC controls", sorted(set(not_applicable) - known))
    report("applicability.yaml: controls listed twice", duplicates(not_applicable))

    entries = dataset.evidence.entries
    documented = [entry.control for entry in entries]
    report("evidence.yaml: unknown ECC controls", sorted(set(documented) - known))
    report("evidence.yaml: controls listed twice", duplicates(documented))
    report(
        "evidence.yaml: entries for Not applicable controls",
        sorted(set(documented) & set(not_applicable)),
    )
    missing = {
        document
        for entry in entries
        for document in entry.documents
        if not (dataset.root / document).is_file()
    }
    report("evidence.yaml: documents that do not exist", sorted(missing))

    risks = dataset.risks.risks
    covered = {control for risk in risks for control in risk.controls}
    report("risks.yaml: risk ids used twice", duplicates(risk.id for risk in risks))
    report("risks.yaml: unknown ECC controls", sorted(covered - known))

    report("snapshots: labels used twice", duplicates(s.label for s in snapshots))
    check_ids = {check.id for check in dataset.policy.checks}
    expected_policy = dataset.policy.policy.id
    for snapshot in snapshots:
        name = f"snapshot '{snapshot.label}'"
        if snapshot.policy.id != expected_policy:
            problems.append(
                f"{name}: policy {snapshot.policy.id} does not match cis_checks.yaml "
                f"({expected_policy})"
            )
        if snapshot.policy.checks_total != len(check_ids):
            problems.append(
                f"{name}: expects {snapshot.policy.checks_total} checks, "
                f"cis_checks.yaml has {len(check_ids)}"
            )
        extra = sorted({check.id for check in snapshot.checks} - check_ids)
        report(f"{name}: unknown check ids", [str(check_id) for check_id in extra])
        results = assess(dataset, snapshot).results
        report(
            f"{name}: controls with no rating (add them to evidence.yaml)",
            [r.control.id for r in results if r.status is None],
        )
        report(
            f"{name}: gaps with no risk in risks.yaml",
            [r.control.id for r in results if r.is_gap and r.control.id not in covered],
        )
    return problems
```

- [ ] **Step 4: Run the tests to make sure they pass**

Run: `.venv/Scripts/python -m pytest tests/test_validate.py -v`
Expected: 10 passed.

- [ ] **Step 5: Lint and commit**

```bash
.venv/Scripts/python -m ruff check .
git add ecc/validate.py tests/test_validate.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Validate data files and snapshots, collecting every problem"
```

---

### Task 10: Risk helpers

**Files:**
- Create: `ecc/risk.py`
- Test: `tests/test_risk.py`

**Interfaces:**
- Consumes: `Assessment`, `Risk`, `RiskRegister`, `Status`.
- Produces: `rating(score) -> str` (`Low` 1–4, `Medium` 5–9, `High` 10–16, `Critical` 20–25); `bucket(due, as_of) -> str` (`30 days`, `60 days`, `90 days`, `Later`; overdue counts as `30 days`); `BUCKET_ORDER`; `RiskRow(risk, score, rating, closed, bucket)`; `risk_rows(register, assessment) -> list[RiskRow]` (score descending, then id; `closed` when every linked control is Implemented or Not applicable); `roadmap(rows) -> list[RiskRow]` (open rows, soonest bucket first).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_risk.py`:

```python
from datetime import date, timedelta

import pytest

from ecc.assess import assess
from ecc.risk import BUCKET_ORDER, bucket, rating, risk_rows, roadmap


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (1, "Low"),
        (4, "Low"),
        (5, "Medium"),
        (9, "Medium"),
        (10, "High"),
        (16, "High"),
        (20, "Critical"),
        (25, "Critical"),
    ],
)
def test_rating_bands(score, expected):
    assert rating(score) == expected


def test_rating_rejects_zero():
    with pytest.raises(ValueError):
        rating(0)


@pytest.mark.parametrize(
    ("days", "expected"),
    [(-5, "30 days"), (30, "30 days"), (31, "60 days"), (60, "60 days"), (90, "90 days"),
     (91, "Later")],
)
def test_buckets(days, expected):
    as_of = date(2026, 10, 12)
    assert bucket(as_of + timedelta(days=days), as_of) == expected


def test_bucket_order():
    assert BUCKET_ORDER == ("30 days", "60 days", "90 days", "Later")


def test_rows_are_sorted_by_score(dataset, baseline):
    rows = risk_rows(dataset.risks, assess(dataset, baseline))
    assert [(row.risk.id, row.score, row.rating) for row in rows] == [
        ("R-02", 16, "High"),
        ("R-01", 12, "High"),
        ("R-03", 4, "Low"),
    ]
    assert [row.bucket for row in rows] == ["90 days", "30 days", "Later"]
    assert not any(row.closed for row in rows)


def test_a_risk_closes_when_its_controls_are_implemented(dataset, after):
    rows = risk_rows(dataset.risks, assess(dataset, after))
    assert {row.risk.id: row.closed for row in rows} == {
        "R-01": True,
        "R-02": False,
        "R-03": False,
    }
    assert [(row.bucket, row.risk.id) for row in roadmap(rows)] == [
        ("60 days", "R-02"),
        ("Later", "R-03"),
    ]
```

- [ ] **Step 2: Run the tests to make sure they fail**

Run: `.venv/Scripts/python -m pytest tests/test_risk.py -v`
Expected: `ModuleNotFoundError: No module named 'ecc.risk'`.

- [ ] **Step 3: Write the risk helpers**

Create `ecc/risk.py`:

```python
"""Risk ratings, roadmap buckets and the rows shared by the workbook and the report."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date

from ecc.assess import Assessment
from ecc.models import Risk, RiskRegister, Status

BANDS = ((20, "Critical"), (10, "High"), (5, "Medium"), (1, "Low"))
BUCKETS = ((30, "30 days"), (60, "60 days"), (90, "90 days"))
LATER = "Later"
BUCKET_ORDER = (*(name for _, name in BUCKETS), LATER)
DONE = (Status.IMPLEMENTED, Status.NOT_APPLICABLE)


def rating(score: int) -> str:
    for floor, name in BANDS:
        if score >= floor:
            return name
    raise ValueError(f"risk score must be 1-25, got {score}")


def bucket(due: date, as_of: date) -> str:
    days = (due - as_of).days
    for limit, name in BUCKETS:
        if days <= limit:
            return name
    return LATER


@dataclass(frozen=True)
class RiskRow:
    risk: Risk
    score: int
    rating: str
    closed: bool
    bucket: str


def risk_rows(register: RiskRegister, assessment: Assessment) -> list[RiskRow]:
    status = {result.control.id: result.status for result in assessment.results}
    as_of = assessment.snapshot.taken_at.date()
    rows = [
        RiskRow(
            risk=risk,
            score=risk.score,
            rating=rating(risk.score),
            closed=all(status.get(control) in DONE for control in risk.controls),
            bucket=bucket(risk.due, as_of),
        )
        for risk in register.risks
    ]
    return sorted(rows, key=lambda row: (-row.score, row.risk.id))


def roadmap(rows: Iterable[RiskRow]) -> list[RiskRow]:
    """Open risks, soonest bucket first, highest score first within a bucket."""
    open_rows = [row for row in rows if not row.closed]
    return sorted(
        open_rows, key=lambda row: (BUCKET_ORDER.index(row.bucket), -row.score, row.risk.id)
    )
```

- [ ] **Step 4: Run the tests to make sure they pass**

Run: `.venv/Scripts/python -m pytest tests/test_risk.py -v`
Expected: 18 passed.

- [ ] **Step 5: Lint and commit**

```bash
.venv/Scripts/python -m ruff check .
git add ecc/risk.py tests/test_risk.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Add risk ratings, roadmap buckets and risk rows"
```

---

### Task 11: Privacy guard

**Files:**
- Create: `ecc/privacy.py`
- Test: `tests/test_privacy.py`

**Interfaces:**
- Consumes: `Snapshot`.
- Produces: `PrivacyError(Exception)`; `forbidden_terms(env, extra=()) -> list[str]` (from `USERNAME`, `COMPUTERNAME`, comma-separated `ECC_FORBIDDEN_TERMS`, plus `extra`; terms shorter than 3 characters dropped; sorted case-insensitively); `find_leaks(text, terms) -> list[str]` (case-insensitive); `snapshot_json(snapshot) -> str`; `write_snapshot(snapshot, path, terms)` (raises `PrivacyError` on a leak, `FileExistsError` if the file exists; writes LF line endings).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_privacy.py`:

```python
import json

import pytest

from ecc.models import Snapshot
from ecc.privacy import PrivacyError, find_leaks, forbidden_terms, snapshot_json, write_snapshot
from tests.fixtures import BASELINE


def test_terms_come_from_the_environment_and_extras():
    env = {
        "USERNAME": "jdoe",
        "COMPUTERNAME": "DESKTOP-TEST1",
        "ECC_FORBIDDEN_TERMS": " Jane , Doe,,x",
    }
    assert forbidden_terms(env, extra=["lab-agent"]) == [
        "DESKTOP-TEST1",
        "Doe",
        "Jane",
        "jdoe",
        "lab-agent",
    ]


def test_short_and_missing_terms_are_dropped():
    assert forbidden_terms({"USERNAME": "ab"}) == []


def test_leaks_are_found_case_insensitively():
    assert find_leaks('{"label": "jane-test"}', ["Jane", "Doe"]) == ["Jane"]


def test_a_snapshot_is_written_with_the_schema_key(tmp_path):
    snapshot = Snapshot.model_validate(BASELINE)
    path = tmp_path / "snapshots" / "2026-10-baseline.json"
    write_snapshot(snapshot, path, ["Jane"])
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema"] == 1
    assert data["host"] == "WS-01"
    assert path.read_bytes() == snapshot_json(snapshot).encode("utf-8")


def test_a_leak_stops_the_write(tmp_path):
    snapshot = Snapshot.model_validate({**BASELINE, "label": "jane-test"})
    path = tmp_path / "out.json"
    with pytest.raises(PrivacyError, match="1 forbidden term"):
        write_snapshot(snapshot, path, ["Jane"])
    assert not path.exists()


def test_existing_snapshots_are_never_overwritten(tmp_path):
    path = tmp_path / "out.json"
    path.write_text("old", encoding="utf-8")
    with pytest.raises(FileExistsError):
        write_snapshot(Snapshot.model_validate(BASELINE), path, [])
    assert path.read_text(encoding="utf-8") == "old"
```

- [ ] **Step 2: Run the tests to make sure they fail**

Run: `.venv/Scripts/python -m pytest tests/test_privacy.py -v`
Expected: `ModuleNotFoundError: No module named 'ecc.privacy'`.

- [ ] **Step 3: Write the privacy guard**

Create `ecc/privacy.py`:

```python
"""Keep personal names out of snapshots before they reach the disk."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from pathlib import Path

from ecc.models import Snapshot

MIN_TERM_LENGTH = 3


class PrivacyError(Exception):
    """A snapshot still contains a forbidden term, so it was not written."""


def forbidden_terms(env: Mapping[str, str], extra: Iterable[str] = ()) -> list[str]:
    """Names that must never appear in a snapshot: Windows user, computer, and any extras."""
    raw = [
        env.get("USERNAME", ""),
        env.get("COMPUTERNAME", ""),
        *env.get("ECC_FORBIDDEN_TERMS", "").split(","),
        *extra,
    ]
    terms = {term.strip() for term in raw if len(term.strip()) >= MIN_TERM_LENGTH}
    return sorted(terms, key=str.lower)


def find_leaks(text: str, terms: Iterable[str]) -> list[str]:
    lowered = text.lower()
    return [term for term in terms if term.lower() in lowered]


def snapshot_json(snapshot: Snapshot) -> str:
    return snapshot.model_dump_json(by_alias=True, indent=2) + "\n"


def write_snapshot(snapshot: Snapshot, path: Path, terms: Iterable[str]) -> None:
    """Write the snapshot, refusing leaks and never overwriting an existing file."""
    text = snapshot_json(snapshot)
    leaks = find_leaks(text, terms)
    if leaks:
        raise PrivacyError(
            f"Snapshot not written: it contains {len(leaks)} forbidden term(s). Nothing was saved."
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as file:
        file.write(text)
```

- [ ] **Step 4: Run the tests to make sure they pass**

Run: `.venv/Scripts/python -m pytest tests/test_privacy.py -v`
Expected: 6 passed.

- [ ] **Step 5: Lint and commit**

```bash
.venv/Scripts/python -m ruff check .
git add ecc/privacy.py tests/test_privacy.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Refuse snapshots that contain forbidden names"
```

---

### Task 12: Collector

**Files:**
- Create: `ecc/collect.py`
- Test: `tests/test_collect.py`

**Interfaces:**
- Consumes: `HOST_PLACEHOLDER`, `CheckResult`, `CisPolicy`, `LoggingFacts`, `Snapshot`, `SnapshotPolicy`, `VulnerabilityCounts`.
- Produces: `CollectError(Exception)`; `IndexerSettings(url, user, password, ca_cert=None, server_name=None)` with `.from_env(env)` and `.client() -> httpx.Client`; `Indexer(client, server_name=None)` with `.search(index, body)` and `.count(index, query)`; `find_agent(indexer, requested) -> str`; `latest_results(indexer, agent) -> dict[int, str]`; `vulnerability_counts(indexer, agent) -> VulnerabilityCounts`; `parse_timestamp(value) -> datetime`; `logging_facts(indexer, agent, now) -> LoggingFacts`; `build_snapshot(label, now, policy, results, vulnerabilities, logging) -> Snapshot`; `@dataclass(frozen=True) Collected(snapshot: Snapshot, agent: str)`; `collect(indexer, policy, label, now, agent=None) -> Collected`; `snapshot_path(directory, snapshot) -> Path` (`<yyyy-mm>-<label>.json`).

Wazuh facts this code relies on (checked against SENTINEL's recorded alerts): SCA check alerts have `rule.groups: ["sca"]`, `data.sca.type: "check"`, `data.sca.check.id` as a string such as `"26138"`, `data.sca.check.result` (`passed`/`failed`/`not applicable`), `agent.name`, and `timestamp` like `2026-09-27T23:17:30.577+0000`. The indexer certificate in `wazuh-docker` is issued to `DNS:wazuh.indexer` only, hence `WAZUH_TLS_SERVER_NAME`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_collect.py`:

```python
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from ecc.collect import (
    CollectError,
    Indexer,
    IndexerSettings,
    collect,
    find_agent,
    latest_results,
    logging_facts,
    parse_timestamp,
    snapshot_path,
    vulnerability_counts,
)

NOW = datetime(2026, 10, 12, 18, 0, 30, 123456, tzinfo=UTC)
BASE_URL = "https://indexer.test"


def sca(check_id: int, result: str, status: str | None = None) -> dict[str, Any]:
    check: dict[str, Any] = {"id": str(check_id), "result": result}
    if status is not None:
        check["status"] = status
    return {"_source": {"data": {"sca": {"check": check}}}}


def page(docs: list[dict[str, Any]], relation: str = "eq", total: int | None = None) -> dict:
    value = len(docs) if total is None else total
    return {"hits": {"total": {"value": value, "relation": relation}, "hits": docs}}


@dataclass
class FakeIndexer:
    """Answers the queries collect makes, from canned data."""

    agents: tuple[str, ...] = ("lab-agent",)
    sca_hits: list[dict[str, Any]] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    oldest: str | None = "2026-09-28T10:00:00.000+0000"
    recent: int = 5
    relation: str = "eq"
    requests: list[dict[str, Any]] = field(default_factory=list)

    def handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.requests.append(body)
        path = request.url.path
        if path.endswith("/_count"):
            return httpx.Response(200, json={"count": self.recent})
        if "aggs" in body:
            buckets = [{"key": name, "doc_count": 3} for name in self.agents]
            aggregations = {"agents": {"buckets": buckets}}
            return httpx.Response(200, json={**page([]), "aggregations": aggregations})
        if "vulnerabilities" in path:
            return httpx.Response(200, json=page(self.vulnerabilities))
        if body["size"] == 1:
            docs = [] if self.oldest is None else [{"_source": {"timestamp": self.oldest}}]
            return httpx.Response(200, json=page(docs, total=len(docs) * 500))
        return httpx.Response(200, json=page(self.sca_hits, relation=self.relation))

    def indexer(self) -> Indexer:
        transport = httpx.MockTransport(self.handle)
        return Indexer(httpx.Client(transport=transport, base_url=BASE_URL))


def test_settings_need_an_indexer_url():
    with pytest.raises(CollectError, match="WAZUH_INDEXER_URL"):
        IndexerSettings.from_env({})


def test_settings_read_the_environment():
    settings = IndexerSettings.from_env(
        {
            "WAZUH_INDEXER_URL": "https://127.0.0.1:9200/",
            "WAZUH_INDEXER_USER": "admin",
            "WAZUH_INDEXER_PASSWORD": "not-a-real-password",
            "WAZUH_CA_CERT": "root-ca.pem",
            "WAZUH_TLS_SERVER_NAME": "wazuh.indexer",
        }
    )
    assert settings == IndexerSettings(
        "https://127.0.0.1:9200", "admin", "not-a-real-password", "root-ca.pem", "wazuh.indexer"
    )
    assert "not-a-real-password" not in repr(settings)


def test_one_agent_is_picked_automatically():
    assert find_agent(FakeIndexer().indexer(), None) == "lab-agent"


def test_no_agent_is_an_error():
    with pytest.raises(CollectError, match="No agent has SCA results"):
        find_agent(FakeIndexer(agents=()).indexer(), None)


def test_several_agents_need_a_choice():
    fake = FakeIndexer(agents=("agent-a", "agent-b"))
    with pytest.raises(CollectError, match="2 agents"):
        find_agent(fake.indexer(), None)
    assert find_agent(fake.indexer(), "agent-b") == "agent-b"


def test_an_unknown_requested_agent_is_an_error():
    with pytest.raises(CollectError, match="--agent"):
        find_agent(FakeIndexer().indexer(), "other-agent")


def test_the_newest_result_per_check_wins():
    fake = FakeIndexer(sca_hits=[sca(26000, "failed"), sca(26000, "passed"), sca(26001, "passed")])
    assert latest_results(fake.indexer(), "lab-agent") == {26000: "failed", 26001: "passed"}


def test_not_applicable_can_come_from_the_status_field():
    fake = FakeIndexer(sca_hits=[sca(26139, "", status="Not applicable"), sca(26140, "odd")])
    assert latest_results(fake.indexer(), "lab-agent") == {26139: "not applicable"}


def test_cut_off_results_stop_the_collection():
    fake = FakeIndexer(sca_hits=[sca(26000, "passed")], relation="gte")
    with pytest.raises(CollectError, match="cut off"):
        latest_results(fake.indexer(), "lab-agent")


def test_vulnerabilities_are_counted_by_severity():
    severities = ("Critical", "High", "High", "Medium", "Low", "Untriaged")
    docs = [{"_source": {"vulnerability": {"severity": s}}} for s in severities]
    counts = vulnerability_counts(FakeIndexer(vulnerabilities=docs).indexer(), "lab-agent")
    assert counts.model_dump() == {"critical": 1, "high": 2, "medium": 1, "low": 1}


def test_logging_facts():
    facts = logging_facts(FakeIndexer().indexer(), "lab-agent", NOW)
    assert facts.oldest_alert == datetime(2026, 9, 28, 10, 0, tzinfo=UTC)
    assert facts.agent_active is True
    quiet = logging_facts(FakeIndexer(oldest=None, recent=0).indexer(), "lab-agent", NOW)
    assert quiet.oldest_alert is None
    assert quiet.agent_active is False


def test_wazuh_timestamps_parse():
    expected = datetime(2026, 9, 27, 23, 17, 30, 577000, tzinfo=UTC)
    assert parse_timestamp("2026-09-27T23:17:30.577+0000") == expected


def test_collect_builds_an_allowlisted_snapshot(dataset):
    hits = [sca(26000, "failed"), sca(26001, "passed"), sca(99999, "passed")]
    collected = collect(FakeIndexer(sca_hits=hits).indexer(), dataset.policy, "baseline", NOW)
    snapshot = collected.snapshot
    assert collected.agent == "lab-agent"
    assert snapshot.host == "WS-01"
    assert snapshot.taken_at == NOW.replace(microsecond=0)
    assert snapshot.policy.checks_total == 4
    assert [(check.id, check.result) for check in snapshot.checks] == [
        (26000, "failed"),
        (26001, "passed"),
        (26139, "not scanned"),
        (26140, "not scanned"),
    ]
    assert "lab-agent" not in snapshot.model_dump_json()


def test_every_query_is_limited_to_the_agent(dataset):
    fake = FakeIndexer(sca_hits=[sca(26000, "failed")])
    collect(fake.indexer(), dataset.policy, "baseline", NOW)
    queries = [body for body in fake.requests if "aggs" not in body]
    assert len(queries) == 4
    for body in queries:
        assert {"term": {"agent.name": "lab-agent"}} in body["query"]["bool"]["filter"]


def test_an_unreachable_indexer_is_a_clear_error():
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    indexer = Indexer(httpx.Client(transport=httpx.MockTransport(refuse), base_url=BASE_URL))
    with pytest.raises(CollectError, match="Start Docker and Wazuh"):
        find_agent(indexer, None)


def test_a_wrong_password_is_a_clear_error():
    transport = httpx.MockTransport(lambda request: httpx.Response(401))
    indexer = Indexer(httpx.Client(transport=transport, base_url=BASE_URL))
    with pytest.raises(CollectError, match="WAZUH_INDEXER_PASSWORD"):
        find_agent(indexer, None)


def test_the_tls_server_name_is_sent_with_every_request():
    seen = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request.extensions.get("sni_hostname"))
        return httpx.Response(200, json={"count": 0})

    client = httpx.Client(transport=httpx.MockTransport(handle), base_url=BASE_URL)
    Indexer(client, server_name="wazuh.indexer").count("wazuh-alerts-*", {"match_all": {}})
    assert seen == ["wazuh.indexer"]


def test_snapshot_path_uses_the_month_and_label(baseline, tmp_path):
    assert snapshot_path(tmp_path, baseline) == tmp_path / "2026-10-baseline.json"
```

- [ ] **Step 2: Run the tests to make sure they fail**

Run: `.venv/Scripts/python -m pytest tests/test_collect.py -v`
Expected: `ModuleNotFoundError: No module named 'ecc.collect'`.

- [ ] **Step 3: Write the collector**

Create `ecc/collect.py`:

```python
"""Read one agent's CIS check results, vulnerabilities and log facts from the Wazuh indexer."""

from __future__ import annotations

import re
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from ecc.models import (
    HOST_PLACEHOLDER,
    CheckResult,
    CisPolicy,
    LoggingFacts,
    Snapshot,
    SnapshotPolicy,
    VulnerabilityCounts,
)

ALERTS_INDEX = "wazuh-alerts-*"
VULNERABILITIES_INDEX = "wazuh-states-vulnerabilities-*"
MANAGER_AGENT_ID = "000"
MAX_DOCS = 10000
ACTIVE_WINDOW = timedelta(hours=24)
RESULTS = ("passed", "failed", "not applicable")
SEVERITIES = ("critical", "high", "medium", "low")
UNREACHABLE = "Could not reach the Wazuh indexer. Start Docker and Wazuh, then retry."


class CollectError(Exception):
    """Collecting from Wazuh failed; the message says what to do next."""


@dataclass(frozen=True)
class IndexerSettings:
    url: str
    user: str
    password: str = field(repr=False)
    ca_cert: str | None = None
    server_name: str | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> IndexerSettings:
        url = env.get("WAZUH_INDEXER_URL", "").strip()
        if not url:
            raise CollectError(
                "WAZUH_INDEXER_URL is not set. Start Docker and Wazuh, then set "
                "WAZUH_INDEXER_URL, WAZUH_INDEXER_USER and WAZUH_INDEXER_PASSWORD."
            )
        return cls(
            url=url.rstrip("/"),
            user=env.get("WAZUH_INDEXER_USER", ""),
            password=env.get("WAZUH_INDEXER_PASSWORD", ""),
            ca_cert=env.get("WAZUH_CA_CERT") or None,
            server_name=env.get("WAZUH_TLS_SERVER_NAME") or None,
        )

    def client(self) -> httpx.Client:
        verify: ssl.SSLContext | bool = True
        if self.ca_cert:
            try:
                verify = ssl.create_default_context(cafile=self.ca_cert)
            except OSError as error:
                raise CollectError("WAZUH_CA_CERT points to a file that cannot be read.") from error
        return httpx.Client(
            base_url=self.url, auth=(self.user, self.password), verify=verify, timeout=30.0
        )


class Indexer:
    """A thin wrapper over the indexer's search and count APIs."""

    def __init__(self, client: httpx.Client, server_name: str | None = None) -> None:
        self._client = client
        self._extensions = {"sni_hostname": server_name} if server_name else {}

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self._client.post(path, json=body, extensions=self._extensions)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as error:
            code = error.response.status_code
            hint = ""
            if code in (401, 403):
                hint = " Check WAZUH_INDEXER_USER and WAZUH_INDEXER_PASSWORD."
            message = f"The Wazuh indexer answered HTTP {code} for {path}.{hint}"
            raise CollectError(message) from error
        except (httpx.HTTPError, ValueError) as error:
            raise CollectError(UNREACHABLE) from error

    def search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._post(f"/{index}/_search", body)

    def count(self, index: str, query: dict[str, Any]) -> int:
        answer = self._post(f"/{index}/_count", {"query": query})
        try:
            return int(answer["count"])
        except (KeyError, TypeError, ValueError) as error:
            raise CollectError("The Wazuh indexer sent an unexpected count answer.") from error


def hits_of(answer: dict[str, Any], *, complete: bool = True) -> list[dict[str, Any]]:
    """The documents in a search answer. With complete=True, a cut-off answer is an error."""
    try:
        hits = answer["hits"]
        docs = [hit["_source"] for hit in hits["hits"]]
    except (KeyError, TypeError) as error:
        raise CollectError("The Wazuh indexer sent an unexpected search answer.") from error
    total = hits.get("total")
    if isinstance(total, dict):
        cut = total.get("relation") == "gte" or int(total.get("value", 0)) > len(docs)
    else:
        cut = isinstance(total, int) and total > len(docs)
    if complete and cut:
        raise CollectError(
            f"More than {MAX_DOCS} matching documents, so the results would be cut off. "
            "Nothing was saved."
        )
    return docs


def agent_filter(agent: str) -> dict[str, Any]:
    return {"term": {"agent.name": agent}}


def find_agent(indexer: Indexer, requested: str | None) -> str:
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [{"term": {"rule.groups": "sca"}}],
                "must_not": [{"term": {"agent.id": MANAGER_AGENT_ID}}],
            }
        },
        "aggs": {"agents": {"terms": {"field": "agent.name", "size": 100}}},
    }
    answer = indexer.search(ALERTS_INDEX, body)
    buckets = answer.get("aggregations", {}).get("agents", {}).get("buckets", [])
    names = sorted(str(bucket["key"]) for bucket in buckets)
    if requested is not None:
        if requested not in names:
            raise CollectError("The agent given with --agent has no SCA results.")
        return requested
    if not names:
        raise CollectError("No agent has SCA results yet. Wait for the first scan, then retry.")
    if len(names) > 1:
        raise CollectError(f"{len(names)} agents have SCA results. Choose one with --agent.")
    return names[0]


def check_result(check: dict[str, Any]) -> str | None:
    result = str(check.get("result") or "").strip().lower()
    if result in RESULTS:
        return result
    if str(check.get("status") or "").strip().lower() == "not applicable":
        return "not applicable"
    return None


def latest_results(indexer: Indexer, agent: str) -> dict[int, str]:
    """The newest SCA result per check id; older alerts for the same check are ignored."""
    body = {
        "size": MAX_DOCS,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["data.sca.check.id", "data.sca.check.result", "data.sca.check.status"],
        "query": {
            "bool": {
                "filter": [
                    {"term": {"rule.groups": "sca"}},
                    {"term": {"data.sca.type": "check"}},
                    agent_filter(agent),
                ]
            }
        },
    }
    seen: set[int] = set()
    latest: dict[int, str] = {}
    for doc in hits_of(indexer.search(ALERTS_INDEX, body)):
        check = doc.get("data", {}).get("sca", {}).get("check", {})
        try:
            check_id = int(check.get("id"))
        except (TypeError, ValueError):
            continue
        if check_id in seen:
            continue
        seen.add(check_id)
        result = check_result(check)
        if result is not None:
            latest[check_id] = result
    return latest


def vulnerability_counts(indexer: Indexer, agent: str) -> VulnerabilityCounts:
    body = {
        "size": MAX_DOCS,
        "_source": ["vulnerability.severity"],
        "query": {"bool": {"filter": [agent_filter(agent)]}},
    }
    counts = dict.fromkeys(SEVERITIES, 0)
    for doc in hits_of(indexer.search(VULNERABILITIES_INDEX, body)):
        severity = str(doc.get("vulnerability", {}).get("severity") or "").strip().lower()
        if severity in counts:
            counts[severity] += 1
    return VulnerabilityCounts(**counts)


def parse_timestamp(value: str) -> datetime:
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value.strip()).replace("Z", "+00:00")
    moment = datetime.fromisoformat(text)
    if moment.tzinfo is None:
        raise ValueError(f"timestamp has no time zone: {value!r}")
    return moment


def logging_facts(indexer: Indexer, agent: str, now: datetime) -> LoggingFacts:
    body = {
        "size": 1,
        "sort": [{"timestamp": {"order": "asc"}}],
        "_source": ["timestamp"],
        "query": {"bool": {"filter": [agent_filter(agent)]}},
    }
    docs = hits_of(indexer.search(ALERTS_INDEX, body), complete=False)
    oldest: datetime | None = None
    if docs:
        try:
            oldest = parse_timestamp(str(docs[0]["timestamp"])).astimezone(UTC)
        except (KeyError, ValueError) as error:
            raise CollectError("The oldest alert has an unreadable timestamp.") from error
    since = (now - ACTIVE_WINDOW).isoformat()
    recent = indexer.count(
        ALERTS_INDEX,
        {"bool": {"filter": [agent_filter(agent), {"range": {"timestamp": {"gte": since}}}]}},
    )
    return LoggingFacts(oldest_alert=oldest, agent_active=recent > 0)


@dataclass(frozen=True)
class Collected:
    snapshot: Snapshot
    agent: str


def build_snapshot(
    label: str,
    now: datetime,
    policy: CisPolicy,
    results: Mapping[int, str],
    vulnerabilities: VulnerabilityCounts,
    logging: LoggingFacts,
) -> Snapshot:
    checks = [
        CheckResult(id=check.id, result=results.get(check.id, "not scanned"))
        for check in policy.checks
    ]
    return Snapshot(
        label=label,
        taken_at=now.replace(microsecond=0),
        host=HOST_PLACEHOLDER,
        policy=SnapshotPolicy(id=policy.policy.id, checks_total=len(policy.checks)),
        checks=checks,
        vulnerabilities=vulnerabilities,
        logging=logging,
    )


def collect(
    indexer: Indexer, policy: CisPolicy, label: str, now: datetime, agent: str | None = None
) -> Collected:
    name = find_agent(indexer, agent)
    snapshot = build_snapshot(
        label,
        now,
        policy,
        latest_results(indexer, name),
        vulnerability_counts(indexer, name),
        logging_facts(indexer, name, now),
    )
    return Collected(snapshot, name)


def snapshot_path(directory: Path, snapshot: Snapshot) -> Path:
    return directory / f"{snapshot.taken_at:%Y-%m}-{snapshot.label}.json"
```

- [ ] **Step 4: Run the tests to make sure they pass**

Run: `.venv/Scripts/python -m pytest tests/test_collect.py -v`
Expected: 18 passed.

- [ ] **Step 5: Lint and commit**

```bash
.venv/Scripts/python -m ruff check .
git add ecc/collect.py tests/test_collect.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Collect SCA results, vulnerabilities and log facts from Wazuh"
```

---

### Task 13: Excel workbook

**Files:**
- Create: `ecc/excel.py`
- Test: `tests/test_excel.py`

**Interfaces:**
- Consumes: `Assessment`, `compliance`, `domain_scores`, `controls_for`, `risk_rows`, `roadmap`, `Status`, `Dataset`.
- Produces: `SHEETS = ("Summary", "Controls", "Technical evidence", "Risk register", "Roadmap")`; `write_workbook(path, dataset, after, before=None)`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_excel.py`:

```python
from openpyxl import load_workbook

from ecc.assess import assess
from ecc.excel import SHEETS, write_workbook


def workbook(tmp_path, dataset, after, before=None):
    path = tmp_path / "out.xlsx"
    old = assess(dataset, before) if before is not None else None
    write_workbook(path, dataset, assess(dataset, after), old)
    return load_workbook(path)


def values(sheet, row):
    return [cell.value for cell in sheet[row]]


def test_the_workbook_has_five_sheets(tmp_path, dataset, after):
    assert workbook(tmp_path, dataset, after).sheetnames == list(SHEETS)


def test_the_summary_compares_two_snapshots(tmp_path, dataset, baseline, after):
    sheet = workbook(tmp_path, dataset, after, baseline)["Summary"]
    assert values(sheet, 1) == ["Area", "baseline %", "after %", "Change"]
    assert values(sheet, 2) == ["Overall", 50.0, 75.0, 25.0]
    assert values(sheet, 4) == ["2 Cybersecurity Defense", 50.0, 83.3, 33.3]
    assert values(sheet, 5) == [
        "4 Third-Party and Cloud Computing Cybersecurity",
        "n/a",
        "n/a",
        "n/a",
    ]


def test_the_summary_for_one_snapshot(tmp_path, dataset, after):
    sheet = workbook(tmp_path, dataset, after)["Summary"]
    assert values(sheet, 1) == ["Area", "after %"]
    assert values(sheet, 2) == ["Overall", 75.0]


def test_the_controls_sheet_colours_the_status(tmp_path, dataset, after):
    sheet = workbook(tmp_path, dataset, after)["Controls"]
    rows = list(sheet.iter_rows(min_row=2, values_only=True))
    assert [row[0] for row in rows] == ["1-3-1", "2-2-1", "2-2-3", "2-12-3", "4-2-1"]
    assert rows[2][4] == "Implemented"
    assert sheet["E4"].fill.start_color.rgb.endswith("C6EFCE")


def test_technical_evidence_lists_every_check(tmp_path, dataset, after):
    sheet = workbook(tmp_path, dataset, after)["Technical evidence"]
    rows = list(sheet.iter_rows(min_row=2, values_only=True))
    assert [row[0] for row in rows] == [26000, 26001, 26139, 26140]
    assert rows[0][3:] == ("passed", "2-2-3")


def test_closed_risks_leave_the_roadmap(tmp_path, dataset, after):
    book = workbook(tmp_path, dataset, after)
    register = book["Risk register"].iter_rows(min_row=2, values_only=True)
    assert {row[0]: row[10] for row in register} == {
        "R-01": "Closed",
        "R-02": "Open",
        "R-03": "Open",
    }
    plan = [row[:2] for row in book["Roadmap"].iter_rows(min_row=2, values_only=True)]
    assert plan == [("60 days", "R-02"), ("Later", "R-03")]
```

- [ ] **Step 2: Run the tests to make sure they fail**

Run: `.venv/Scripts/python -m pytest tests/test_excel.py -v`
Expected: `ModuleNotFoundError: No module named 'ecc.excel'`.

- [ ] **Step 3: Write the workbook writer**

Create `ecc/excel.py`:

```python
"""Write the gap assessment workbook."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.worksheet import Worksheet

from ecc.assess import Assessment, compliance, domain_scores
from ecc.load import Dataset
from ecc.mapping import controls_for
from ecc.models import Status
from ecc.risk import risk_rows, roadmap

SHEETS = ("Summary", "Controls", "Technical evidence", "Risk register", "Roadmap")
STATUS_COLOURS = {
    Status.IMPLEMENTED: "C6EFCE",
    Status.PARTIAL: "FFEB9C",
    Status.NOT_IMPLEMENTED: "FFC7CE",
    Status.NOT_APPLICABLE: "D9D9D9",
}
RESULT_COLOURS = {
    "passed": "C6EFCE",
    "failed": "FFC7CE",
    "not applicable": "D9D9D9",
    "not scanned": "D9D9D9",
}


def fill(colour: str) -> PatternFill:
    return PatternFill(fill_type="solid", start_color=colour, end_color=colour)


def table(
    sheet: Worksheet,
    header: Sequence[str],
    rows: Iterable[Sequence[Any]],
    widths: Sequence[int],
) -> None:
    sheet.append(list(header))
    for cell in sheet[1]:
        cell.font = Font(bold=True)
    for row in rows:
        sheet.append(list(row))
    sheet.freeze_panes = "A2"
    for index, width in enumerate(widths, start=1):
        sheet.column_dimensions[get_column_letter(index)].width = width
    for row in sheet.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = Alignment(wrap_text=True, vertical="top")


def score(value: float | None) -> float | str:
    return "n/a" if value is None else value


def change(before: float | None, after: float | None) -> float | str:
    if before is None or after is None:
        return "n/a"
    return round(after - before, 1)


def label(status: Status | None, empty: str = "") -> str:
    return status.value if status is not None else empty


def write_summary(
    sheet: Worksheet, dataset: Dataset, after: Assessment, before: Assessment | None
) -> None:
    titles = {c.domain: f"{c.domain} {c.domain_title}" for c in dataset.catalog}
    after_domains = domain_scores(after)
    before_domains = domain_scores(before) if before is not None else {}
    overall_before = compliance(before.results) if before is not None else None
    areas = [("Overall", compliance(after.results), overall_before)]
    areas += [(titles[d], after_domains[d], before_domains.get(d)) for d in after_domains]
    if before is None:
        header = ["Area", f"{after.snapshot.label} %"]
        rows = [[area, score(now)] for area, now, _ in areas]
    else:
        header = ["Area", f"{before.snapshot.label} %", f"{after.snapshot.label} %", "Change"]
        rows = [[area, score(old), score(now), change(old, now)] for area, now, old in areas]
    table(sheet, header, rows, [48, 14, 14, 10])
    sheet.append([])
    sheet.append(["Status", "Controls"])
    for column in (1, 2):
        sheet.cell(row=sheet.max_row, column=column).font = Font(bold=True)
    for status in Status:
        sheet.append([status.value, sum(1 for r in after.results if r.status is status)])
        sheet.cell(row=sheet.max_row, column=1).fill = fill(STATUS_COLOURS[status])


def write_controls(sheet: Worksheet, after: Assessment) -> None:
    rows = [
        [
            r.control.id,
            f"{r.control.domain} {r.control.domain_title}",
            f"{r.control.subdomain} {r.control.subdomain_title}",
            r.control.text,
            label(r.status, "No rating"),
            label(r.technical),
            label(r.documentary),
            r.summary,
        ]
        for r in after.results
    ]
    header = ["ID", "Domain", "Subdomain", "Control", "Status", "Technical", "Documentary",
              "Evidence"]
    table(sheet, header, rows, [9, 24, 30, 60, 22, 22, 22, 60])
    for row_number, result in enumerate(after.results, start=2):
        if result.status is not None:
            sheet.cell(row=row_number, column=5).fill = fill(STATUS_COLOURS[result.status])


def write_checks(sheet: Worksheet, dataset: Dataset, after: Assessment) -> None:
    results = {check.id: check.result for check in after.snapshot.checks}
    rows = [
        [
            check.id,
            check.cis,
            check.title,
            results.get(check.id, "not scanned"),
            ", ".join(controls_for(check, dataset.mapping)),
        ]
        for check in dataset.policy.checks
    ]
    table(sheet, ["Check ID", "CIS", "Title", "Result", "ECC controls"], rows, [10, 12, 80, 16, 18])
    for row_number, row in enumerate(rows, start=2):
        sheet.cell(row=row_number, column=4).fill = fill(RESULT_COLOURS[row[3]])


def write_risks(register: Worksheet, plan: Worksheet, dataset: Dataset, after: Assessment) -> None:
    rows = risk_rows(dataset.risks, after)
    table(
        register,
        ["ID", "Controls", "Risk", "Likelihood", "Impact", "Score", "Rating", "Treatment",
         "Owner", "Due", "State"],
        [
            [
                row.risk.id,
                ", ".join(row.risk.controls),
                row.risk.statement,
                row.risk.likelihood,
                row.risk.impact,
                row.score,
                row.rating,
                row.risk.treatment,
                row.risk.owner,
                row.risk.due,
                "Closed" if row.closed else "Open",
            ]
            for row in rows
        ],
        [8, 14, 60, 11, 9, 8, 10, 11, 20, 12, 9],
    )
    table(
        plan,
        ["When", "Risk ID", "Controls", "Risk", "Score", "Owner", "Due"],
        [
            [
                row.bucket,
                row.risk.id,
                ", ".join(row.risk.controls),
                row.risk.statement,
                row.score,
                row.risk.owner,
                row.risk.due,
            ]
            for row in roadmap(rows)
        ],
        [10, 9, 14, 60, 8, 20, 12],
    )


def write_workbook(
    path: Path, dataset: Dataset, after: Assessment, before: Assessment | None = None
) -> None:
    book = Workbook()
    summary = book.active
    summary.title = SHEETS[0]
    sheets = [summary, *(book.create_sheet(title) for title in SHEETS[1:])]
    write_summary(sheets[0], dataset, after, before)
    write_controls(sheets[1], after)
    write_checks(sheets[2], dataset, after)
    write_risks(sheets[3], sheets[4], dataset, after)
    path.parent.mkdir(parents=True, exist_ok=True)
    book.save(path)
```

- [ ] **Step 4: Run the tests to make sure they pass**

Run: `.venv/Scripts/python -m pytest tests/test_excel.py -v`
Expected: 6 passed.

- [ ] **Step 5: Lint and commit**

```bash
.venv/Scripts/python -m ruff check .
git add ecc/excel.py tests/test_excel.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Write the five-sheet gap assessment workbook"
```

---

### Task 14: Web page and PDF

**Files:**
- Create: `ecc/html.py`, `ecc/templates/report.html.j2`
- Test: `tests/test_html.py`

**Interfaces:**
- Consumes: `Assessment`, `compare`, `compliance`, `domain_scores`, `Dataset`, `Status`, `BUCKET_ORDER`, `rating`, `risk_rows`, `roadmap`.
- Produces: `PdfError(Exception)`; `report_context(dataset, after, before=None) -> dict`; `render_html(dataset, after, before=None) -> str`; `find_browser(env) -> str | None` (`CHROME` first, then PATH, then standard Windows install paths); `write_pdf(html_path, pdf_path, browser)`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_html.py`:

```python
import dataclasses
import os

import pytest

from ecc.assess import assess
from ecc.html import PdfError, find_browser, render_html, write_pdf
from ecc.models import RiskRegister

BROWSER = find_browser(os.environ)


def test_the_report_shows_the_score_and_every_control(dataset, baseline):
    html = render_html(dataset, assess(dataset, baseline))
    assert "50.0%" in html
    for control in dataset.catalog:
        assert f"<td>{control.id}</td>" in html
    assert "WS-01" in html
    assert "What changed" not in html


def test_the_report_compares_two_snapshots(dataset, baseline, after):
    html = render_html(dataset, assess(dataset, after), assess(dataset, baseline))
    assert "What changed" in html
    assert "75.0%" in html
    assert "(was 50.0%)" in html


def test_text_from_data_files_is_escaped(dataset, baseline):
    risk = dataset.risks.risks[0].model_copy(update={"statement": "<b>bold</b>"})
    changed = dataclasses.replace(
        dataset, risks=RiskRegister(risks=(risk, *dataset.risks.risks[1:]))
    )
    html = render_html(changed, assess(changed, baseline))
    assert "&lt;b&gt;bold&lt;/b&gt;" in html
    assert "<b>bold</b>" not in html


def test_the_heatmap_counts_open_risks(dataset, baseline):
    html = render_html(dataset, assess(dataset, baseline))
    assert html.count('<td class="high">1</td>') == 2  # R-01 (3x4) and R-02 (4x4)
    assert '<td class="low">1</td>' in html  # R-03 (2x2)


def test_the_chrome_variable_wins():
    assert find_browser({"CHROME": "/opt/chrome"}) == "/opt/chrome"


def test_no_browser_means_none(monkeypatch):
    monkeypatch.setattr("ecc.html.shutil.which", lambda name: None)
    monkeypatch.setattr("ecc.html.WINDOWS_BROWSERS", ())
    assert find_browser({}) is None


def test_a_missing_browser_is_a_clear_error(tmp_path):
    page = tmp_path / "index.html"
    page.write_text("<p>x</p>", encoding="utf-8")
    with pytest.raises(PdfError):
        write_pdf(page, tmp_path / "out.pdf", str(tmp_path / "no-browser.exe"))


@pytest.mark.skipif(
    BROWSER is None or os.environ.get("CI") == "true", reason="needs a local Chrome or Edge"
)
def test_the_pdf_is_printed(tmp_path, dataset, baseline):
    page = tmp_path / "index.html"
    page.write_text(render_html(dataset, assess(dataset, baseline)), encoding="utf-8")
    pdf = tmp_path / "report.pdf"
    write_pdf(page, pdf, BROWSER)
    assert pdf.read_bytes().startswith(b"%PDF")
```

- [ ] **Step 2: Run the tests to make sure they fail**

Run: `.venv/Scripts/python -m pytest tests/test_html.py -v`
Expected: `ModuleNotFoundError: No module named 'ecc.html'`.

- [ ] **Step 3: Write the template**

Create `ecc/templates/report.html.j2`:

```jinja
{% macro pct(value) %}{{ "n/a" if value is none else "%.1f%%"|format(value) }}{% endmacro %}
{% macro badge(status) %}{% if status %}<span class="badge {{ status_class[status] }}">{{ status }}</span>{% else %}<span class="badge na">No rating</span>{% endif %}{% endmacro %}
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NCA ECC Gap Assessment</title>
<style>
:root {
  --bg: #ffffff; --fg: #1d2330; --muted: #5b6475; --line: #d9dde5; --panel: #f5f7fa;
  --ok: #1e7f4f; --ok-bg: #dff3e7; --part: #8a6100; --part-bg: #fff1c7;
  --gap: #b42318; --gap-bg: #fde3e1; --na: #5b6475; --na-bg: #eceef2;
  --low: #dff3e7; --medium: #fff1c7; --high: #fdd9b5; --critical: #f9c0bb;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #12151b; --fg: #e6e9ef; --muted: #a0a8b8; --line: #2c323d; --panel: #1a1f27;
    --ok: #7dd3a4; --ok-bg: #173826; --part: #f2c94c; --part-bg: #3a2f10;
    --gap: #f59a92; --gap-bg: #44201d; --na: #a0a8b8; --na-bg: #262b34;
    --low: #173826; --medium: #3a2f10; --high: #4a2c12; --critical: #4d1f1c;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 1100px; margin: 0 auto; padding: 32px 16px 64px; }
h1 { font-size: 28px; margin: 0 0 4px; }
h2 { font-size: 20px; margin: 40px 0 12px; padding-top: 8px; border-top: 1px solid var(--line); }
h3 { font-size: 16px; margin: 16px 0 6px; }
.meta, .note { color: var(--muted); }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 12px; margin: 24px 0; }
.tile { background: var(--panel); border: 1px solid var(--line); border-radius: 8px;
  padding: 12px 14px; }
.tile b { display: block; font-size: 26px; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; vertical-align: top; padding: 6px 8px;
  border-bottom: 1px solid var(--line); }
th { font-size: 13px; color: var(--muted); font-weight: 600; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 13px;
  white-space: nowrap; }
.ok { color: var(--ok); background: var(--ok-bg); }
.part { color: var(--part); background: var(--part-bg); }
.gap { color: var(--gap); background: var(--gap-bg); }
.na { color: var(--na); background: var(--na-bg); }
.bar { height: 10px; background: var(--na-bg); border-radius: 5px; min-width: 120px; }
.bar span { display: block; height: 100%; background: var(--ok); border-radius: 5px; }
.filters { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }
.filters input, .filters select { font: inherit; padding: 6px 8px; border: 1px solid var(--line);
  border-radius: 6px; background: var(--bg); color: var(--fg); }
.heatmap { width: auto; }
.heatmap td { width: 52px; height: 44px; text-align: center; border: 1px solid var(--line); }
.heatmap th { text-align: center; }
.low { background: var(--low); }
.medium { background: var(--medium); }
.high { background: var(--high); }
.critical { background: var(--critical); }
.downloads a { margin-right: 16px; }
@media print {
  @page { size: A4; margin: 16mm 14mm; }
  body { font-size: 11px; }
  main { max-width: none; padding: 0; }
  .filters, .downloads { display: none; }
  h2 { break-after: avoid; }
  tr { break-inside: avoid; }
  .page-break { break-before: page; }
}
</style>
</head>
<body>
<main>
<header>
  <h1>NCA ECC-2:2024 Gap Assessment</h1>
  <p class="meta">Workstation {{ snapshot.host }} &middot; snapshot &ldquo;{{ snapshot.label }}&rdquo; taken {{ snapshot.taken_at.strftime("%d %B %Y") }}{% if before_snapshot %} &middot; compared with &ldquo;{{ before_snapshot.label }}&rdquo; ({{ before_snapshot.taken_at.strftime("%d %B %Y") }}){% endif %}</p>
  <p class="downloads"><a href="ecc-gap-assessment.xlsx">Download the workbook (.xlsx)</a><a href="ecc-gap-assessment.pdf">Download the report (PDF)</a></p>
</header>

<section class="tiles">
  <div class="tile"><b>{{ pct(overall) }}</b>Compliance{% if overall_before is not none %} (was {{ pct(overall_before) }}){% endif %}</div>
{% for status in statuses %}
  <div class="tile"><b>{{ counts[status] }}</b>{{ status }}</div>
{% endfor %}
  <div class="tile"><b>{{ open_risks|length }}</b>Open risks</div>
</section>

<h2>Results by domain</h2>
<div class="table-wrap"><table>
<thead><tr><th>Domain</th>{% if before_snapshot %}<th>{{ before_snapshot.label }}</th>{% endif %}<th>{{ snapshot.label }}</th><th>Compliance</th></tr></thead>
<tbody>
{% for d in domains %}
<tr><td>{{ d.id }} {{ d.title }}</td>{% if before_snapshot %}<td>{{ pct(d.before) }}</td>{% endif %}<td>{{ pct(d.after) }}</td><td><div class="bar"><span style="width: {{ d.after or 0 }}%"></span></div></td></tr>
{% endfor %}
</tbody></table></div>

{% if before_snapshot %}
<h2>What changed</h2>
{% if changes %}
<div class="table-wrap"><table>
<thead><tr><th>Control</th><th>Before</th><th>After</th></tr></thead>
<tbody>
{% for c in changes %}
<tr><td>{{ c.control.id }} {{ c.control.subdomain_title }}</td><td>{{ badge(c.before) }}</td><td>{{ badge(c.after) }}</td></tr>
{% endfor %}
</tbody></table></div>
{% else %}
<p class="note">No control changed status.</p>
{% endif %}
{% endif %}

<h2>Controls</h2>
<div class="filters">
  <input id="q" type="search" placeholder="Filter by id or text" aria-label="Filter controls">
  <select id="status" aria-label="Filter by status"><option value="">All statuses</option>{% for status in statuses %}<option>{{ status }}</option>{% endfor %}</select>
</div>
<div class="table-wrap"><table id="controls">
<thead><tr><th>ID</th><th>Control</th><th>Status</th><th>Evidence</th></tr></thead>
<tbody>
{% for r in results %}
<tr data-status="{{ r.status or '' }}"><td>{{ r.control.id }}</td><td><b>{{ r.control.subdomain_title }}</b><br>{{ r.control.text }}</td><td>{{ badge(r.status) }}</td><td>{{ r.summary }}</td></tr>
{% endfor %}
</tbody></table></div>

<h2>Risk heatmap</h2>
<p class="note">Open risks by likelihood (across) and impact (down).</p>
<table class="heatmap">
<thead><tr><th>Impact</th>{% for likelihood in range(1, 6) %}<th>{{ likelihood }}</th>{% endfor %}</tr></thead>
<tbody>
{% for row in heatmap %}
{% set impact = 6 - loop.index %}
<tr><th>{{ impact }}</th>{% for count in row %}<td class="{{ rating_class[rating(impact * loop.index)] }}">{{ count or "" }}</td>{% endfor %}</tr>
{% endfor %}
</tbody></table>

<h2>Risk register</h2>
<div class="table-wrap"><table>
<thead><tr><th>ID</th><th>Risk</th><th>Controls</th><th>Likelihood</th><th>Impact</th><th>Score</th><th>Rating</th><th>Treatment</th><th>Owner</th><th>Due</th><th>State</th></tr></thead>
<tbody>
{% for row in risks %}
<tr><td>{{ row.risk.id }}</td><td>{{ row.risk.statement }}</td><td>{{ row.risk.controls|join(", ") }}</td><td>{{ row.risk.likelihood }}</td><td>{{ row.risk.impact }}</td><td>{{ row.score }}</td><td><span class="badge {{ rating_class[row.rating] }}">{{ row.rating }}</span></td><td>{{ row.risk.treatment }}</td><td>{{ row.risk.owner }}</td><td>{{ row.risk.due }}</td><td>{{ "Closed" if row.closed else "Open" }}</td></tr>
{% endfor %}
</tbody></table></div>

<h2>Roadmap</h2>
{% for name in bucket_order %}
{% set items = roadmap|selectattr("bucket", "equalto", name)|list %}
{% if items %}
<h3>{{ name }}</h3>
<ul>
{% for row in items %}
<li><b>{{ row.risk.id }}</b> {{ row.risk.statement }} ({{ row.risk.owner }}, due {{ row.risk.due }})</li>
{% endfor %}
</ul>
{% endif %}
{% endfor %}
{% if not roadmap %}
<p class="note">No open risks.</p>
{% endif %}

<h2>Scope and applicability</h2>
<p>The assessment covers one Windows 11 workstation ({{ snapshot.host }}) and the Wazuh SIEM that monitors it. Technical results are measured by Wazuh; governance ratings are judged against the company's own documents.</p>
{% if not_applicable %}
<div class="table-wrap"><table>
<thead><tr><th>ID</th><th>Subdomain</th><th>Why it does not apply</th></tr></thead>
<tbody>
{% for r in not_applicable %}
<tr><td>{{ r.control.id }}</td><td>{{ r.control.subdomain_title }}</td><td>{{ r.na_reason }}</td></tr>
{% endfor %}
</tbody></table></div>
{% endif %}

<h2 class="page-break">Method</h2>
<ul>
  <li>Framework: NCA Essential Cybersecurity Controls (ECC-2:2024), {{ results|length }} main controls.</li>
  <li>Technical evidence: {{ check_count }} checks from the {{ policy_name }}, collected by Wazuh Security Configuration Assessment, plus open vulnerability counts and log retention.</li>
  <li>Checks rate a control Implemented when all usable checks pass, Partially implemented when some pass and Not implemented when none pass. Checks that are not applicable or were not scanned are left out.</li>
  <li>When a control has both technical and documentary evidence, it gets the weaker rating.</li>
  <li>Compliance = (Implemented + &frac12; &times; Partially implemented) &divide; applicable controls.</li>
  <li>Risk score = likelihood &times; impact (1&ndash;5 each): 1&ndash;4 Low, 5&ndash;9 Medium, 10&ndash;16 High, 20&ndash;25 Critical.</li>
</ul>

<h2 class="page-break">Appendix: CIS to ECC mapping</h2>
<div class="table-wrap"><table>
<thead><tr><th>CIS section</th><th>ECC controls</th><th>Why</th></tr></thead>
<tbody>
{% for rule in rules %}
<tr><td>{{ rule.cis }}</td><td>{{ rule.ecc|join(", ") }}</td><td>{{ rule.why }}</td></tr>
{% endfor %}
</tbody></table></div>

<p class="note">Sources: NCA Essential Cybersecurity Controls ECC-2:2024 (Public, TLP: White); CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 through the Wazuh SCA policy.</p>
</main>
<script>
(() => {
  const query = document.getElementById("q");
  const status = document.getElementById("status");
  const rows = Array.from(document.querySelectorAll("#controls tbody tr"));
  const apply = () => {
    const text = query.value.trim().toLowerCase();
    rows.forEach((row) => {
      const textMatch = !text || row.textContent.toLowerCase().includes(text);
      const statusMatch = !status.value || row.dataset.status === status.value;
      row.hidden = !(textMatch && statusMatch);
    });
  };
  query.addEventListener("input", apply);
  status.addEventListener("change", apply);
})();
</script>
</body>
</html>
```

- [ ] **Step 4: Write the renderer**

Create `ecc/html.py`:

```python
"""Render the report page and print it to PDF with headless Chrome or Edge."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from ecc.assess import Assessment, compare, compliance, domain_scores
from ecc.load import Dataset
from ecc.models import Status
from ecc.risk import BUCKET_ORDER, rating, risk_rows, roadmap

BROWSER_NAMES = ("chrome", "google-chrome", "google-chrome-stable", "chromium", "msedge")
WINDOWS_BROWSERS = (
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
)
STATUS_CLASS = {
    Status.IMPLEMENTED: "ok",
    Status.PARTIAL: "part",
    Status.NOT_IMPLEMENTED: "gap",
    Status.NOT_APPLICABLE: "na",
}
RATING_CLASS = {"Low": "low", "Medium": "medium", "High": "high", "Critical": "critical"}


class PdfError(Exception):
    """The PDF could not be printed."""


def environment() -> Environment:
    return Environment(
        loader=PackageLoader("ecc", "templates"),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def report_context(
    dataset: Dataset, after: Assessment, before: Assessment | None = None
) -> dict[str, Any]:
    titles = {control.domain: control.domain_title for control in dataset.catalog}
    after_domains = domain_scores(after)
    before_domains = domain_scores(before) if before is not None else {}
    rows = risk_rows(dataset.risks, after)
    open_rows = [row for row in rows if not row.closed]
    heatmap = [
        [
            sum(1 for row in open_rows if (row.risk.likelihood, row.risk.impact) == (lk, im))
            for lk in range(1, 6)
        ]
        for im in range(5, 0, -1)
    ]
    domains = [
        {"id": d, "title": titles[d], "after": after_domains[d], "before": before_domains.get(d)}
        for d in after_domains
    ]
    return {
        "snapshot": after.snapshot,
        "before_snapshot": before.snapshot if before is not None else None,
        "overall": compliance(after.results),
        "overall_before": compliance(before.results) if before is not None else None,
        "domains": domains,
        "statuses": list(Status),
        "counts": {s: sum(1 for r in after.results if r.status is s) for s in Status},
        "results": after.results,
        "changes": compare(before, after) if before is not None else (),
        "risks": rows,
        "open_risks": open_rows,
        "heatmap": heatmap,
        "roadmap": roadmap(rows),
        "bucket_order": BUCKET_ORDER,
        "rules": dataset.mapping.rules,
        "not_applicable": [r for r in after.results if r.status is Status.NOT_APPLICABLE],
        "check_count": len(dataset.policy.checks),
        "policy_name": dataset.policy.policy.name,
        "status_class": STATUS_CLASS,
        "rating_class": RATING_CLASS,
        "rating": rating,
    }


def render_html(dataset: Dataset, after: Assessment, before: Assessment | None = None) -> str:
    template = environment().get_template("report.html.j2")
    return template.render(**report_context(dataset, after, before))


def find_browser(env: Mapping[str, str]) -> str | None:
    if env.get("CHROME"):
        return env["CHROME"]
    for name in BROWSER_NAMES:
        found = shutil.which(name)
        if found:
            return found
    for path in WINDOWS_BROWSERS:
        if Path(path).is_file():
            return path
    return None


def write_pdf(html_path: Path, pdf_path: Path, browser: str) -> None:
    command = [
        browser,
        "--headless=new",
        "--disable-gpu",
        "--no-pdf-header-footer",
        f"--print-to-pdf={pdf_path.resolve()}",
        html_path.resolve().as_uri(),
    ]
    try:
        subprocess.run(command, check=True, capture_output=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as error:
        raise PdfError(f"Printing the PDF with {Path(browser).name} failed: {error}") from error
    if not pdf_path.is_file() or pdf_path.stat().st_size == 0:
        raise PdfError("The browser finished without writing the PDF.")
```

- [ ] **Step 5: Run the tests to make sure they pass**

Run: `.venv/Scripts/python -m pytest tests/test_html.py -v`
Expected: 8 passed (7 if no Chrome or Edge is installed; `test_the_pdf_is_printed` is then skipped).

- [ ] **Step 6: Lint and commit**

```bash
.venv/Scripts/python -m ruff check .
git add ecc/html.py ecc/templates/report.html.j2 tests/test_html.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Render the report page and print it to PDF"
```

---

### Task 15: Command line, data stubs, CI and README

**Files:**
- Create: `ecc/cli.py`, `ecc/__main__.py`, `data/evidence.yaml`, `data/applicability.yaml`, `data/risks.yaml`, `.github/workflows/ci.yml`, `README.md`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: everything above.
- Produces: `main(argv=None, env=None, now=None) -> int`; `python -m ecc collect --label L [--agent NAME] [--root DIR]`, `python -m ecc check [--root DIR]`, `python -m ecc build [--after L] [--before L] [--no-pdf] [--root DIR]`. Outputs go to `build/ecc-gap-assessment.xlsx`, `build/index.html`, `build/ecc-gap-assessment.pdf`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_cli.py`:

```python
import pytest

from ecc import cli
from ecc.collect import Collected
from ecc.models import Snapshot
from tests.fixtures import BASELINE, RISKS, rewrite

ENV = {"WAZUH_INDEXER_URL": "https://indexer.test", "USERNAME": "jdoe"}


def run(*args: str, env: dict[str, str] | None = None) -> int:
    return cli.main(list(args), env=ENV if env is None else env)


def fake_collect(indexer, policy, label, now, agent=None) -> Collected:
    return Collected(Snapshot.model_validate({**BASELINE, "label": label}), "lab-agent")


def test_check_passes_on_valid_data(root, capsys):
    assert run("check", "--root", str(root)) == 0
    assert "OK: 5 controls, 4 checks, 2 snapshot(s)." in capsys.readouterr().out


def test_check_lists_problems(root, capsys):
    rewrite(root, "risks.yaml", {"risks": RISKS["risks"][1:]})
    assert run("check", "--root", str(root)) == 1
    err = capsys.readouterr().err
    assert "1 problem(s):" in err
    assert "gaps with no risk" in err


def test_build_writes_the_workbook_and_page(root, capsys):
    assert run("build", "--root", str(root), "--before", "baseline", "--no-pdf") == 0
    assert (root / "build" / "ecc-gap-assessment.xlsx").is_file()
    assert "What changed" in (root / "build" / "index.html").read_text(encoding="utf-8")
    assert "75.0% compliant (after)" in capsys.readouterr().out


def test_build_reports_a_chosen_snapshot(root, capsys):
    assert run("build", "--root", str(root), "--after", "baseline", "--no-pdf") == 0
    assert "50.0% compliant (baseline)" in capsys.readouterr().out


def test_build_with_an_unknown_label_fails(root, capsys):
    assert run("build", "--root", str(root), "--after", "nope", "--no-pdf") == 1
    assert "No snapshot with label 'nope'" in capsys.readouterr().err


def test_build_without_a_browser_fails_cleanly(root, capsys, monkeypatch):
    monkeypatch.setattr(cli, "find_browser", lambda env: None)
    assert run("build", "--root", str(root)) == 1
    assert "Chrome or Edge was not found" in capsys.readouterr().err


def test_collect_writes_a_snapshot_for_review(root, capsys, monkeypatch):
    monkeypatch.setattr(cli, "collect", fake_collect)
    assert run("collect", "--root", str(root), "--label", "test") == 0
    assert (root / "snapshots" / "2026-10-test.json").is_file()
    out = capsys.readouterr().out
    assert "1 passed, 2 failed, 1 not applicable, 0 not scanned" in out
    assert "Review the file before committing it." in out


def test_collect_refuses_a_forbidden_term(root, capsys, monkeypatch):
    monkeypatch.setattr(cli, "collect", fake_collect)
    env = {**ENV, "ECC_FORBIDDEN_TERMS": "WS-01"}
    assert run("collect", "--root", str(root), "--label", "test", env=env) == 1
    assert not (root / "snapshots" / "2026-10-test.json").exists()
    assert "forbidden term" in capsys.readouterr().err


def test_collect_never_overwrites(root, capsys, monkeypatch):
    monkeypatch.setattr(cli, "collect", fake_collect)
    assert run("collect", "--root", str(root), "--label", "baseline") == 1
    assert "2026-10-baseline.json already exists" in capsys.readouterr().err


def test_collect_needs_the_indexer_url(root, capsys):
    assert run("collect", "--root", str(root), "--label", "test", env={}) == 1
    assert "WAZUH_INDEXER_URL" in capsys.readouterr().err


def test_labels_must_be_simple(root):
    with pytest.raises(SystemExit):
        run("collect", "--root", str(root), "--label", "Bad Label")
```

- [ ] **Step 2: Run the tests to make sure they fail**

Run: `.venv/Scripts/python -m pytest tests/test_cli.py -v`
Expected: `ImportError: cannot import name 'cli' from 'ecc'`.

- [ ] **Step 3: Write the command line**

Create `ecc/cli.py`:

```python
"""Command line: collect a snapshot, check the data, build the outputs."""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from ecc.assess import assess, compliance
from ecc.collect import CollectError, Indexer, IndexerSettings, collect, snapshot_path
from ecc.excel import write_workbook
from ecc.html import PdfError, find_browser, render_html, write_pdf
from ecc.load import DataError, load_dataset, load_model, load_snapshots
from ecc.models import LABEL_PATTERN, CisPolicy, Snapshot
from ecc.privacy import PrivacyError, forbidden_terms, write_snapshot
from ecc.validate import validate

WORKBOOK = "ecc-gap-assessment.xlsx"
PAGE = "index.html"
PDF = "ecc-gap-assessment.pdf"


def label(value: str) -> str:
    if not re.fullmatch(LABEL_PATTERN, value):
        raise argparse.ArgumentTypeError("use lowercase letters, digits and dashes, e.g. baseline")
    return value


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(prog="python -m ecc", description=__doc__)
    commands = top.add_subparsers(dest="command", required=True)
    collect_cmd = commands.add_parser("collect", help="read Wazuh and write a snapshot")
    collect_cmd.add_argument("--label", type=label, required=True)
    collect_cmd.add_argument("--agent", help="Wazuh agent name, if more than one has results")
    check_cmd = commands.add_parser("check", help="validate the data files and snapshots")
    build_cmd = commands.add_parser("build", help="write the workbook, web page and PDF")
    build_cmd.add_argument("--after", type=label, help="snapshot to report (default: newest)")
    build_cmd.add_argument("--before", type=label, help="snapshot to compare against")
    build_cmd.add_argument("--no-pdf", action="store_true", help="skip printing the PDF")
    for command in (collect_cmd, check_cmd, build_cmd):
        command.add_argument("--root", default=".", help="repository root (default: .)")
    return top


def main(
    argv: Sequence[str] | None = None,
    env: Mapping[str, str] | None = None,
    now: datetime | None = None,
) -> int:
    args = parser().parse_args(argv)
    env = os.environ if env is None else env
    root = Path(args.root)
    try:
        if args.command == "collect":
            return run_collect(root, args, env, now or datetime.now(UTC))
        if args.command == "check":
            return run_check(root)
        return run_build(root, args, env)
    except (DataError, CollectError, PrivacyError, PdfError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except FileExistsError as error:
        name = Path(str(error.filename)).name
        print(f"Error: {name} already exists. Choose another --label.", file=sys.stderr)
        return 1


def run_collect(
    root: Path, args: argparse.Namespace, env: Mapping[str, str], now: datetime
) -> int:
    policy = load_model(CisPolicy, root / "data" / "cis_checks.yaml")
    settings = IndexerSettings.from_env(env)
    with settings.client() as client:
        indexer = Indexer(client, settings.server_name)
        collected = collect(indexer, policy, args.label, now, args.agent)
    path = snapshot_path(root / "snapshots", collected.snapshot)
    write_snapshot(collected.snapshot, path, forbidden_terms(env, extra=[collected.agent]))
    counts = Counter(check.result for check in collected.snapshot.checks)
    print(
        f"Wrote snapshots/{path.name}: {counts['passed']} passed, {counts['failed']} failed, "
        f"{counts['not applicable']} not applicable, {counts['not scanned']} not scanned."
    )
    print("Review the file before committing it.")
    return 0


def report(problems: Sequence[str]) -> None:
    print(f"{len(problems)} problem(s):", file=sys.stderr)
    for problem in problems:
        print(f"- {problem}", file=sys.stderr)


def run_check(root: Path) -> int:
    dataset = load_dataset(root)
    snapshots = load_snapshots(root / "snapshots")
    problems = validate(dataset, snapshots)
    if problems:
        report(problems)
        return 1
    print(
        f"OK: {len(dataset.catalog)} controls, {len(dataset.policy.checks)} checks, "
        f"{len(snapshots)} snapshot(s)."
    )
    return 0


def pick(snapshots: Sequence[Snapshot], wanted: str) -> Snapshot:
    for snapshot in snapshots:
        if snapshot.label == wanted:
            return snapshot
    raise DataError(f"No snapshot with label '{wanted}' in snapshots/.")


def run_build(root: Path, args: argparse.Namespace, env: Mapping[str, str]) -> int:
    dataset = load_dataset(root)
    snapshots = load_snapshots(root / "snapshots")
    if not snapshots:
        raise DataError("No snapshots yet. Run 'python -m ecc collect --label baseline' first.")
    problems = validate(dataset, snapshots)
    if problems:
        report(problems)
        return 1
    after = assess(dataset, pick(snapshots, args.after) if args.after else snapshots[-1])
    before = assess(dataset, pick(snapshots, args.before)) if args.before else None
    out = root / "build"
    out.mkdir(exist_ok=True)
    write_workbook(out / WORKBOOK, dataset, after, before)
    (out / PAGE).write_text(render_html(dataset, after, before), encoding="utf-8")
    built = [WORKBOOK, PAGE]
    if not args.no_pdf:
        browser = find_browser(env)
        if browser is None:
            raise PdfError(
                "Chrome or Edge was not found. Set CHROME to the browser's path, or use --no-pdf."
            )
        write_pdf(out / PAGE, out / PDF, browser)
        built.append(PDF)
    names = ", ".join(f"build/{name}" for name in built)
    score = compliance(after.results)
    print(f"Built {names}: {score}% compliant ({after.snapshot.label}).")
    return 0
```

Create `ecc/__main__.py`:

```python
from ecc.cli import main

raise SystemExit(main())
```

- [ ] **Step 4: Run the tests to make sure they pass**

Run: `.venv/Scripts/python -m pytest tests/test_cli.py -v`
Expected: 11 passed.

- [ ] **Step 5: Add the data stubs, CI and README**

Create `data/evidence.yaml`:

```yaml
# Documentary evidence per ECC control: status, documents and a note. Filled in plan 2.
entries: []
```

Create `data/applicability.yaml`:

```yaml
# Statement of Applicability: controls that are Not applicable, each with a reason.
# Filled in plan 2.
not_applicable: []
```

Create `data/risks.yaml`:

```yaml
# Risk register: at least one risk for every control rated Partially or Not implemented.
# Filled in plan 2.
risks: []
```

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r requirements.txt
      - run: ruff check .
      - run: pytest -q
```

Create `README.md`:

```markdown
# NCA ECC Gap Assessment

Work in progress. A GRC project that assesses a small fictional Saudi company against the
National Cybersecurity Authority's Essential Cybersecurity Controls (ECC-2:2024), using real
evidence from a Wazuh home lab.

The design is in [docs/superpowers/specs](docs/superpowers/specs/2026-10-08-ecc-gap-assessment-design.md).

## Run it

    python -m venv .venv
    .venv/Scripts/python -m pip install -r requirements.txt
    .venv/Scripts/python -m pytest
    .venv/Scripts/python -m ecc check
```

- [ ] **Step 6: Run the whole suite and check the real data**

Run: `.venv/Scripts/python -m pytest -q`
Expected: all tests pass (one may be skipped if no browser is installed).

Run: `.venv/Scripts/python -m ecc check`
Expected: `OK: 108 controls, 482 checks, 0 snapshot(s).`

- [ ] **Step 7: Lint and commit**

```bash
.venv/Scripts/python -m ruff check .
git add ecc/cli.py ecc/__main__.py data/evidence.yaml data/applicability.yaml data/risks.yaml .github/workflows/ci.yml README.md tests/test_cli.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Add the command line, empty assessment data, CI and a README"
```

---

### Task 16: Baseline snapshot from the live lab (with Ahmed)

**Files:**
- Create: `snapshots/<yyyy-mm>-baseline.json` (written by `collect`, committed only after Ahmed's review)

This task needs Ahmed at the keyboard. Claude prepares and explains each step but does not type the password, run `collect` or change settings.

- [ ] **Step 1: Ahmed starts Docker and Wazuh**

Ahmed opens Docker Desktop and waits until it says the engine is running. Wazuh needs about 4–5 GB of RAM, so close Discord and spare browser tabs first. Then, in PowerShell from the folder that holds both repositories:

```powershell
cd wazuh-docker\single-node
docker compose up -d
```

Expected: the indexer, manager and dashboard containers report `Started` or `Running`. Wait about two minutes, then open the Wazuh dashboard and confirm the Windows agent is active and shows a Configuration Assessment result for "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0". If the manager is not running after a WSL or Docker restart, start it with `docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control start` (check the container name with `docker ps` first).

- [ ] **Step 2: Ahmed sets the connection settings in the same PowerShell window**

From the `ecc-gap-assessment` folder:

```powershell
$env:WAZUH_INDEXER_URL = "https://127.0.0.1:9200"
$env:WAZUH_INDEXER_USER = "admin"
$env:WAZUH_INDEXER_PASSWORD = Read-Host "Wazuh indexer password"
$env:WAZUH_CA_CERT = (Resolve-Path "..\wazuh-docker\single-node\config\wazuh_indexer_ssl_certs\root-ca.pem").Path
$env:WAZUH_TLS_SERVER_NAME = "wazuh.indexer"
$env:ECC_FORBIDDEN_TERMS = Read-Host "Your names, comma separated (kept in memory only)"
```

These values live only in this PowerShell session. Nothing is written to a file.

- [ ] **Step 3: Ahmed collects the baseline**

```powershell
.venv\Scripts\python -m ecc collect --label baseline
```

Expected: `Wrote snapshots/2026-10-baseline.json: N passed, M failed, K not applicable, 0 not scanned.` followed by `Review the file before committing it.` (The month in the file name is the month it runs.) If it reports `not scanned` checks, the agent's first scan has not finished: delete the file and retry later. If there is a TLS error, check that `WAZUH_TLS_SERVER_NAME` and `WAZUH_CA_CERT` are set.

- [ ] **Step 4: Review the snapshot before committing**

Claude reads the snapshot and checks, with Ahmed:
1. It has only the keys `schema`, `label`, `taken_at`, `host`, `policy`, `checks`, `vulnerabilities`, `logging`, and `host` is `WS-01`.
2. The passed/failed counts are close to the Configuration Assessment numbers shown in the Wazuh dashboard.
3. `logging.oldest_alert` matches when this Wazuh install started collecting (late September 2026).

Then run: `.venv/Scripts/python -m ecc check`
Expected: exit code 1 with problems saying controls have no rating and gaps have no risk. That is the to-do list for plan 2, not a failure of this task. No problem may mention the snapshot's policy, check ids or labels.

- [ ] **Step 5: Commit after Ahmed approves**

Only after Ahmed says the snapshot is fine to publish:

```bash
git add snapshots/
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Add the baseline snapshot of WS-01"
```

---

## After this plan

- Run the whole suite and the linter once more: `.venv/Scripts/python -m pytest -q` and `.venv/Scripts/python -m ruff check .`.
- Then write plan 2 from the baseline results: company profile and name check, `applicability.yaml`, `evidence.yaml` and the six policies, `risks.yaml`, report narrative, and the GitHub Pages workflow.
