import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from ecc.load import load_dataset, load_snapshots
from ecc.validate import listed, validate
from tests.fixtures import (
    APPLICABILITY,
    CATALOG,
    CIS_CHECKS,
    EVIDENCE,
    MAPPING,
    RISKS,
    rewrite,
)


def problems(root: Path) -> list[str]:
    return validate(load_dataset(root), load_snapshots(root / "snapshots"))


def test_the_fixture_is_valid(root):
    assert problems(root) == []


def test_lists_show_every_item():
    items = [str(n) for n in range(20)]
    assert listed("things", items) == "things (20): " + ", ".join(items)


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


def test_a_snapshot_missing_policy_checks(root):
    path = root / "snapshots" / "2026-10-baseline.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["checks"] = data["checks"][:2]
    path.write_text(json.dumps(data), encoding="utf-8")
    found = problems(root)
    assert "snapshot 'baseline': holds 2 check results but says 4" in found
    expected = "snapshot 'baseline': policy checks missing from the snapshot (2): 26139, 26140"
    assert expected in found


def test_a_snapshot_listing_a_check_twice(root):
    path = root / "snapshots" / "2026-10-baseline.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["checks"][3] = {"id": 26000, "result": "failed"}
    path.write_text(json.dumps(data), encoding="utf-8")
    found = problems(root)
    assert "snapshot 'baseline': check ids listed twice (1): 26000" in found
    assert "snapshot 'baseline': policy checks missing from the snapshot (1): 26140" in found


def test_documents_must_stay_inside_the_repository(root):
    entry = {
        "control": "1-3-1",
        "status": "Partially implemented",
        "documents": ["../outside.md"],
        "note": "Draft.",
    }
    rewrite(root, "evidence.yaml", {"entries": [entry, *EVIDENCE["entries"][1:]]})
    (root.parent / "outside.md").write_text("x", encoding="utf-8")
    expected = "evidence.yaml: document paths outside the repository (1): ../outside.md"
    assert expected in problems(root)


def test_duplicate_policy_check_ids(root):
    checks = [*CIS_CHECKS["checks"], CIS_CHECKS["checks"][0]]
    rewrite(root, "cis_checks.yaml", {**CIS_CHECKS, "checks": checks})
    assert "cis_checks.yaml: check ids listed twice (1): 26000" in problems(root)


def variant(source: dict[str, Any], edit: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    """A deep copy of a fixture constant with one edit applied; the constant stays untouched."""
    data = copy.deepcopy(source)
    edit(data)
    return data


def edit_data(name: str, content: dict[str, Any]) -> Callable[[Path], None]:
    return lambda root: rewrite(root, name, content)


def edit_baseline(change: Callable[[dict[str, Any]], None]) -> Callable[[Path], None]:
    def mutate(root: Path) -> None:
        path = root / "snapshots" / "2026-10-baseline.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        change(data)
        path.write_text(json.dumps(data), encoding="utf-8")

    return mutate


def add_check_99999(data: dict[str, Any]) -> None:
    data["checks"].append({"id": 99999, "result": "passed"})
    data["policy"]["checks_total"] = 5


def claim_five_checks(data: dict[str, Any]) -> None:
    data["policy"]["checks_total"] = 5


def logging_document(root: Path) -> str:
    return str((root / "docs" / "policies" / "logging.md").resolve())


def use_absolute_logging_document(root: Path) -> None:
    entries = copy.deepcopy(EVIDENCE["entries"])
    entries[2]["documents"] = [logging_document(root)]
    rewrite(root, "evidence.yaml", {"entries": entries})


CASES = [
    pytest.param(
        edit_data(
            "catalog.yaml",
            variant(
                CATALOG,
                lambda d: d["domains"][0]["subdomains"][0]["controls"].append(
                    {"id": "1-3-1", "text": "Policies shall be reviewed."}
                ),
            ),
        ),
        ["catalog.yaml: duplicate control ids (1): 1-3-1"],
        id="duplicate catalog control",
    ),
    pytest.param(
        edit_data(
            "mapping.yaml",
            variant(MAPPING, lambda d: d["rules"].append(copy.deepcopy(d["rules"][1]))),
        ),
        ["mapping.yaml: duplicate rules (1): 17"],
        id="duplicate mapping rule",
    ),
    pytest.param(
        edit_data(
            "applicability.yaml",
            variant(
                APPLICABILITY,
                lambda d: d["not_applicable"].append({"control": "4-2-9", "reason": "None."}),
            ),
        ),
        ["applicability.yaml: unknown ECC controls (1): 4-2-9"],
        id="applicability unknown control",
    ),
    pytest.param(
        edit_data(
            "applicability.yaml",
            variant(
                APPLICABILITY,
                lambda d: d["not_applicable"].append(copy.deepcopy(d["not_applicable"][0])),
            ),
        ),
        ["applicability.yaml: controls listed twice (1): 4-2-1"],
        id="applicability listed twice",
    ),
    pytest.param(
        edit_data(
            "evidence.yaml",
            variant(
                EVIDENCE,
                lambda d: d["entries"].append(
                    {"control": "1-3-9", "status": "Implemented", "note": "Unknown."}
                ),
            ),
        ),
        ["evidence.yaml: unknown ECC controls (1): 1-3-9"],
        id="evidence unknown control",
    ),
    pytest.param(
        edit_data(
            "evidence.yaml",
            variant(EVIDENCE, lambda d: d["entries"].append(copy.deepcopy(d["entries"][0]))),
        ),
        ["evidence.yaml: controls listed twice (1): 1-3-1"],
        id="evidence listed twice",
    ),
    pytest.param(
        edit_data(
            "risks.yaml",
            variant(RISKS, lambda d: d["risks"].append(copy.deepcopy(d["risks"][2]))),
        ),
        ["risks.yaml: risk ids used twice (1): R-03"],
        id="risk id used twice",
    ),
    pytest.param(
        edit_data(
            "risks.yaml",
            variant(RISKS, lambda d: d["risks"][0].update(controls=["2-2-9"])),
        ),
        ["risks.yaml: unknown ECC controls (1): 2-2-9"],
        id="risk unknown control",
    ),
    pytest.param(
        edit_baseline(claim_five_checks),
        [
            "snapshot 'baseline': holds 4 check results but says 5",
            "snapshot 'baseline': expects 5 checks, cis_checks.yaml has 4",
        ],
        id="snapshot total does not match its checks",
    ),
    pytest.param(
        edit_baseline(add_check_99999),
        ["snapshot 'baseline': unknown check ids (1): 99999"],
        id="snapshot unknown check id",
    ),
    pytest.param(
        use_absolute_logging_document,
        ["evidence.yaml: document paths outside the repository (1): {logging_document}"],
        id="evidence absolute document path",
    ),
]


@pytest.mark.parametrize(("mutate", "expected"), CASES)
def test_other_problems_are_reported(root, mutate, expected):
    mutate(root)
    found = problems(root)
    for message in expected:
        assert message.format(logging_document=logging_document(root)) in found
