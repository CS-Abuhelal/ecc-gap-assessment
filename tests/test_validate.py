import json
from pathlib import Path

from ecc.load import load_dataset, load_snapshots
from ecc.validate import listed, validate
from tests.fixtures import CIS_CHECKS, EVIDENCE, MAPPING, RISKS, rewrite


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
