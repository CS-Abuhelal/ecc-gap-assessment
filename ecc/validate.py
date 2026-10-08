"""Cross-file checks. Every problem is collected, so one run shows them all."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from pathlib import Path

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


def inside(root: Path, document: str) -> bool:
    """True when a relative document path stays inside the repository root."""
    path = Path(document)
    if path.is_absolute():
        return False
    return (root / path).resolve().is_relative_to(root.resolve())


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
    outside = {
        document
        for entry in entries
        for document in entry.documents
        if not inside(dataset.root, document)
    }
    report("evidence.yaml: document paths outside the repository", sorted(outside))

    risks = dataset.risks.risks
    covered = {control for risk in risks for control in risk.controls}
    report("risks.yaml: risk ids used twice", duplicates(risk.id for risk in risks))
    report("risks.yaml: unknown ECC controls", sorted(covered - known))

    report("snapshots: labels used twice", duplicates(s.label for s in snapshots))
    check_ids = {check.id for check in dataset.policy.checks}
    report(
        "cis_checks.yaml: check ids listed twice",
        duplicates(str(check.id) for check in dataset.policy.checks),
    )
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
        snapshot_ids = [check.id for check in snapshot.checks]
        if len(snapshot_ids) != snapshot.policy.checks_total:
            problems.append(
                f"{name}: holds {len(snapshot_ids)} check results "
                f"but says {snapshot.policy.checks_total}"
            )
        report(f"{name}: check ids listed twice", duplicates(str(i) for i in snapshot_ids))
        extra = sorted(set(snapshot_ids) - check_ids)
        report(f"{name}: unknown check ids", [str(check_id) for check_id in extra])
        absent = sorted(check_ids - set(snapshot_ids))
        report(f"{name}: policy checks missing from the snapshot", [str(i) for i in absent])
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
