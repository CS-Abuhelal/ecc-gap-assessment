"""What each fix in remediation/fixes.json changed, measured in the snapshots."""

from __future__ import annotations

from dataclasses import dataclass

from ecc.load import Dataset
from ecc.mapping import controls_for
from ecc.models import CisCheck, Fix, Snapshot


@dataclass(frozen=True)
class FixResult:
    """A fix with its ECC controls and passing checks.

    `applied` is False only for an optional fix missing from report.yaml's optional_fixes_applied.
    """

    fix: Fix
    controls: tuple[str, ...]
    before: int | None
    after: int
    applied: bool


@dataclass(frozen=True)
class CheckChange:
    check: CisCheck
    before: str
    after: str


def control_key(control_id: str) -> tuple[int, ...]:
    return tuple(int(part) for part in control_id.split("-"))


def passing(snapshot: Snapshot, checks: tuple[int, ...]) -> int:
    """How many of the given checks passed in a snapshot."""
    results = {check.id: check.result for check in snapshot.checks}
    return sum(1 for check in checks if results.get(check) == "passed")


def fix_results(
    dataset: Dataset, after: Snapshot, before: Snapshot | None = None
) -> tuple[FixResult, ...]:
    """Each fix with the ECC controls its checks map to and how many of its checks pass."""
    by_id = {check.id: check for check in dataset.policy.checks}
    chosen = set(dataset.report.optional_fixes_applied)
    rows: list[FixResult] = []
    for fix in dataset.fixes.fixes:
        controls = {
            control
            for check in fix.checks
            if check in by_id
            for control in controls_for(by_id[check], dataset.mapping)
        }
        rows.append(
            FixResult(
                fix=fix,
                controls=tuple(sorted(controls, key=control_key)),
                before=passing(before, fix.checks) if before is not None else None,
                after=passing(after, fix.checks),
                applied=not fix.optional or fix.id in chosen,
            )
        )
    return tuple(rows)


def other_changes(dataset: Dataset, before: Snapshot, after: Snapshot) -> tuple[CheckChange, ...]:
    """CIS checks that no applied fix targets but whose result changed between two snapshots."""
    chosen = set(dataset.report.optional_fixes_applied)
    targeted = {
        check
        for fix in dataset.fixes.fixes
        if not fix.optional or fix.id in chosen
        for check in fix.checks
    }
    old = {check.id: check.result for check in before.checks}
    new = {check.id: check.result for check in after.checks}
    return tuple(
        CheckChange(check, old[check.id], new[check.id])
        for check in dataset.policy.checks
        if check.id not in targeted
        and check.id in old
        and check.id in new
        and old[check.id] != new[check.id]
    )
