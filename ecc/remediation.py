"""What each fix in remediation/fixes.json changed, measured in the snapshots."""

from __future__ import annotations

from dataclasses import dataclass

from ecc.load import Dataset
from ecc.mapping import controls_for
from ecc.models import Fix, Snapshot


@dataclass(frozen=True)
class FixResult:
    fix: Fix
    controls: tuple[str, ...]
    before: int | None
    after: int


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
            )
        )
    return tuple(rows)
