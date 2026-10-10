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


@dataclass(frozen=True)
class CheckProgress:
    control: Control
    before: tuple[int, int]
    after: tuple[int, int]


def check_counts(result: ControlResult) -> tuple[int, int]:
    """Passed and usable CIS checks of one control."""
    usable = [outcome.result for outcome in result.checks if outcome.result in USABLE]
    return usable.count("passed"), len(usable)


def check_progress(before: Assessment, after: Assessment) -> tuple[CheckProgress, ...]:
    """Passed checks in both snapshots, for every control that CIS checks measure."""
    old = {result.control.id: result for result in before.results}
    return tuple(
        CheckProgress(result.control, check_counts(old[result.control.id]), check_counts(result))
        for result in after.results
        if result.checks and result.control.id in old
    )
