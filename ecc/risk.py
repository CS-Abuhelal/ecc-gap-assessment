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
