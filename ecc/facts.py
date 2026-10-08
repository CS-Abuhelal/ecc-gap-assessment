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
