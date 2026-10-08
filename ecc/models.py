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
NOT_BLANK = r"\S"  # at least one character that is not whitespace
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
    why: str = Field(min_length=1, pattern=NOT_BLANK)


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
    note: str = Field(min_length=1, pattern=NOT_BLANK)

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
    reason: str = Field(min_length=1, pattern=NOT_BLANK)


class Applicability(Strict):
    not_applicable: tuple[NotApplicable, ...] = ()


class Risk(Strict):
    id: str = Field(pattern=r"^R-\d{2,3}$")
    controls: tuple[ControlId, ...] = Field(min_length=1)
    statement: str = Field(min_length=1, pattern=NOT_BLANK)
    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)
    treatment: Treatment
    owner: str = Field(min_length=1, pattern=NOT_BLANK)
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
