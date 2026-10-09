"""Data models. Every model rejects unknown fields, so files cannot carry extra data."""

from __future__ import annotations

from datetime import date
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

CONTROL_PATTERN = r"^[1-4]-\d{1,2}-\d{1,2}$"
SUBDOMAIN_PATTERN = r"^[1-4]-\d{1,2}$"
SUBCONTROL_PATTERN = r"^[1-4]\.\d{1,2}\.\d{1,2}\.\d{1,2}$"
CIS_PATTERN = r"^\d+(\.\d+)*$"
LABEL_PATTERN = r"^[a-z0-9][a-z0-9-]*$"
FIX_PATTERN = r"^F\d{2}$"
# Fixes may only touch policy keys and the two security-option keys under Control.
REGISTRY_PATTERN = (
    r"^HKLM:\\(SOFTWARE\\Policies\\.+"
    r"|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\.+"
    r"|SYSTEM\\CurrentControlSet\\Control\\(Lsa|SAM))$"
)
AUDIT_GUID_PATTERN = r"^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$"
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


Paragraph = Annotated[str, Field(min_length=1, pattern=NOT_BLANK)]


class ReportText(Strict):
    """The report's words: who was assessed, the summary, key findings and limitations."""

    company: Paragraph
    executive_summary: tuple[Paragraph, ...] = Field(min_length=1)
    key_findings: tuple[Paragraph, ...] = ()
    limitations: tuple[Paragraph, ...] = ()


SamaId = Annotated[str, Field(pattern=r"^3\.[1-4]\.\d{1,2}$")]


class SamaSubdomain(Strict):
    id: SamaId
    title: Paragraph


class SamaDomain(Strict):
    id: str = Field(pattern=r"^3\.[1-4]$")
    title: Paragraph
    subdomains: tuple[SamaSubdomain, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _subdomains_belong_here(self) -> SamaDomain:
        strays = [s.id for s in self.subdomains if not s.id.startswith(f"{self.id}.")]
        if strays:
            raise ValueError(f"subdomains outside domain {self.id}: {', '.join(strays)}")
        return self


class SamaLevel(Strict):
    level: int = Field(ge=0, le=5)
    name: Paragraph
    meaning: Paragraph


class SamaFramework(Strict):
    """SAMA Cyber Security Framework structure: domains, subdomains and maturity levels."""

    framework: Paragraph
    source: Paragraph
    domains: tuple[SamaDomain, ...] = Field(min_length=1)
    levels: tuple[SamaLevel, ...] = Field(min_length=6, max_length=6)

    @model_validator(mode="after")
    def _levels_are_0_to_5(self) -> SamaFramework:
        if [level.level for level in self.levels] != list(range(6)):
            raise ValueError("levels must be 0 to 5, each once, in order")
        return self


class SamaLink(Strict):
    """A SAMA subdomain and the ECC controls whose ratings stand in for it.

    `rating` overrides the derived score when the linked ECC control only partly matches the
    subdomain; it must come with `rating_note` saying why.
    """

    subdomain: SamaId
    ecc: tuple[ControlId, ...] = Field(min_length=1)
    why: Paragraph
    rating: Status | None = None
    rating_note: Paragraph | None = None

    @model_validator(mode="after")
    def _override_is_explained(self) -> SamaLink:
        if self.rating is Status.NOT_APPLICABLE:
            raise ValueError("list subdomains that do not apply under not_applicable")
        if (self.rating is None) != (self.rating_note is None):
            raise ValueError("rating and rating_note must be given together")
        return self


class SamaExclusion(Strict):
    subdomain: SamaId
    reason: Paragraph


class SamaMapping(Strict):
    links: tuple[SamaLink, ...]
    not_applicable: tuple[SamaExclusion, ...] = ()


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


class RegistryItem(Strict):
    """A registry value that apply.ps1 sets."""

    kind: Literal["registry"]
    path: str = Field(pattern=REGISTRY_PATTERN)
    name: str = Field(min_length=1, pattern=NOT_BLANK)
    type: Literal["DWord", "String"]
    value: int | str

    @model_validator(mode="after")
    def _value_fits_type(self) -> RegistryItem:
        if self.type == "DWord" and not (
            isinstance(self.value, int) and 0 <= self.value <= 0xFFFFFFFF
        ):
            raise ValueError("a DWord value must be a whole number from 0 to 4294967295")
        if self.type == "String" and not isinstance(self.value, str):
            raise ValueError("a String value must be text")
        return self


class AuditItem(Strict):
    """An advanced audit policy subcategory; apply.ps1 adds the required results to it."""

    kind: Literal["audit"]
    guid: str = Field(pattern=AUDIT_GUID_PATTERN)
    subcategory: Paragraph
    require: Literal["success", "failure", "both"]


class AccountItem(Strict):
    """A local account policy that apply.ps1 sets with 'net accounts'."""

    kind: Literal["account"]
    option: Literal[
        "uniquepw", "minpwage", "minpwlen", "lockoutthreshold", "lockoutduration", "lockoutwindow"
    ]
    value: int = Field(ge=0, le=999)


FixItem = Annotated[RegistryItem | AuditItem | AccountItem, Field(discriminator="kind")]


class Fix(Strict):
    """One reversible change to WS-01 and the failed CIS checks it should make pass."""

    id: str = Field(pattern=FIX_PATTERN)
    title: Paragraph
    why: Paragraph
    effect: Paragraph
    optional: bool = False
    checks: tuple[int, ...] = Field(min_length=1)
    items: tuple[FixItem, ...] = Field(min_length=1)


class FixList(Strict):
    fixes: tuple[Fix, ...]
