"""An indicative SAMA Cyber Security Framework view derived from the ECC ratings."""

from __future__ import annotations

from dataclasses import dataclass

from ecc.assess import POINTS, Assessment, compliance
from ecc.load import Dataset
from ecc.models import SamaDomain, SamaSubdomain, Status

NOT_RATED = "Its ECC controls are not applicable or not rated, so no level is derived."


@dataclass(frozen=True)
class SamaResult:
    domain: SamaDomain
    subdomain: SamaSubdomain
    ecc: tuple[str, ...]
    why: str | None
    score: float | None
    level: int | None
    note: str | None


def maturity(score: float | None, any_implemented: bool) -> int | None:
    """Indicative SAMA maturity level from the ECC ratings of the linked controls.

    Level 3 when every linked control is Implemented, 2 at 50% or more with at least one
    Implemented, 1 above 0%, otherwise 0. Levels 4 and 5 need measured control effectiveness,
    which the ECC ratings do not carry.
    """
    if score is None:
        return None
    if score >= 100.0:
        return 3
    if score >= 50.0 and any_implemented:
        return 2
    if score > 0.0:
        return 1
    return 0


def sama_view(dataset: Dataset, assessment: Assessment) -> tuple[SamaResult, ...]:
    by_id = {result.control.id: result for result in assessment.results}
    links = {link.subdomain: link for link in dataset.sama_mapping.links}
    excluded = {item.subdomain: item.reason for item in dataset.sama_mapping.not_applicable}
    view: list[SamaResult] = []
    for domain in dataset.sama.domains:
        for subdomain in domain.subdomains:
            if subdomain.id in excluded:
                reason = excluded[subdomain.id]
                view.append(SamaResult(domain, subdomain, (), None, None, None, reason))
                continue
            link = links.get(subdomain.id)
            if link is None:
                continue
            if link.rating is not None:
                score: float | None = 100 * POINTS[link.rating]
                implemented = link.rating is Status.IMPLEMENTED
                note: str | None = link.rating_note
            else:
                results = [by_id[c] for c in link.ecc if c in by_id]
                score = compliance(results)
                implemented = any(r.status is Status.IMPLEMENTED for r in results)
                note = None if score is not None else NOT_RATED
            level = maturity(score, implemented)
            view.append(SamaResult(domain, subdomain, link.ecc, link.why, score, level, note))
    return tuple(view)


def level_counts(view: tuple[SamaResult, ...]) -> dict[int, int]:
    """How many applicable subdomains sit at each indicative level, 0 to 3."""
    counts = dict.fromkeys(range(4), 0)
    for result in view:
        if result.level is not None:
            counts[result.level] += 1
    return counts
