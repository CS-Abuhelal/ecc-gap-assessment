from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from ecc.models import HOST_PLACEHOLDER, EvidenceEntry, Risk, Rule, Snapshot, Status, weakest

SNAPSHOT = {
    "schema": 1,
    "label": "baseline",
    "taken_at": "2026-10-12T18:00:00Z",
    "host": "WS-01",
    "policy": {"id": "cis_win11_enterprise", "checks_total": 1},
    "checks": [{"id": 26000, "result": "failed"}],
    "vulnerabilities": {"critical": 0, "high": 1, "medium": 2, "low": 3},
    "logging": {"oldest_alert": "2026-09-28T10:00:00Z", "agent_active": True},
}


def test_weakest_picks_the_lowest_rating():
    assert weakest(Status.IMPLEMENTED, Status.PARTIAL) is Status.PARTIAL
    assert weakest(Status.PARTIAL, Status.NOT_IMPLEMENTED) is Status.NOT_IMPLEMENTED
    assert weakest(Status.IMPLEMENTED) is Status.IMPLEMENTED


def test_weakest_refuses_not_applicable_and_empty_input():
    with pytest.raises(ValueError):
        weakest(Status.NOT_APPLICABLE)
    with pytest.raises(ValueError):
        weakest()


def test_evidence_cannot_claim_not_applicable():
    with pytest.raises(ValidationError):
        EvidenceEntry(control="1-3-1", status=Status.NOT_APPLICABLE, note="Not used.")


def test_snapshot_round_trip_keeps_the_schema_key():
    snapshot = Snapshot.model_validate(SNAPSHOT)
    assert snapshot.format_version == 1
    assert snapshot.taken_at == datetime(2026, 10, 12, 18, 0, tzinfo=UTC)
    dumped = snapshot.model_dump(by_alias=True, mode="json")
    assert dumped["schema"] == 1
    assert "format_version" not in dumped


def test_snapshot_rejects_extra_fields():
    with pytest.raises(ValidationError):
        Snapshot.model_validate({**SNAPSHOT, "raw_alert": {"full_log": "secret"}})


def test_snapshot_only_accepts_the_placeholder_host():
    assert HOST_PLACEHOLDER == "WS-01"
    with pytest.raises(ValidationError):
        Snapshot.model_validate({**SNAPSHOT, "host": "real-computer-name"})


def test_snapshot_needs_time_zones():
    with pytest.raises(ValidationError):
        Snapshot.model_validate({**SNAPSHOT, "taken_at": "2026-10-12T18:00:00"})


def test_risk_score_is_likelihood_times_impact():
    risk = Risk(
        id="R-01",
        controls=["2-2-3"],
        statement="Weak passwords allow account takeover.",
        likelihood=3,
        impact=4,
        treatment="mitigate",
        owner="IT Manager",
        due="2026-11-01",
    )
    assert risk.score == 12


def test_rule_needs_a_well_formed_target_control():
    with pytest.raises(ValidationError):
        Rule(cis="1.1", ecc=[], why="Password rules.")
    with pytest.raises(ValidationError):
        Rule(cis="1.1", ecc=["2.2.3"], why="Wrong id format.")
