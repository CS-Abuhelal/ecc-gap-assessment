from ecc.facts import rate_fact, rate_log_retention, rate_vulnerabilities
from ecc.models import Snapshot, Status
from tests.fixtures import BASELINE


def snapshot(**changes) -> Snapshot:
    return Snapshot.model_validate({**BASELINE, **changes})


def counts(critical: int = 0, high: int = 0) -> dict[str, int]:
    return {"critical": critical, "high": high, "medium": 4, "low": 1}


def test_no_critical_or_high_vulnerabilities_is_implemented():
    result = rate_vulnerabilities(snapshot(vulnerabilities=counts()))
    assert result.status is Status.IMPLEMENTED
    assert result.detail == "Open vulnerabilities: 0 critical, 0 high, 4 medium, 1 low"


def test_high_but_no_critical_is_partial():
    assert rate_vulnerabilities(snapshot(vulnerabilities=counts(high=2))).status is Status.PARTIAL


def test_any_critical_is_not_implemented():
    result = rate_vulnerabilities(snapshot(vulnerabilities=counts(critical=1)))
    assert result.status is Status.NOT_IMPLEMENTED


def test_a_year_of_logs_is_implemented():
    logging = {"oldest_alert": "2025-10-12T18:00:00Z", "agent_active": True}
    assert rate_log_retention(snapshot(logging=logging)).status is Status.IMPLEMENTED


def test_short_retention_with_an_active_agent_is_partial():
    result = rate_log_retention(snapshot())
    assert result.status is Status.PARTIAL
    assert result.detail == "Oldest stored alert is 10 days old; ECC asks for 365 (2.12.3.5)"


def test_short_retention_with_a_silent_agent_is_not_implemented():
    logging = {"oldest_alert": "2026-10-02T18:00:00Z", "agent_active": False}
    assert rate_log_retention(snapshot(logging=logging)).status is Status.NOT_IMPLEMENTED


def test_no_stored_alerts_is_not_implemented():
    logging = {"oldest_alert": None, "agent_active": True}
    assert rate_log_retention(snapshot(logging=logging)).status is Status.NOT_IMPLEMENTED


def test_rate_fact_dispatches_by_name():
    assert rate_fact("vulnerabilities", snapshot()).name == "vulnerabilities"
    assert rate_fact("log_retention", snapshot()).name == "log_retention"
