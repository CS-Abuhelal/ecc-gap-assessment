import json
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from ecc.collect import (
    CollectError,
    Indexer,
    IndexerSettings,
    collect,
    find_agent,
    hits_of,
    latest_results,
    logging_facts,
    parse_timestamp,
    snapshot_path,
    vulnerability_counts,
)

NOW = datetime(2026, 10, 12, 18, 0, 30, 123456, tzinfo=UTC)
BASE_URL = "https://indexer.test"


def sca(check_id: int, result: str, status: str | None = None) -> dict[str, Any]:
    check: dict[str, Any] = {"id": str(check_id), "result": result}
    if status is not None:
        check["status"] = status
    return {"_source": {"data": {"sca": {"check": check}}}}


def page(docs: list[dict[str, Any]], relation: str = "eq", total: int | None = None) -> dict:
    value = len(docs) if total is None else total
    return {"hits": {"total": {"value": value, "relation": relation}, "hits": docs}}


@dataclass
class FakeIndexer:
    """Answers the queries collect makes, from canned data."""

    agents: tuple[str, ...] = ("lab-agent",)
    sca_hits: list[dict[str, Any]] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(
        default_factory=lambda: [{"_source": {"vulnerability": {"severity": "Low"}}}]
    )
    vulnerability_total: int = 7
    oldest: str | None = "2026-09-28T10:00:00.000+0000"
    recent: int = 5
    relation: str = "eq"
    requests: list[dict[str, Any]] = field(default_factory=list)

    def handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.requests.append(body)
        path = request.url.path
        if path.endswith("/_count"):
            count = self.vulnerability_total if "vulnerabilities" in path else self.recent
            return httpx.Response(200, json={"count": count})
        if "aggs" in body:
            buckets = [{"key": name, "doc_count": 3} for name in self.agents]
            aggregations = {"agents": {"buckets": buckets}}
            return httpx.Response(200, json={**page([]), "aggregations": aggregations})
        if "vulnerabilities" in path:
            return httpx.Response(200, json=page(self.vulnerabilities))
        if body["size"] == 1:
            docs = [] if self.oldest is None else [{"_source": {"timestamp": self.oldest}}]
            return httpx.Response(200, json=page(docs, total=len(docs) * 500))
        return httpx.Response(200, json=page(self.sca_hits, relation=self.relation))

    def indexer(self) -> Indexer:
        transport = httpx.MockTransport(self.handle)
        return Indexer(httpx.Client(transport=transport, base_url=BASE_URL))


def test_settings_need_an_indexer_url():
    with pytest.raises(CollectError, match="WAZUH_INDEXER_URL"):
        IndexerSettings.from_env({})


@pytest.mark.parametrize("url", ["http://127.0.0.1:9200", "127.0.0.1:9200"])
def test_settings_need_an_https_url(url):
    with pytest.raises(CollectError, match="must start with https://"):
        IndexerSettings.from_env({"WAZUH_INDEXER_URL": url})


def test_settings_accept_https_in_any_case():
    settings = IndexerSettings.from_env({"WAZUH_INDEXER_URL": "HTTPS://127.0.0.1:9200"})
    assert settings.url == "HTTPS://127.0.0.1:9200"


def test_settings_read_the_environment():
    settings = IndexerSettings.from_env(
        {
            "WAZUH_INDEXER_URL": "https://127.0.0.1:9200/",
            "WAZUH_INDEXER_USER": "admin",
            "WAZUH_INDEXER_PASSWORD": "not-a-real-password",
            "WAZUH_CA_CERT": "root-ca.pem",
            "WAZUH_TLS_SERVER_NAME": "wazuh.indexer",
        }
    )
    assert settings == IndexerSettings(
        "https://127.0.0.1:9200", "admin", "not-a-real-password", "root-ca.pem", "wazuh.indexer"
    )
    assert "not-a-real-password" not in repr(settings)


def test_one_agent_is_picked_automatically():
    assert find_agent(FakeIndexer().indexer(), None) == "lab-agent"


def test_no_agent_is_an_error():
    with pytest.raises(CollectError, match="No agent has SCA results"):
        find_agent(FakeIndexer(agents=()).indexer(), None)


def test_several_agents_need_a_choice():
    fake = FakeIndexer(agents=("agent-a", "agent-b"))
    with pytest.raises(CollectError, match="2 agents"):
        find_agent(fake.indexer(), None)
    assert find_agent(fake.indexer(), "agent-b") == "agent-b"


def test_an_unknown_requested_agent_is_an_error():
    with pytest.raises(CollectError, match="--agent"):
        find_agent(FakeIndexer().indexer(), "other-agent")


def test_the_newest_result_per_check_wins():
    fake = FakeIndexer(sca_hits=[sca(26000, "failed"), sca(26000, "passed"), sca(26001, "passed")])
    assert latest_results(fake.indexer(), "lab-agent") == {26000: "failed", 26001: "passed"}


def test_not_applicable_can_come_from_the_status_field():
    fake = FakeIndexer(sca_hits=[sca(26139, "", status="Not applicable"), sca(26140, "odd")])
    assert latest_results(fake.indexer(), "lab-agent") == {26139: "not applicable"}


def test_cut_off_results_stop_the_collection():
    fake = FakeIndexer(sca_hits=[sca(26000, "passed")], relation="gte")
    with pytest.raises(CollectError, match="cut off"):
        latest_results(fake.indexer(), "lab-agent")


def test_vulnerabilities_are_counted_by_severity():
    severities = ("Critical", "High", "High", "Medium", "Low", "Untriaged")
    docs = [{"_source": {"vulnerability": {"severity": s}}} for s in severities]
    counts = vulnerability_counts(FakeIndexer(vulnerabilities=docs).indexer(), "lab-agent")
    assert counts.model_dump() == {"critical": 1, "high": 2, "medium": 1, "low": 1}


def test_logging_facts():
    facts = logging_facts(FakeIndexer().indexer(), "lab-agent", NOW)
    assert facts.oldest_alert == datetime(2026, 9, 28, 10, 0, tzinfo=UTC)
    assert facts.agent_active is True
    quiet = logging_facts(FakeIndexer(oldest=None, recent=0).indexer(), "lab-agent", NOW)
    assert quiet.oldest_alert is None
    assert quiet.agent_active is False


def test_wazuh_timestamps_parse():
    expected = datetime(2026, 9, 27, 23, 17, 30, 577000, tzinfo=UTC)
    assert parse_timestamp("2026-09-27T23:17:30.577+0000") == expected


def test_collect_builds_an_allowlisted_snapshot(dataset):
    hits = [sca(26000, "failed"), sca(26001, "passed"), sca(99999, "passed")]
    collected = collect(FakeIndexer(sca_hits=hits).indexer(), dataset.policy, "baseline", NOW)
    snapshot = collected.snapshot
    assert collected.agent == "lab-agent"
    assert snapshot.host == "WS-01"
    assert snapshot.taken_at == NOW.replace(microsecond=0)
    assert snapshot.policy.checks_total == 4
    assert [(check.id, check.result) for check in snapshot.checks] == [
        (26000, "failed"),
        (26001, "passed"),
        (26139, "not scanned"),
        (26140, "not scanned"),
    ]
    assert "lab-agent" not in snapshot.model_dump_json()


def test_every_query_is_limited_to_the_agent(dataset):
    fake = FakeIndexer(sca_hits=[sca(26000, "failed")])
    collect(fake.indexer(), dataset.policy, "baseline", NOW)
    queries = [body for body in fake.requests if "aggs" not in body]
    assert len(queries) == 4
    for body in queries:
        assert {"term": {"agent.name": "lab-agent"}} in body["query"]["bool"]["filter"]


def test_an_unreachable_indexer_is_a_clear_error():
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    indexer = Indexer(httpx.Client(transport=httpx.MockTransport(refuse), base_url=BASE_URL))
    with pytest.raises(CollectError, match="Start Docker and Wazuh"):
        find_agent(indexer, None)


def test_a_wrong_password_is_a_clear_error():
    transport = httpx.MockTransport(lambda request: httpx.Response(401))
    indexer = Indexer(httpx.Client(transport=transport, base_url=BASE_URL))
    with pytest.raises(CollectError, match="WAZUH_INDEXER_PASSWORD"):
        find_agent(indexer, None)


def test_the_tls_server_name_is_sent_with_every_request():
    seen = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request.extensions.get("sni_hostname"))
        return httpx.Response(200, json={"count": 0})

    client = httpx.Client(transport=httpx.MockTransport(handle), base_url=BASE_URL)
    Indexer(client, server_name="wazuh.indexer").count("wazuh-alerts-*", {"match_all": {}})
    assert seen == ["wazuh.indexer"]


def test_snapshot_path_uses_the_month_and_label(baseline, tmp_path):
    assert snapshot_path(tmp_path, baseline) == tmp_path / "2026-10-baseline.json"


def test_partial_answers_are_errors():
    for answer in (
        {**page([]), "timed_out": True},
        {**page([]), "_shards": {"total": 2, "successful": 1, "failed": 1}},
    ):
        with pytest.raises(CollectError, match="partial answer"):
            hits_of(answer)


def test_an_answer_without_a_total_cannot_prove_it_is_complete():
    with pytest.raises(CollectError, match="cut off"):
        hits_of({"hits": {"hits": []}})
    assert hits_of({"hits": {"hits": []}}, complete=False) == []


def test_a_malformed_total_is_an_error():
    with pytest.raises(CollectError, match="unexpected answer"):
        hits_of({"hits": {"total": {"value": "many", "relation": "eq"}, "hits": []}})


def test_hits_without_check_ids_are_an_error():
    fake = FakeIndexer(sca_hits=[{"_source": {"data": "odd"}}, {"_source": {}}])
    with pytest.raises(CollectError, match="unexpected answer"):
        latest_results(fake.indexer(), "lab-agent")


def test_a_non_json_answer_is_an_error():
    transport = httpx.MockTransport(lambda request: httpx.Response(200, text="<html>"))
    indexer = Indexer(httpx.Client(transport=transport, base_url=BASE_URL))
    with pytest.raises(CollectError, match="unexpected answer"):
        find_agent(indexer, None)


def test_a_tls_failure_names_the_tls_settings():
    def fail(request: httpx.Request) -> httpx.Response:
        try:
            raise ssl.SSLCertVerificationError("certificate verify failed")
        except ssl.SSLError as cause:
            raise httpx.ConnectError("TLS handshake failed", request=request) from cause

    indexer = Indexer(httpx.Client(transport=httpx.MockTransport(fail), base_url=BASE_URL))
    with pytest.raises(CollectError, match="WAZUH_TLS_SERVER_NAME"):
        find_agent(indexer, None)


def test_no_vulnerability_data_at_all_is_an_error():
    fake = FakeIndexer(vulnerabilities=[], vulnerability_total=0)
    with pytest.raises(CollectError, match="no vulnerability data"):
        vulnerability_counts(fake.indexer(), "lab-agent")


def test_an_agent_without_vulnerabilities_counts_zero():
    fake = FakeIndexer(vulnerabilities=[], vulnerability_total=5)
    counts = vulnerability_counts(fake.indexer(), "lab-agent")
    assert counts.model_dump() == {"critical": 0, "high": 0, "medium": 0, "low": 0}


def test_an_invalid_url_is_a_clear_error():
    with pytest.raises(CollectError, match="not a valid URL"):
        IndexerSettings("https://x:abc", "admin", "not-a-real-password").client()


def test_malformed_agent_buckets_are_an_error():
    answer = {**page([]), "aggregations": {"agents": {"buckets": [{}]}}}
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=answer))
    indexer = Indexer(httpx.Client(transport=transport, base_url=BASE_URL))
    with pytest.raises(CollectError, match="unexpected answer"):
        find_agent(indexer, None)


def test_a_partial_count_is_an_error():
    answer = {"count": 0, "_shards": {"total": 2, "successful": 1, "failed": 1}}
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=answer))
    indexer = Indexer(httpx.Client(transport=transport, base_url=BASE_URL))
    with pytest.raises(CollectError, match="partial answer"):
        indexer.count("wazuh-alerts-*", {"match_all": {}})
