"""Read one agent's CIS check results, vulnerabilities and log facts from the Wazuh indexer."""

from __future__ import annotations

import re
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from ecc.models import (
    HOST_PLACEHOLDER,
    CheckResult,
    CisPolicy,
    LoggingFacts,
    Snapshot,
    SnapshotPolicy,
    VulnerabilityCounts,
)

ALERTS_INDEX = "wazuh-alerts-*"
VULNERABILITIES_INDEX = "wazuh-states-vulnerabilities-*"
MANAGER_AGENT_ID = "000"
MAX_DOCS = 10000
ACTIVE_WINDOW = timedelta(hours=24)
RESULTS = ("passed", "failed", "not applicable")
SEVERITIES = ("critical", "high", "medium", "low")
UNREACHABLE = "Could not reach the Wazuh indexer. Start Docker and Wazuh, then retry."


class CollectError(Exception):
    """Collecting from Wazuh failed; the message says what to do next."""


@dataclass(frozen=True)
class IndexerSettings:
    url: str
    user: str
    password: str = field(repr=False)
    ca_cert: str | None = None
    server_name: str | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> IndexerSettings:
        url = env.get("WAZUH_INDEXER_URL", "").strip()
        if not url:
            raise CollectError(
                "WAZUH_INDEXER_URL is not set. Start Docker and Wazuh, then set "
                "WAZUH_INDEXER_URL, WAZUH_INDEXER_USER and WAZUH_INDEXER_PASSWORD."
            )
        return cls(
            url=url.rstrip("/"),
            user=env.get("WAZUH_INDEXER_USER", ""),
            password=env.get("WAZUH_INDEXER_PASSWORD", ""),
            ca_cert=env.get("WAZUH_CA_CERT") or None,
            server_name=env.get("WAZUH_TLS_SERVER_NAME") or None,
        )

    def client(self) -> httpx.Client:
        verify: ssl.SSLContext | bool = True
        if self.ca_cert:
            try:
                verify = ssl.create_default_context(cafile=self.ca_cert)
            except OSError as error:
                raise CollectError("WAZUH_CA_CERT points to a file that cannot be read.") from error
        return httpx.Client(
            base_url=self.url, auth=(self.user, self.password), verify=verify, timeout=30.0
        )


class Indexer:
    """A thin wrapper over the indexer's search and count APIs."""

    def __init__(self, client: httpx.Client, server_name: str | None = None) -> None:
        self._client = client
        self._extensions = {"sni_hostname": server_name} if server_name else {}

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self._client.post(path, json=body, extensions=self._extensions)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as error:
            code = error.response.status_code
            hint = ""
            if code in (401, 403):
                hint = " Check WAZUH_INDEXER_USER and WAZUH_INDEXER_PASSWORD."
            message = f"The Wazuh indexer answered HTTP {code} for {path}.{hint}"
            raise CollectError(message) from error
        except (httpx.HTTPError, ValueError) as error:
            raise CollectError(UNREACHABLE) from error

    def search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._post(f"/{index}/_search", body)

    def count(self, index: str, query: dict[str, Any]) -> int:
        answer = self._post(f"/{index}/_count", {"query": query})
        try:
            return int(answer["count"])
        except (KeyError, TypeError, ValueError) as error:
            raise CollectError("The Wazuh indexer sent an unexpected count answer.") from error


def hits_of(answer: dict[str, Any], *, complete: bool = True) -> list[dict[str, Any]]:
    """The documents in a search answer. With complete=True, a cut-off answer is an error."""
    try:
        hits = answer["hits"]
        docs = [hit["_source"] for hit in hits["hits"]]
    except (KeyError, TypeError) as error:
        raise CollectError("The Wazuh indexer sent an unexpected search answer.") from error
    total = hits.get("total")
    if isinstance(total, dict):
        cut = total.get("relation") == "gte" or int(total.get("value", 0)) > len(docs)
    else:
        cut = isinstance(total, int) and total > len(docs)
    if complete and cut:
        raise CollectError(
            f"More than {MAX_DOCS} matching documents, so the results would be cut off. "
            "Nothing was saved."
        )
    return docs


def agent_filter(agent: str) -> dict[str, Any]:
    return {"term": {"agent.name": agent}}


def find_agent(indexer: Indexer, requested: str | None) -> str:
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [{"term": {"rule.groups": "sca"}}],
                "must_not": [{"term": {"agent.id": MANAGER_AGENT_ID}}],
            }
        },
        "aggs": {"agents": {"terms": {"field": "agent.name", "size": 100}}},
    }
    answer = indexer.search(ALERTS_INDEX, body)
    buckets = answer.get("aggregations", {}).get("agents", {}).get("buckets", [])
    names = sorted(str(bucket["key"]) for bucket in buckets)
    if requested is not None:
        if requested not in names:
            raise CollectError("The agent given with --agent has no SCA results.")
        return requested
    if not names:
        raise CollectError("No agent has SCA results yet. Wait for the first scan, then retry.")
    if len(names) > 1:
        raise CollectError(f"{len(names)} agents have SCA results. Choose one with --agent.")
    return names[0]


def check_result(check: dict[str, Any]) -> str | None:
    result = str(check.get("result") or "").strip().lower()
    if result in RESULTS:
        return result
    if str(check.get("status") or "").strip().lower() == "not applicable":
        return "not applicable"
    return None


def latest_results(indexer: Indexer, agent: str) -> dict[int, str]:
    """The newest SCA result per check id; older alerts for the same check are ignored."""
    body = {
        "size": MAX_DOCS,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["data.sca.check.id", "data.sca.check.result", "data.sca.check.status"],
        "query": {
            "bool": {
                "filter": [
                    {"term": {"rule.groups": "sca"}},
                    {"term": {"data.sca.type": "check"}},
                    agent_filter(agent),
                ]
            }
        },
    }
    seen: set[int] = set()
    latest: dict[int, str] = {}
    for doc in hits_of(indexer.search(ALERTS_INDEX, body)):
        check = doc.get("data", {}).get("sca", {}).get("check", {})
        try:
            check_id = int(check.get("id"))
        except (TypeError, ValueError):
            continue
        if check_id in seen:
            continue
        seen.add(check_id)
        result = check_result(check)
        if result is not None:
            latest[check_id] = result
    return latest


def vulnerability_counts(indexer: Indexer, agent: str) -> VulnerabilityCounts:
    body = {
        "size": MAX_DOCS,
        "_source": ["vulnerability.severity"],
        "query": {"bool": {"filter": [agent_filter(agent)]}},
    }
    counts = dict.fromkeys(SEVERITIES, 0)
    for doc in hits_of(indexer.search(VULNERABILITIES_INDEX, body)):
        severity = str(doc.get("vulnerability", {}).get("severity") or "").strip().lower()
        if severity in counts:
            counts[severity] += 1
    return VulnerabilityCounts(**counts)


def parse_timestamp(value: str) -> datetime:
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value.strip()).replace("Z", "+00:00")
    moment = datetime.fromisoformat(text)
    if moment.tzinfo is None:
        raise ValueError(f"timestamp has no time zone: {value!r}")
    return moment


def logging_facts(indexer: Indexer, agent: str, now: datetime) -> LoggingFacts:
    body = {
        "size": 1,
        "sort": [{"timestamp": {"order": "asc"}}],
        "_source": ["timestamp"],
        "query": {"bool": {"filter": [agent_filter(agent)]}},
    }
    docs = hits_of(indexer.search(ALERTS_INDEX, body), complete=False)
    oldest: datetime | None = None
    if docs:
        try:
            oldest = parse_timestamp(str(docs[0]["timestamp"])).astimezone(UTC)
        except (KeyError, ValueError) as error:
            raise CollectError("The oldest alert has an unreadable timestamp.") from error
    since = (now - ACTIVE_WINDOW).isoformat()
    recent = indexer.count(
        ALERTS_INDEX,
        {"bool": {"filter": [agent_filter(agent), {"range": {"timestamp": {"gte": since}}}]}},
    )
    return LoggingFacts(oldest_alert=oldest, agent_active=recent > 0)


@dataclass(frozen=True)
class Collected:
    snapshot: Snapshot
    agent: str


def build_snapshot(
    label: str,
    now: datetime,
    policy: CisPolicy,
    results: Mapping[int, str],
    vulnerabilities: VulnerabilityCounts,
    logging: LoggingFacts,
) -> Snapshot:
    checks = [
        CheckResult(id=check.id, result=results.get(check.id, "not scanned"))
        for check in policy.checks
    ]
    return Snapshot(
        label=label,
        taken_at=now.replace(microsecond=0),
        host=HOST_PLACEHOLDER,
        policy=SnapshotPolicy(id=policy.policy.id, checks_total=len(policy.checks)),
        checks=checks,
        vulnerabilities=vulnerabilities,
        logging=logging,
    )


def collect(
    indexer: Indexer, policy: CisPolicy, label: str, now: datetime, agent: str | None = None
) -> Collected:
    name = find_agent(indexer, agent)
    snapshot = build_snapshot(
        label,
        now,
        policy,
        latest_results(indexer, name),
        vulnerability_counts(indexer, name),
        logging_facts(indexer, name, now),
    )
    return Collected(snapshot, name)


def snapshot_path(directory: Path, snapshot: Snapshot) -> Path:
    return directory / f"{snapshot.taken_at:%Y-%m}-{snapshot.label}.json"
