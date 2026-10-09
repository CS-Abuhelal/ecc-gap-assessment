"""A tiny, self-consistent repo used by the tests. Every name in it is made up."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import yaml

CATALOG = {
    "framework": "ECC-2:2024",
    "source": "https://example.test/ecc.pdf",
    "domains": [
        {
            "id": 1,
            "title": "Cybersecurity Governance",
            "subdomains": [
                {
                    "id": "1-3",
                    "title": "Cybersecurity Policies and Procedures",
                    "controls": [{"id": "1-3-1", "text": "Policies shall be documented."}],
                }
            ],
        },
        {
            "id": 2,
            "title": "Cybersecurity Defense",
            "subdomains": [
                {
                    "id": "2-2",
                    "title": "Identity and Access Management",
                    "controls": [
                        {"id": "2-2-1", "text": "IAM requirements shall be documented."},
                        {
                            "id": "2-2-3",
                            "text": "IAM requirements shall include the following as a minimum:",
                            "subcontrols": [
                                {"id": "2.2.3.1", "text": "Single-factor authentication."}
                            ],
                        },
                    ],
                },
                {
                    "id": "2-12",
                    "title": "Cybersecurity Event Logs and Monitoring Management",
                    "controls": [
                        {"id": "2-12-3", "text": "Logging shall include the following:"}
                    ],
                },
            ],
        },
        {
            "id": 4,
            "title": "Third-Party and Cloud Computing Cybersecurity",
            "subdomains": [
                {
                    "id": "4-2",
                    "title": "Cloud Computing and Hosting Cybersecurity",
                    "controls": [
                        {"id": "4-2-1", "text": "Cloud requirements shall be documented."}
                    ],
                }
            ],
        },
    ],
}

CIS_CHECKS = {
    "policy": {
        "id": "cis_win11_enterprise",
        "name": "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0",
    },
    "checks": [
        {"id": 26000, "cis": "1.1.1", "title": "Ensure 'Enforce password history' is set."},
        {"id": 26001, "cis": "1.1.2", "title": "Ensure 'Maximum password age' is set."},
        {"id": 26139, "cis": "17.1.1", "title": "Ensure 'Audit Credential Validation' is set."},
        {"id": 26140, "cis": "17.2.1", "title": "Ensure 'Audit Application Group Management'."},
    ],
}

MAPPING = {
    "rules": [
        {"cis": "1", "ecc": ["2-2-3"], "why": "Password rules protect sign-in."},
        {"cis": "17", "ecc": ["2-12-3"], "why": "Audit policy turns on event logs."},
    ],
    "facts": [{"fact": "log_retention", "ecc": ["2-12-3"]}],
}

EVIDENCE = {
    "entries": [
        {
            "control": "1-3-1",
            "status": "Partially implemented",
            "note": "Policy drafted, not yet approved.",
        },
        {
            "control": "2-2-1",
            "status": "Implemented",
            "documents": ["docs/policies/access-control.md"],
            "note": "Access control policy approved.",
        },
        {
            "control": "2-12-3",
            "status": "Implemented",
            "documents": ["docs/policies/logging.md"],
            "note": "Logging policy approved.",
        },
    ]
}

APPLICABILITY = {
    "not_applicable": [{"control": "4-2-1", "reason": "The company uses no cloud hosting."}]
}

RISKS = {
    "risks": [
        {
            "id": "R-01",
            "controls": ["2-2-3"],
            "statement": "Weak passwords allow account takeover.",
            "likelihood": 3,
            "impact": 4,
            "treatment": "mitigate",
            "owner": "IT Manager",
            "due": "2026-11-01",
        },
        {
            "id": "R-02",
            "controls": ["2-12-3"],
            "statement": "Missing logs hide attacks.",
            "likelihood": 4,
            "impact": 4,
            "treatment": "mitigate",
            "owner": "Cybersecurity Lead",
            "due": "2026-12-15",
        },
        {
            "id": "R-03",
            "controls": ["1-3-1"],
            "statement": "Unapproved policies are not followed.",
            "likelihood": 2,
            "impact": 2,
            "treatment": "accept",
            "owner": "General Manager",
            "due": "2027-03-01",
        },
    ]
}

BASELINE = {
    "schema": 1,
    "label": "baseline",
    "taken_at": "2026-10-12T18:00:00Z",
    "host": "WS-01",
    "policy": {"id": "cis_win11_enterprise", "checks_total": 4},
    "checks": [
        {"id": 26000, "result": "failed"},
        {"id": 26001, "result": "passed"},
        {"id": 26139, "result": "failed"},
        {"id": 26140, "result": "not applicable"},
    ],
    "vulnerabilities": {"critical": 1, "high": 3, "medium": 5, "low": 2},
    "logging": {"oldest_alert": "2026-10-02T18:00:00Z", "agent_active": True},
}

AFTER = {
    **copy.deepcopy(BASELINE),
    "label": "after",
    "taken_at": "2026-10-20T18:00:00Z",
    "checks": [
        {"id": 26000, "result": "passed"},
        {"id": 26001, "result": "passed"},
        {"id": 26139, "result": "passed"},
        {"id": 26140, "result": "not applicable"},
    ],
    "vulnerabilities": {"critical": 0, "high": 1, "medium": 5, "low": 2},
}

REPORT = {
    "company": "Example Co (fictional)",
    "executive_summary": ["Example Co is a made-up company used by the tests."],
    "key_findings": ["Password rules need work."],
    "limitations": ["All data here is made up."],
}

SAMA_CSF = {
    "framework": "SAMA Cyber Security Framework",
    "source": "https://example.test/sama",
    "domains": [
        {
            "id": "3.1",
            "title": "Cyber Security Leadership and Governance",
            "subdomains": [
                {"id": "3.1.3", "title": "Cyber Security Policy"},
                {"id": "3.1.4", "title": "Cyber Security Roles and Responsibilities"},
            ],
        },
        {
            "id": "3.3",
            "title": "Cyber Security Operations and Technology",
            "subdomains": [
                {"id": "3.3.5", "title": "Identity and Access Management"},
                {"id": "3.3.12", "title": "Payment Systems"},
                {"id": "3.3.14", "title": "Cyber Security Event Management"},
            ],
        },
        {
            "id": "3.4",
            "title": "Third Party Cyber Security",
            "subdomains": [{"id": "3.4.3", "title": "Cloud Computing"}],
        },
    ],
    "levels": [
        {"level": n, "name": name, "meaning": f"Level {n}."}
        for n, name in enumerate(
            [
                "Non-existent",
                "Ad-hoc",
                "Repeatable but informal",
                "Structured and formalized",
                "Managed and measurable",
                "Adaptive",
            ]
        )
    ],
}

SAMA_MAPPING = {
    "links": [
        {"subdomain": "3.1.3", "ecc": ["1-3-1"], "why": "Policies."},
        {
            "subdomain": "3.1.4",
            "ecc": ["1-3-1"],
            "why": "Roles are part of the policy.",
            "rating": "Not implemented",
            "rating_note": "Roles are not written down.",
        },
        {"subdomain": "3.3.5", "ecc": ["2-2-1", "2-2-3"], "why": "Access management."},
        {"subdomain": "3.3.14", "ecc": ["2-12-3"], "why": "Event logs."},
        {"subdomain": "3.4.3", "ecc": ["4-2-1"], "why": "Cloud."},
    ],
    "not_applicable": [{"subdomain": "3.3.12", "reason": "Example Co runs no payment systems."}],
}

DATA_FILES = {
    "catalog.yaml": CATALOG,
    "cis_checks.yaml": CIS_CHECKS,
    "mapping.yaml": MAPPING,
    "evidence.yaml": EVIDENCE,
    "applicability.yaml": APPLICABILITY,
    "risks.yaml": RISKS,
    "report.yaml": REPORT,
    "sama_csf.yaml": SAMA_CSF,
    "sama_mapping.yaml": SAMA_MAPPING,
}


def rewrite(root: Path, name: str, content: object) -> None:
    (root / "data" / name).write_text(yaml.safe_dump(content, sort_keys=False), encoding="utf-8")


def write_root(root: Path) -> Path:
    (root / "data").mkdir(parents=True)
    for name, content in DATA_FILES.items():
        rewrite(root, name, content)
    policies = root / "docs" / "policies"
    policies.mkdir(parents=True)
    for document in ("access-control.md", "logging.md"):
        (policies / document).write_text("# Policy\n", encoding="utf-8")
    snapshots = root / "snapshots"
    snapshots.mkdir()
    for name, content in (("2026-10-baseline.json", BASELINE), ("2026-10-after.json", AFTER)):
        (snapshots / name).write_text(json.dumps(content, indent=2), encoding="utf-8")
    return root
