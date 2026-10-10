from collections import Counter
from pathlib import Path

from ecc.assess import assess, check_progress, compliance, domain_scores
from ecc.load import load_dataset, load_snapshots
from ecc.models import Status
from ecc.remediation import fix_results, other_changes
from ecc.sama import level_counts, sama_view
from ecc.validate import validate

ROOT = Path(__file__).resolve().parents[1]


def baseline_assessment():
    dataset = load_dataset(ROOT)
    snapshots = load_snapshots(ROOT / "snapshots")
    baseline = next(snapshot for snapshot in snapshots if snapshot.label == "baseline")
    return dataset, snapshots, assess(dataset, baseline)


def test_the_committed_assessment_is_complete():
    dataset, snapshots, _ = baseline_assessment()
    assert validate(dataset, snapshots) == []


def test_the_baseline_results():
    _, _, assessment = baseline_assessment()
    assert compliance(assessment.results) == 26.0
    assert domain_scores(assessment) == {1: 30.9, 2: 25.4, 3: 0.0, 4: 21.4}
    statuses = Counter(result.status.value for result in assessment.results)
    assert statuses == {
        "Implemented": 6,
        "Partially implemented": 41,
        "Not implemented": 55,
        "Not applicable": 6,
    }


def test_the_sama_view():
    dataset, _, assessment = baseline_assessment()
    view = sama_view(dataset, assessment)
    assert len(view) == 32
    assert level_counts(view) == {0: 8, 1: 14, 2: 6, 3: 0}
    destruction = next(item for item in view if item.subdomain.id == "3.3.11")
    assert (destruction.score, destruction.level) == (0.0, 0)
    assert destruction.note is not None


def test_the_sama_finding_matches_the_view():
    dataset, _, assessment = baseline_assessment()
    counts = level_counts(sama_view(dataset, assessment))
    finding = next(item for item in dataset.report.key_findings if "SAMA" in item)
    assert counts[3] == 0
    assert f"none of the {sum(counts.values())} applicable subdomains" in " ".join(finding.split())


def test_the_planned_fixes():
    dataset, _, assessment = baseline_assessment()
    rows = fix_results(dataset, assessment.snapshot)
    assert len(rows) == 12
    assert sum(len(row.fix.checks) for row in rows) == 57
    assert [row.fix.id for row in rows if row.fix.optional] == ["F08"]
    assert all(row.after == 0 for row in rows)
    assert {control for row in rows for control in row.controls} == {
        "2-2-3", "2-3-3", "2-5-3", "2-7-2", "2-12-3"
    }


def test_the_narrative_quotes_the_computed_figures():
    dataset, snapshots, before = baseline_assessment()
    later = next(snapshot for snapshot in snapshots if snapshot.label == "after")
    after = assess(dataset, later)
    report = dataset.report
    paragraphs = (*report.executive_summary, *report.key_findings, *report.limitations)
    text = " ".join(" ".join(paragraph.split()) for paragraph in paragraphs)

    def passed(snapshot):
        return sum(1 for check in snapshot.checks if check.result == "passed")

    usable = sum(1 for check in later.checks if check.result in ("passed", "failed"))
    progress = {p.control.id: p for p in check_progress(before, after)}
    logging, encryption = progress["2-12-3"], progress["2-8-3"]
    applicable = sum(1 for r in after.results if r.status is not Status.NOT_APPLICABLE)
    rows = fix_results(dataset, later, before.snapshot)
    measured = sum(1 for r in after.results if r.checks or r.facts)
    touched = {control for row in rows if row.applied for control in row.controls}
    days = (later.taken_at - later.logging.oldest_alert).days
    failing_logs = logging.after[1] - logging.after[0]
    risks = " ".join(" ".join(risk.statement.split()) for risk in dataset.risks.risks)
    assert all(row.after == len(row.fix.checks) for row in rows if row.applied)
    assert other_changes(dataset, before.snapshot, later) == ()
    for figure in (
        f"about {days} days of alerts are stored",
        f"{failing_logs} of the {logging.after[1]} CIS logging checks still fail",
    ):
        assert figure in risks, figure
    figures = [
        f"Wazuh measures {measured} of the {applicable} applicable controls",
        f"the fixes touched {len(touched)}",
        f"The {encryption.after[1]} BitLocker checks",
        f"go back only about {days} days",
        f"{applicable} apply",
        f"met {compliance(before.results)}% of them",
        f"from {passed(before.snapshot)} to {passed(later)} of {usable}",
        f"from {compliance(before.results)}% to {compliance(after.results)}%",
        f"{passed(later)} of {usable} applicable CIS checks pass on WS-01, up from "
        f"{passed(before.snapshot)}",
        f"Encryption scores {encryption.after[0]} of {encryption.after[1]}",
        f"{logging.after[0]} of {logging.after[1]} logging checks pass, up from "
        f"{logging.before[0]}",
        f"{later.vulnerabilities.high} high-severity ones are",
        f"The {len(dataset.risks.risks)} risks",
    ]
    for figure in figures:
        assert figure in text, figure
    assert later.vulnerabilities.critical == 0
    assert "No critical vulnerabilities are open" in text
