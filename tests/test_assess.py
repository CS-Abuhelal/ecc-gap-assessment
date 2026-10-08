from dataclasses import replace

import pytest

from ecc.assess import assess, compare, compliance, domain_scores, rate_checks
from ecc.models import CheckResult, Evidence, EvidenceEntry, Status


@pytest.mark.parametrize(
    ("results", "expected"),
    [
        (["passed", "passed"], Status.IMPLEMENTED),
        (["passed", "failed"], Status.PARTIAL),
        (["failed", "failed"], Status.NOT_IMPLEMENTED),
        (["passed", "not applicable", "not scanned"], Status.IMPLEMENTED),
        (["not applicable", "not scanned"], None),
        ([], None),
    ],
)
def test_rate_checks(results, expected):
    assert rate_checks(results) == expected


def statuses(assessment):
    return {result.control.id: result.status for result in assessment.results}


def test_baseline_statuses(dataset, baseline):
    assert statuses(assess(dataset, baseline)) == {
        "1-3-1": Status.PARTIAL,  # documents only
        "2-2-1": Status.IMPLEMENTED,  # documents only
        "2-2-3": Status.PARTIAL,  # one of two checks passed
        "2-12-3": Status.NOT_IMPLEMENTED,  # weaker of failed checks and approved policy
        "4-2-1": Status.NOT_APPLICABLE,
    }


def test_a_control_gets_the_weaker_of_technical_and_documentary(dataset, baseline):
    result = assess(dataset, baseline).result("2-12-3")
    assert result.technical is Status.NOT_IMPLEMENTED
    assert result.documentary is Status.IMPLEMENTED
    assert [fact.name for fact in result.facts] == ["log_retention"]
    assert [(o.check.id, o.result) for o in result.checks] == [
        (26139, "failed"),
        (26140, "not applicable"),
    ]


def test_documentary_evidence_can_be_the_weaker_side(dataset, after):
    draft = EvidenceEntry(control="2-2-3", status=Status.PARTIAL, note="Policy drafted.")
    evidence = Evidence(entries=(*dataset.evidence.entries, draft))
    result = assess(replace(dataset, evidence=evidence), after).result("2-2-3")
    assert result.technical is Status.IMPLEMENTED
    assert result.documentary is Status.PARTIAL
    assert result.status is Status.PARTIAL


def test_after_statuses(dataset, after):
    found = statuses(assess(dataset, after))
    assert found["2-2-3"] is Status.IMPLEMENTED
    assert found["2-12-3"] is Status.PARTIAL  # checks pass, but logs are kept only 18 days


def test_missing_results_count_as_not_scanned(dataset, baseline):
    trimmed = baseline.model_copy(update={"checks": baseline.checks[:1]})
    result = assess(dataset, trimmed).result("2-2-3")
    assert [outcome.result for outcome in result.checks] == ["failed", "not scanned"]
    assert result.status is Status.NOT_IMPLEMENTED


def test_summary_lines(dataset, baseline):
    assessment = assess(dataset, baseline)
    assert assessment.result("2-2-3").summary == "1 of 2 CIS checks passed"
    assert assessment.result("2-2-1").summary == (
        "Access control policy approved. (docs/policies/access-control.md)"
    )
    assert assessment.result("4-2-1").summary == "The company uses no cloud hosting."


def test_the_summary_says_when_no_check_has_a_usable_result(dataset, baseline):
    skipped = tuple(
        CheckResult(id=check.id, result="not applicable") if check.id == 26139 else check
        for check in baseline.checks
    )
    result = assess(dataset, baseline.model_copy(update={"checks": skipped})).result("2-12-3")
    assert result.summary.startswith("No usable CIS results (2 not applicable or not scanned)")


def test_compliance_and_domain_scores(dataset, baseline, after):
    before_assessment = assess(dataset, baseline)
    after_assessment = assess(dataset, after)
    assert compliance(before_assessment.results) == 50.0
    assert compliance(after_assessment.results) == 75.0
    assert domain_scores(before_assessment) == {1: 50.0, 2: 50.0, 4: None}
    assert domain_scores(after_assessment) == {1: 50.0, 2: 83.3, 4: None}


def test_compare_lists_changed_controls(dataset, baseline, after):
    changes = compare(assess(dataset, baseline), assess(dataset, after))
    assert [(c.control.id, c.before, c.after) for c in changes] == [
        ("2-2-3", Status.PARTIAL, Status.IMPLEMENTED),
        ("2-12-3", Status.NOT_IMPLEMENTED, Status.PARTIAL),
    ]
