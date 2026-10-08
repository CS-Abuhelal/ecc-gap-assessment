from datetime import date, timedelta

import pytest

from ecc.assess import assess
from ecc.risk import BUCKET_ORDER, bucket, rating, risk_rows, roadmap


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (1, "Low"),
        (4, "Low"),
        (5, "Medium"),
        (9, "Medium"),
        (10, "High"),
        (16, "High"),
        (20, "Critical"),
        (25, "Critical"),
    ],
)
def test_rating_bands(score, expected):
    assert rating(score) == expected


def test_rating_rejects_zero():
    with pytest.raises(ValueError):
        rating(0)


@pytest.mark.parametrize(
    ("days", "expected"),
    [(-5, "30 days"), (30, "30 days"), (31, "60 days"), (60, "60 days"), (90, "90 days"),
     (91, "Later")],
)
def test_buckets(days, expected):
    as_of = date(2026, 10, 12)
    assert bucket(as_of + timedelta(days=days), as_of) == expected


def test_bucket_order():
    assert BUCKET_ORDER == ("30 days", "60 days", "90 days", "Later")


def test_rows_are_sorted_by_score(dataset, baseline):
    rows = risk_rows(dataset.risks, assess(dataset, baseline))
    assert [(row.risk.id, row.score, row.rating) for row in rows] == [
        ("R-02", 16, "High"),
        ("R-01", 12, "High"),
        ("R-03", 4, "Low"),
    ]
    assert [row.bucket for row in rows] == ["90 days", "30 days", "Later"]
    assert not any(row.closed for row in rows)


def test_the_baseline_roadmap_runs_soonest_first(dataset, baseline):
    rows = roadmap(risk_rows(dataset.risks, assess(dataset, baseline)))
    assert [row.risk.id for row in rows] == ["R-01", "R-02", "R-03"]


def test_a_risk_closes_when_its_controls_are_implemented(dataset, after):
    rows = risk_rows(dataset.risks, assess(dataset, after))
    assert {row.risk.id: row.closed for row in rows} == {
        "R-01": True,
        "R-02": False,
        "R-03": False,
    }
    assert [(row.bucket, row.risk.id) for row in roadmap(rows)] == [
        ("60 days", "R-02"),
        ("Later", "R-03"),
    ]
