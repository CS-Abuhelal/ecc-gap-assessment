import pytest
from pydantic import ValidationError

from ecc.assess import assess
from ecc.models import SamaLink
from ecc.sama import level_counts, maturity, sama_view


@pytest.mark.parametrize(
    ("score", "level"),
    [(None, None), (0.0, 0), (0.1, 1), (49.9, 1), (50.0, 2), (99.9, 2), (100.0, 3)],
)
def test_maturity_levels(score, level):
    assert maturity(score) == level


def view_of(dataset, snapshot):
    return {item.subdomain.id: item for item in sama_view(dataset, assess(dataset, snapshot))}


def test_the_baseline_view(dataset, baseline):
    view = view_of(dataset, baseline)
    assert list(view) == ["3.1.3", "3.1.4", "3.3.5", "3.3.12", "3.3.14", "3.4.3"]
    assert (view["3.1.3"].score, view["3.1.3"].level) == (50.0, 2)
    assert (view["3.3.5"].score, view["3.3.5"].level) == (75.0, 2)
    assert (view["3.3.14"].score, view["3.3.14"].level) == (0.0, 0)


def test_after_fixes_a_subdomain_reaches_level_3(dataset, after):
    view = view_of(dataset, after)
    assert (view["3.3.5"].score, view["3.3.5"].level) == (100.0, 3)
    assert view["3.3.14"].level == 2


def test_an_override_replaces_the_derived_score(dataset, baseline):
    item = view_of(dataset, baseline)["3.1.4"]
    assert (item.score, item.level) == (0.0, 0)
    assert item.note == "Roles are not written down."


def test_not_applicable_subdomains_have_no_level(dataset, baseline):
    view = view_of(dataset, baseline)
    assert view["3.3.12"].level is None
    assert view["3.3.12"].note == "Example Co runs no payment systems."
    assert view["3.4.3"].level is None  # its only ECC control is Not applicable


def test_level_counts(dataset, baseline):
    view = sama_view(dataset, assess(dataset, baseline))
    assert level_counts(view) == {0: 2, 1: 0, 2: 2, 3: 0}


def test_an_override_needs_a_note():
    with pytest.raises(ValidationError):
        SamaLink(subdomain="3.1.4", ecc=["1-3-1"], why="Roles.", rating="Not implemented")
    with pytest.raises(ValidationError):
        SamaLink(
            subdomain="3.1.4",
            ecc=["1-3-1"],
            why="Roles.",
            rating="Not applicable",
            rating_note="Does not apply.",
        )
