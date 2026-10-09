import pytest
from pydantic import ValidationError

from ecc.assess import assess
from ecc.models import SamaDomain, SamaFramework, SamaLink
from ecc.sama import NOT_RATED, level_counts, maturity, sama_view
from tests.fixtures import SAMA_CSF


@pytest.mark.parametrize(
    ("score", "any_implemented", "level"),
    [
        (None, False, None),
        (0.0, False, 0),
        (0.1, False, 1),
        (49.9, True, 1),
        (50.0, False, 1),
        (50.0, True, 2),
        (99.9, True, 2),
        (100.0, True, 3),
    ],
)
def test_maturity_levels(score, any_implemented, level):
    assert maturity(score, any_implemented) == level


def view_of(dataset, snapshot):
    return {item.subdomain.id: item for item in sama_view(dataset, assess(dataset, snapshot))}


def test_the_baseline_view(dataset, baseline):
    view = view_of(dataset, baseline)
    assert list(view) == ["3.1.3", "3.1.4", "3.3.5", "3.3.12", "3.3.14", "3.4.3"]
    assert (view["3.3.5"].score, view["3.3.5"].level) == (75.0, 2)
    assert view["3.3.5"].why == "Access management."
    assert (view["3.3.14"].score, view["3.3.14"].level) == (0.0, 0)


def test_level_2_needs_an_implemented_control(dataset, baseline):
    item = view_of(dataset, baseline)["3.1.3"]  # its only control is Partially implemented
    assert (item.score, item.level) == (50.0, 1)


def test_after_fixes_a_subdomain_reaches_level_3(dataset, after):
    view = view_of(dataset, after)
    assert (view["3.3.5"].score, view["3.3.5"].level) == (100.0, 3)
    assert (view["3.3.14"].score, view["3.3.14"].level) == (50.0, 1)


def test_an_override_replaces_the_derived_score(dataset, baseline):
    item = view_of(dataset, baseline)["3.1.4"]
    assert (item.score, item.level) == (0.0, 0)
    assert item.note == "Roles are not written down."


def test_not_applicable_subdomains_have_no_level(dataset, baseline):
    view = view_of(dataset, baseline)
    assert view["3.3.12"].level is None
    assert view["3.3.12"].note == "Example Co runs no payment systems."
    assert view["3.3.12"].why is None


def test_a_link_with_no_rated_control_says_why_it_has_no_level(dataset, baseline):
    item = view_of(dataset, baseline)["3.4.3"]  # its only ECC control is Not applicable
    assert (item.ecc, item.score, item.level) == (("4-2-1",), None, None)
    assert item.note == NOT_RATED


def test_level_counts(dataset, baseline):
    view = sama_view(dataset, assess(dataset, baseline))
    assert level_counts(view) == {0: 2, 1: 1, 2: 1, 3: 0}


def test_an_override_needs_a_note():
    with pytest.raises(ValidationError):
        SamaLink(subdomain="3.1.4", ecc=["1-3-1"], why="Roles.", rating="Not implemented")
    with pytest.raises(ValidationError):
        SamaLink(subdomain="3.1.4", ecc=["1-3-1"], why="Roles.", rating_note="No rating.")
    with pytest.raises(ValidationError):
        SamaLink(
            subdomain="3.1.4",
            ecc=["1-3-1"],
            why="Roles.",
            rating="Not applicable",
            rating_note="Does not apply.",
        )


def test_subdomains_sit_under_their_own_domain():
    with pytest.raises(ValidationError, match="outside domain 3.1: 3.4.9"):
        SamaDomain(id="3.1", title="Governance", subdomains=[{"id": "3.4.9", "title": "Stray"}])


def test_levels_run_from_0_to_5_once_each():
    levels = list(SAMA_CSF["levels"])
    levels[4] = {**levels[4], "level": 3}
    with pytest.raises(ValidationError, match="each once"):
        SamaFramework.model_validate({**SAMA_CSF, "levels": levels})
    assert SamaFramework.model_validate(SAMA_CSF).levels[5].name == "Adaptive"
