import dataclasses

import pytest

from ecc.load import DataError, load_dataset
from ecc.models import FixList
from ecc.remediation import fix_results, other_changes
from tests.fixtures import FIXES, write_fixes


def test_the_fixes_are_loaded(dataset):
    first, second = dataset.fixes.fixes
    assert (first.id, first.optional, second.optional) == ("F01", False, True)
    assert [item.kind for item in first.items] == ["account", "registry"]


def test_each_fix_reports_its_controls_and_passing_checks(dataset, baseline, after):
    first, second = fix_results(dataset, after, baseline)
    assert (first.fix.id, first.controls, first.before, first.after) == ("F01", ("2-2-3",), 0, 1)
    assert (second.controls, second.before, second.after) == (("2-12-3",), 0, 1)


def test_without_an_earlier_snapshot_there_is_no_before(dataset, baseline):
    first, _ = fix_results(dataset, baseline)
    assert (first.before, first.after) == (None, 0)


def item_with(**changes):
    registry = FIXES["fixes"][0]["items"][1]
    fix = {**FIXES["fixes"][0], "items": [{**registry, **changes}]}
    return {"fixes": [fix]}


@pytest.mark.parametrize(
    "changes",
    [
        {"path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {"path": "HKCU:\\SOFTWARE\\Policies\\Microsoft"},
        {"path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Extra"},
        {"path": "HKLM:\\SOFTWARE\\Policies\\..\\Microsoft\\Windows\\CurrentVersion\\Run"},
        {"path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\*"},
        {"path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\x'; Remove-Item C:\\; '"},
        {"path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\n"},
        {"name": "Run'; Start-Process calc; '"},
        {"name": ""},
        {"path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"},
        {"path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths"},
        {"type": "QWord"},
        {"value": "1"},
        {"value": -1},
        {"value": 2147483648},
        {"type": "String", "value": 1},
    ],
)
def test_registry_items_are_limited(changes):
    with pytest.raises(ValueError):
        FixList.model_validate(item_with(**changes))


def test_policy_keys_are_allowed():
    path = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient"
    assert FixList.model_validate(item_with(path=path)).fixes[0].items[0].path == path


def test_a_broken_fix_list_names_the_file(root):
    write_fixes(root, {"fixes": [{"id": "F1"}]})
    with pytest.raises(DataError, match="fixes.json"):
        load_dataset(root)


def test_an_optional_fix_counts_as_applied_only_when_listed(dataset, baseline, after):
    first, second = fix_results(dataset, after, baseline)
    assert (first.applied, second.applied) == (True, True)
    report = dataset.report.model_copy(update={"optional_fixes_applied": ()})
    unlisted = fix_results(dataclasses.replace(dataset, report=report), after, baseline)
    assert [row.applied for row in unlisted] == [True, False]
    assert [row.applied for row in fix_results(dataset, baseline)] == [None, None]


def test_changes_outside_the_fixes_are_listed(dataset, baseline, after):
    assert other_changes(dataset, baseline, after) == ()
    results = [
        check.model_copy(update={"result": "failed"}) if check.id == 26001 else check
        for check in after.checks
    ]
    changed = other_changes(dataset, baseline, after.model_copy(update={"checks": tuple(results)}))
    assert [(c.check.id, c.before, c.after) for c in changed] == [(26001, "passed", "failed")]
