import json

import pytest

from ecc.models import Snapshot
from ecc.privacy import PrivacyError, find_leaks, forbidden_terms, snapshot_json, write_snapshot
from tests.fixtures import BASELINE


def test_terms_come_from_the_environment_and_extras():
    env = {
        "USERNAME": "jdoe",
        "COMPUTERNAME": "DESKTOP-TEST1",
        "ECC_FORBIDDEN_TERMS": " Jane , Doe,,x",
    }
    assert forbidden_terms(env, extra=["lab-agent"]) == [
        "DESKTOP-TEST1",
        "Doe",
        "Jane",
        "jdoe",
        "lab-agent",
    ]


def test_short_and_missing_terms_are_dropped():
    assert forbidden_terms({"USERNAME": "ab"}) == []


def test_leaks_are_found_case_insensitively():
    assert find_leaks('{"label": "jane-test"}', ["Jane", "Doe"]) == ["Jane"]


def test_a_snapshot_is_written_with_the_schema_key(tmp_path):
    snapshot = Snapshot.model_validate(BASELINE)
    path = tmp_path / "snapshots" / "2026-10-baseline.json"
    write_snapshot(snapshot, path, ["Jane"])
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema"] == 1
    assert data["host"] == "WS-01"
    assert path.read_bytes() == snapshot_json(snapshot).encode("utf-8")


def test_a_leak_stops_the_write(tmp_path):
    snapshot = Snapshot.model_validate({**BASELINE, "label": "jane-test"})
    path = tmp_path / "out.json"
    with pytest.raises(PrivacyError, match="1 forbidden term"):
        write_snapshot(snapshot, path, ["Jane"])
    assert not path.exists()


def test_existing_snapshots_are_never_overwritten(tmp_path):
    path = tmp_path / "out.json"
    path.write_text("old", encoding="utf-8")
    with pytest.raises(FileExistsError):
        write_snapshot(Snapshot.model_validate(BASELINE), path, [])
    assert path.read_text(encoding="utf-8") == "old"
