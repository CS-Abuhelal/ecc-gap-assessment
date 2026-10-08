from pathlib import Path

import pytest

from ecc.load import DataError, load_dataset, load_snapshots
from tests.fixtures import RISKS, rewrite


def test_dataset_flattens_the_catalog(dataset):
    assert [control.id for control in dataset.catalog] == [
        "1-3-1",
        "2-2-1",
        "2-2-3",
        "2-12-3",
        "4-2-1",
    ]
    control = dataset.catalog[2]
    assert (control.domain, control.subdomain) == (2, "2-2")
    assert control.domain_title == "Cybersecurity Defense"
    assert control.subdomain_title == "Identity and Access Management"
    assert control.subcontrols[0].id == "2.2.3.1"


def test_dataset_reads_every_file(dataset):
    assert len(dataset.policy.checks) == 4
    assert [rule.cis for rule in dataset.mapping.rules] == ["1", "17"]
    assert len(dataset.evidence.entries) == 3
    assert dataset.applicability.not_applicable[0].control == "4-2-1"
    assert [risk.id for risk in dataset.risks.risks] == ["R-01", "R-02", "R-03"]


def test_snapshots_are_sorted_by_time(root: Path):
    labels = [snapshot.label for snapshot in load_snapshots(root / "snapshots")]
    assert labels == ["baseline", "after"]


def test_a_missing_snapshot_folder_means_no_snapshots(tmp_path: Path):
    assert load_snapshots(tmp_path / "snapshots") == []


def test_a_missing_file_names_the_file(root: Path):
    (root / "data" / "risks.yaml").unlink()
    with pytest.raises(DataError, match="risks.yaml"):
        load_dataset(root)


def test_invalid_values_name_the_file(root: Path):
    rewrite(root, "risks.yaml", {"risks": [{**RISKS["risks"][0], "likelihood": 9}]})
    with pytest.raises(DataError, match="risks.yaml"):
        load_dataset(root)


def test_broken_yaml_names_the_file(root: Path):
    (root / "data" / "mapping.yaml").write_text("rules: [", encoding="utf-8")
    with pytest.raises(DataError, match="mapping.yaml: not valid YAML"):
        load_dataset(root)


def test_a_snapshot_with_extra_data_is_rejected(root: Path):
    path = root / "snapshots" / "2026-10-baseline.json"
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace('"host"', '"agent_ip": "10.0.0.5", "host"'), encoding="utf-8")
    with pytest.raises(DataError, match="2026-10-baseline.json"):
        load_snapshots(root / "snapshots")
