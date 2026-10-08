from pathlib import Path

import pytest

from ecc.load import Dataset, load_dataset, load_snapshots
from ecc.models import Snapshot
from tests.fixtures import write_root


@pytest.fixture
def root(tmp_path: Path) -> Path:
    return write_root(tmp_path / "repo")


@pytest.fixture
def dataset(root: Path) -> Dataset:
    return load_dataset(root)


@pytest.fixture
def baseline(root: Path) -> Snapshot:
    return load_snapshots(root / "snapshots")[0]


@pytest.fixture
def after(root: Path) -> Snapshot:
    return load_snapshots(root / "snapshots")[1]
