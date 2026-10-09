from collections import Counter
from pathlib import Path

from ecc.assess import assess, compliance, domain_scores
from ecc.load import load_dataset, load_snapshots
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
