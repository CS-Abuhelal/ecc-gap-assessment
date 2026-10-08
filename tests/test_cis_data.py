from pathlib import Path

from ecc.load import load_model
from ecc.models import CisPolicy

POLICY_FILE = Path(__file__).resolve().parents[1] / "data" / "cis_checks.yaml"


def test_policy_is_the_cis_windows_11_enterprise_benchmark():
    policy = load_model(CisPolicy, POLICY_FILE)
    assert policy.policy.id == "cis_win11_enterprise"
    assert policy.policy.name == "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0"


def test_policy_has_482_checks_numbered_26000_to_26481():
    ids = [check.id for check in load_model(CisPolicy, POLICY_FILE).checks]
    assert ids == list(range(26000, 26482))


def test_spot_check_sections_and_titles():
    checks = {check.id: check for check in load_model(CisPolicy, POLICY_FILE).checks}
    assert checks[26005].cis == "1.2.1"
    assert checks[26403].cis == "18.10.42.17"
    assert "Turn off Microsoft Defender AntiVirus" in checks[26403].title
