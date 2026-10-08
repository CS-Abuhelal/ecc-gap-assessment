import pytest

from tools.gen_cis_checks import cis_id, convert

TITLE = "Ensure 'Enforce password history' is set to '24 or more password(s)'."
POLICY = {
    "policy": {"id": "cis_win11_enterprise", "name": "CIS Benchmark", "file": "x.yml"},
    "checks": [
        {"id": 26000, "title": TITLE, "compliance": [{"cis": ["1.1.1"]}, {"cis_csc_v8": ["5.2"]}]}
    ],
}


def test_convert_keeps_id_cis_section_and_title():
    assert convert(POLICY) == {
        "policy": {"id": "cis_win11_enterprise", "name": "CIS Benchmark"},
        "checks": [{"id": 26000, "cis": "1.1.1", "title": TITLE}],
    }


def test_a_check_needs_exactly_one_cis_id():
    with pytest.raises(ValueError, match="no CIS id"):
        cis_id({"id": 1, "compliance": [{"pci_dss": ["2.2"]}]})
    with pytest.raises(ValueError, match="2 CIS ids"):
        cis_id({"id": 2, "compliance": [{"cis": ["1.1", "1.2"]}]})
