from collections import Counter
from pathlib import Path

from ecc.load import load_catalog

CATALOG = Path(__file__).resolve().parents[1] / "data" / "catalog.yaml"
EXPECTED = {
    "1-1": 3, "1-2": 3, "1-3": 4, "1-4": 2, "1-5": 4, "1-6": 4, "1-7": 1, "1-8": 3,
    "1-9": 6, "1-10": 5, "2-1": 6, "2-2": 4, "2-3": 4, "2-4": 4, "2-5": 4, "2-6": 4,
    "2-7": 3, "2-8": 4, "2-9": 4, "2-10": 4, "2-11": 4, "2-12": 4, "2-13": 4, "2-14": 4,
    "2-15": 4, "3-1": 4, "4-1": 4, "4-2": 4,
}
ALLOWED_NON_ASCII = set("’“”")
FURNITURE = ("Essential Cybersecurity Controls", "Document classification", "Objective")


def test_108_controls_in_28_subdomains_and_4_domains():
    controls = load_catalog(CATALOG)
    assert len(controls) == 108
    assert dict(Counter(control.subdomain for control in controls)) == EXPECTED
    assert sorted({control.domain for control in controls}) == [1, 2, 3, 4]


def test_controls_are_numbered_in_order():
    controls = load_catalog(CATALOG)
    for subdomain, count in EXPECTED.items():
        ids = [control.id for control in controls if control.subdomain == subdomain]
        assert ids == [f"{subdomain}-{n}" for n in range(1, count + 1)]


def test_92_subcontrols_sit_under_their_parent():
    pairs = [(c.id, s.id) for c in load_catalog(CATALOG) for s in c.subcontrols]
    assert len(pairs) == 92
    for parent, child in pairs:
        assert child.replace(".", "-").startswith(parent + "-")


def test_known_texts():
    controls = {control.id: control for control in load_catalog(CATALOG)}
    assert controls["1-7-1"].subdomain_title == (
        "Compliance with Cybersecurity Standards, Laws and Regulations"
    )
    assert controls["3-1-1"].subdomain_title == (
        "Cybersecurity Resilience Aspects of Business Continuity Management (BCM)"
    )
    assert controls["2-2-1"].text == (
        "Cybersecurity requirements for identity and access management of the entity shall be "
        "identified, documented, and approved."
    )
    retention = {s.id: s.text for s in controls["2-12-3"].subcontrols}["2.12.3.5"]
    assert retention == (
        "Retention period of cybersecurity event logs (shall be at least 12 months)."
    )


def test_no_page_furniture_leaked_into_the_text():
    for control in load_catalog(CATALOG):
        for text in (control.text, *(sub.text for sub in control.subcontrols)):
            for marker in FURNITURE:
                assert marker not in text, control.id
            assert all(ord(ch) < 128 or ch in ALLOWED_NON_ASCII for ch in text), control.id
