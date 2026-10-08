# NCA ECC Gap Assessment

Work in progress. A GRC project that assesses a small fictional Saudi company against the
National Cybersecurity Authority's Essential Cybersecurity Controls (ECC-2:2024), using real
evidence from a Wazuh home lab.

The design is in [docs/superpowers/specs](docs/superpowers/specs/2026-10-08-ecc-gap-assessment-design.md).

## Run it

    python -m venv .venv
    .venv/Scripts/python -m pip install -r requirements.txt
    .venv/Scripts/python -m pytest
    .venv/Scripts/python -m ecc check
