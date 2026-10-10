# NCA ECC Gap Assessment: Rimal Byte (fictional)

A governance, risk and compliance (GRC) project: a gap assessment of a small fictional Saudi IT
company against the National Cybersecurity Authority's **Essential Cybersecurity Controls
(ECC-2:2024)**. It uses **real security evidence from my own Windows 11 PC**, collected by a Wazuh
SIEM, and ends with a **measured before/after**: I fixed 54 failing checks that were safe to
change, reversibly, and scanned again.

**Live report:** <https://cs-abuhelal.github.io/ecc-gap-assessment/>. The page also links the PDF
report and the Excel workbook.

## Results

| | Baseline (8 Oct 2026) | After the fixes (10 Oct 2026) |
|---|---|---|
| CIS benchmark checks passing on the workstation | 122 of 473 | **176 of 473** |
| ECC compliance (Partially implemented counts as half) | 26.0% | **26.5%** |
| ECC controls Implemented / Partially / Not implemented | 6 / 41 / 55 | 6 / 42 / 54 |
| Logging checks passing (ECC 2-12-3) | 16 of 53 | **51 of 53** |
| Open critical / high vulnerabilities | 0 / 5 | 0 / 5 |
| Indicative SAMA CSF subdomains at Level 3 | 0 of 28 | 0 of 28 |

- **Every one of the 54 targeted checks now passes, and no other check changed.**
- **ECC compliance barely moved, and the report explains why.** Compliance counts controls, not
  checks.
  - Wazuh measures 8 of the 102 applicable controls, and the fixes touched 5.
  - Four of those were already Partially implemented. They stay so until *every* one of their
    checks passes, which is this assessment's rating rule.
  - Only 2-7-2 moved, from Not implemented to Partially implemented.
  - The 47 BitLocker checks cannot pass on Windows 11 Home.
  - Most of the remaining gaps are governance: strategy, awareness training, incident response
    and continuity planning.
- **One fix was left out on purpose.** The account lockout policy (F08) would interrupt the
  failed-logon tests I run on this PC. It is recorded as a time-limited exception to the company's
  access control policy, approved by the General Manager with compensating controls (R-27), as it
  would be in a real assessment.

## What is in it

- **Assessment of all 108 ECC controls.** Each control is rated Implemented, Partially
  implemented, Not implemented or Not applicable, with its evidence. Six controls are not
  applicable, each with a written reason (Statement of Applicability).
- **Company profile and six policies**: cybersecurity, roles, risk method, access control,
  vulnerability management, and logging and monitoring. They give the governance controls
  something to be judged against.
- **Risk register and roadmap**: 27 risks, each with likelihood × impact, a treatment, an owner and
  a due date, grouped into 30/60/90-day and later buckets.
- **Technical evidence**: 482 checks from the CIS Microsoft Windows 11 Enterprise Benchmark, run by
  Wazuh's Security Configuration Assessment, each mapped to the ECC control it supports. Open
  vulnerabilities and log retention come from the same Wazuh instance.
- **Remediation**: 12 fixes in `remediation/fixes.json`, applied by `apply.ps1`.
  - `apply.ps1` shows a preview, backs up every current value, checks each change, and undoes
    everything if any change fails.
  - `undo.ps1` restores a backup.
  - CI applies and undoes all 57 settings on a throwaway GitHub Windows runner on every push.
- **Indicative SAMA Cyber Security Framework view.** It maps ECC results onto the Saudi Central
  Bank's 32 subdomains, to show how the company would look to a bank client. It is labelled
  indicative, because Rimal Byte is not regulated by SAMA.

## What is measured and what is judged

- **Measured:** the CIS check results, the vulnerability counts and the log retention. They come
  from a real Wazuh installation monitoring a real PC (labelled `WS-01`), via committed JSON
  snapshots that hold only check ids and results, counts and two dates.
- **Judged:** the governance ratings. They are rated against the policies and profile I wrote for
  the fictional company, and nobody has audited them independently.
- The report's Limitations section says this too, alongside the other limits: one workstation
  standing in for 30 laptops, a benchmark written for Enterprise run on Home, and an author-made
  CIS-to-ECC mapping.

## How it works

```
Wazuh (live) --collect--> snapshots/*.json --assess--> ratings, risks, roadmap --build--> web page, PDF, workbook
                           (allowlisted)       ^
                                               |
          catalog, CIS-to-ECC mapping, evidence, applicability, risks, fix list (data/, remediation/)
```

- **Only `collect` talks to Wazuh.** Everything after it runs from committed files, so anyone can
  rebuild the report, and CI does on every push.
- **The snapshot is an allowlist.** Before writing, `collect` scans it for the Windows user name,
  the computer name and any names passed at run time, and stops if it finds one.

## Run it

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # .venv/bin/python on Linux or macOS
.venv/Scripts/python -m pytest                            # tests
.venv/Scripts/python -m ecc check                         # validate every data file and snapshot
.venv/Scripts/python -m ecc build --before baseline --after after   # writes build/; add --no-pdf without Chrome or Edge
```

On a Windows PC with Wazuh:
- `python -m ecc collect --label <name>` takes a new snapshot. It needs `WAZUH_INDEXER_URL`,
  `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD`, `WAZUH_CA_CERT` and `WAZUH_TLS_SERVER_NAME`.
- `python -m tools.check_fixes` checks every fix value against the installed Wazuh policy.
- In an administrator PowerShell,
  `powershell -ExecutionPolicy Bypass -File .\remediation\apply.ps1 -WhatIf` previews the fixes.
  - Without `-WhatIf` it applies them; add `-IncludeLockout` for the optional F08.
  - `.\remediation\undo.ps1 -Backup <file>`, run the same way, reverts them.

## Repository layout

| Path | What it holds |
|---|---|
| `ecc/` | The Python package: models, loading, validation, assessment, risks, SAMA view, collect, workbook, report |
| `data/` | ECC catalogue, CIS checks, CIS-to-ECC mapping, evidence, applicability, risks, report text, SAMA framework and mapping |
| `docs/company-profile.md`, `docs/policies/` | The fictional company and its six policies |
| `snapshots/` | The baseline and after snapshots (allowlisted fields only) |
| `remediation/` | The fix list and the PowerShell scripts that apply and undo it |
| `tools/` | Generators and the fix checker |
| `docs/superpowers/` | The design spec and the implementation plans the project was built from |

## How it was built

I built this with help from Claude Code, an AI coding assistant. It wrote much of the code and
text from the design spec and plans in `docs/superpowers/`, and every change was tested and
reviewed before it was merged. I ran the Wazuh scans and applied the fixes on my own PC myself.

## Licence

The code is released under the MIT licence (see `LICENSE`). Some data files keep their sources'
terms; `NOTICE` lists them: the NCA ECC text, Wazuh's GPLv2 SCA policy, the CIS Benchmark titles
and the SAMA framework structure.

Rimal Byte is fictional, and any resemblance to a real company is unintended.
