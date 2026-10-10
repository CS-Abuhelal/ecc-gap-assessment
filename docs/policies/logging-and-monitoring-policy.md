# Rimal Byte (fictional): Logging and Monitoring Policy

| | |
|---|---|
| Version | 1.0 |
| Owner | Cybersecurity Lead |
| Approved by | General Manager (Authorized Official) |
| Approved on | 5 October 2026 |
| Next review | October 2027 |
| ECC-2:2024 controls | 2-12-1, 2-12-2, 2-12-3, 2-12-4 |

> Rimal Byte is a fictional company. This policy was written for a portfolio GRC project.

## Purpose

This policy sets how Rimal Byte records security events on its laptops, collects them in one
place and watches them, so that an attack or a misuse can be seen, investigated and proved. The
General Manager approves it as the company's event logging and monitoring requirements.
[2-12-1]

## Scope

Every company laptop and the Wazuh SIEM that collects its logs.

## Policy

1. The IT Manager and the Cybersecurity Lead must put the requirements in this policy into
   practice. [2-12-2]
2. Every laptop must have security event logging turned on, as the audit policy in the CIS
   baseline requires. [2.12.3.1]
3. The logs must include events for privileged and administrator accounts (such as sign-ins,
   changes to accounts and groups, and use of administrator rights) and for remote access (such
   as remote sign-ins and remote desktop sessions). [2.12.3.1, 2.12.3.2]
4. Logs must be collected centrally in the Wazuh SIEM. The IT Manager must install the Wazuh
   agent on each laptop and restore any laptop that stops sending logs. [2.12.3.3]
5. Event logging must stay turned on, the Wazuh agent must keep running and the logs must not be
   cleared on a laptop, unless the Cybersecurity Lead approves it. [2.12.3.1]
6. The Cybersecurity Lead must review the Wazuh alerts every working day and keep a dated record
   that the review was done. When the Cybersecurity Lead is absent, the IT Manager must review
   the alerts instead. If the IT Manager finds a real problem, they must tell the Cybersecurity
   Lead at once, or the General Manager if the Cybersecurity Lead cannot be reached. On return,
   the Cybersecurity Lead must check the IT Manager's review records. [2.12.3.4]
7. An alert that shows a real threat must be treated as a security incident: the reviewer must
   record it, tell the Cybersecurity Lead at once, and the Cybersecurity Lead coordinates the
   response. [2.12.3.4]
8. Logs must be kept for at least 12 months and must not be deleted earlier. The IT Manager must
   make sure the Wazuh server has the storage to do this. [2.12.3.5]
9. The clocks on laptops and on the Wazuh server must be synchronised with a trusted time
   source, so that events from different machines can be put in order. [2.12.3.3]
10. Access to the logs must be limited to the Cybersecurity Lead and the IT Manager. A log record
    must not be changed or deleted. [2-12-2]
11. Every quarter the Cybersecurity Lead must report to the supervisory committee how many
    laptops are sending logs, whether the daily reviews were done, and the oldest log still
    kept. [2-12-4]

## Roles

- **General Manager:** approves this policy and any exception.
- **Cybersecurity Lead:** owns this policy, reviews the alerts, coordinates incident response and
  reports to the committee.
- **IT Manager:** keeps the Wazuh server and agents working, keeps clocks synchronised, keeps
  enough log storage and covers the daily alert review when the Cybersecurity Lead is absent.
- **Staff:** do not turn off logging, stop the Wazuh agent or clear logs, and report anything
  suspicious to the Cybersecurity Lead.

## Exceptions

An exception must be requested from the Cybersecurity Lead in writing. The Cybersecurity Lead
assesses it with the risk management method and the General Manager approves or refuses it. An
approved exception has an owner and an end date no more than 12 months away, and is recorded in
the risk register.

## Compliance

A breach of this policy is handled under the HR disciplinary rules. Anyone who suspects a breach
must report it to the Cybersecurity Lead.

## Review

The Cybersecurity Lead reviews this policy every year in October, or sooner if the law or the
business changes significantly. Changes are recorded and approved by the General Manager. [1-3-4]
