# Rimal Byte (fictional): Company Profile

> Rimal Byte is a fictional company created for a portfolio GRC project. It does not describe
> any real company. Its technical evidence comes from a real Windows 11 workstation in a home
> lab, labelled WS-01.

## The company

- An IT services company in Jeddah, Saudi Arabia, with about 30 staff.
- Services: managed IT support for small and medium businesses, and small custom software
  projects for clients.
- Why ECC: Rimal Byte is bidding for government contracts. ECC-2:2024 is mandatory for government
  agencies, their affiliated companies and critical infrastructure operators; the National
  Cybersecurity Authority (NCA) encourages every other entity to adopt it, and government clients
  expect their suppliers to show alignment. Rimal Byte has adopted it voluntarily.
- Authorized Official: the General Manager.

## People and roles

| Role | Who | Notes |
|---|---|---|
| General Manager | Authorized Official | Approves policies and accepts High and Critical risks |
| Cybersecurity Lead | A systems engineer, part-time (about 40% of their time) | Reports to the General Manager; separate from the IT Manager |
| IT Manager | Runs laptops, accounts, Microsoft 365 and the office network | |
| HR Officer | Hiring, contracts, leavers | |
| Project Manager | Client software projects | |
| Supervisory committee | General Manager, Cybersecurity Lead, IT Manager | Meets quarterly; first meeting planned |

## Technology

- **Laptops:** one Windows 11 laptop per employee. WS-01 represents them and is the only device
  with technical evidence in this assessment. It runs Windows 11 Home; the company plans to move
  its laptops to Windows 11 Pro or Enterprise. Laptops are not encrypted (Windows 11 Home has no
  full BitLocker). Support staff reach client systems from company laptops, using client-issued
  accounts protected by multi-factor authentication.
- **Microsoft 365 Business:** email, Teams, OneDrive and SharePoint. Multi-factor authentication
  is enforced for every account, and there are two named administrators. Email uses Microsoft
  365's default spam and malware filtering; the domain publishes SPF only (no DKIM or DMARC), and
  there is no email archiving. Every person has their own named account, but staff and IT accounts
  have broader access than their jobs need, and access has never been reviewed.
- **Wazuh SIEM:** a single-node Wazuh server in the office collects security events and
  vulnerability data from the laptops. It was installed in late September 2026 and collects from
  the laptops only, not yet from Microsoft 365 or the router.
- **Office network:** the internet provider's router with its built-in firewall, and a separate
  guest Wi-Fi. There are no servers in the office apart from the Wazuh server.
- **Phones:** staff use their personal phones for email and Teams. There is no mobile device
  management.
- **Website:** a static brochure page at a web hosting provider, with no logins or forms.
- **Backups:** files in OneDrive and SharePoint are covered by Microsoft 365 retention. Laptops are
  not backed up, and no restore has ever been tested.
- **Software projects:** delivered into client environments through an informal process, with no
  secure coding standard or security testing.

## Facilities

The office is in a shared building in Jeddah. The landlord runs badge access to the building and
CCTV in the lobby; the office door uses a key. There is no secure disposal service for old devices
or paper.

## Suppliers and clients

- Suppliers: Microsoft (cloud services, assessed under ECC 4-2), the internet provider and the
  web hosting provider, all on their standard terms.
- Client contracts include non-disclosure clauses.
- Rimal Byte does not outsource IT or cybersecurity operations.

## People practices

- Employment contracts include a confidentiality clause. There is no background screening.
- When someone leaves, the IT Manager disables their accounts, with no checklist or record.
- There is no awareness program. The Cybersecurity Lead has done some self-paced training.
- On 6 October 2026 the Cybersecurity Lead published the six policies on SharePoint and emailed
  all staff; acknowledgments are being collected.

## Assets and data

The IT Manager keeps a spreadsheet of laptops and accounts, which is incomplete and not updated on
a schedule. Information is not classified or labelled.

## Assessment scope

- **Framework:** NCA Essential Cybersecurity Controls ECC-2:2024, all 108 main controls. Six do
  not apply; the reasons are in `data/applicability.yaml`.
- **Technical evidence:** WS-01, measured by Wazuh: the CIS Microsoft Windows 11 Enterprise
  Benchmark v3.0.0 checks, open vulnerabilities and log retention.
- **Documentary evidence:** the six policies in `docs/policies/`, approved on 5 October 2026.
- **Baseline:** the snapshot of 8 October 2026.
