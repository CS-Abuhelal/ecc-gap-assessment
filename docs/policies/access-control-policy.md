# Rimal Byte (fictional): Access Control Policy

| | |
|---|---|
| Version | 1.0 |
| Owner | Cybersecurity Lead |
| Approved by | General Manager (Authorized Official) |
| Approved on | 5 October 2026 |
| Next review | October 2027 |
| ECC-2:2024 controls | 1-9-5, 2-2-1, 2-2-2, 2-2-3, 2-2-4 |

> Rimal Byte is a fictional company. This policy was written for a portfolio GRC project.

## Purpose

This policy sets the rules for who may sign in to Rimal Byte's systems and what they may do once
they are in, so that each person has the access their work needs and no more. The General Manager
approves it as the company's identity and access management requirements. [2-2-1]

## Scope

All staff and contractors, and every account on company laptops and in Microsoft 365, including
administrator accounts and any remote access to company systems.

## Policy

1. The IT Manager must put the requirements in this policy into practice. [2-2-2]
2. Every person must have their own named account. Shared and generic accounts must not be used.
   Passwords must not be shared. [2.2.3.1]
3. Windows sign-in on company laptops must follow the CIS baseline for passwords: at least 14
   characters, no reuse of the last 24 passwords, and an account lockout after no more than 5
   failed sign-in attempts. Microsoft 365 accounts must rely on multi-factor authentication and
   Microsoft's password rules. [2.2.3.1]
4. Multi-factor authentication means at least two factors. It must be turned on for every
   Microsoft 365 account, including administrators, and for any remote access to company
   systems. It must not be switched off for any account. The accepted factors are these:
   [2.2.3.2]
   - Every user must use an authenticator app with number matching.
   - Every Microsoft 365 administrator must use a phishing-resistant method, such as a hardware
     security key, on their administrator accounts.
   - SMS must be used only as a temporary fallback, for example while a user's authenticator app
     is being set up or replaced. Administrators must not use the SMS fallback.
5. Access must follow least privilege. People get only the access their job needs, and only for
   as long as they need it. [2.2.3.3]
6. Administrator rights must be held only by IT staff. Each administrator must use a separate
   administrator account for administrator work and a normal account for email and browsing.
   [2.2.3.3, 2.2.3.4]
7. Access must be granted only on a request from the HR Officer. The request must name the
   person, their role and the access they need. The IT Manager must grant it and record the
   date. [2.2.3.3]
8. Access must be changed when a person changes role, and removed on the person's last day. The
   IT Manager must disable all of a leaver's accounts on their last day and record the date.
   [2.2.3.3, 1-9-5]
9. Every quarter the IT Manager must review all accounts and access rights, including
   administrator accounts and accounts of contractors, remove what is no longer needed, and
   report the results to the Cybersecurity Lead. [2.2.3.5, 2-2-4]
10. The Cybersecurity Lead must check each quarterly report against the HR requests for the
    quarter, follow up anything found, and report the results to the supervisory committee
    every quarter. [2-2-4]

## Roles

- **General Manager:** approves this policy.
- **Cybersecurity Lead:** owns this policy and checks the IT Manager's quarterly reports.
- **IT Manager:** creates, changes and disables accounts, enforces multi-factor authentication
  and the password rules, and carries out the quarterly review.
- **HR Officer:** sends the access request when someone joins, changes role or leaves.
- **Project Manager:** tells the HR Officer which contractors need access and when it ends.
- **Staff:** use only their own account, keep their password and sign-in factors private, and
  report a lost or stolen device, or a password they think someone else knows, at once.

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
