# Part 2 — IAM: JML Automation & Role-Based Access Control

Extends the detection lab into **Identity & Access Management**. Instead of clicking through
Active Directory Users and Computers, the entire **Joiner–Mover–Leaver (JML)** identity lifecycle is
automated with **PowerShell**, and access is granted through a **role-based (RBAC)** group model —
so a person's access always matches their current job, with a full audit trail landing in Splunk.

## Why this matters
Manual identity management is where real breaches start: over-provisioned accounts, privilege creep
when people change roles, and dormant accounts of ex-employees that never get disabled. This module
demonstrates the controls that prevent all three — automated, consistent, and logged.

## The RBAC model (AGDLP)

Access is never assigned to a user directly. It flows through groups:

```
User  →  Role group (Global, "Role-*")  →  Resource group (Domain Local, "RES-*")  →  Permission
```

- **Role groups** (`Role-IT`, `Role-Finance`, …) represent *who someone is* (their job).
- **Resource groups** (`RES-Finance-Share-RW`, `RES-Fileshare-RO`, …) represent *what can be accessed*.
- A single catalog — [`config/Roles.psd1`](config/Roles.psd1) — maps each **role → department → OU → groups**.
  Change a role's access in one place and every future joiner/mover inherits it.

## OU structure created

```
OU=RobinsCapital
├── OU=Users
│   ├── OU=IT   ├── OU=HR   ├── OU=Finance   └── OU=Sales
├── OU=Groups
│   ├── OU=Roles       (Global "Role-*" groups)
│   └── OU=Resources   (Domain-Local "RES-*" groups)
└── OU=Disabled Users  (leavers land here)
```

## The scripts

| Script | Lifecycle stage | What it does |
|---|---|---|
| [`Setup-LabIAM.ps1`](scripts/Setup-LabIAM.ps1) | one-time | Builds the OU tree + all RBAC groups from the catalog (idempotent). |
| [`New-Joiner.ps1`](scripts/New-Joiner.ps1) | **Joiner** | Creates the account in the right OU, sets title/dept/manager, grants the role's groups, returns a random first-logon password. |
| [`Move-User.ps1`](scripts/Move-User.ps1) | **Mover** | Removes the old role's groups, grants the new role's, updates attributes and OU — kills privilege creep. |
| [`Disable-Leaver.ps1`](scripts/Disable-Leaver.ps1) | **Leaver** | Disables the account, rotates the password, strips all groups, hides from GAL, moves to Disabled Users — retained for audit. |

All scripts share [`scripts/Common.ps1`](scripts/Common.ps1) (logging, role loader, username/password
generators) and support `-WhatIf` for a safe dry run.

## 📖 Full step-by-step walkthrough

For the detailed do-this-then-that guide (with expected output and what to verify at each step), see
**[BUILD-GUIDE-PART2.md](BUILD-GUIDE-PART2.md)**. The quick runbook below is the condensed version.

## Runbook (on ADDC01, elevated PowerShell)

```powershell
cd C:\iam-jml\scripts      # or wherever you cloned it

# 0) one-time build of OUs + RBAC groups
.\Setup-LabIAM.ps1

# 1) JOINER — onboard a new finance analyst
.\New-Joiner.ps1 -First "Alice" -Last "Nguyen" -Role "Financial Analyst" -Manager "jsmith"

# 2) MOVER — she transfers to IT
.\Move-User.ps1 -SamAccountName "alice.nguyen" -NewRole "IT Support" -Manager "jsmith"

# 3) LEAVER — she leaves the company
.\Disable-Leaver.ps1 -SamAccountName "alice.nguyen"
```

Add `-WhatIf` to any command to preview every change without touching AD. Actions are logged to
`logs/jml-YYYY-MM-DD.log`.

## Tie-back to detection (this is the payoff)

Every JML action generates Windows Security events already flowing into Splunk from Part 1. Hunt the
lifecycle end-to-end:

```spl
index=endpoint host=ADDC01 (EventCode=4720 OR EventCode=4722 OR EventCode=4725
    OR EventCode=4726 OR EventCode=4728 OR EventCode=4732 OR EventCode=4738)
| eval action=case(
    EventCode=4720,"User created (Joiner)",
    EventCode=4722,"User enabled",
    EventCode=4728,"Added to global group",
    EventCode=4732,"Added to local group",
    EventCode=4738,"User changed (Mover)",
    EventCode=4725,"User disabled (Leaver)",
    EventCode=4726,"User deleted")
| table _time, action, Account_Name, Target_Account_Name
| sort _time
```

This turns identity operations into detections too — e.g. alert on a **user added to a privileged
group outside the JML process**, or a **disabled leaver account being re-enabled**.

## Roadmap (Part 3+)
- Scheduled **access review** report (stale accounts, users in groups their role doesn't grant).
- Privileged-group change alerting (Domain Admins / Enterprise Admins).
- Identity attack paths — Kerberoasting, AS-REP roasting, BloodHound mapping — with detections.
