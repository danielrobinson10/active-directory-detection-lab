# Part 2 Build Guide — IAM: JML Automation & RBAC (step by step)

A detailed, do-this-then-that walkthrough for building the Identity & Access Management layer on top of
the Part 1 lab. Everything runs on **ADDC01** (the domain controller) in an **elevated PowerShell**.
By the end you'll have a role-based access model and three working automations — Joiner, Mover, Leaver —
with every action auditable in Splunk.

> **Prerequisites:** Part 1 is complete (domain `robinscapital.test` is up, ADDC01 is a DC, Splunk is
> ingesting from ADDC01). The Active Directory PowerShell module ships on a DC by default — no install.

---

## Step 1 — Get the scripts onto ADDC01

You need the whole `iam-jml` folder (scripts + config + logs) on the server.

**Option A — download the repo ZIP (simplest, no git needed):**
1. On ADDC01, open a browser to your repo: `https://github.com/danielrobinson10/active-directory-detection-lab`
2. Green **Code** button → **Download ZIP**.
3. Extract it. Copy the **`iam-jml`** folder to `C:\iam-jml`.

**Option B — git clone (if git is installed):**
```powershell
cd C:\
git clone https://github.com/danielrobinson10/active-directory-detection-lab.git
# scripts are then in C:\active-directory-detection-lab\iam-jml\scripts
```

Either way, note the path to the **`scripts`** folder — you'll `cd` there next.

---

## Step 2 — Open elevated PowerShell and allow the scripts to run

1. Start menu → type **PowerShell** → right-click **Windows PowerShell** → **Run as administrator**.
2. Allow local scripts for this session (safe, scoped to the current window):
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
3. Move into the scripts folder (adjust the path to where you put it):
   ```powershell
   cd C:\iam-jml\scripts
   ```
4. Confirm the AD module loads (it should, silently):
   ```powershell
   Import-Module ActiveDirectory
   ```
   *If this errors, you're not on the DC or RSAT isn't present — run it on ADDC01.*

---

## Step 3 — Build the OU tree and RBAC groups (one time)

This is the foundation. It reads the role catalog (`config\Roles.psd1`) and creates the OUs and security
groups. It's **idempotent** — re-running it just reports "exists" and changes nothing.

**Preview first (optional but recommended)** — `-WhatIf` shows every change without touching AD:
```powershell
.\Setup-LabIAM.ps1 -WhatIf
```

**Then run it for real:**
```powershell
.\Setup-LabIAM.ps1
```

**What you'll see** — green `OK` lines as it creates each object:
```
2026-09-17 10:00:01 [OK] === Setting up RobinsCapital IAM structure ===
2026-09-17 10:00:01 [OK] Created OU: OU=RobinsCapital,DC=robinscapital,DC=test
2026-09-17 10:00:01 [OK] Created OU: OU=Users,OU=RobinsCapital,...
...
2026-09-17 10:00:02 [OK] Created group: Role-Finance (Global)
2026-09-17 10:00:02 [OK] Created group: RES-Finance-Share-RW (DomainLocal)
...
2026-09-17 10:00:02 [OK] === Setup complete. Roles available: IT Support, HR Specialist, Financial Analyst, Sales Representative ===
```

**Verify in the GUI** (this is a good screenshot):
1. **Server Manager → Tools → Active Directory Users and Computers**.
2. View → **Advanced Features** (so you can see everything).
3. Expand `robinscapital.test` → you'll see the new **RobinsCapital** OU containing **Users**, **Groups**
   (with **Roles** and **Resources** sub-OUs), and **Disabled Users**.
4. Open **Groups → Roles** — you'll see `Role-IT`, `Role-HR`, `Role-Finance`, `Role-Sales`.

📸 *Screenshot: the OU tree + the Role groups.*

---

## Step 4 — JOINER: onboard a new employee

One command provisions a complete account for a new hire based on their role.

```powershell
.\New-Joiner.ps1 -First "Alice" -Last "Nguyen" -Role "Financial Analyst" -Manager "jsmith"
```

**What you'll see:**
```
2026-09-17 10:05:10 [INFO] JOINER: Alice Nguyen | role='Financial Analyst' | dept='Finance' | sam='alice.nguyen'
2026-09-17 10:05:11 [OK]   Created account alice.nguyen in OU=Finance,OU=Users,OU=RobinsCapital,...
2026-09-17 10:05:11 [INFO] Manager set to jsmith
2026-09-17 10:05:11 [OK]   Added to group: Role-Finance
2026-09-17 10:05:11 [OK]   Added to group: RES-Finance-Share-RW
2026-09-17 10:05:11 [OK]   Added to group: RES-Fileshare-RO
2026-09-17 10:05:11 [OK]   JOINER COMPLETE: alice.nguyen (alice.nguyen@robinscapital.test)
  Temporary password (deliver securely, user must change at logon):
  <random 16-char password>
```

**Available roles** (from `config\Roles.psd1`): `IT Support`, `HR Specialist`, `Financial Analyst`,
`Sales Representative`. Add more by editing that one file and re-running `Setup-LabIAM.ps1`.

**Verify:**
```powershell
Get-ADUser alice.nguyen -Properties Title,Department,MemberOf |
  Select-Object Name,Title,Department,Enabled
Get-ADPrincipalGroupMembership alice.nguyen | Select-Object Name
```
You should see Title `Financial Analyst`, Department `Finance`, Enabled `True`, and membership in the
three Finance groups (plus `Domain Users`). In ADUC, the user appears under **RobinsCapital → Users → Finance**.

📸 *Screenshot: the console output + `Get-ADPrincipalGroupMembership` result.*

---

## Step 5 — MOVER: handle a role change

Alice transfers from Finance to IT. This removes her old role's access and grants the new one — the
control that prevents **privilege creep**.

**Preview the change:**
```powershell
.\Move-User.ps1 -SamAccountName "alice.nguyen" -NewRole "IT Support" -WhatIf
```

**Run it:**
```powershell
.\Move-User.ps1 -SamAccountName "alice.nguyen" -NewRole "IT Support" -Manager "jsmith"
```

**What you'll see** — old groups removed (yellow `WARN`), new ones added (green `OK`), attributes + OU updated:
```
2026-09-17 10:10:02 [INFO] MOVER: alice.nguyen | 'Financial Analyst' -> 'IT Support'
2026-09-17 10:10:02 [WARN] Removed from old group: Role-Finance
2026-09-17 10:10:02 [WARN] Removed from old group: RES-Finance-Share-RW
2026-09-17 10:10:02 [WARN] Removed from old group: RES-Fileshare-RO
2026-09-17 10:10:03 [OK]   Added to new group: Role-IT
2026-09-17 10:10:03 [OK]   Added to new group: RES-Helpdesk-RW
2026-09-17 10:10:03 [OK]   Added to new group: RES-Fileshare-RW
2026-09-17 10:10:03 [OK]   Moved to OU: OU=IT,OU=Users,OU=RobinsCapital,...
2026-09-17 10:10:03 [OK]   MOVER COMPLETE: alice.nguyen is now 'IT Support'
```

**Verify:** re-run the `Get-ADPrincipalGroupMembership` check — the Finance groups are **gone**, replaced
by the IT groups. In ADUC she's now under **Users → IT**. That clean swap is the whole point.

📸 *Screenshot: before/after group membership.*

---

## Step 6 — LEAVER: securely offboard

Alice leaves the company. This disables the account, kills any known credential, strips all access, and
archives the account for audit (it is **not deleted**, so historical logs still resolve who she was).

```powershell
.\Disable-Leaver.ps1 -SamAccountName "alice.nguyen"
```

**What you'll see:**
```
2026-09-17 10:15:20 [INFO] LEAVER: offboarding alice.nguyen (Alice Nguyen)
2026-09-17 10:15:20 [OK]   Account disabled
2026-09-17 10:15:20 [OK]   Password rotated to random 24-char value
2026-09-17 10:15:20 [WARN] Removed from group: Role-IT
2026-09-17 10:15:20 [WARN] Removed from group: RES-Helpdesk-RW
2026-09-17 10:15:20 [WARN] Removed from group: RES-Fileshare-RW
2026-09-17 10:15:21 [OK]   Stamped description; hidden from GAL (if Exchange schema present)
2026-09-17 10:15:21 [OK]   Moved to OU=Disabled Users,OU=RobinsCapital,...
2026-09-17 10:15:21 [OK]   LEAVER COMPLETE: alice.nguyen fully offboarded (retained for audit)
```

**Verify:**
```powershell
Get-ADUser alice.nguyen -Properties Enabled,Description,MemberOf |
  Select-Object Name,Enabled,Description
```
Enabled `False`, description stamped `LEAVER - disabled <date>`, no group memberships beyond
`Domain Users`, and the object now lives in **RobinsCapital → Disabled Users**.

📸 *Screenshot: the disabled account in the Disabled Users OU.*

---

## Step 7 — Audit the whole lifecycle in Splunk

Every step above wrote Windows Security events that Part 1's forwarder already ships to Splunk. Open
Splunk (`http://10.10.10.10:8000`) → **Search & Reporting**, set time to **Last 60 minutes**, and run:

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

You'll see the Joiner → Mover → Leaver story laid out in order. This is where IAM meets detection:
you can now alert on identity actions taken **outside** this process (e.g. a manual add to a
privileged group).

📸 *Screenshot: the JML timeline in Splunk — this is your Part 2 headline visual.*

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `running scripts is disabled on this system` | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in the same window. |
| `Import-Module ActiveDirectory` fails | You're not on the DC (or not elevated). Run on ADDC01 as Administrator. |
| Joiner: `Could not add to 'Role-Finance'` | You skipped Step 3 — run `.\Setup-LabIAM.ps1` first. |
| `Role '...' not found in Roles.psd1` | Use an exact role name from `config\Roles.psd1` (case-sensitive match on the key). |
| Nothing appears in Splunk | Confirm ADDC01's forwarder is running and time range covers your run; see Part 1 §16. |
| Want to undo a test | Delete the test user: `Remove-ADUser alice.nguyen -Confirm:$false` (lab only). |

---

*All actions are logged to `iam-jml/logs/jml-YYYY-MM-DD.log`. Lab use only.*
