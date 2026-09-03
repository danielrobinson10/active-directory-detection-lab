# Screenshots

Add your build/attack/detection screenshots here and reference them from the main README or BUILD-GUIDE.

Suggested set (the ones recruiters actually look at):

- `01-proxmox-vms.png` — the 5 VMs running in Proxmox
- `02-network-diagram.png` — architecture (already in repo root)
- `03-splunk-hosts.png` — both hosts reporting into `index=endpoint`
- `04-ad-users.png` — Active Directory Users and Computers (OUs + users)
- `05-hydra-crack.png` — Hydra recovering the credential
- `06-splunk-4625-burst.png` — the failed-logon burst in Splunk
- `07-splunk-4624-success.png` — the successful logon + source IP
- `08-triggered-alert.png` — the brute-force alert firing in Activity → Triggered Alerts
- `09-atomic-red-team.png` — an ART test + the resulting event (or the gap)

Reference them in Markdown like:

```md
![Hydra cracking the RDP credential](screenshots/05-hydra-crack.png)
```
