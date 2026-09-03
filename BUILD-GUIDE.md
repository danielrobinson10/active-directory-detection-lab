# Active Directory Detection Lab on Proxmox VE

> A home SOC / detection-engineering lab built on **Proxmox VE** instead of VirtualBox.
> Four purpose-built VMs behind an **OPNsense** firewall, centralized logging with **Splunk**,
> endpoint telemetry with **Sysmon**, an **RDP brute-force attack** from Kali, and
> **Atomic Red Team** technique simulation — all analysed in Splunk.
>
> Adapted from the classic MyDFIR / [avulman active-directory-project](https://github.com/avulman/active-directory-project)
> VirtualBox lab and re-engineered for a Proxmox hypervisor with a firewalled, isolated network.

![Logical Network Diagram](logical-network.png)
*Ref 1. Proxmox Active Directory Detection Lab — Logical Network Diagram*

---

## Table of Contents

- [1. Overview & Objectives](#1-overview--objectives)
- [2. Architecture & Address Plan](#2-architecture--address-plan)
- [3. Prerequisites](#3-prerequisites)
- [4. Phase 0 — Prepare the Proxmox Host](#4-phase-0--prepare-the-proxmox-host)
- [5. Phase 1 — OPNsense Firewall / Router (the gateway)](#5-phase-1--opnsense-firewall--router-the-gateway)
- [6. Phase 2 — SPLUNK01 (Ubuntu Server + Splunk Enterprise)](#6-phase-2--splunk01-ubuntu-server--splunk-enterprise)
- [7. Phase 3 — ADDC01 (Windows Server 2022 Domain Controller)](#7-phase-3--addc01-windows-server-2022-domain-controller)
- [8. Phase 4 — WIN11-01 (Windows 11 Domain Workstation)](#8-phase-4--win11-01-windows-11-domain-workstation)
- [9. Phase 5 — Splunk Forwarding & Sysmon on both Windows hosts](#9-phase-5--splunk-forwarding--sysmon-on-both-windows-hosts)
- [10. Phase 6 — Build the Active Directory Domain](#10-phase-6--build-the-active-directory-domain)
- [11. Phase 7 — Join WIN11-01 to the Domain](#11-phase-7--join-win11-01-to-the-domain)
- [12. Phase 8 — KALI01 (Attacker) + RDP Brute Force](#12-phase-8--kali01-attacker--rdp-brute-force)
- [13. Phase 9 — Detection & Analysis in Splunk](#13-phase-9--detection--analysis-in-splunk)
- [14. Phase 10 — Atomic Red Team (find the detection gaps)](#14-phase-10--atomic-red-team-find-the-detection-gaps)
- [15. Portfolio: recording & documentation checklist](#15-portfolio-recording--documentation-checklist)
- [16. Troubleshooting](#16-troubleshooting)

---

## 1. Overview & Objectives

This lab stands up a small enterprise Active Directory environment, ships every Windows security
and Sysmon event into Splunk, then attacks the environment and hunts the attack in the logs.

**What makes this build different from the original:**

| Original (VirtualBox) | This build (Proxmox) |
|---|---|
| Oracle VM VirtualBox | Proxmox VE Type-1 hypervisor |
| Flat NAT network `192.168.10.0/24` | Firewalled/routed lab `10.10.10.0/24` behind OPNsense |
| No perimeter device | **OPNsense** firewall/router (WAN DHCP → LAN `10.10.10.1`) |
| Windows 10 target | **Windows 11 Pro** domain workstation |
| Guest-additions shared folder to move the Splunk `.deb` | Direct `wget` download inside the VM |
| Single default bridge | Dedicated **isolated lab bridge `vmbr3`** with no physical uplink |

**Skills demonstrated:** hypervisor administration, virtual networking & bridges, firewall/router
deployment (OPNsense), Linux server administration, SIEM deployment (Splunk), endpoint telemetry
(Sysmon), Active Directory Domain Services & DNS, domain join, adversary emulation (Hydra,
Atomic Red Team), and log-based detection engineering (Windows Event IDs 4624/4625, Sysmon).

---

## 2. Architecture & Address Plan

**Domain:** `robinscapital.test`  ·  **Network:** `10.10.10.0/24`  ·  **Gateway:** `10.10.10.1`  ·  **DNS:** `10.10.10.7`

| Host | Role | OS | vmbr | IP | Gateway | DNS | Agents |
|---|---|---|---|---|---|---|---|
| **OPNsense** | Firewall / Router | OPNsense (FreeBSD) | net0→`vmbr0` (WAN), net1→`vmbr3` (LAN) | WAN: DHCP · LAN: `10.10.10.1` | — | — | — |
| **ADDC01** | AD DS + DNS | Windows Server 2022 | `vmbr3` | `10.10.10.7` | `10.10.10.1` | `127.0.0.1` (self) | Splunk UF, Sysmon |
| **SPLUNK01** | SIEM (indexer) | Ubuntu Server 24.04 LTS | `vmbr3` | `10.10.10.10` | `10.10.10.1` | `10.10.10.1` | — |
| **WIN11-01** | Domain workstation / victim | Windows 11 Pro | `vmbr3` | `10.10.10.100` | `10.10.10.1` | `10.10.10.7` | Splunk UF, Sysmon, ART |
| **KALI01** | Attacker | Kali Linux | `vmbr3` | `10.10.10.250` | `10.10.10.1` | `10.10.10.1` | Hydra |

**Data flows (per the diagram):**
- **Solid line** = network connectivity (all VMs ↔ `vmbr3` ↔ OPNsense ↔ internet).
- **Green dashed** = log forwarding: Windows Event Logs + Sysmon → Splunk over **TCP 9997**.
- **Red dashed** = controlled security testing: KALI01 → WIN11-01 (RDP brute force).

**Why the DNS split:** Domain machines (ADDC01, WIN11-01) must use the **domain controller (`10.10.10.7`)**
for DNS or AD breaks. Non-domain infrastructure (SPLUNK01, KALI01) can use OPNsense (`10.10.10.1`)
as a plain resolver. ADDC01 uses itself and forwards unknown queries out through OPNsense.

---

## 3. Prerequisites

- A working **Proxmox VE 8.x** host with internet access and enough resources:
  - **RAM:** ~20 GB across the lab (OPNsense 2–4 GB, Splunk 8 GB, Server 4 GB, Win11 4 GB, Kali 2–4 GB).
  - **Disk:** ~250 GB free on the VM storage (`local-lvm` or a ZFS pool).
  - **CPU:** 4+ physical cores recommended.
- Admin access to the Proxmox web UI (`https://<proxmox-ip>:8006`).
- You have **already created the `10.10.10.0/24` network in OPNsense** — this guide still shows the
  full OPNsense build so the repo is self-contained; skip the parts you've done.

### ISOs to download (get these first)

Download on your workstation, then upload to Proxmox in Phase 0.

| ISO | Where |
|---|---|
| **OPNsense** (`dvd` amd64, decompress the `.bz2`) | https://opnsense.org/download/ |
| **Ubuntu Server 24.04 LTS** (or 22.04 LTS) | https://ubuntu.com/download/server |
| **Windows Server 2022** Evaluation (Desktop Experience) | https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022 |
| **Windows 11 Enterprise** Evaluation | https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise |
| **VirtIO drivers** (`virtio-win.iso`, stable) | https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso |
| **Kali Linux** (Installer ISO, amd64) | https://www.kali.org/get-kali/#kali-installer-images |

> 🎥 **Recording tip:** Phase 0 (host prep, bridges, ISO upload) makes a strong 2–3 minute opening
> segment — it shows you understand the hypervisor and virtual networking before any VM exists.

---

## 4. Phase 0 — Prepare the Proxmox Host

### 4.1 Upload the ISOs

1. In the Proxmox UI, select your node → **local** (or your ISO storage) → **ISO Images** → **Upload**.
2. Upload each ISO from the table above. For the VirtIO ISO you can also use **Download from URL** and
   paste the direct link, which is faster than uploading.

### 4.2 Create the isolated lab bridge `vmbr3`

`vmbr0` already exists as your **WAN bridge** (it has your physical NIC and reaches your home network).
You now add `vmbr3` — an internal-only bridge with **no physical uplink** — so the lab is isolated and
only touches the outside world through OPNsense.

1. Node → **System** → **Network** → **Create** → **Linux Bridge**.
2. Fill in:

   | Field | Value |
   |---|---|
   | **Name** | `vmbr3` |
   | **IPv4/CIDR** | *(leave blank — the host must NOT have an IP on the lab net)* |
   | **Gateway** | *(leave blank)* |
   | **Bridge ports** | *(leave blank — no physical port = isolated)* |
   | **Autostart** | ✅ |
   | **VLAN aware** | *(leave unchecked)* |
   | **Comment** | `Isolated Lab Bridge 10.10.10.0/24` |

3. Click **Create**, then click **Apply Configuration** (needs `ifupdown2`, installed by default on PVE 8).

You now have **`vmbr0` = WAN** and **`vmbr3` = isolated LAN**, exactly as in the diagram.

---

## 5. Phase 1 — OPNsense Firewall / Router (the gateway)

OPNsense is the first VM because it provides the gateway (`10.10.10.1`) and NAT that every other VM
depends on. It has **two virtual NICs**: WAN on `vmbr0` (gets DHCP from your home router) and LAN on
`vmbr3` (serves `10.10.10.1/24`).

### 5.1 Create the VM — wizard tab by tab

Proxmox → **Create VM**. Set the fields in each tab exactly as below.

**General**
| Field | Value |
|---|---|
| Node | *your node* |
| VM ID | `100` |
| Name | `OPNsense` |
| Resource Pool | *(none)* |
| Start at boot | ✅ (recommended — it's the gateway) |

**OS**
| Field | Value |
|---|---|
| Use CD/DVD disc image (ISO) | ✅ |
| Storage | `local` |
| ISO image | `OPNsense-*-dvd-amd64.iso` |
| Guest OS Type | **Other** |

**System**
| Field | Value |
|---|---|
| Graphic card | Default |
| Machine | `q35` |
| BIOS | **OVMF (UEFI)** *(SeaBIOS also works; OVMF is fine)* |
| Add EFI Disk | ✅ (Storage: `local-lvm`) — *if you chose OVMF* |
| Pre-Enroll keys | **uncheck** (Secure Boot off — simpler for FreeBSD) |
| SCSI Controller | `VirtIO SCSI single` |
| Qemu Agent | ☐ (OPNsense doesn't need it) |

**Disks**
| Field | Value |
|---|---|
| Bus/Device | `SCSI` `0` |
| Storage | `local-lvm` |
| Disk size (GiB) | `32` |
| Cache | Default (No cache) |
| Discard | ✅ (if on SSD/thin storage) |

**CPU**
| Field | Value |
|---|---|
| Sockets | `1` |
| Cores | `2` |
| Type | `host` |

**Memory**
| Field | Value |
|---|---|
| Memory (MiB) | `2048` (4096 if you'll run IDS/IPS later) |
| Ballooning | leave default |

**Network** (this is the WAN NIC — you add LAN next)
| Field | Value |
|---|---|
| Bridge | **`vmbr0`** |
| Model | `VirtIO (paravirtualized)` |
| Firewall | ☐ (uncheck — OPNsense is the firewall) |

**Confirm** → **uncheck** "Start after created" → **Finish**.

### 5.2 Add the second (LAN) NIC

1. Select the `OPNsense` VM → **Hardware** → **Add** → **Network Device**.
2. Bridge **`vmbr3`**, Model **VirtIO**, Firewall **unchecked** → **Add**.

You now have `net0` = WAN (`vmbr0`) and `net1` = LAN (`vmbr3`).

### 5.3 Install OPNsense

1. Start the VM → **Console**.
2. At the boot menu let it boot the live system. Log in at the prompt with **`installer` / `opnsense`**.
3. Choose the installer, keyboard defaults → **Install (UFS)** (or ZFS) → target disk → proceed.
4. Set the **root password** when prompted. When it finishes → **Reboot**.
5. Remove the ISO: VM → **Hardware** → **CD/DVD Drive** → **Edit** → **Do not use any media**.

### 5.4 Assign interfaces & set the LAN IP (console)

After reboot, the OPNsense **console menu** appears.

1. **Option 1) Assign interfaces** — when asked "Do VLANs now?" → `n`.
   - **WAN** → `vtnet0`
   - **LAN** → `vtnet1`
   - Confirm.
2. **Option 2) Set interface IP address** → choose **LAN**:
   - IPv4 via DHCP? → **`n`**
   - IPv4 address → **`10.10.10.1`**
   - Subnet bit count → **`24`**
   - Upstream gateway for LAN → *(press Enter for none)*
   - IPv6? → **`n`**
   - **Enable DHCP server on LAN?** → **`n`** *(this lab uses static IPs)*
   - Change web GUI protocol to HTTPS → **`y`**
3. WAN should already pull an IP from your home network via DHCP. Confirm the console shows a WAN IP.

### 5.5 First-boot web configuration

You need a machine on `vmbr3` to reach the GUI at **`https://10.10.10.1`**. Easiest path: build
**SPLUNK01** (Phase 2) next, give it `10.10.10.10`, and browse from it — or temporarily attach a
throwaway VM to `vmbr3`. Then:

1. Browse to `https://10.10.10.1` → log in **`root`** / *your password*.
2. Run the **Setup Wizard** (System → Wizard): set hostname `OPNsense`, domain `robinscapital.test`,
   DNS `1.1.1.1` / `8.8.8.8`. On the WAN step leave **"Block private networks"** and **"Block bogon
   networks"** *unchecked* (your WAN is an RFC1918 home LAN). Finish and apply.
3. **Firewall rules for the lab (LAN):** Firewall → Rules → **LAN**. The default *"Default allow LAN to
   any"* rule is enough for this lab (LAN can reach the internet; WAN blocks inbound by default). Leave it.
4. (Optional, more realistic) Later you can tighten LAN rules, add IDS/IPS (Suricata), and log to Splunk.

> 🎥 **Recording tip:** Narrate *why* OPNsense sits between the lab and your home network — segmentation,
> NAT, default-deny inbound. This is the segment that shows security architecture thinking.

---

## 6. Phase 2 — SPLUNK01 (Ubuntu Server + Splunk Enterprise)

### 6.1 Create the VM — wizard tab by tab

**General**
| Field | Value |
|---|---|
| VM ID | `110` |
| Name | `SPLUNK01` |
| Start at boot | ✅ |

**OS**
| Field | Value |
|---|---|
| ISO image | `ubuntu-24.04-live-server-amd64.iso` |
| Guest OS Type | **Linux** |
| Version | `6.x - 2.6 Kernel` |

**System**
| Field | Value |
|---|---|
| Machine | `q35` |
| BIOS | `OVMF (UEFI)` |
| Add EFI Disk | ✅ (`local-lvm`) |
| SCSI Controller | `VirtIO SCSI single` |
| Qemu Agent | ✅ (install guest agent later) |

**Disks**
| Field | Value |
|---|---|
| Bus/Device | `SCSI` `0` |
| Storage | `local-lvm` |
| Disk size (GiB) | `100` |
| Discard | ✅ |
| SSD emulation | ✅ (if backing store is SSD) |

**CPU**
| Field | Value |
|---|---|
| Sockets | `1` |
| Cores | `2` |
| Type | `host` |

**Memory**
| Field | Value |
|---|---|
| Memory (MiB) | `8192` |
| Ballooning | on (min 4096) |

**Network**
| Field | Value |
|---|---|
| Bridge | **`vmbr3`** |
| Model | `VirtIO (paravirtualized)` |
| Firewall | ☐ |

**Confirm** → Start after created ✅ → **Finish**.

### 6.2 Install Ubuntu Server

1. Boot → **Try or Install Ubuntu Server**.
2. Language / keyboard → defaults.
3. **Network:** the installer will show the interface (usually `ens18`) trying DHCP and **failing**
   (there's no DHCP on the lab net — expected). Select the interface → **Edit IPv4** → **Manual**:
   - Subnet: `10.10.10.0/24`
   - Address: `10.10.10.10`
   - Gateway: `10.10.10.1`
   - Name servers: `10.10.10.1`
   - Search domains: *(blank)* → **Save**.
4. Proxy → blank. Mirror → default.
5. Storage → **Use an entire disk** → default → **Done** → **Continue** (confirm destructive write).
6. **Profile:** your name, server name `splunk01`, a username (e.g. `splunkadmin`), and a password.
7. **Install OpenSSH server** → ✅ (handy for remote admin).
8. Skip featured snaps → **Done**. Let it install → **Reboot Now**. Remove the ISO if prompted.
9. Log in and update:
   ```bash
   sudo apt-get update && sudo apt-get upgrade -y
   sudo apt-get install -y qemu-guest-agent
   sudo systemctl enable --now qemu-guest-agent
   ```

### 6.3 Confirm static networking (Netplan)

Ubuntu's installer already wrote a netplan file. Verify it:

```bash
ip a          # confirm 10.10.10.10/24 — note the interface NAME here
ping -c3 10.10.10.1     # gateway (OPNsense)
ping -c3 8.8.8.8        # internet through NAT
```

> ⚠️ **Two things to check here (learned during the build):**
> 1. **The interface name may be `eth0`, not `ens18`.** Proxmox VirtIO NICs sometimes enumerate as `eth0`. Use whatever `ip a` actually shows in your netplan file.
> 2. **If `ip a` shows a different IP than `10.10.10.10` (e.g. `10.10.10.2`), OPNsense DHCP handed you a lease** — meaning the install didn't apply the static IP and/or LAN DHCP is still enabled. Pin it static below, and turn off OPNsense LAN DHCP (Services → DHCPv4 → LAN) so nothing else grabs an address you plan to assign by hand.

If you need to set it manually, the file lives in `/etc/netplan/` (name varies, e.g.
`50-cloud-init.yaml`). Match the interface name to what `ip a` reported:

```yaml
network:
  version: 2
  ethernets:
    eth0:          # <-- use YOUR interface name (eth0 or ens18)
      dhcp4: false
      addresses: [10.10.10.10/24]
      routes:
        - to: default
          via: 10.10.10.1
      nameservers:
        addresses: [10.10.10.1, 8.8.8.8]
```
Apply with `sudo netplan apply`, then re-check `ip a`.

> If `netplan apply` warns that cloud-init manages the network, make the static config stick across reboots:
> ```bash
> echo 'network: {config: disabled}' | sudo tee /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
> sudo netplan apply
> ```

### 6.4 Install Splunk Enterprise

Unlike the VirtualBox guide (which copied the `.deb` in via a shared folder), on Proxmox you download
it straight into the VM.

1. On any browser, create a free Splunk account and open the **Splunk Enterprise → Linux → .deb**
   download page. Click **"Download via Command Line (wget)"** and copy the generated `wget` command.
2. Paste that command into the SPLUNK01 shell to pull `splunk-*-linux-amd64.deb` into your home dir.
3. Install and start:
   ```bash
   sudo dpkg -i splunk-*-linux-amd64.deb
   sudo /opt/splunk/bin/splunk start --accept-license
   ```
   - Press **`q`** to skip the license pager, then create the **admin username/password** when prompted.
4. Enable start on boot as the `splunk` user:
   ```bash
   sudo /opt/splunk/bin/splunk enable boot-start -user splunk
   ```
5. From any lab machine's browser, open **`http://10.10.10.10:8000`** and log in.

### 6.5 Create the index and receiver (do this once, in the web UI)

1. **Settings → Indexes → New Index** → Name: **`endpoint`** → **Save**.
2. **Settings → Forwarding and receiving → Configure receiving → New Receiving Port** → **`9997`** → **Save**.

Splunk is now listening for forwarders on TCP 9997 and has an `endpoint` index to hold their data.

---

## 7. Phase 3 — ADDC01 (Windows Server 2022 Domain Controller)

> Windows on Proxmox uses **VirtIO** disk/network for best performance, so you load a storage driver
> during setup from the `virtio-win.iso`. This is the professional Proxmox pattern.

### 7.1 Create the VM — wizard tab by tab

**General**
| Field | Value |
|---|---|
| VM ID | `107` |
| Name | `ADDC01` |
| Start at boot | ✅ |

**OS**
| Field | Value |
|---|---|
| ISO image | `Windows Server 2022 Eval` ISO |
| Guest OS Type | **Microsoft Windows** |
| Version | `11/2022/2025` |

**System**
| Field | Value |
|---|---|
| Graphic card | Default |
| Machine | **`q35`** |
| BIOS | **`OVMF (UEFI)`** |
| Add EFI Disk | ✅ (`local-lvm`) · Pre-Enroll keys ✅ |
| SCSI Controller | **`VirtIO SCSI single`** |
| Qemu Agent | ✅ |
| TPM | *(optional for Server; required only for Win11)* |

**Disks**
| Field | Value |
|---|---|
| Bus/Device | `SCSI` `0` |
| Storage | `local-lvm` |
| Disk size (GiB) | `60` |
| Cache | `Write back` (fine for a lab) |
| Discard | ✅ · SSD emulation ✅ |

**CPU**
| Field | Value |
|---|---|
| Sockets | `1` |
| Cores | `2` |
| Type | `host` |

**Memory**
| Field | Value |
|---|---|
| Memory (MiB) | `4096` |
| Ballooning | on |

**Network**
| Field | Value |
|---|---|
| Bridge | **`vmbr3`** |
| Model | **`VirtIO (paravirtualized)`** |
| Firewall | ☐ |

**Confirm** → Start after created **unchecked** → **Finish**.

### 7.2 Add the VirtIO driver CD (second CD-ROM)

1. VM → **Hardware** → **Add** → **CD/DVD Drive** → Bus `IDE` `3` → ISO `virtio-win.iso` → **Add**.
2. Start the VM → **Console**.

### 7.3 Install Windows Server 2022

1. Boot from the Server ISO → **Install now**.
2. Edition: **Windows Server 2022 Standard Evaluation (Desktop Experience)** → Next.
3. Accept license → **Custom: Install Windows only (advanced)**.
4. **No disks are listed** (Windows lacks the VirtIO driver) → **Load driver** → **Browse** →
   the **virtio CD** → `vioscsi\2k22\amd64` → OK → select the driver → **Next**. The VirtIO disk appears.
5. Select the disk → **Next** and let Windows install and reboot.
6. Set the **Administrator** password at first logon.
7. Install the guest tools: open the virtio CD in File Explorer → run **`virtio-win-guest-tools.exe`**
   (installs NIC driver, QEMU guest agent, balloon, etc.). Reboot if asked.

### 7.4 Rename & set static IP

1. **Rename:** Start → search **About** → **Rename this PC** → **`ADDC01`** → restart.
2. **Static IP:** right-click the network icon → **Open Network & Internet settings** → **Change
   adapter options** → right-click the adapter → **Properties** → **Internet Protocol Version 4
   (TCP/IPv4)** → **Properties** → **Use the following IP address**:

   | Field | Value |
   |---|---|
   | IP address | `10.10.10.7` |
   | Subnet mask | `255.255.255.0` |
   | Default gateway | `10.10.10.1` |
   | Preferred DNS | `127.0.0.1` *(the DC resolves for itself; set after promotion)* |

   > Before promotion you can temporarily set DNS to `10.10.10.1` so you can download the Splunk
   > forwarder and Sysmon. **After** you promote it to a DC (Phase 6) set DNS to `127.0.0.1`.
3. Confirm with `ipconfig /all` in Command Prompt.

> Continue to **Phase 5** to install the Splunk Universal Forwarder + Sysmon on this server, then come
> back to Phase 6 to promote it. (You can also do forwarder/Sysmon after promotion — order isn't critical.)

---

## 8. Phase 4 — WIN11-01 (Windows 11 Domain Workstation)

Windows 11 on Proxmox **requires** UEFI + **TPM 2.0** + Secure Boot, plus the VirtIO storage driver.

### 8.1 Create the VM — wizard tab by tab

**General**
| Field | Value |
|---|---|
| VM ID | `111` |
| Name | `WIN11-01` |

**OS**
| Field | Value |
|---|---|
| ISO image | Windows 11 ISO (Enterprise Eval **or** the retail multi-edition ISO — see note) |
| Guest OS Type | **Microsoft Windows** |
| Version | `11/2022/2025` |

> **Edition note (from the build):** The **Enterprise Evaluation** ISO is ideal (no product key, 90 days).
> If you instead downloaded the **retail/consumer ISO**, its "Select Image" screen lists Home / Pro /
> Education variants but **no Enterprise** — choose **Windows 11 Pro**. Pro is fully sufficient here
> (domain join ✅, RDP host ✅). **Do NOT pick any Home edition** — Windows 11 Home **cannot join a
> domain and cannot host Remote Desktop**, which dead-ends Phases 7 and 8.

**System**
| Field | Value |
|---|---|
| Graphic card | Default |
| Machine | **`q35`** |
| BIOS | **`OVMF (UEFI)`** |
| Add EFI Disk | ✅ (`local-lvm`) · **Pre-Enroll keys ✅** (Secure Boot) |
| SCSI Controller | **`VirtIO SCSI single`** |
| Qemu Agent | ✅ |
| **Add TPM** | ✅ → Storage `local-lvm`, Version **`v2.0`** |

**Disks**
| Field | Value |
|---|---|
| Bus/Device | `SCSI` `0` |
| Storage | `local-lvm` |
| Disk size (GiB) | `64` |
| Discard | ✅ · SSD emulation ✅ |

**CPU**
| Field | Value |
|---|---|
| Sockets | `1` |
| Cores | `2` |
| Type | `host` |

**Memory**
| Field | Value |
|---|---|
| Memory (MiB) | `4096` |
| Ballooning | on |

**Network**
| Field | Value |
|---|---|
| Bridge | **`vmbr3`** |
| Model | **`VirtIO (paravirtualized)`** |
| Firewall | ☐ |

**Confirm** → Start after created **unchecked** → **Finish**.

### 8.2 Add the VirtIO driver CD

VM → **Hardware** → **Add** → **CD/DVD Drive** → `IDE 3` → `virtio-win.iso` → **Add**. Start → **Console**.

### 8.3 Install Windows 11

1. Boot the Win11 ISO (press a key at "Press any key…"). Choose language/region → **Install now**.
   - *If you land on the firmware boot menu instead, the "Press any key" prompt timed out — select the
     Windows **DVD-ROM** entry again and tap a key immediately. Booting the empty HARDDISK just loops back.*
2. "I don't have a product key" → edition **Windows 11 Enterprise Evaluation** (or **Windows 11 Pro** on
   the retail ISO — **not Home**) → accept license → **Custom**.
3. No disk shown → **Load driver** → **Browse** → virtio CD → `vioscsi\w11\amd64` → OK → **Next**.
4. Select the disk → **Next**; Windows installs and reboots into OOBE.
5. **OOBE / local account (isolated lab):** at the network step, to avoid a forced Microsoft account:
   - Press **`Shift + F10`** to open a command prompt, then run **`start ms-cxh:localonly`**
     (on older builds use `oobe\bypassnro` then reconnect). Create a **local admin** account
     (e.g. `labadmin`) and password.
6. On the desktop, open the virtio CD → run **`virtio-win-guest-tools.exe`** → reboot.

### 8.4 Rename & set static IP

1. **Rename:** Settings → System → About → **Rename this PC** → **`WIN11-01`** → restart.
2. **Static IP** (same path as ADDC01 → IPv4 properties):

   | Field | Value |
   |---|---|
   | IP address | `10.10.10.100` |
   | Subnet mask | `255.255.255.0` |
   | Default gateway | `10.10.10.1` |
   | Preferred DNS | `10.10.10.7` *(the domain controller)* |

3. Confirm with `ipconfig /all`.

---

## 9. Phase 5 — Splunk Forwarding & Sysmon on both Windows hosts

Do this on **both ADDC01 and WIN11-01** (identical steps). This produces the green dashed
"log forwarding" flow in the diagram.

### 9.1 Install the Splunk Universal Forwarder

1. Browse to Splunk → **Products → Free Trials & Downloads → Universal Forwarder → Windows 64-bit MSI**.
   (Temporarily point the box's DNS at `10.10.10.1` if it can't resolve yet.)
2. Run the MSI:
   - Accept license → **Customize Options** is optional; use defaults.
   - **On-premises Splunk Enterprise instance** → you may leave username/password blank.
   - **Deployment Server** → leave blank (skip).
   - **Receiving Indexer** → **`10.10.10.10`** port **`9997`**.
   - Finish the install.

### 9.2 Install Sysmon with a good config

1. Download **Sysmon** from https://learn.microsoft.com/sysinternals/downloads/sysmon and extract it.
2. Download Olaf Hartong's config: https://github.com/olafhartong/sysmon-modular → open
   **`sysmonconfig.xml`** → **Raw** → save it next to `Sysmon64.exe`.
3. Open **PowerShell as Administrator**, `cd` to that folder, and run:
   ```powershell
   .\Sysmon64.exe -accepteula -i sysmonconfig.xml
   ```
   Sysmon installs as a service and logs to **Microsoft-Windows-Sysmon/Operational**.

### 9.3 Tell the forwarder which logs to ship (`inputs.conf`)

1. In File Explorer go to
   `C:\Program Files\SplunkUniversalForwarder\etc\system\local`.
2. Open **Notepad as Administrator**, paste:
   ```ini
   [WinEventLog://Application]
   index = endpoint
   disabled = false

   [WinEventLog://Security]
   index = endpoint
   disabled = false

   [WinEventLog://System]
   index = endpoint
   disabled = false

   [WinEventLog://Microsoft-Windows-Sysmon/Operational]
   index = endpoint
   disabled = false
   renderXml = true
   source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
   ```
3. **File → Save As** → set **Save as type: All Files** → filename **`inputs.conf`** in that `local` folder.

### 9.4 Run the forwarder as Local System and restart

1. Open **Services** (as admin) → double-click **SplunkForwarder** → **Log On** tab → **Local System
   account** → OK.
2. Right-click **SplunkForwarder** → **Restart**.

### 9.5 Verify ingestion in Splunk

On SPLUNK01's web UI → **Search & Reporting** → run:
```spl
index=endpoint
```
Under **Selected Fields → host** you should see **ADDC01** and **WIN11-01** once both are configured.

---

## 10. Phase 6 — Build the Active Directory Domain

On **ADDC01**:

### 10.1 Install the AD DS role

1. **Server Manager → Manage → Add Roles and Features** → Next → Next → Next.
2. Check **Active Directory Domain Services** → **Add Features** → Next → Next → **Install**.
3. When it reports *"Configuration required… succeeded on ADDC01"*, proceed.

### 10.2 Promote to a Domain Controller

1. Click the **notifications flag** → **Promote this server to a domain controller**.
2. **Add a new forest** → Root domain name: **`robinscapital.test`** → Next.
3. Set a **DSRM password** (leave functional levels at defaults, DNS server ✅) → Next through the
   warnings (a DNS delegation warning is normal) → the NetBIOS name auto-fills as **`ROBINSCAPITAL`**.
4. Leave paths default → **Next** → **Install**. The server reboots.
5. After reboot log in as **`ROBINSCAPITAL\Administrator`**.
6. **Fix DNS:** set ADDC01's own Preferred DNS to **`127.0.0.1`** and add a DNS **forwarder** to
   `10.10.10.1` (DNS Manager → server → Properties → Forwarders) so it can resolve the internet.

### 10.3 Create OUs and users

1. **Server Manager → Tools → Active Directory Users and Computers**.
2. Right-click `robinscapital.test` → **New → Organizational Unit** → **`IT`**.
3. In the **IT** OU → right-click → **New → User**:
   - First `Jenny`, Last `Smith`, logon name **`jsmith`** → set a password → uncheck "must change" →
     check "Password never expires" (lab convenience) → Finish.
4. Create a second OU **`HR`** and a second user, e.g. First `Terry`, Last `Smith`, logon **`tsmith`**.
   - > For the brute-force phase to succeed, give **`tsmith`** a weak password that appears in the
   >   attacker's short list (e.g. one of the first 20 lines of `rockyou.txt`, such as `password`).

---

## 11. Phase 7 — Join WIN11-01 to the Domain

On **WIN11-01**:

1. Confirm **Preferred DNS = `10.10.10.7`** (from Phase 4). Verify with `ipconfig /all`.
2. Settings → **System → About → Domain or workgroup** (or run `sysdm.cpl`) → **Change** →
   **Domain:** **`robinscapital.test`** → OK.
3. Authenticate as **`ROBINSCAPITAL\Administrator`** → welcome message → restart.
4. At the login screen choose **Other user** and confirm it targets the **ROBINSCAPITAL** domain.
   Log in as a domain user, e.g. **`robinscapital\jsmith`**, to confirm the join works.

---

## 12. Phase 8 — KALI01 (Attacker) + RDP Brute Force

### 12.1 Create the VM — wizard tab by tab

**General**
| Field | Value |
|---|---|
| VM ID | `250` |
| Name | `KALI01` |

**OS**
| Field | Value |
|---|---|
| ISO image | `kali-linux-*-installer-amd64.iso` |
| Guest OS Type | **Linux** · Version `6.x - 2.6 Kernel` |

**System**
| Field | Value |
|---|---|
| Machine | `q35` |
| BIOS | `OVMF (UEFI)` · Add EFI Disk ✅ (`local-lvm`) · **UNCHECK "Pre-Enroll keys"** |
| SCSI Controller | `VirtIO SCSI single` |
| Qemu Agent | ✅ |

> ⚠️ **Secure Boot will block the Kali installer (learned during the build).** If you leave
> **"Pre-Enroll keys" checked**, OVMF enables Secure Boot with Microsoft's 2023 certs, and booting the
> Kali ISO fails with **`... DVD-ROM ... : Access Denied`** / *"No bootable option was found."* Kali's
> bootloader isn't trusted by that key set. Windows 11 needs Secure Boot; **Kali does not** — so
> **uncheck "Pre-Enroll keys"** when adding the EFI disk (or use **SeaBIOS** instead of OVMF for Linux).
>
> Already created it with Secure Boot on? Fix without rebuilding: **Stop** the VM → Hardware → select
> **EFI Disk** → **Remove** → Remove the resulting *Unused Disk* too → **Add → EFI Disk**, Storage
> `local-lvm`, **Pre-Enroll keys unchecked** → **Add** → Start.

**Disks:** `SCSI 0`, `local-lvm`, **40 GiB**, Discard ✅.
**CPU:** `1` socket / `2` cores / Type `host`.
**Memory:** `4096` MiB.
**Network:** Bridge **`vmbr3`**, Model **VirtIO**, Firewall ☐.

**Confirm** → Start after created ✅ → **Finish**.

### 12.2 Install Kali & set a static IP

1. Run the **Graphical Install**; set locale, a user, and password; use guided full-disk partitioning.
2. After first boot, set the static IP. Easiest via the NetworkManager GUI (top-right network icon →
   **Edit Connections → Wired connection 1 → IPv4 → Manual**):
   - Address `10.10.10.250` · Netmask `24` · Gateway `10.10.10.1` · DNS `10.10.10.1` → **Save**,
     toggle the connection off/on.
3. Verify:
   ```bash
   ip a
   ping -c3 10.10.10.1        # gateway (OPNsense) — should reply
   sudo apt-get update && sudo apt-get upgrade -y
   ```

   > **`ping 10.10.10.100` (WIN11-01) will FAIL — that's normal.** Windows blocks ICMP by default, so a
   > failed ping does **not** mean the host is down. What matters for the attack is that the RDP port is
   > reachable — test that instead:
   > ```bash
   > nc -zv 10.10.10.100 3389        # "open"/"succeeded" = good to attack
   > ```
   > (Optional, purely cosmetic for a demo: on WIN11-01, admin PowerShell:
   > `New-NetFirewallRule -DisplayName "Allow ICMPv4-In (lab)" -Protocol ICMPv4 -IcmpType 8 -Direction Inbound -Action Allow`)

### 12.3 Enable RDP on the target (WIN11-01)

1. On WIN11-01: Settings → System → **Remote Desktop → On** (or **This PC → Properties → Advanced
   system settings → Remote**).
2. Authorize the domain users to log on via RDP. GUI: **Select Users → Add** → `ROBINSCAPITAL\tsmith`
   (and `jsmith`). Or, faster and verifiable, in **admin PowerShell**:
   ```powershell
   net localgroup "Remote Desktop Users" ROBINSCAPITAL\tsmith /add
   net localgroup "Remote Desktop Users" ROBINSCAPITAL\jsmith /add
   net localgroup "Remote Desktop Users"     # <-- MUST list the users you added
   ```
   > **This is not optional and it's the #1 thing that breaks the attack.** If the target account isn't
   > in **Remote Desktop Users**, RDP returns *"account not active for remote desktop"* for **every**
   > password — the tool can't distinguish the correct one and reports 0 found even when it's in your list.

### 12.4 Build the wordlist and attack

Build the target's password into the list so the attack is deterministic (this is the intended lab
scenario — a user with a weak, guessable password). On **ADDC01**, reset `tsmith`'s (or `jsmith`'s)
password to a known value and make sure it appears in `passwords.txt`.

On **KALI01**, build the wordlist:
```bash
mkdir -p ~/Desktop/ad-project && cd ~/Desktop/ad-project
cp /usr/share/wordlists/rockyou.txt.gz . && gunzip rockyou.txt.gz
head -n 20 rockyou.txt > passwords.txt      # short list for a quick demo
# append the real password if it isn't already in the first 20 lines:
echo 'P@$$w0rd!' >> passwords.txt
cat passwords.txt                            # confirm it's in there
```

**Run the attack with Hydra (not Crowbar).**

> ⚠️ **Crowbar is deprecated on modern Kali (learned during the build).** Crowbar 0.4.2 calls
> `/usr/bin/xfreerdp`, but Kali now ships **FreeRDP 3** as `xfreerdp3`, so Crowbar errors with
> *"`/usr/bin/xfreerdp` path doesn't exists"* and silently finds nothing. **Use Hydra**, which has its
> own working RDP engine. *(If you must use Crowbar: `sudo ln -s /usr/bin/xfreerdp3 /usr/bin/xfreerdp` —
> but it can still misbehave with FreeRDP 3's changed flags, so Hydra is recommended.)*

```bash
hydra -t 1 -V -l tsmith -P passwords.txt rdp://10.10.10.100
```
- `-t 1` (one attempt at a time) keeps the experimental RDP module stable and avoids
  *"all children were disabled due too many connection errors."*
- A hit looks like: `[3389][rdp] host: 10.10.10.100  login: tsmith  password: P@$$w0rd!`

**Optional — verify the crack with a real login** (note the **single quotes** — a password containing
`$` or `!` gets mangled by the shell if unquoted or double-quoted):
```bash
xfreerdp3 /v:10.10.10.100 /u:tsmith /d:robinscapital.test /p:'P@$$w0rd!' /cert:ignore
```
A desktop opening = proven compromise. *(A file like `passwords.txt` is read literally by Hydra, so the
quoting caveat only applies to passwords typed on the command line.)*

> **If it reports 0 found after all this**, the account is almost certainly **locked out** from the
> failed attempts. On **ADDC01** → Active Directory Users and Computers → the user → **Properties →
> Account → tick "Unlock account"**, then re-run. (Raise `LockoutThreshold` via
> `Get-ADDefaultDomainPasswordPolicy` if it keeps re-locking mid-demo.)

> ⚠️ **Ethics/scope:** Only ever attack machines in *this* lab that you own. Keep `vmbr3` isolated.

---

## 13. Phase 9 — Detection & Analysis in Splunk

In Splunk **Search & Reporting**:

1. Scope to the attack:
   ```spl
   index=endpoint host=WIN11-01 tsmith
   ```
2. Expand the **EventCode** field. You'll see a spike of **`4625`** (an account failed to log on) —
   roughly one per password tried, clustered within seconds → classic **brute-force signature**.
3. When the attack succeeds you'll also see a **`4624`** (successful logon). Expand it
   ("Show all N lines") to read the **Source Network Address** — it will be **`10.10.10.250`** (KALI01),
   your smoking gun.
4. Reference Microsoft docs to justify the analysis:
   [Event 4625](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625) ·
   [Event 4624](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624).

### Turn it into a detection (build the alert)

**Step 1 — run the search.** Set the time picker to **Last 15 minutes** and run:
```spl
index=endpoint host=WIN11-01 EventCode=4625
| bucket _time span=1m
| stats count by _time, Account_Name, Source_Network_Address
| where count >= 5
```
Any row returned = 5+ failed logons from one source in a minute = a brute-force hit.

**Step 2 — Save As → Alert.** Top-right **Save As ▾ → Alert**, then:

| Field | Value |
|---|---|
| Title | `RDP Brute Force - Multiple Failed Logons` |
| Permissions | **Shared in App** |
| Alert type | **Scheduled** → **Run on Cron Schedule** |
| Cron Expression | `*/5 * * * *` (every 5 min) |

**Step 3 — Trigger Conditions:** *Trigger alert when* **Number of Results** **is Greater than** `0`
(the search already filters to `count >= 5`, so any result is a real hit). Trigger **Once**.

**Step 4 — Trigger Actions:** **+ Add Actions → Add to Triggered Alerts**, Severity **High** → **Save**.

**Step 5 — see it fire:** re-run the Hydra attack from Kali, wait for the next 5-minute tick, then
**Activity → Triggered Alerts** shows it. Manage/edit later under **Settings → Searches, reports, and
alerts**. This is the piece that turns the project from "I ran an attack" into "I engineered a detection."

> 🎥 **Recording tip:** This is your headline segment. Walk from raw `4625` events → the time
> clustering → the matching `4624` → the source IP → the saved alert firing. Narrate the analyst's reasoning.

---

## 14. Phase 10 — Atomic Red Team (find the detection gaps)

On **WIN11-01**, open **PowerShell as Administrator**:

```powershell
Set-ExecutionPolicy Bypass -Scope CurrentUser   # answer Y
```
Add a Defender exclusion so ART's artifacts aren't quarantined (lab only): **Windows Security →
Virus & threat protection → Manage settings → Exclusions → Add → Folder →** `C:\`.

Install ART:
```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics       # answer Y
```
Run a technique — **T1136.001, Create Local Account** (a persistence technique):
```powershell
Invoke-AtomicTest T1136.001
```
Now hunt it in Splunk:
```spl
index=endpoint host=WIN11-01 EventCode=4720      # A user account was created
```
Cross-reference the technique on [MITRE ATT&CK](https://attack.mitre.org/) (the `T####` IDs).
If the newly created local account **doesn't** appear in Splunk, you've found a **detection gap** —
document it, fix the logging (e.g. ensure account-management auditing is on / the right channel is
forwarded), and re-test. Repeat with more techniques to map coverage.

---

## 15. Portfolio: recording & documentation checklist

You're publishing this to GitHub, LinkedIn, your resume, and your portfolio site with OBS
voice-over videos. Suggested capture plan (each is a clean, self-contained clip):

| # | Segment | What to show / narrate |
|---|---|---|
| 1 | **Architecture** | Walk the diagram: bridges, OPNsense, the four VMs, the three data flows. |
| 2 | **Host & bridges** | Creating `vmbr3` isolated bridge; why no uplink = isolation. |
| 3 | **OPNsense** | Interface assignment, LAN `10.10.10.1`, default-deny inbound, NAT out. |
| 4 | **Splunk** | Ubuntu static IP, Splunk install, index `endpoint` + receiver 9997. |
| 5 | **Windows + VirtIO** | Loading the VirtIO storage driver — shows real Proxmox skill. |
| 6 | **AD build** | Forest `robinscapital.test`, OUs (IT/HR), users jsmith/tsmith. |
| 7 | **Telemetry** | Sysmon config, `inputs.conf`, both hosts appearing in Splunk. |
| 8 | **Attack** | Hydra RDP brute force from Kali (Crowbar is deprecated on modern Kali). |
| 9 | **Detection** | 4625 clustering → 4624 → source IP → saved alert. (Your best clip.) |
| 10 | **ART / gaps** | T1136.001, hunt EventCode 4720, find & close the gap. |

**Resume/LinkedIn one-liner you can adapt:**
> Built a segmented Active Directory detection lab on Proxmox VE (OPNsense-firewalled `10.10.10.0/24`),
> centralized Windows/Sysmon telemetry in Splunk, emulated an RDP brute-force (Hydra) and MITRE
> ATT&CK techniques (Atomic Red Team), and engineered Splunk detections from Windows Event IDs
> 4624/4625/4720.

**Repo hygiene:** commit this `BUILD-GUIDE.md`, the `logical-network.png` (export your PDF to PNG so it
renders on GitHub), screenshots per phase, your saved Splunk searches/alerts (`.spl`), and your
`inputs.conf` / `sysmonconfig.xml`. Add a short top-level `README.md` that links here.

---

## 16. Troubleshooting

| Symptom | Fix |
|---|---|
| Windows setup shows **no disk** | Load VirtIO storage driver `vioscsi\<os>\amd64` from the virtio CD. |
| Win11 install blocked (**TPM/Secure Boot**) | VM needs `q35` + OVMF + **Pre-Enroll keys** + a **TPM v2.0** device. |
| No network in a Windows VM | Run `virtio-win-guest-tools.exe` to install the NetKVM NIC driver. |
| VM can't reach internet | Check OPNsense WAN has a DHCP lease; VM gateway = `10.10.10.1`, DNS reachable. |
| Domain join fails / can't find domain | WIN11-01's **DNS must be `10.10.10.7`** (the DC), not `10.10.10.1`. |
| DC can't resolve internet | Add a **DNS forwarder** (`10.10.10.1`) in DNS Manager on ADDC01. |
| No hosts in Splunk `index=endpoint` | Confirm receiver on 9997, `inputs.conf` in `...\system\local`, forwarder service running as Local System, and firewall isn't blocking 9997. |
| **Kali ISO won't boot** (`Access Denied` / no bootable device) | Secure Boot is on. Re-add the **EFI Disk with "Pre-Enroll keys" unchecked**, or use SeaBIOS (§12.1). |
| **Win11 ISO has no Enterprise edition** | It's the retail ISO — pick **Windows 11 Pro** (§8.1). Never Home (no domain join / no RDP host). |
| **`crowbar` finds nothing / `xfreerdp path doesn't exist`** | Crowbar is broken on modern Kali (FreeRDP 3). Use **Hydra** instead (§12.4). |
| Attack reports *"account not active for remote desktop"* | The user isn't in **Remote Desktop Users** — add it and verify with `net localgroup` (§12.3). |
| Attack finds 0 even with the right password in the list | Account is **locked out** from prior attempts — unlock on ADDC01 (§12.4). |
| `xfreerdp3` login fails with a `$`/`!` password | Wrap the password in **single quotes** on the command line (§12.4). |
| ART scripts deleted by Defender | Add the `C:\` folder exclusion (lab only) before installing ART. |

---

*Credit: adapted from the MyDFIR / avulman Active Directory project, re-engineered for Proxmox VE with
an OPNsense-segmented network. Lab use only — keep `vmbr3` isolated and never point these tools at
systems you don't own.*
