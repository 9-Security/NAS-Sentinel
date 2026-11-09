# NAS Sentinel — Zero-Footprint Real-Time Security & File Integrity Monitoring for Synology DSM

<p align="center">
  <b>English</b> | <a href="README.zh-TW.md">繁體中文</a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://www.synology.com"><img src="https://img.shields.io/badge/Target-Synology%20DSM%207.x-00e5ff.svg" alt="Target: Synology DSM 7.x"></a>
  <img src="https://img.shields.io/badge/NAS%20Footprint-Zero%20(No%20Packages)-00ff41.svg" alt="Zero Footprint">
  <img src="https://img.shields.io/badge/Architecture-ARM64%20%7C%20x86__64-orange.svg" alt="Architecture">
  <a href="http://127.0.0.1:8088"><img src="https://img.shields.io/badge/UI-Cyber%20SOC%20Dashboard-purple.svg" alt="Cyber SOC Dashboard"></a>
</p>

**NAS Sentinel** is an open-source, beginner-friendly, **zero-footprint, millisecond-level File Integrity Monitoring (FIM) and Rootkit / Anti-Trojan security watchdog** specifically engineered for **Synology NAS (DSM 7.x)** devices.

Equipped with a built-in **Web Setup Wizard**, it requires zero Linux hacking skills. Simply enter your NAS IP, click "Test & Probe", and your high-tech Cyberpunk Security Operations Center (SOC) dashboard is up and running in **under 3 minutes**!

---

## 📋 Prerequisites

Before running NAS Sentinel, ensure your Synology NAS has SSH enabled:
1. Log in to your Synology DSM as an administrator.
2. Go to **Control Panel ➔ Terminal & SNMP**.
3. Check **"Enable SSH service"** (Default Port: `22`).
> *Note: Synology DSM 7.x includes Python 3 natively in system firmware. You do NOT need to install any packages on the NAS!*

---

## ⚡ 3-Minute Quickstart (Beginner-Friendly)

### Step 1: Clone or Download
Clone this repository or download and extract the release zip:
```bash
git clone https://github.com/9-Security/NAS-Sentinel.git
cd NAS-Sentinel
```

### Step 2: One-Click Launch
- **Windows Users**: Double-click [`start-nas-sentinel.bat`](start-nas-sentinel.bat).  
  *(Runs completely detached in the background without annoying console windows, and automatically opens your default browser)*
- **macOS / Linux Users**: Run `./start-nas-sentinel.sh`.
- **Docker Users**: Run `docker-compose up -d`.

### Step 3: Web Setup Wizard
Your browser will open `http://127.0.0.1:8088`. On first launch, the **Setup Wizard** will greet you:
1. **Host Info**: Enter your Synology NAS IP and SSH username (the wizard automatically detects existing SSH keys in your `~/.ssh/` directory or offers an auto-generation tool).
2. **Click "⚡ Test SSH Connection & Probe NAS"**: Automatically inspects DSM version, hardware architecture (`x86_64` vs `aarch64`), and Python 3 readiness.
3. **Click "🛡️ Save & Launch SOC"**: Automatically generates baseline profiles for 1,786 critical system & web files, listening ports, and Linux kernel modules (LKM), then transitions directly into your live Cyber SOC War Room!

---

## 🚀 Background Daemon & Auto-Start Management

NAS Sentinel runs as an independent daemon decoupled from your terminal or IDE:

### 1. Manual Background Start
Double-click `start-nas-sentinel.bat` to run silently in the background:
```bat
start-nas-sentinel.bat
```
- **Dashboard URL**: `http://127.0.0.1:8088`

### 2. Auto-Start on Windows Logon (Recommended)
Register NAS Sentinel as a Windows Scheduled Task that launches silently whenever you log in:
```bat
install-autostart-service.bat
```
- To uninstall auto-start: double-click `uninstall-autostart-service.bat`.

### 3. Stop Service
To cleanly terminate the background server and release port 8088:
```bat
stop-nas-sentinel.bat
```

---

## 🌟 Key Features

### 1. 🛡️ Zero Footprint on NAS (No Package Installation)
- Synology root partitions `/` are tiny (~2.3 GB). Heavy enterprise SIEM agents (Wazuh, OSquery, Tripwire) quickly exhaust flash storage or RAM on home/entry-level NAS models.
- NAS Sentinel streams execution directly over SSH stdin and outputs to stdout. **Zero files are written to NAS flash storage, and no package managers (ipkg/opkg/gcc/auditd) are required**. CPU and RAM consumption on the NAS is near 0%.

### 2. ⚡ Linux Kernel inotify Millisecond Event Streaming
- Bypasses auditd entirely by calling the Linux kernel's `libc.so.6` `inotify` syscall directly via standard library `ctypes`.
- Real-time event monitoring across 254 critical web and system directories, catching file creation, modification, attribute changes, moves, and deletions in sub-second time.

### 3. 🕸️ Web Server & File Integrity Monitoring (FIM)
- Continuously inspects Nginx configurations (`/etc/nginx`), DSM web portals (`/usr/syno/synoman`), user web directories (`/volume1/web`), and core security configurations across 1,786+ files.
- Computes SHA-256 hashes, permission modes, and owners while running a sliding-window Webshell pattern matcher.

### 4. 🕵️ DSM Rootkit & Trojan Detection Engine
- Implements 6 core checks inspired by `chkrootkit` and `rkhunter`:
  - **20 System Binaries SHA-256 Baseline**: Validates `/bin/ps`, `ls`, `netstat`, `sshd`, `sudo`, `nginx`, etc., following symlinks to real executable binaries.
  - **`LD_PRELOAD` Hijacking**: Checks `/etc/ld.so.preload` and inspects `/proc/*/environ`.
  - **Hidden / Phantom Processes**: Cross-compares kernel `/proc` PIDs against `ps -eo pid` to identify invisible rootkits.
  - **Promiscuous Network Sniffing**: Inspects `IFF_PROMISC` (`0x100`) flags on all physical network adapters.
  - **Kernel Module (LKM) Whitelisting**: Compares loaded modules in `/proc/modules` against a verified baseline (`lkm_baseline.json`).
  - **Known Rootkit Directories & `/dev/shm`, `/tmp` ELF Scan**: Identifies suspicious ELF executables dropped in temporary locations.

### 5. 🌐 Network Matrix & Port Anomaly Detection
- Categorizes connections into Local, LAN, and WAN in real time.
- Compares active listening ports against baseline; any unauthorized newly opened port immediately triggers high-severity visual alarms.

### 6. 🌐 Cloudflare Edge Threat Intelligence (WAF Probes)
- Designed for NAS setups exposed via Cloudflare Tunnels (Zero Trust). Connects directly to Cloudflare's GraphQL Analytics API (`firewallEventsAdaptive`).
- Pulls edge directory probing logs (`/.env`, `wp-config.php`, `/.git`, bot scanners) directly from Cloudflare Anycast edge nodes without turning on DSM Nginx access logs or wearing down disks.
- Categorizes attack attempts (Sensitive Config Probe, CMS Scanner, Database Admin Probe) and shows TOP 5 targeted paths and origin countries.

### 7. 🎨 Nine-Security Cyber SOC Visual Theme
- Cyberpunk Command Center theme crafted by [Nine-Security](https://nine-security.com): Deep Black grid backdrop (`#050505`), subtle scanlines, Terminal Matrix Green (`#00ff41`), and Cyber Cyan (`#00e5ff`).
- High-DPR smooth responsive charts with 2-second anti-spam cooldown, global state locks, and interactive modals.

---

## 📁 Repository Structure

```
NAS-Sentinel/
├── nas-sentinel/                # [Core Server & Agent Code]
│   ├── server.py                # Local HTTP server, telemetry engine, REST API & scheduler
│   ├── collector_remote.py      # NAS remote read-only FIM, Rootkit & telemetry collector
│   ├── inotify_stream_remote.py # NAS remote Linux kernel inotify streaming engine (ctypes)
│   ├── cloudflare_intel.py      # Cloudflare GraphQL edge threat intelligence client
│   ├── static/                  # Cyber SOC Web Frontend
│   │   ├── index.html           # Dashboard UI & Web Setup Wizard
│   │   ├── app.js               # Frontend controller, polling loop & wizard logic
│   │   ├── logo_v2.png          # Nine-Security brand emblem
│   │   └── favicon.png          # Browser favicon
│   └── data/                    # Storage for baselines & configs (private configs gitignored)
│       ├── config.example.json  # Configuration template
│       ├── fim_baseline.json    # File integrity baseline
│       ├── port_baseline.json   # Listening ports baseline
│       └── lkm_baseline.json    # Kernel modules baseline
│
├── start-nas-sentinel.bat       # Windows one-click silent background launcher
├── stop-nas-sentinel.bat        # Windows stop server script
├── install-autostart-service.bat# Windows register Scheduled Task on logon
├── uninstall-autostart-service.bat # Windows unregister Scheduled Task
├── start-nas-sentinel.sh        # Linux / macOS one-click launcher
├── Dockerfile                   # Docker container definition
├── docker-compose.yml           # Docker Compose deployment file
├── LICENSE                      # MIT Open-Source License
├── README.md                    # Primary English documentation (this file)
└── README.zh-TW.md              # Traditional Chinese documentation (繁體中文說明)
```

---

## 🔒 Privacy & Security First

NAS Sentinel is built with strict privacy-preserving principles:
- **Zero Cloud Telemetry**: None of your telemetry or scan results leave your local machine.
- **Git-Safe Credentials**: Sensitive configuration files (`config.json`, `cloudflare_config.json`, `events.json`) are strictly excluded in `.gitignore`.
- **Read-Only Telemetry**: Remote execution on the NAS is 100% read-only and never makes unauthorized modifications to your DSM system.

---

## 📜 License

Distributed under the **[MIT License](LICENSE)**. Maintained with ❤️ by **[Nine-Security.INC](https://nine-security.com)**.
