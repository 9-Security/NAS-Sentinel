# NAS Sentinel — Zero-Footprint Real-Time Security & File Integrity Monitoring for Synology DSM

<p align="center">
  <b>English</b> | <a href="README.zh-TW.md">繁體中文</a> | <a href="docs/USER_GUIDE.md">📖 User Guide</a> | <a href="docs/ARCHITECTURE.md">🏗️ Architecture</a> | <a href="CHANGELOG.md">Changelog</a>
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

## 📋 Step 1: Enable SSH Access on Synology DSM (Prerequisites)

NAS Sentinel performs zero-footprint security telemetry over an encrypted SSH connection. Complete these 3 quick checks on your NAS:

### 1. Enable DSM SSH Service
1. Log in to your Synology DSM web desktop with an administrator account.
2. Go to **Control Panel ➔ Terminal & SNMP ➔ Terminal**.
3. Check **"Enable SSH service"** (Default Port: `22`) and click **Apply**.

### 2. Ensure User is in `administrators` Group
By default, Synology DSM security policies **only allow users in the `administrators` group to log in via SSH**. Ensure your account belongs to the `administrators` group in **Control Panel ➔ User & Group**.

### 3. Set Up Passwordless SSH Key Authentication (Choose One)
Because NAS Sentinel operates as a silent background daemon, it requires SSH Key authentication (`BatchMode=yes`). Choose whichever method is easiest:

- **Method A: Via DSM Web UI (Recommended for Beginners - No Terminal Required)**:
  1. Retrieve your SSH public key (`~/.ssh/id_ed25519.pub`, beginning with `ssh-ed25519 AAAA...`). *If you don't have one, click "🔑 Generate Passphrase-Protected Key" in the Setup Wizard (empty passphrases are refused; load the key into `ssh-agent` for BatchMode scans).*
  2. Log in to DSM, open **Control Panel ➔ Task Scheduler**.
  3. Click **Create ➔ Scheduled Task ➔ User-defined script**:
     - General: Task Name `Add-SSH-Key`, **User: Select your login username** (e.g., `admin`).
     - Task Settings: In User-defined script, paste this single line (replace with your actual public key):
       ```bash
       mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo "YOUR_PUBLIC_KEY_HERE (e.g. ssh-ed25519 AAAA...)" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
       ```
  4. Click **OK**, select the task in the list, and click **Run** once. Your key is permanently authorized!

- **Method B: Via Your Computer's Terminal (PowerShell / macOS)**:
  Run this one-liner from your local terminal (enter your NAS password once when prompted):
  ```bash
  # Windows PowerShell:
  type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh <USER>@<NAS-IP> "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys"

  # macOS / Linux:
  ssh-copy-id -i ~/.ssh/id_ed25519.pub <USER>@<NAS-IP>
  ```

> *Note: Synology DSM 7.x firmware includes Python 3 natively. You do NOT need to install anything from Package Center on the NAS!*

---

## ⚡ Step 2: 3-Minute Quickstart & Launch SOC

### Step 1: Clone or Download
Clone this repository or download and extract the release zip:
```bash
git clone https://github.com/9-Security/NAS-Sentinel.git
cd NAS-Sentinel
```

### Step 2: One-Click Launch (Starts Local Web Server)
*(This launches the local server on your **own computer**—you do NOT need to edit configuration files beforehand; your default browser will open automatically)*
- **Windows Users**: Double-click [`start-nas-sentinel.bat`](start-nas-sentinel.bat).  
  *(Runs completely detached in the background without annoying console windows, and automatically opens your browser)*
- **macOS / Linux Users**: Run `./start-nas-sentinel.sh`.
- **Docker Users**: Copy `.env.example` → `.env`, set a high-entropy `API_TOKEN`, then run `docker compose up -d`.  
  Compose **binds `127.0.0.1:8088` only** (not `0.0.0.0`). Mount a **single dedicated SSH key** if needed — never the entire `~/.ssh` directory. Publishing the port on all interfaces without auth is **unsupported**.

### Step 3: Unlock the UI with your API token, then configure NAS
Your browser will open `http://127.0.0.1:8088`. **All `/api/*` routes require** `Authorization: Bearer <API_TOKEN>`:
1. On first start the server prints the token and writes `nas-sentinel/data/api_token.txt` (or use `API_TOKEN` from `.env`).
2. Paste that token into the auth gate in the browser (stored in localStorage for this origin only).
3. The **Setup Wizard** then asks for NAS connection details:
   - **NAS IP / Hostname**: e.g., `192.168.1.100` or your internal domain.
   - **SSH Username**: e.g., `admin` or your administrative user.
   - **SSH Port**: Defaults to `22`. **If you customized your Synology SSH port for security (e.g., `2222`, `5022`, `60022`), simply enter it here!**
   - **SSH Key**: Must be a file under `~/.ssh/`. Generate a **passphrase-protected** Ed25519 key in the wizard, or use an existing key loaded in `ssh-agent`.
4. **Click "⚡ Test SSH Connection & Probe NAS"**: Validates the connection, shows the SSH host-key fingerprint (pinned on save), and detects DSM/arch.
5. **Click "🛡️ Save & Launch SOC"**: Done! Saves to `data/config.json` (mode `0600`), establishes baselines, and launches the SOC.

> 💡 **Prefer text configuration files? (Optional)**  
> Copy `.env.example` to `.env` and set `API_TOKEN`, `NAS_HOST`, `NAS_USER`, and `NAS_PORT` prior to Step 2.

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
├── CHANGELOG.md                 # Keep a Changelog release notes
├── README.md                    # Primary English documentation (this file)
└── README.zh-TW.md              # Traditional Chinese documentation (繁體中文說明)
```

---

## 🔒 Privacy & Security First

NAS Sentinel is built with strict privacy-preserving principles:
- **Localhost-first**: Default bind is `127.0.0.1`. Docker Compose publishes `127.0.0.1:8088` only. **Network exposure without authentication is unsupported.**
- **API authentication**: Every `/api/*` route (except `/api/auth/status`) requires `Authorization: Bearer <API_TOKEN>` (header-based, CSRF-resistant). Cloudflare tokens are never returned in API responses (masked/presence only).
- **SSH hardening**: Key paths must stay under `~/.ssh`; auto-generated keys require a passphrase; host-key fingerprints are pinned after first successful setup.
- **Zero Cloud Telemetry**: None of your telemetry or scan results leave your local machine.
- **Git-Safe Credentials**: Live configs, API token file, known_hosts, and machine baselines are gitignored; only `*.example.json` templates are tracked.
- **Read-Only Telemetry**: Remote execution on the NAS is 100% read-only and never makes unauthorized modifications to your DSM system.

---

## 📜 License

Distributed under the **[MIT License](LICENSE)**. Maintained with ❤️ by **[Nine-Security.INC](https://nine-security.com)**.
