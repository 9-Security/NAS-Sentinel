# NAS Sentinel — Feature & Operations Guide

<p align="center">
  <b>English</b> | <a href="USER_GUIDE.zh-TW.md">繁體中文</a>
</p>

This manual provides a comprehensive operational guide for **NAS Sentinel**, detailing architecture principles, initial setup, dual telemetry engines, baseline management, and troubleshooting.

---

## 1. 🚀 Quick Start

### 1.1 Architecture & Principles
NAS Sentinel employs an **agentless, zero-footprint architecture**:
* **Controller (Local Host)**: The local Python server runs on `http://127.0.0.1:8088`, managing dashboard presentation, baseline verification, alert dispatching, and historical telemetry persistence.
* **Target (Synology NAS)**: Zero packages required (no auditd, gcc, etc.). Zero temporary files are written to NAS disks or the root partition `/`. All telemetry scripts are executed via non-interactive SSH stdin in memory, streaming results back through stdout.

Labels below match the in-app Setup Wizard / Admin menus. For Docker, portable Windows Python, and OpenSSH Client details, see the project [README](../README.md).

### 1.2 First launch on this PC (localhost unlock)
1. Start the local server (`start-nas-sentinel.bat` on Windows, or `./start-nas-sentinel.sh` on macOS/Linux). Your browser opens `http://127.0.0.1:8088`.
2. **Preferred:** visiting from this machine auto-loads the API token (loopback only — `127.0.0.1` / `::1`). You should not need to open `api_token.txt` on the happy path.
3. **Backup:** the server still prints the token and writes `nas-sentinel/data/api_token.txt` (or set `API_TOKEN` in `.env`) if you must paste it manually. Every other `/api/*` call still requires `Authorization: Bearer <token>`.

### 1.3 Initial Setup & Configuration (first NAS connection)
**Prerequisites (same as the wizard step cards):** enable SSH in DSM (**Control Panel ➔ Terminal & SNMP ➔ Terminal**), and use an account in the `administrators` group. On Windows, keep **OpenSSH Client** enabled so the wizard can run `ssh` / `ssh-keygen`.

1. Open the dashboard and click **"⚙️ Admin ▾" ➔ "⚙️ System Connection & Settings..."** (or follow the first-run Setup Wizard).
2. Enter your **NAS LAN IP** (e.g. `192.168.1.100` — never `127.0.0.1`, that is this PC’s UI) and **SSH Username** (must belong to `administrators`).
3. **Custom SSH Port**: If your NAS uses a custom SSH port (e.g. `2222` or `5022`), specify it in the port input.
4. **SSH Key Setup** (wizard path — recommended):
   - Click **"🔑 Generate key"** and set a protection passphrase (**at least 8 characters**; empty passphrases are refused). The private key is written to **`~/.ssh/nas_sentinel_ed25519`** on this PC (not under `data/`). Config, API token, and known_hosts live under `nas-sentinel/data/`.
   - Click **Copy**, then in DSM open **Control Panel ➔ Task Scheduler** → **Create ➔ Scheduled Task ➔ User-defined script**. Set the task user to your admin account, paste the one-liner, save, and **Run once**.
   - Unlock the key once on this PC with **`ssh-agent`** so background BatchMode scans can use it.
5. Click **"Test connection & probe NAS"** to verify communication and fetch DSM / arch (on success the host-key fingerprint is pinned). On failure, the UI maps the error to what to do next.
6. Click **"🛡️ Test & go live"** to save `data/config.json`, establish baselines when SSH works, and open the SOC. You can also **Save connection settings** first and go live later.

> **Optional / advanced:** authorizing via a computer terminal (PowerShell / macOS) is a backup path — see the README Method B samples. Those examples use a personal key such as `id_ed25519`; the wizard’s dedicated key is always `nas_sentinel_ed25519`.

---

## 2. 🔍 File Integrity Monitoring (FIM & Scan)

### 2.1 Scan Modes
* **Fast Scan (~0.4s)**:
  - Focuses on high-risk web extensions (`.php`, `.sh`, `.cgi`, `.conf`, `.mustache`) and key security configs (`/etc/passwd`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `authorized_keys`).
  - Suitable for automated background polling (default: every 15 seconds).
* **Deep Scan (~3.5s)**:
  - Computes complete **SHA-256 hashes** across the DSM web tree and critical system binaries (thousands of paths on a typical DSM — exact count is baseline/DSM-dependent).
  - Detects stealthy trojan replacements, unauthorized code alterations, or file ownership tampering.

### 2.2 Search Monitored Files
- Click **"⚙️ Admin ▾" ➔ "🗄️ Search Monitored Files"** (the menu may show the count from your current baseline).
- In the FIM tab, quickly filter and inspect full paths, file sizes, modification timestamps (mtime), and SHA-256 hashes.

### 2.3 When to "Rebuild Baseline"?
* Legitimate system modifications will raise file change alerts:
  1. Immediately after a Synology DSM firmware update.
  2. Installing or updating official Synology packages (e.g. Web Station, Python).
  3. Legitimate administrator edits to configuration files or SSH keys.
* **Procedure**:
  1. Click **"⚙️ Admin ▾" ➔ "🛡️ Rebuild Baseline..."**.
  2. Review the confirmation checklist and click **"⚠️ Confirm Rebuild Baseline"**.
  3. The system captures the current clean state as the new Golden Baseline and clears anomaly alerts.

---

## 3. ⚡ Real-Time inotify Kernel Stream

### 3.1 Millisecond-Level Event Interception
In addition to periodic polling, NAS Sentinel features a continuous inotify kernel stream:
- Directly utilizes Linux kernel `inotify` syscalls to intercept `IN_CLOSE_WRITE` (file write complete), `IN_MOVED_TO` (file moved in), `IN_CREATE` (file created), and `IN_ATTRIB` (permissions changed).
- Alerts are dispatched to the dashboard within milliseconds.

### 3.2 Built-In Threat Heuristics
* **Dynamic Webshell Detection**:
  - Automatically inspects files written to `/volume1/public`, `/volume1/tmp`, or DSM web directories for backdoor patterns (e.g., `eval(base64_decode(...))`, `passthru`, `shell_exec`, `assert`).
* **SUID Privilege Escalation**:
  - Flags unauthorized binaries granted `chmod +s` execution flags.
* **Key Injection Defense**:
  - Traps unauthorized writes to `~/.ssh/authorized_keys` or `/root/.ssh/authorized_keys` in real time.

---

## 4. 🌐 Cloudflare Edge Threat Intelligence

### 4.1 Edge Threat Visibility
* Blocks malicious path scans and WAF violations at Cloudflare's global edge before traffic reaches your NAS, eliminating disk I/O and CPU overhead.
* Tracks attacker IPs, geographic origin, target malicious paths (e.g. `/.git/config`, `/wp-login.php`, `/.env`), and WAF rules triggered.

### 4.2 Configuration Steps
1. Navigate to Cloudflare Dashboard ➔ **My Profile** ➔ **API Tokens**.
2. Create an API Token with a single read-only permission: **`Zone - Analytics - Read`**.
3. Go to your domain overview page and copy the 32-character **Zone ID** from the bottom right.
4. Open **"⚙️ Admin ▾" ➔ "System Connection & Settings..."** and expand the Cloudflare section.
5. Click **"🧪 Test Connection"** to verify your Token and Zone ID before saving. Check "Enable automatic sync" to poll threat intel every 60 seconds.

---

## 5. 🔌 Network Ports & Security Auditing

### 5.1 Listening Ports Matrix
* **Baseline Verification**: Maintains a trusted baseline of legitimate ports (SSH 22, DSM 5000/5001, Nginx 80/443).
* **Rogue Port Detection**: Any unknown listening port opened by rogue background services or reverse shells (e.g. 4444, 9999) is immediately highlighted in red.

### 5.2 Active Sessions (utmp) & Key Fingerprints
* **Active Logins**: Parses `/var/run/utmp` in real-time, detailing active terminals (TTY), client IPs, and login timestamps.
* **SSH Public Key Auditing**: Audits `authorized_keys` across user home directories, computing 16-character SHA-256 fingerprint prefixes to expose unauthorized backdoor keys.

---

## 6. 🎨 Themes & Multilingual Support

* **Dark / Light Mode Toggle**:
  - Click the top-right icon (`🌙` / `☀️`) to switch instantly.
  - Dark mode delivers a cyberpunk green SOC aesthetic; Light mode leverages 180° hue rotation to deliver clean, corporate blue (#0056b3) visuals matching Nine-Security standards.
* **Language Selector (zh-TW / EN / JP)**:
  - Click the top-right `🌐 Language Selector` to seamlessly switch between **Traditional Chinese (TW)**, **English (EN)**, and **Japanese (JP)**.

---

## 7. ❓ Frequently Asked Questions (FAQ)

### Q1: An alert banner says "🚨 File Integrity or Security Anomaly Detected!". What should I do?
1. Inspect the "File Change Alerts" table to verify the modified paths and timestamps.
2. **If it was your legitimate action** (e.g., DSM update or config change): Click **"⚙️ Admin ▾ ➔ Rebuild Baseline"** to acknowledge.
3. **If unexpected**: Disconnect the NAS from external networks, inspect active utmp sessions, and quarantine suspicious files immediately.

### Q2: Why does a Fast Scan take only 0.4s? Does it miss changes?
- Fast Scan targets high-risk extensions and critical security configurations while verifying mtime and size. Combined with real-time inotify streaming, it keeps detection responsive with low NAS overhead.

### Q3: How do I stop or restart the service?
- **Windows:** the launcher runs a detached background process — closing a command window does **not** stop it. Double-click [`stop-nas-sentinel.bat`](../stop-nas-sentinel.bat) to terminate the server and free port 8088, then [`start-nas-sentinel.bat`](../start-nas-sentinel.bat) to relaunch.
- **macOS / Linux:** stop the Python process listening on port 8088 (for example kill the PID from `./start-nas-sentinel.sh`), then run `./start-nas-sentinel.sh` again.
- **Docker:** `docker compose down` / `docker compose up -d` from the project root (Compose binds `127.0.0.1:8088` only).
