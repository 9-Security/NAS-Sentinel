# NAS Sentinel — Feature & Operations Guide

<p align="center">
  <b>English</b> | <a href="USER_GUIDE.zh-TW.md">繁體中文</a>
</p>

This manual provides a comprehensive operational guide for **NAS Sentinel**, detailing architecture principles, initial setup, dual telemetry engines, baseline management, and troubleshooting.

---

## 1. 🚀 Quick Start

### 1.1 Architecture & Principles
NAS Sentinel employs an **agentless, zero-footprint architecture**:
* **Controller (Local Host / Windows)**: The local Python server runs on `http://127.0.0.1:8088`, managing dashboard presentation, baseline verification, alert dispatching, and historical telemetry persistence.
* **Target (Synology NAS)**: Zero packages required (no auditd, gcc, etc.). Zero temporary files are written to NAS disks or the root partition `/`. All telemetry scripts are executed via non-interactive SSH stdin in memory, streaming results back through stdout.

### 1.2 Initial Setup & Configuration
1. Open the dashboard and click **"⚙️ Admin ▾" ➔ "⚙️ System Connection & Settings..."**.
2. Enter your **NAS IP** (e.g. `192.168.1.100`) and **SSH Username** (e.g. `admin`, must belong to the `administrators` group).
3. **Custom SSH Port**: If your NAS uses a custom SSH port (e.g. `2222` or `5022`), specify it in the port input.
4. **SSH Key Setup**:
   - Click **"🔑 Generate Dedicated Ed25519 Key"** to auto-generate a strong private/public key pair in the local `data/` directory.
   - Expand the **Quick Authorization Command**, copy the single-line script, and paste it into your NAS terminal once.
5. Click **"🧪 Test NAS Connection"** to verify communication and fetch DSM / Linux kernel versions, then click **"🛡️ Save & Launch"**.

---

## 2. 🔍 File Integrity Monitoring (FIM & Scan)

### 2.1 Scan Modes
* **Fast Scan (~0.4s)**:
  - Focuses on high-risk web extensions (`.php`, `.sh`, `.cgi`, `.conf`, `.mustache`) and key security configs (`/etc/passwd`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `authorized_keys`).
  - Suitable for automated background polling (default: every 15 seconds).
* **Deep Scan (~3.5s)**:
  - Computes complete **SHA-256 hashes** across all 1,786 DSM web files and critical system binaries.
  - Detects stealthy trojan replacements, unauthorized code alterations, or file ownership tampering.

### 2.2 Search Monitored Files
- Click **"⚙️ Admin ▾" ➔ "🗄️ Search 1,786 Monitored Files"**.
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
- Fast Scan targets high-risk extensions and critical security configurations while verifying mtime and size. Combined with real-time inotify streaming, it achieves zero-latency defense with less than 1% CPU utilization.

### Q3: How do I stop or restart the service?
- The local server is an independent process. Close the command window to stop; double-click [`start-nas-sentinel.bat`](file:///D:/nas/start-nas-sentinel.bat) to relaunch.
