# NAS Sentinel — System Architecture & Design Specification

<p align="center">
  <b>English</b> | <a href="ARCHITECTURE.zh-TW.md">繁體中文</a>
</p>

> **Version**: 2.0 (Integrated Linux Kernel inotify Stream & Package-Free Rootkit Engine)  
> **Target**: Synology DSM 7.x (DSM 7.0 ~ 7.4+ aarch64 / x86_64)  
> **Protocol**: Ed25519 / RSA SSH Key Authentication (Zero-Footprint Memory Injection Mode)

---

## 1. System Architecture Overview

**NAS Sentinel** is an open-source, **agentless, zero-footprint, millisecond-level File Integrity Monitoring (FIM) and Rootkit / Anti-Trojan security watchdog** specifically designed for **Synology NAS (DSM 7.x)** devices.

The central server runs locally on the monitoring host (`nas-sentinel/`), executing non-interactive, read-only telemetry and kernel event streaming on the remote NAS over an encrypted SSH connection, providing an intuitive, high-tech Web SOC Dashboard (`http://127.0.0.1:8088`).

```
+---------------------------------------------------------------------------------+
| Monitoring Controller (Local Host / 127.0.0.1)                                  |
|                                                                                 |
|  [ start-nas-sentinel.bat ] -> Double-click to launch                           |
|                                                                                 |
|  +---------------------------------------------------------------------------+  |
|  | NAS Sentinel Server (server.py) : Port 8088                               |  |
|  |  - Web UI / REST API: /api/status, /api/scan, /api/setup/save, ...        |  |
|  |  - MonitorState: Thread-safe state, baseline auditing, security scoring    |  |
|  |  - Storage: data/*.json (FIM, Ports, LKM, Events, History)                |  |
|  +---------------------------------------------------------------------------+  |
|          | (SSH non-interactive stdin stream)      ^ (inotify NDJSON stdout stream)|
+----------|-----------------------------------------|----------------------------+
           v                                         |
+----------------------------------------------------+----------------------------+
| Synology NAS (Target DSM 7.x Host)                                              |
|                                                                                 |
|  1. collector_remote.py (Periodic 15s Fast / Manual Deep Polling)               |
|     - Telemetry: CPU, RAM, Temperature, Storage Volume, SMART Health             |
|     - Web & System FIM: thousands of critical files (baseline/DSM-dependent)     |
|     - Ports & Connections: netstat baseline verification                        |
|     - Rootkit Checks: 6 core security checks (equivalent to rkhunter/chkrootkit) |
|                                                                                 |
|  2. inotify_stream_remote.py (Linux Kernel ctypes Real-Time Stream)             |
|     - Watches critical web/system dirs (/etc/nginx, /usr/syno/synoman, /bin…)  |
|     - Intercepts CREATE, MODIFY, CLOSE_WRITE, ATTRIB, DELETE, MOVE              |
|     - Sub-second SHA-256 re-computation, zero packages, zero disk writes        |
+---------------------------------------------------------------------------------+
```

---

## 2. Core Modules Architecture

### 2.1 Central Controller Server (`nas-sentinel/server.py`)
- **Web UI & REST API**: High-performance HTTP daemon built with Python's standard library, serving static assets and dynamic JSON endpoints.
- **Baseline Engine**:
  - `fim_baseline.json`: Stores SHA-256 hashes, file modes, and ownership for monitored files (count is baseline/DSM-dependent).
  - `port_baseline.json`: Authorized TCP/UDP listening ports matrix.
  - `http_baseline.json`: Nginx HTTP/HTTPS endpoint response hashes and TLS certificate fingerprints.
  - `lkm_baseline.json`: Whitelist of legitimate Linux Kernel Modules.
- **Dual-Track Event Engine**:
  - **Track 1**: Periodic background polling every 15 seconds (`collector_remote.py`).
  - **Track 2**: Long-lived background inotify stream thread intercepting file changes in real-time.

### 2.2 Remote Telemetry & FIM Collector (`nas-sentinel/collector_remote.py`)
- Injected into the remote Python runtime via SSH stdin (`ssh <user>@<host> "python3 - <mode>"`), leaving zero temporary files on the NAS.
- Monitoring Targets:
  - `/etc/nginx`, `/usr/syno/share/nginx` (Nginx configuration and templates)
  - `/usr/syno/synoman`, `/var/tmp/nginx/html` (DSM administration desktop web roots)
  - `/volume1/web` (User website directories)
  - `/bin`, `/usr/bin`, `/usr/sbin`, `/usr/syno/bin`, `/usr/syno/sbin` (Critical system binaries)
  - `/etc/sysctl.d`, `/usr/syno/etc/firewall.d`, `/etc/ssh` (Security configurations)
  - `/volume1/public`, `/volume1/tmp` (Sensitive shared and temporary directories)

### 2.3 DSM Rootkit Detection Engine (6 Core Checks)
1. **Critical Binary Integrity**: Computes SHA-256 for `/bin/ps`, `/bin/ls`, `/bin/netstat`, `/usr/bin/sudo`, etc., with symlink resolution.
2. **`LD_PRELOAD` Linker Hijacking**: Audits `/etc/ld.so.preload` and inspects `/proc/<pid>/environ` across all processes.
3. **Hidden / Fileless Processes**: Cross-references `/proc` PIDs against `ps -eo pid`, flagging deleted binary executions and binaries launched from `/dev/shm` or `/tmp`.
4. **Promiscuous Interface Detection**: Inspects `/sys/class/net/*/flags` for unauthorized packet sniffing (`IFF_PROMISC` `0x100`).
5. **LKM Kernel Module Baseline**: Compares active `/proc/modules` against the authorized module whitelist.
6. **Rootkit Backdoor Artifacts**: Scans for known rootkit signatures and verifies unexpected ELF executables in `/dev/shm`, `/tmp`, and `/var/tmp`.

### 2.4 Real-Time inotify Stream Engine (`nas-sentinel/inotify_stream_remote.py`)
- Direct invocation of Linux kernel `libc.so.6` inotify syscalls (`inotify_init1`, `inotify_add_watch`, `read`) via Python `ctypes`.
- Monitors hundreds of system and web directories (exact watch set is DSM/baseline-dependent). Supports single-file parent directory filtering to maintain watch handles even during atomic text editor replacements (`vim`, `sed -i`).
- Computes SHA-256 hashes and evaluates sliding-window Webshell heuristic patterns upon write completion (`IN_CLOSE_WRITE`), streaming NDJSON lines back to the controller.

### 2.5 Cloudflare Edge Threat Intelligence Engine (`nas-sentinel/cloudflare_intel.py`)
- Queries Cloudflare GraphQL Analytics API (`firewallEventsAdaptive`).
- Pulls edge WAF blocks, suspicious bot crawls, and path scans (e.g., `/.env`, `wp-login.php`, `phpmyadmin`, `/.git`) without touching NAS disk I/O.
- Categorizes threat activities automatically and alerts in the dashboard.

---

## 3. Directory Structure

```
nas-sentinel-repo/
├── start-nas-sentinel.bat       # Windows startup script
├── README.md                    # Project README (English)
├── README.zh-TW.md              # Project README (Traditional Chinese)
│
├── nas-sentinel/                # [Core Application Directory]
│   ├── server.py                # Local server, state engine & REST API
│   ├── collector_remote.py      # Remote read-only telemetry & FIM collector
│   ├── inotify_stream_remote.py # Remote real-time inotify stream engine
│   ├── cloudflare_intel.py      # Cloudflare GraphQL edge intel client
│   ├── static/                  # Web Frontend
│   │   ├── index.html           # Cyber SOC Dashboard
│   │   ├── app.js               # Frontend controller & polling logic
│   │   ├── logo_v2.png          # High-resolution Logo
│   │   └── favicon.png          # Favicon
│   └── data/                    # Storage and Baseline Files
│       ├── config.example.json  # Configuration template
│       ├── fim_baseline.json    # FIM golden baseline (DSM-dependent size)
│       ├── port_baseline.json   # Network listening ports baseline
│       ├── http_baseline.json   # Web endpoints baseline
│       └── lkm_baseline.json    # Kernel modules baseline
│
└── docs/                        # [Documentation]
    ├── ARCHITECTURE.md          # Architecture specification (English)
    ├── ARCHITECTURE.zh-TW.md    # Architecture specification (Traditional Chinese)
    ├── USER_GUIDE.md            # Feature & operations guide (English)
    └── USER_GUIDE.zh-TW.md      # Feature & operations guide (Traditional Chinese)
```

---

## 4. Operation & Maintenance

- **Start**: Double-click `start-nas-sentinel.bat` to launch in the background. The browser opens `http://127.0.0.1:8088`.
- **Rebuild Baseline**: When DSM is legitimately upgraded or web configurations are intentionally altered, navigate to **Admin ➔ Rebuild Baseline** or send `POST /api/baseline/reset` to capture a new golden reference.
