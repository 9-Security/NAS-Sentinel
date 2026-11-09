#!/usr/bin/env python3
"""
Remote read-only collector executed on Synology NAS over SSH stdin:
    ssh shar@10.253.2.126 "python3 - fast" < collector_remote.py
    ssh shar@10.253.2.126 "python3 - deep" < collector_remote.py

Zero footprint on NAS: writes no files, modifies no state, outputs JSON to stdout.
Includes Web Server FIM, Network/Port Matrix, and DSM Rootkit Scanner (chkrootkit + rkhunter checks).
"""
import grp
import hashlib
import ipaddress
import json
import os
import pwd
import re
import socket
import stat
import struct
import subprocess
import sys
import time

MODE = sys.argv[1] if len(sys.argv) > 1 else "fast"

KNOWN_DSM_SPECIAL_FILES = {
    "/usr/syno/synoman/webapi/otp.cgi",
    "/usr/syno/synoman/scripts/uistrings.php",
    "/usr/syno/synoman/webman/modules/Indexer/indexer.php",
}

FAST_SYNOMAN_EXTS = {
    ".cgi", ".html", ".htm", ".js", ".php", ".sh", ".py", ".pl",
    ".conf", ".mustache", ".json", ".css"
}

SUSPICIOUS_EXTS = {".php", ".phtml", ".php5", ".sh", ".pl", ".py", ".elf", ".jsp", ".asp", ".aspx"}
SCRIPT_SCAN_EXTS = SUSPICIOUS_EXTS | {".cgi", ".js", ".html", ".htm"}

CRITICAL_SYSTEM_BINARIES = [
    "/bin/sh",
    "/bin/bash",
    "/bin/ps",
    "/bin/ls",
    "/bin/netstat",
    "/bin/login",
    "/bin/kmod",
    "/usr/bin/sshd",
    "/usr/bin/sudo",
    "/usr/bin/nginx",
    "/usr/bin/find",
    "/usr/bin/top",
    "/usr/bin/kill",
    "/usr/bin/sha256sum",
    "/usr/sbin/ip",
    "/usr/sbin/lsmod",
    "/usr/sbin/tcpdump",
    "/usr/sbin/aa-status",
    "/usr/syno/bin/synowebapi",
    "/usr/syno/sbin/synotifyd",
]

# Known benign DSM hidden files in /tmp and /var/tmp
KNOWN_TMP_DOTFILES = {
    ".sess.timeout.check",
    ".scemd_ready",
    ".not.dualhead",
    ".syno_dbus_session_address",
    ".bash_history",
    ".ICE-unix",
    ".X11-unix",
}

# Known Rootkit & Backdoor file/dir signatures (rkhunter & chkrootkit database subset)
KNOWN_ROOTKIT_PATHS = [
    "/etc/ld.so.preload",
    "/dev/.udev",
    "/dev/.initramfs",
    "/dev/.lib",
    "/dev/shm/.x",
    "/dev/shm/.ice",
    "/tmp/.X11-unix/.x",
    "/tmp/.font-unix/.x",
    "/usr/lib/libproc.a",
    "/lib/libproc.so",
    "/usr/lib/libkeyutils.so.1.9",
    "/lib64/libkeyutils.so.1.9",
    "/etc/rc.d/init.d/network.bak",
    "/usr/bin/xsf",
    "/usr/bin/xchk",
    "/sbin/ttymon",
    "/sbin/ttyload",
]

SUSPICIOUS_LKM_NAMES = {
    "diamorphine", "reptile", "suterusu", "enyelkm", "kisni",
    "azazel", "jynx", "vlany", "bdvl", "rootkit", "hide", "backdoor"
}

FIM_TARGETS = [
    {
        "id": "nginx_etc",
        "label": "Nginx 伺服器設定 (/etc/nginx)",
        "path": "/etc/nginx",
        "max_depth": 4,
        "category": "web_config",
    },
    {
        "id": "nginx_share",
        "label": "Nginx 樣板與錯誤頁 (/usr/syno/share/nginx)",
        "path": "/usr/syno/share/nginx",
        "max_depth": 4,
        "category": "web_config",
    },
    {
        "id": "nginx_tmp_html",
        "label": "HTTP 入口導向頁 (/var/tmp/nginx/html)",
        "path": "/var/tmp/nginx/html",
        "max_depth": 3,
        "category": "web_root",
    },
    {
        "id": "dsm_synoman",
        "label": "DSM 網頁管理系統 (/usr/syno/synoman)",
        "path": "/usr/syno/synoman",
        "max_depth": 4 if MODE == "deep" else 3,
        "category": "web_root",
        "fast_exts": FAST_SYNOMAN_EXTS,
    },
    {
        "id": "letsencrypt_root",
        "label": "Let's Encrypt 驗證目錄 (/var/lib/letsencrypt)",
        "path": "/var/lib/letsencrypt",
        "max_depth": 3,
        "category": "web_root",
    },
    {
        "id": "web_station",
        "label": "自架網站目錄 (/volume1/web)",
        "path": "/volume1/web",
        "max_depth": 4,
        "category": "user_web",
    },
    {
        "id": "security_configs",
        "label": "系統安全與防火牆設定 (/etc/sysctl.d, firewall.d, ssh)",
        "paths": [
            "/etc/sysctl.d",
            "/usr/syno/etc/firewall.d",
            "/etc/ssh/sshd_config",
            "/etc/crontab",
            "/etc/chrony.conf.user",
            "/etc/ld.so.conf",
            "/var/services/homes/shar/.ssh/authorized_keys",
        ],
        "max_depth": 2,
        "category": "security_config",
    },
    {
        "id": "system_binaries",
        "label": "核心系統指令防木馬基線 (rkhunter Binary Check)",
        "paths": CRITICAL_SYSTEM_BINARIES,
        "max_depth": 1,
        "category": "system_binary",
    },
    {
        "id": "shared_watched",
        "label": "共享與暫存敏感區 (/volume1/public, /volume1/tmp)",
        "paths": [
            "/volume1/public",
            "/volume1/tmp",
        ],
        "max_depth": 2,
        "category": "shared_watch",
    },
]

WEBSHELL_PATTERNS = re.compile(
    rb"(eval\s*\(\s*(base64_decode|gzinflate|str_rot13|\$_POST|\$_GET|\$_REQUEST)"
    rb"|shell_exec\s*\(|passthru\s*\(|system\s*\(\s*\$_(POST|GET|REQUEST)"
    rb"|/dev/tcp/[0-9]+\.[0-9]+|nc\s+-e\s+/bin/(sh|bash)|bash\s+-i\s+>&)",
    re.IGNORECASE,
)


def run_cmd(args, timeout=8):
    try:
        p = subprocess.run(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return p.stdout
    except Exception as e:
        return f"ERROR: {e}"


def get_owner_name(uid, gid):
    try:
        u = pwd.getpwuid(uid).pw_name
    except KeyError:
        u = str(uid)
    try:
        g = grp.getgrgid(gid).gr_name
    except KeyError:
        g = str(gid)
    return f"{u}:{g}"


def collect_system_metrics():
    def read_cpu():
        with open("/proc/stat", "r") as f:
            line = f.readline()
        parts = [int(x) for x in line.split()[1:]]
        idle = parts[3] + (parts[4] if len(parts) > 4 else 0)
        total = sum(parts)
        return idle, total

    idle1, total1 = read_cpu()
    time.sleep(0.18)
    idle2, total2 = read_cpu()
    dt = max(1, total2 - total1)
    cpu_pct = round(100.0 * (1.0 - (idle2 - idle1) / dt), 1)

    with open("/proc/loadavg", "r") as f:
        la = f.read().split()
    with open("/proc/uptime", "r") as f:
        uptime_sec = float(f.read().split()[0])

    mem = {}
    with open("/proc/meminfo", "r") as f:
        for line in f:
            if ":" in line:
                k, v = line.split(":", 1)
                mem[k.strip()] = int(v.strip().split()[0]) * 1024

    mem_total = mem.get("MemTotal", 1)
    mem_avail = mem.get("MemAvailable", mem.get("MemFree", 0) + mem.get("Cached", 0))
    mem_used = max(0, mem_total - mem_avail)
    swap_total = mem.get("SwapTotal", 0)
    swap_free = mem.get("SwapFree", 0)
    swap_used = max(0, swap_total - swap_free)

    temp_c = None
    for tpath in ("/sys/class/thermal/thermal_zone0/temp", "/sys/class/hwmon/hwmon0/temp1_input"):
        if os.path.exists(tpath):
            try:
                with open(tpath, "r") as f:
                    raw = int(f.read().strip())
                temp_c = round(raw / 1000.0 if raw > 200 else float(raw), 1)
                break
            except Exception:
                pass

    disks = []
    for mount, label in (("/", "系統分割區 (/)"), ("/volume1", "資料儲存空間 (/volume1)")):
        if os.path.exists(mount):
            try:
                st = os.statvfs(mount)
                total_b = st.f_blocks * st.f_frsize
                avail_b = st.f_bavail * st.f_frsize
                used_b = total_b - (st.f_bfree * st.f_frsize)
                pct = round((used_b / total_b) * 100.0, 1) if total_b else 0.0
                disks.append({
                    "mount": mount,
                    "label": label,
                    "total_gb": round(total_b / (1024 ** 3), 2),
                    "used_gb": round(used_b / (1024 ** 3), 2),
                    "avail_gb": round(avail_b / (1024 ** 3), 2),
                    "percent": pct,
                })
            except Exception:
                pass

    version_info = {}
    if os.path.exists("/etc.defaults/VERSION"):
        with open("/etc.defaults/VERSION", "r") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    version_info[k] = v.strip('"')

    return {
        "hostname": socket.gethostname(),
        "kernel": os.uname().release,
        "arch": os.uname().machine,
        "dsm_version": f"DSM {version_info.get('productversion', '')}-{version_info.get('buildnumber', '')} Update {version_info.get('smallfixnumber', '')}".strip(),
        "uptime_seconds": int(uptime_sec),
        "cpu_percent": cpu_pct,
        "load_1m": float(la[0]),
        "load_5m": float(la[1]),
        "load_15m": float(la[2]),
        "mem_total_mb": round(mem_total / (1024 ** 2), 1),
        "mem_used_mb": round(mem_used / (1024 ** 2), 1),
        "mem_percent": round((mem_used / mem_total) * 100.0, 1) if mem_total else 0.0,
        "swap_total_mb": round(swap_total / (1024 ** 2), 1),
        "swap_used_mb": round(swap_used / (1024 ** 2), 1),
        "swap_percent": round((swap_used / swap_total) * 100.0, 1) if swap_total else 0.0,
        "temp_c": temp_c,
        "disks": disks,
    }


def scan_file_entry(fpath, category, target_id):
    try:
        st = os.lstat(fpath)
    except OSError:
        return None

    is_link = stat.S_ISLNK(st.st_mode)
    is_reg = stat.S_ISREG(st.st_mode)
    if not (is_reg or is_link):
        return None

    mode_oct = oct(stat.S_IMODE(st.st_mode))[2:].zfill(4)
    owner = get_owner_name(st.st_uid, st.st_gid)
    ext = os.path.splitext(fpath)[1].lower()

    sha256_hex = None
    hash_type = "sha256"
    suspicious_reasons = []

    if is_link:
        try:
            target = os.readlink(fpath)
            link_str = f"SYMLINK->{target}"
            if category == "system_binary" and os.path.isfile(fpath):
                h_tgt = hashlib.sha256()
                with open(fpath, "rb") as tf:
                    while True:
                        chunk = tf.read(65536)
                        if not chunk:
                            break
                        h_tgt.update(chunk)
                link_str += f"|TARGET_SHA256->{h_tgt.hexdigest()}"
            sha256_hex = hashlib.sha256(link_str.encode("utf-8", "replace")).hexdigest()
            hash_type = "symlink"
        except OSError:
            sha256_hex = f"META:{st.st_size}:{st.st_mtime_ns}:{mode_oct}:{owner}"
            hash_type = "metadata"
    elif is_reg:
        if (st.st_mode & stat.S_IWOTH) and category in ("web_root", "web_config", "user_web", "security_config", "system_binary"):
            suspicious_reasons.append("檔案權限含全員可寫入 (World-Writable)")
        if (st.st_mode & stat.S_ISUID) and category in ("web_root", "user_web", "shared_watch"):
            if fpath not in KNOWN_DSM_SPECIAL_FILES:
                suspicious_reasons.append("發現非預期 SUID 權限檔案")
        if category in ("web_root", "web_config") and ext in {".php", ".phtml", ".php5", ".jsp", ".asp", ".aspx"}:
            if fpath not in KNOWN_DSM_SPECIAL_FILES:
                suspicious_reasons.append(f"DSM 系統網頁目錄出現非預期腳本檔 ({ext})")

        if st.st_size <= 15 * 1024 * 1024:
            try:
                h = hashlib.sha256()
                check_sig = ext in SCRIPT_SCAN_EXTS
                matched_sig = False
                tail = b""
                with open(fpath, "rb") as f:
                    while True:
                        chunk = f.read(65536)
                        if not chunk:
                            break
                        h.update(chunk)
                        if check_sig and not matched_sig:
                            window = tail + chunk
                            if WEBSHELL_PATTERNS.search(window):
                                matched_sig = True
                            tail = chunk[-256:]
                sha256_hex = h.hexdigest()
                if matched_sig:
                    suspicious_reasons.append("檔案內容命中高風險 Webshell/遠端執行特徵")
            except (PermissionError, OSError):
                meta_str = f"META:size={st.st_size}:mtime={st.st_mtime_ns}:ctime={st.st_ctime_ns}:ino={st.st_ino}:mode={mode_oct}:owner={owner}"
                sha256_hex = hashlib.sha256(meta_str.encode()).hexdigest()
                hash_type = "meta_protected"
        else:
            meta_str = f"LARGE:size={st.st_size}:mtime={st.st_mtime_ns}:ctime={st.st_ctime_ns}:ino={st.st_ino}:mode={mode_oct}:owner={owner}"
            sha256_hex = hashlib.sha256(meta_str.encode()).hexdigest()
            hash_type = "meta_large"

    return {
        "path": fpath,
        "target_id": target_id,
        "category": category,
        "size": st.st_size,
        "mtime": int(st.st_mtime),
        "ctime": int(st.st_ctime),
        "mode": mode_oct,
        "owner": owner,
        "hash": sha256_hex,
        "hash_type": hash_type,
        "suspicious": suspicious_reasons,
    }


def walk_target(base_path, max_depth, category, target_id, fast_exts=None):
    results = {}
    if not os.path.exists(base_path):
        return results

    if os.path.isfile(base_path) or os.path.islink(base_path):
        entry = scan_file_entry(base_path, category, target_id)
        if entry:
            results[base_path] = entry
        return results

    base_path = base_path.rstrip("/")

    def _recurse(curr_dir, depth):
        if depth > max_depth:
            return
        try:
            with os.scandir(curr_dir) as it:
                for de in it:
                    if de.name in (".", "..", "@eaDir", "#recycle", "@tmp"):
                        continue
                    full = de.path
                    try:
                        if de.is_symlink():
                            entry = scan_file_entry(full, category, target_id)
                            if entry:
                                results[full] = entry
                        elif de.is_dir(follow_symlinks=False):
                            _recurse(full, depth + 1)
                        elif de.is_file(follow_symlinks=False):
                            if fast_exts is not None and depth >= 2:
                                ext = os.path.splitext(de.name)[1].lower()
                                if ext not in fast_exts and ext not in SUSPICIOUS_EXTS:
                                    continue
                            entry = scan_file_entry(full, category, target_id)
                            if entry:
                                results[full] = entry
                    except OSError:
                        continue
        except (PermissionError, OSError):
            return

    _recurse(base_path, 1)
    return results


def collect_fim():
    t0 = time.time()
    all_files = {}
    target_summaries = []

    for tgt in FIM_TARGETS:
        tid = tgt["id"]
        cat = tgt["category"]
        max_depth = tgt.get("max_depth", 3)
        fast_exts = tgt.get("fast_exts") if MODE == "fast" else None
        paths = tgt.get("paths") or [tgt["path"]]

        group_files = {}
        exists_any = False
        for p in paths:
            if os.path.exists(p):
                exists_any = True
                group_files.update(walk_target(p, max_depth, cat, tid, fast_exts))

        all_files.update(group_files)
        susp_count = sum(1 for v in group_files.values() if v.get("suspicious"))
        target_summaries.append({
            "id": tid,
            "label": tgt["label"],
            "paths": paths if len(paths) <= 4 else paths[:3] + [f"...共 {len(paths)} 個系統執行檔"],
            "category": cat,
            "exists": exists_any,
            "file_count": len(group_files),
            "suspicious_count": susp_count,
        })

    return {
        "scan_mode": MODE,
        "duration_ms": int((time.time() - t0) * 1000),
        "total_files": len(all_files),
        "targets": target_summaries,
        "files": all_files,
    }


def collect_rootkit_checks():
    """
    DSM-tailored Rootkit & Trojan scanner implementing core chkrootkit + rkhunter checks
    without requiring gcc/strings or modifying the root partition.
    """
    t0 = time.time()

    # 1. LD_PRELOAD & Dynamic Linker Hijack Check
    ld_preload_anomalies = []
    if os.path.exists("/etc/ld.so.preload"):
        try:
            with open("/etc/ld.so.preload", "r", errors="replace") as f:
                content = f.read().strip()
            ld_preload_anomalies.append(f"發現 /etc/ld.so.preload 檔案 (內容: {content[:80] or '空白'})")
        except OSError:
            ld_preload_anomalies.append("發現 /etc/ld.so.preload 檔案 (無讀取權限)")

    # Scan readable /proc/<pid>/environ for exact LD_PRELOAD variable injection
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        env_path = f"/proc/{entry}/environ"
        try:
            with open(env_path, "rb") as f:
                raw_env = f.read(16384)
            for kv in raw_env.split(b"\x00"):
                if kv.startswith(b"LD_PRELOAD="):
                    val = kv[11:].decode("utf-8", "replace")[:60]
                    ld_preload_anomalies.append(f"PID {entry} 環境變數含 LD_PRELOAD={val}")
                    break
        except OSError:
            continue

    # 2. Hidden Processes & Deleted Running Executables Check (chkrootkit chkproc)
    proc_before = {int(x) for x in os.listdir("/proc") if x.isdigit()}
    ps_raw = run_cmd(["ps", "-eo", "pid"])
    ps_pids = {int(x.strip()) for x in ps_raw.splitlines()[1:] if x.strip().isdigit()}
    proc_after = {int(x) for x in os.listdir("/proc") if x.isdigit()}
    persistent_pids = proc_before & proc_after
    hidden_pids = sorted(list(persistent_pids - ps_pids))

    deleted_exes = []
    for pid in persistent_pids:
        try:
            exe_target = os.readlink(f"/proc/{pid}/exe")
            if "(deleted)" in exe_target or exe_target.startswith(("/dev/shm/", "/tmp/")):
                deleted_exes.append({"pid": pid, "exe": exe_target})
        except OSError:
            continue

    # 3. Network Interface Promiscuous Mode Check (chkrootkit ifpromisc)
    ifaces = []
    promisc_ifaces = []
    if os.path.isdir("/sys/class/net"):
        for netif in sorted(os.listdir("/sys/class/net")):
            try:
                with open(f"/sys/class/net/{netif}/flags", "r") as f:
                    fl = int(f.read().strip(), 16)
                is_promisc = bool(fl & 0x100)
                ifaces.append({"name": netif, "flags_hex": f"0x{fl:x}", "promisc": is_promisc})
                if is_promisc:
                    promisc_ifaces.append(netif)
            except OSError:
                continue

    # 4. Loaded Kernel Modules (LKM Rootkit Check)
    loaded_modules = []
    suspicious_lkms = []
    if os.path.exists("/proc/modules"):
        try:
            with open("/proc/modules", "r") as f:
                for line in f:
                    parts = line.split()
                    if parts:
                        mname = parts[0]
                        loaded_modules.append(mname)
                        if any(bad in mname.lower() for bad in SUSPICIOUS_LKM_NAMES):
                            suspicious_lkms.append(mname)
        except OSError:
            pass

    # 5. Hidden Dotfiles & ELF Executables in /dev/shm, /tmp, /var/tmp
    unexpected_tmp_files = []
    for tmp_dir in ("/dev/shm", "/tmp", "/var/tmp"):
        if not os.path.isdir(tmp_dir):
            continue
        try:
            for fname in os.listdir(tmp_dir):
                full_p = os.path.join(tmp_dir, fname)
                if fname.startswith(".") and fname not in KNOWN_TMP_DOTFILES:
                    unexpected_tmp_files.append(full_p)
                    continue
                try:
                    st_tmp = os.lstat(full_p)
                except OSError:
                    continue
                if tmp_dir == "/dev/shm":
                    is_known_shm = (fname == "nginx_mod" or fname.startswith("PostgreSQL."))
                    is_exec = bool(st_tmp.st_mode & 0o111)
                    if not is_known_shm or is_exec:
                        unexpected_tmp_files.append(full_p)
                        continue
                if stat.S_ISREG(st_tmp.st_mode) and st_tmp.st_size >= 4:
                    try:
                        with open(full_p, "rb") as tf:
                            magic = tf.read(4)
                        if magic == b"\x7fELF":
                            unexpected_tmp_files.append(f"{full_p} (ELF 可執行檔)")
                    except OSError:
                        pass
        except OSError:
            continue

    # 6. Known Rootkit & Backdoor File Signatures (rkhunter / chkrootkit database)
    matched_rootkit_paths = [p for p in KNOWN_ROOTKIT_PATHS if os.path.exists(p)]

    return {
        "duration_ms": int((time.time() - t0) * 1000),
        "ld_preload_anomalies": ld_preload_anomalies,
        "hidden_pids": hidden_pids,
        "deleted_running_exes": deleted_exes,
        "interfaces": ifaces,
        "promisc_interfaces": promisc_ifaces,
        "loaded_modules": sorted(loaded_modules),
        "suspicious_lkms": suspicious_lkms,
        "unexpected_tmp_files": unexpected_tmp_files,
        "matched_rootkit_paths": matched_rootkit_paths,
        "critical_binaries_count": sum(1 for b in CRITICAL_SYSTEM_BINARIES if os.path.exists(b)),
    }


def classify_ip_scope(ip_str):
    clean = ip_str.strip("[]")
    if clean.startswith("::ffff:"):
        clean = clean[7:]
    try:
        addr = ipaddress.ip_address(clean)
        if addr.is_loopback:
            return "loopback"
        if addr.is_private or addr.is_link_local:
            return "lan"
        return "external"
    except ValueError:
        if clean.startswith("127.") or clean == "::1":
            return "loopback"
        if clean.startswith(("10.", "192.168.", "172.")):
            return "lan"
        return "external"


def collect_network():
    raw_listen = run_cmd(["netstat", "-lnptu"])
    listeners = []
    seen = set()
    for line in raw_listen.splitlines():
        parts = line.split()
        if len(parts) < 4 or not parts[0].startswith(("tcp", "udp")):
            continue
        proto = parts[0]
        local_addr = parts[3]
        state = parts[5] if proto.startswith("tcp") and len(parts) >= 6 else "LISTEN"
        proc_col = parts[-1] if "/" in parts[-1] or parts[-1] == "-" else ""
        if ":" in local_addr:
            bind_ip, port_s = local_addr.rsplit(":", 1)
        else:
            continue
        try:
            port = int(port_s)
        except ValueError:
            continue
        key = (proto, bind_ip, port)
        if key in seen:
            continue
        seen.add(key)
        listeners.append({
            "proto": proto,
            "bind": bind_ip,
            "port": port,
            "state": state,
            "process": proc_col if proc_col != "-" else "",
        })

    listeners.sort(key=lambda x: (x["port"], x["proto"], x["bind"]))

    raw_conn = run_cmd(["netstat", "-nptu"])
    connections = []
    for line in raw_conn.splitlines():
        parts = line.split()
        if len(parts) < 6 or not parts[0].startswith(("tcp", "udp")):
            continue
        proto = parts[0]
        local_addr = parts[3]
        rem_addr = parts[4]
        state = parts[5] if proto.startswith("tcp") else "ACTIVE"
        proc = parts[6] if len(parts) > 6 else ""
        if ":" not in local_addr or ":" not in rem_addr:
            continue
        lip, lport = local_addr.rsplit(":", 1)
        rip, rport = rem_addr.rsplit(":", 1)
        if rip in ("0.0.0.0", "::", "*"):
            continue

        scope = classify_ip_scope(rip)

        connections.append({
            "proto": proto,
            "local_ip": lip,
            "local_port": int(lport) if lport.isdigit() else lport,
            "remote_ip": rip,
            "remote_port": int(rport) if rport.isdigit() else rport,
            "state": state,
            "process": proc if proc != "-" else "",
            "scope": scope,
        })

    return {
        "listeners": listeners,
        "connections": connections,
    }


def collect_services_and_security():
    ps_out = run_cmd(["ps", "-eo", "pid,user,comm,args"])
    procs = []
    for line in ps_out.splitlines()[1:]:
        parts = line.strip().split(None, 3)
        if len(parts) >= 3:
            procs.append({
                "pid": int(parts[0]) if parts[0].isdigit() else 0,
                "user": parts[1],
                "comm": parts[2],
                "args": parts[3] if len(parts) > 3 else parts[2],
            })

    watched_daemons = [
        ("nginx", "Nginx 網頁與反向代理伺服器", True),
        ("sshd", "OpenSSH 遠端管理服務", True),
        ("cloudflared", "Cloudflare Tunnel 服務", True),
        ("scemd", "Synology 硬體與溫控核心服務 (scemd)", True),
        ("postgres", "PostgreSQL 系統資料庫", True),
        ("syslog-ng", "系統日誌服務 (syslog-ng)", True),
        ("chronyd", "NTP 時間同步服務 (chronyd)", True),
        ("nfsd", "NFS 檔案服務", False),
        ("named", "DNS Server (named)", False),
    ]

    services = []
    for comm_key, label, critical in watched_daemons:
        matched = []
        for p in procs:
            c = p["comm"].strip("[]")
            exe_base = os.path.basename(p["args"].split()[0].rstrip(":")) if p["args"] else ""
            if c == comm_key or exe_base == comm_key or p["args"].startswith(f"{comm_key}:"):
                matched.append(p)
        services.append({
            "name": comm_key,
            "label": label,
            "critical": critical,
            "running": len(matched) > 0,
            "process_count": len(matched),
            "users": sorted(list({p["user"] for p in matched})),
            "pids": [p["pid"] for p in matched[:6]],
        })

    suspicious_procs = []
    for p in procs:
        args = p["args"]
        if any(bad in args for bad in ("/dev/shm/", "/tmp/.", "nc -e", "curl http", "wget http", "base64 -d")):
            suspicious_procs.append(p)

    def read_proc_sys(rel_path):
        full = "/proc/sys/" + rel_path.replace(".", "/")
        try:
            with open(full, "r") as f:
                return f.read().strip()
        except Exception:
            return None

    sysctls = {
        "kernel.kptr_restrict": read_proc_sys("kernel.kptr_restrict"),
        "kernel.dmesg_restrict": read_proc_sys("kernel.dmesg_restrict"),
        "kernel.randomize_va_space": read_proc_sys("kernel.randomize_va_space"),
        "net.ipv4.tcp_syncookies": read_proc_sys("net.ipv4.tcp_syncookies"),
        "net.ipv4.conf.all.accept_source_route": read_proc_sys("net.ipv4.conf.all.accept_source_route"),
        "net.ipv4.conf.eth0.accept_source_route": read_proc_sys("net.ipv4.conf.eth0.accept_source_route"),
        "net.ipv6.conf.lo.disable_ipv6": read_proc_sys("net.ipv6.conf.lo.disable_ipv6"),
    }

    fw_info = {"enabled": False, "profile": None, "rules_count": 0}
    try:
        with open("/usr/syno/etc/firewall.d/firewall_settings.json", "r") as f:
            fw_set = json.load(f)
        fw_info["enabled"] = bool(fw_set.get("status"))
        fw_info["profile"] = fw_set.get("profile")
        for fn in ("1.json", "2.json"):
            p = f"/usr/syno/etc/firewall.d/{fn}"
            if os.path.exists(p):
                with open(p, "r") as pf:
                    pdata = json.load(pf)
                if pdata.get("name") == fw_info["profile"]:
                    rules = pdata.get("rules")
                    fw_info["rules_count"] = len(rules) if isinstance(rules, list) else 0
    except Exception:
        pass

    ak_path = "/var/services/homes/shar/.ssh/authorized_keys"
    ssh_keys = []
    if os.path.exists(ak_path):
        try:
            with open(ak_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        comment = parts[2] if len(parts) > 2 else "no-comment"
                        ktype = parts[0]
                        key_fp = hashlib.sha256(line.encode()).hexdigest()[:16]
                        ssh_keys.append({"type": ktype, "comment": comment, "id": key_fp})
        except Exception:
            pass

    sessions = []
    if os.path.exists("/var/run/utmp"):
        try:
            with open("/var/run/utmp", "rb") as f:
                data = f.read()
            rec_size = 384
            for offset in range(0, len(data) - rec_size + 1, rec_size):
                rec = data[offset:offset + rec_size]
                ut_type = struct.unpack("<h", rec[0:2])[0]
                if ut_type == 7:
                    line_s = rec[8:40].split(b"\x00", 1)[0].decode("utf-8", "replace")
                    user_s = rec[44:76].split(b"\x00", 1)[0].decode("utf-8", "replace")
                    host_s = rec[76:332].split(b"\x00", 1)[0].decode("utf-8", "replace")
                    tv_sec = struct.unpack("<i", rec[340:344])[0]
                    if user_s:
                        sessions.append({
                            "user": user_s,
                            "tty": line_s,
                            "host": host_s,
                            "login_ts": tv_sec,
                        })
        except Exception:
            pass

    return {
        "services": services,
        "suspicious_processes": suspicious_procs,
        "sysctls": sysctls,
        "firewall": fw_info,
        "ssh_keys": ssh_keys,
        "active_sessions": sessions,
    }


def main():
    t_start = time.time()
    payload = {
        "timestamp": int(t_start),
        "iso_time": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(t_start)),
        "system": collect_system_metrics(),
        "network": collect_network(),
        "security": collect_services_and_security(),
        "rootkit": collect_rootkit_checks(),
        "fim": collect_fim(),
    }
    payload["total_elapsed_ms"] = int((time.time() - t_start) * 1000)
    sys.stdout.write(json.dumps(payload, ensure_ascii=False))


if __name__ == "__main__":
    main()
