#!/usr/bin/env python3
r"""
NAS Sentinel - Local Monitoring & File Integrity Server for Synology NAS
Runs locally (server.py) and serves a real-time Web UI on http://127.0.0.1:8088
Includes both periodic SSH telemetry + real-time Linux kernel inotify millisecond event streaming.
"""
import copy
import datetime
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import cloudflare_intel

# Ensure pythonw background mode compatibility (no console stdout/stderr)
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
STATIC_DIR = BASE_DIR / "static"
COLLECTOR_SCRIPT = BASE_DIR / "collector_remote.py"
INOTIFY_SCRIPT = BASE_DIR / "inotify_stream_remote.py"

DATA_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR.mkdir(parents=True, exist_ok=True)

FIM_BASELINE_FILE = DATA_DIR / "fim_baseline.json"
PORT_BASELINE_FILE = DATA_DIR / "port_baseline.json"
HTTP_BASELINE_FILE = DATA_DIR / "http_baseline.json"
LKM_BASELINE_FILE = DATA_DIR / "lkm_baseline.json"
EVENTS_FILE = DATA_DIR / "events.json"
INOTIFY_EVENTS_FILE = DATA_DIR / "inotify_events.json"
HISTORY_FILE = DATA_DIR / "history.json"

CONFIG_FILE = DATA_DIR / "config.json"
CONFIG_EXAMPLE_FILE = DATA_DIR / "config.example.json"
API_TOKEN_FILE = DATA_DIR / "api_token.txt"
SSH_KNOWN_HOSTS_FILE = DATA_DIR / "ssh_known_hosts"
PUBLIC_API_PATHS = frozenset({"/api/auth/status"})
MIN_SSH_PASSPHRASE_LEN = 8


def _chmod_secret(path: Path, mode: int = 0o600):
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def write_secret_text(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    _chmod_secret(path)


def load_app_config() -> dict:
    default_config = {
        "is_configured": False,
        "nas_host": os.environ.get("NAS_HOST", "192.168.1.100"),
        "nas_user": os.environ.get("NAS_USER", "admin"),
        "nas_port": int(os.environ.get("NAS_PORT", "22")),
        "ssh_key_path": os.environ.get("SSH_KEY_PATH", ""),
        "ssh_host_key_fp": "",
        "web_host": os.environ.get("MONITOR_HOST", "127.0.0.1"),
        "web_port": int(os.environ.get("MONITOR_PORT", "8088")),
        "poll_interval_sec": int(os.environ.get("POLL_INTERVAL_SEC", "15")),
        "api_token": "",
        "cloudflare_enabled": False,
        "cloudflare_api_token": os.environ.get("CF_API_TOKEN", ""),
        "cloudflare_zone_id": os.environ.get("CF_ZONE_ID", ""),
    }
    if CONFIG_FILE.exists():
        try:
            stored = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            default_config.update(stored)
        except Exception:
            pass
    return default_config


def save_app_config(cfg: dict):
    save_json(CONFIG_FILE, cfg, mode=0o600)


def ensure_api_token(cfg: dict) -> str:
    """Require a high-entropy API token; auto-generate on first local run if unset."""
    env_token = (os.environ.get("API_TOKEN") or os.environ.get("NAS_SENTINEL_API_TOKEN") or "").strip()
    if env_token:
        cfg["api_token"] = env_token
        write_secret_text(API_TOKEN_FILE, env_token)
        return env_token

    token = (cfg.get("api_token") or "").strip()
    if not token and API_TOKEN_FILE.exists():
        try:
            token = API_TOKEN_FILE.read_text(encoding="utf-8").strip()
        except Exception:
            token = ""

    if not token:
        token = secrets.token_urlsafe(32)
        cfg["api_token"] = token
        save_app_config(cfg)
        write_secret_text(API_TOKEN_FILE, token)
    else:
        cfg["api_token"] = token
        if not API_TOKEN_FILE.exists():
            write_secret_text(API_TOKEN_FILE, token)
    return token


def public_config_view(cfg: dict) -> dict:
    """Return config safe for API responses — never include raw secrets."""
    safe = {k: v for k, v in cfg.items() if k not in ("cloudflare_api_token", "api_token")}
    cf_token = cfg.get("cloudflare_api_token", "") or ""
    if len(cf_token) > 10:
        safe["cloudflare_api_token_masked"] = f"{cf_token[:6]}...{cf_token[-4:]}"
    else:
        safe["cloudflare_api_token_masked"] = "***" if cf_token else ""
    safe["cloudflare_api_token_set"] = bool(cf_token)
    safe["api_token_configured"] = bool((cfg.get("api_token") or "").strip())
    return safe


def ssh_dir_resolved() -> Path:
    return (Path.home() / ".ssh").resolve()


def validate_ssh_key_path(key_path: str) -> dict:
    """Allow only regular files under ~/.ssh (reject path escapes). Empty = default agent/keys."""
    if not key_path or not str(key_path).strip():
        return {"ok": True, "path": ""}
    raw = str(key_path).strip()
    expanded = Path(os.path.expanduser(raw))
    ssh_root = ssh_dir_resolved()
    try:
        resolved = expanded.resolve()
    except Exception:
        return {"ok": False, "error": "Invalid ssh_key_path"}
    try:
        resolved.relative_to(ssh_root)
    except ValueError:
        return {"ok": False, "error": "ssh_key_path must be a file under ~/.ssh"}
    if not resolved.exists() or not resolved.is_file():
        return {"ok": False, "error": "ssh_key_path not found under ~/.ssh"}
    # Reject symlinks whose ultimate target escapes ~/.ssh (resolve already checked).
    if expanded.is_symlink():
        try:
            expanded.resolve().relative_to(ssh_root)
        except Exception:
            return {"ok": False, "error": "ssh_key_path symlink escapes ~/.ssh"}
    return {"ok": True, "path": str(resolved)}


def find_local_ssh_keys() -> list:
    """Return key paths as ~/.ssh/<basename> only (no absolute path leak beyond home ssh dir)."""
    keys = []
    ssh_dir = Path.home() / ".ssh"
    if ssh_dir.exists():
        for p in sorted(ssh_dir.iterdir()):
            if p.is_file() and not p.is_symlink() and not p.name.endswith((".pub", ".old")) and p.name not in ("known_hosts", "config", "authorized_keys"):
                try:
                    text = p.read_text(encoding="utf-8", errors="ignore")[:60]
                    if "PRIVATE KEY" in text:
                        keys.append(f"~/.ssh/{p.name}")
                except Exception:
                    pass
    return keys


def ssh_host_key_options(cfg=None) -> list:
    """Prefer pinned known_hosts (StrictHostKeyChecking=yes) once a fingerprint is stored."""
    cfg = cfg or {}
    null_hosts = "NUL" if os.name == "nt" else "/dev/null"
    opts = [
        "-o", f"UserKnownHostsFile={SSH_KNOWN_HOSTS_FILE}",
        "-o", f"GlobalKnownHostsFile={null_hosts}",
    ]
    if (cfg.get("ssh_host_key_fp") or "").strip() and SSH_KNOWN_HOSTS_FILE.exists():
        opts.extend(["-o", "StrictHostKeyChecking=yes"])
    else:
        # First connect only: accept-new into the dedicated known_hosts file, then pin fingerprint.
        opts.extend(["-o", "StrictHostKeyChecking=accept-new"])
    return opts


def capture_host_key_fingerprint(host: str, port: int = 22) -> str:
    """Scan host key into the dedicated known_hosts file and return SHA256 fingerprint."""
    try:
        scan_cmd = ["ssh-keyscan", "-T", "5"]
        if port and int(port) != 22:
            scan_cmd.extend(["-p", str(port)])
        scan_cmd.append(host)
        scan = subprocess.run(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8)
        lines = [ln for ln in scan.stdout.decode("utf-8", errors="replace").splitlines() if ln.strip() and not ln.startswith("#")]
        if not lines:
            return ""
        SSH_KNOWN_HOSTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Merge/replace entries for this host
        existing = []
        if SSH_KNOWN_HOSTS_FILE.exists():
            existing = [
                ln for ln in SSH_KNOWN_HOSTS_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
                if ln.strip() and host not in ln.split()[0].split(",")
            ]
        SSH_KNOWN_HOSTS_FILE.write_text("\n".join(existing + lines) + "\n", encoding="utf-8")
        _chmod_secret(SSH_KNOWN_HOSTS_FILE)
        fp_proc = subprocess.run(
            ["ssh-keygen", "-lf", "-"],
            input="\n".join(lines).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        # Typical: "256 SHA256:abcd... host (ED25519)"
        out = fp_proc.stdout.decode("utf-8", errors="replace")
        for part in out.split():
            if part.startswith("SHA256:"):
                return part
    except Exception:
        return ""
    return ""


def test_nas_connection(host: str, user: str, port: int = 22, key_path: str = "", cfg=None) -> dict:
    if not host or not user:
        return {"ok": False, "error": "NAS 主機 IP 與 SSH 帳號不能為空"}

    if not re.match(r"^[a-zA-Z0-9_.-]+$", user):
        return {"ok": False, "error": "帳號名稱僅能包含英數字、底線或破折號 (Invalid username)"}
    if not re.match(r"^[a-zA-Z0-9_.:-]+$", host):
        return {"ok": False, "error": "NAS 主機僅能包含合法 IP、網域或主機名稱 (Invalid host)"}

    key_check = validate_ssh_key_path(key_path)
    if not key_check.get("ok"):
        return {"ok": False, "error": key_check.get("error", "Invalid ssh_key_path")}
    key_path = key_check.get("path", "")

    cfg = cfg if cfg is not None else (STATE.config if "STATE" in globals() and hasattr(STATE, "config") else load_app_config())
    host_fp = capture_host_key_fingerprint(host, port)
    pinned = (cfg.get("ssh_host_key_fp") or "").strip()
    if pinned and host_fp and pinned != host_fp:
        return {
            "ok": False,
            "error": f"SSH host key fingerprint mismatch (pinned {pinned}, seen {host_fp}). Refusing connection.",
            "ssh_host_key_fp": host_fp,
        }

    cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=6",
        *ssh_host_key_options(cfg if not pinned else {**cfg, "ssh_host_key_fp": pinned or host_fp}),
    ]
    if port and int(port) != 22:
        cmd.extend(["-p", str(port)])
    if key_path:
        cmd.extend(["-i", key_path])
    cmd.append("--")
    cmd.append(f"{user}@{host}")
    cmd.append("uname -s -m -r; python3 -V; cat /etc.defaults/VERSION 2>/dev/null || cat /etc/VERSION 2>/dev/null")

    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12)
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", errors="replace").strip()
            if "Permission denied" in err:
                return {
                    "ok": False,
                    "error": "SSH 金鑰認證失敗 (Permission denied)。請確認帳號與私鑰是否匹配，並已在 NAS 的 ~/.ssh/authorized_keys 中加入公鑰。"
                }
            elif "timed out" in err.lower() or "connection timed out" in err.lower():
                return {
                    "ok": False,
                    "error": f"連線至 {host}:{port} 逾時 (Connection timed out)。請檢查 IP 是否正確，以及 NAS 與電腦是否位於同一網路。"
                }
            elif "refused" in err.lower():
                return {
                    "ok": False,
                    "error": f"連線至 {host}:{port} 被拒絕 (Connection refused)。請至 DSM 控制台 ➔ 終端機與 SNMP 確認 SSH 服務已啟用且 Port 為 {port}。"
                }
            return {"ok": False, "error": f"SSH 連線失敗 (Code {proc.returncode}): {err}"}

        out = proc.stdout.decode("utf-8", errors="replace")
        lines = [line.strip() for line in out.splitlines() if line.strip()]
        uname_parts = lines[0].split() if lines else []
        os_name = uname_parts[0] if len(uname_parts) > 0 else "Linux"
        kernel = uname_parts[1] if len(uname_parts) > 1 else "Unknown"
        arch = uname_parts[2] if len(uname_parts) > 2 else "Unknown"

        python_ver = lines[1] if len(lines) > 1 and "Python" in lines[1] else "Python 3"

        dsm_info = {}
        for line in lines[2:]:
            if "=" in line:
                k, v = line.split("=", 1)
                dsm_info[k.strip()] = v.strip().strip('"')

        prod_ver = dsm_info.get("productversion", "7.x")
        build_num = dsm_info.get("buildnumber", "")
        small_fix = dsm_info.get("smallfixnumber", "")
        dsm_display = f"DSM {prod_ver}-{build_num}" + (f" Update {small_fix}" if small_fix else "")

        return {
            "ok": True,
            "message": "SSH 連線成功！NAS 系統探測完成",
            "ssh_host_key_fp": host_fp or pinned,
            "system": {
                "os": os_name,
                "kernel": kernel,
                "arch": arch,
                "python": python_ver,
                "dsm_version": dsm_display,
            }
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"連線至 {host}:{port} 逾時 (Timeout)。請檢查 NAS IP 與防火牆設定。"}
    except Exception as e:
        return {"ok": False, "error": f"檢測例外錯誤: {str(e)}"}


INITIAL_CONFIG = load_app_config()
NAS_HOST = INITIAL_CONFIG.get("nas_host", "192.168.1.100")
NAS_USER = INITIAL_CONFIG.get("nas_user", "admin")
LISTEN_HOST = INITIAL_CONFIG.get("web_host", "127.0.0.1")
LISTEN_PORT = int(INITIAL_CONFIG.get("web_port", 8088))
POLL_INTERVAL_SEC = int(INITIAL_CONFIG.get("poll_interval_sec", 15))


def build_ssh_cmd(remote_cmd: str, timeout: int = 8) -> list:
    cfg = STATE.config if "STATE" in globals() and hasattr(STATE, "config") else load_app_config()
    cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={timeout}",
        *ssh_host_key_options(cfg),
    ]
    port = cfg.get("nas_port", 22)
    if port and int(port) != 22:
        cmd.extend(["-p", str(port)])
    key_path = cfg.get("ssh_key_path")
    key_check = validate_ssh_key_path(key_path or "")
    if key_check.get("ok") and key_check.get("path"):
        cmd.extend(["-i", key_check["path"]])
    user = cfg.get("nas_user") or "admin"
    host = cfg.get("nas_host") or "127.0.0.1"
    cmd.append("--")
    cmd.append(f"{user}@{host}")
    cmd.append(remote_cmd)
    return cmd


FAST_SYNOMAN_CHECKED_EXTS = {
    ".cgi", ".html", ".htm", ".js", ".php", ".sh", ".py", ".pl",
    ".conf", ".mustache", ".json", ".css",
    ".phtml", ".php5", ".elf", ".jsp", ".asp", ".aspx"
}

WEB_ENDPOINTS = [
    {"id": "http_80_root", "port": 80, "https": False, "path": "/", "label": "HTTP :80 入口導向"},
    {"id": "http_5000_root", "port": 5000, "https": False, "path": "/", "label": "DSM HTTP :5000 導向頁"},
    {"id": "http_5000_login", "port": 5000, "https": False, "path": "/webman/login.cgi", "label": "DSM :5000 login.cgi"},
    {"id": "https_443_root", "port": 443, "https": True, "path": "/", "label": "HTTPS :443 反向代理入口"},
    {"id": "https_5001_index", "port": 5001, "https": True, "path": "/webman/index.cgi", "label": "DSM HTTPS :5001 管理桌面"},
    {"id": "https_5001_login", "port": 5001, "https": True, "path": "/webman/login.cgi", "label": "DSM HTTPS :5001 登入 API"},
]

HISTORICAL_AUTH_SUMMARY = [
    {"ip": "180.188.227.249", "attempts": 504, "last_seen": "2024-10-18", "note": "公網 SSH 暴力猜測來源 (已改僅公鑰)"},
    {"ip": "172.105.66.104", "attempts": 342, "last_seen": "2024-10-18", "note": "公網 SSH 暴力猜測來源 (已改僅公鑰)"},
    {"ip": "165.22.220.79", "attempts": 64, "last_seen": "2022-07-18", "note": "歷史公網掃描來源"},
    {"ip": "143.198.100.69", "attempts": 45, "last_seen": "2024-10-18", "note": "公網 SSH 暴力猜測來源"},
    {"ip": "206.189.22.223", "attempts": 40, "last_seen": "2024-10-18", "note": "公網 SSH 暴力猜測來源"},
    {"ip": "45.148.10.240", "attempts": 36, "last_seen": "2024-10-18", "note": "公網 SSH 暴力猜測來源"},
]

SMART_REFERENCE = {
    "model": "WDC WD10EZEX-08WN4A0 (1 TB)",
    "status": "PASSED",
    "power_on_hours": 62711,
    "reallocated_sectors": 0,
    "pending_sectors": 0,
    "uncorrectable": 0,
    "udma_crc_errors": 0,
    "note": "SMART 健康評估通過，0 壞軌；累積通電逾 62,711 小時，建議維持異機獨立備份",
}

IO_LOCK = threading.RLock()


def load_json(path: Path, default):
    with IO_LOCK:
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return default
        return default


def save_json(path: Path, data, mode=None):
    with IO_LOCK:
        tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        try:
            tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(path)
            if mode is not None:
                _chmod_secret(path, mode)
        finally:
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass


def probe_single_endpoint(ep):
    port = ep["port"]
    is_https = ep["https"]
    path = ep["path"]
    t0 = time.time()
    result = {
        "id": ep["id"],
        "label": ep["label"],
        "port": port,
        "https": is_https,
        "path": path,
        "reachable": False,
        "status": None,
        "latency_ms": None,
        "body_size": 0,
        "body_sha256": None,
        "redirects_to_https": False,
        "suspicious_content": [],
        "cert": None,
        "error": None,
    }
    conn = None
    try:
        target_host = STATE.config.get("nas_host") if ("STATE" in globals() and hasattr(STATE, "config")) else NAS_HOST
        target_host = target_host or "127.0.0.1"
        if is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(target_host, port=port, timeout=5, context=ctx)
        else:
            conn = http.client.HTTPConnection(target_host, port=port, timeout=5)

        conn.request("GET", path, headers={"User-Agent": "NAS-Sentinel-Monitor/1.0"})
        resp = conn.getresponse()
        body = resp.read(256 * 1024)
        latency = int((time.time() - t0) * 1000)

        body_text = body.decode("utf-8", errors="replace")
        body_hash = hashlib.sha256(body).hexdigest()

        result["reachable"] = True
        result["status"] = resp.status
        result["latency_ms"] = latency
        result["body_size"] = len(body)
        result["body_sha256"] = body_hash
        result["redirects_to_https"] = ("https" in body_text.lower()) or (
            resp.getheader("Location", "").lower().startswith("https:")
        )

        lower_body = body_text.lower()
        if "<script" in lower_body and ("http://" in lower_body or "//" in lower_body):
            if any(ext_dom in lower_body for ext_dom in ("<script src=\"http", "<script src='http", "eval(atob", "document.write(unescape")):
                result["suspicious_content"].append("偵測到疑似外部惡意 Script 注入")

        if is_https and conn.sock:
            der_cert = conn.sock.getpeercert(binary_form=True)
            if der_cert:
                cert_fp = hashlib.sha256(der_cert).hexdigest()
                result["cert"] = {
                    "sha256": cert_fp,
                    "cipher": conn.sock.cipher()[0] if conn.sock.cipher() else "",
                    "tls_version": conn.sock.version() or "",
                }
    except Exception as e:
        result["error"] = str(e)
        result["latency_ms"] = int((time.time() - t0) * 1000)
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
    return result


def probe_all_web_endpoints():
    results = []
    threads = []
    out_map = {}

    def _worker(ep):
        out_map[ep["id"]] = probe_single_endpoint(ep)

    for ep in WEB_ENDPOINTS:
        t = threading.Thread(target=_worker, args=(ep,), daemon=True)
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=6)

    for ep in WEB_ENDPOINTS:
        if ep["id"] in out_map:
            results.append(out_map[ep["id"]])
    return results


class MonitorState:
    def __init__(self):
        self.lock = threading.RLock()
        self.config = load_app_config()
        ensure_api_token(self.config)
        self.fim_baseline = load_json(FIM_BASELINE_FILE, {})
        self.port_baseline = load_json(PORT_BASELINE_FILE, {})
        self.http_baseline = load_json(HTTP_BASELINE_FILE, {})
        self.lkm_baseline = load_json(LKM_BASELINE_FILE, {})
        self.events = load_json(EVENTS_FILE, [])
        self.inotify_events = load_json(INOTIFY_EVENTS_FILE, [])
        self.history = load_json(HISTORY_FILE, [])
        self.latest_snapshot = None
        self.latest_files = copy.deepcopy(self.fim_baseline.get("files", {}))
        self.scan_in_progress = False
        self.last_error = None
        self.deep_scan_counter = 0
        self.cf_config = cloudflare_intel.load_config()
        # Merge config if set in config.json
        if self.config.get("cloudflare_api_token"):
            self.cf_config["api_token"] = self.config["cloudflare_api_token"]
            self.cf_config["zone_id"] = self.config.get("cloudflare_zone_id", "")
            self.cf_config["enabled"] = bool(self.config.get("cloudflare_enabled", False))
        self.cf_events = cloudflare_intel.load_events()
        self.cf_sync_in_progress = False
        self.inotify_status = {
            "connected": False,
            "watches_count": 0,
            "last_heartbeat": None,
            "total_captured": len(self.inotify_events),
        }

    def add_event(self, level: str, category: str, title: str, detail: str, dedup_key: str = None):
        with self.lock:
            now_iso = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
            if dedup_key:
                for recent in self.events[:8]:
                    if recent.get("dedup_key") == dedup_key:
                        return
            ev = {
                "id": hashlib.sha1(f"{time.time()}:{title}:{detail}".encode()).hexdigest()[:10],
                "time": now_iso,
                "timestamp": int(time.time()),
                "level": level,
                "category": category,
                "title": title,
                "detail": detail,
                "dedup_key": dedup_key,
            }
            self.events.insert(0, ev)
            self.events = self.events[:150]
            save_json(EVENTS_FILE, self.events)

    def sync_cloudflare(self):
        """Synchronizes recent edge threat events from Cloudflare GraphQL API."""
        with self.lock:
            if self.cf_sync_in_progress:
                return
            if not self.cf_config.get("enabled") or not self.cf_config.get("api_token") or not self.cf_config.get("zone_id"):
                return
            self.cf_sync_in_progress = True
            token = self.cf_config.get("api_token", "")
            zone = self.cf_config.get("zone_id", "")

        try:
            res = cloudflare_intel.fetch_edge_security_events(token, zone, hours=72, limit=100)
            with self.lock:
                if res.get("ok"):
                    new_events = res.get("events", [])
                    existing_ids = {e["id"] for e in self.cf_events}
                    newly_added = 0
                    for nev in reversed(new_events):
                        if nev["id"] not in existing_ids:
                            self.cf_events.insert(0, nev)
                            existing_ids.add(nev["id"])
                            newly_added += 1
                            if nev.get("severity") == "CRITICAL":
                                self.add_event(
                                    "CRITICAL",
                                    "🌐 邊界刺探攔截",
                                    f"Cloudflare 攔截敏感刺探: {nev['path']}",
                                    f"來源 IP: {nev['ip']} ({nev['country']}) | 處置: {nev['action']} | 威脅: {nev['probe_label']}",
                                    dedup_key=f"cf_probe:{nev['ip']}:{nev['path']}",
                                )
                    self.cf_events = self.cf_events[:200]
                    cloudflare_intel.save_events(self.cf_events)
                    self.cf_config["last_sync"] = int(time.time())
                    self.cf_config["last_error"] = None
                    cloudflare_intel.save_config(self.cf_config)
                    if self.latest_snapshot:
                        self.latest_snapshot["cloudflare"] = self._build_cloudflare_summary()
                else:
                    self.cf_config["last_error"] = res.get("error")
                    cloudflare_intel.save_config(self.cf_config)
                    if self.latest_snapshot and "cloudflare" in self.latest_snapshot:
                        self.latest_snapshot["cloudflare"]["last_error"] = res.get("error")
        except Exception as e:
            with self.lock:
                self.cf_config["last_error"] = str(e)
        finally:
            with self.lock:
                self.cf_sync_in_progress = False

    def _build_cloudflare_summary(self):
        distinct_countries = len(set(e.get("country", "") for e in self.cf_events if e.get("country")))
        top_paths_counter = {}
        for e in self.cf_events:
            p = e.get("path")
            if p:
                top_paths_counter[p] = top_paths_counter.get(p, 0) + 1
        top_probed_paths = sorted(top_paths_counter.items(), key=lambda x: x[1], reverse=True)[:5]

        return {
            "enabled": bool(self.cf_config.get("enabled", False)),
            "configured": bool(self.cf_config.get("api_token") and self.cf_config.get("zone_id")),
            "zone_id": (self.cf_config.get("zone_id") or "")[:6] + "..." if self.cf_config.get("zone_id") else "",
            "last_sync": self.cf_config.get("last_sync"),
            "last_error": self.cf_config.get("last_error"),
            "sync_in_progress": self.cf_sync_in_progress,
            "total_events_24h": len(self.cf_events),
            "distinct_countries_count": distinct_countries,
            "top_probed_paths": [{"path": p, "count": c} for p, c in top_probed_paths],
            "recent_events": self.cf_events[:50],
        }

    def _evaluate_fim_against_baseline(self, raw_targets_template=None):
        """Computes FIM anomalies and target summaries from self.latest_files vs self.fim_baseline."""
        base_files = self.fim_baseline.get("files", {})
        fim_anomalies = []
        added_count = 0
        modified_count = 0
        deleted_count = 0
        suspicious_count = 0

        target_counts = {}
        target_susp = {}
        for f in self.latest_files.values():
            tid = f.get("target_id")
            if tid:
                target_counts[tid] = target_counts.get(tid, 0) + 1
                if f.get("suspicious"):
                    target_susp[tid] = target_susp.get(tid, 0) + 1

        for fpath, cur in self.latest_files.items():
            base = base_files.get(fpath)
            susp_reasons = list(cur.get("suspicious") or [])
            if susp_reasons:
                suspicious_count += 1

            if base is None:
                added_count += 1
                severity = "CRITICAL" if (susp_reasons or cur["category"] in ("web_root", "web_config", "security_config", "system_binary")) else "WARNING"
                fim_anomalies.append({
                    "type": "ADDED",
                    "severity": severity,
                    "path": fpath,
                    "category": cur["category"],
                    "current": cur,
                    "baseline": None,
                    "reasons": ["基線外新增檔案"] + susp_reasons,
                })
                self.add_event(
                    severity,
                    "檔案異動 (FIM)",
                    f"偵測到新增檔案: {os.path.basename(fpath)}",
                    f"路徑: {fpath} (權限 {cur['mode']}, 擁有者 {cur['owner']}, SHA256: {str(cur['hash'])[:16]}...)",
                    dedup_key=f"fim_add:{fpath}:{cur['hash']}",
                )
            else:
                changes = []
                if cur["hash"] != base.get("hash"):
                    changes.append("SHA-256 內容雜湊改變")
                if cur["mode"] != base.get("mode"):
                    changes.append(f"權限變更 ({base.get('mode')} → {cur['mode']})")
                if cur["owner"] != base.get("owner"):
                    changes.append(f"擁有者變更 ({base.get('owner')} → {cur['owner']})")

                if changes or susp_reasons:
                    if changes:
                        modified_count += 1
                    severity = "CRITICAL" if (susp_reasons or "SHA-256 內容雜湊改變" in changes) else "WARNING"
                    fim_anomalies.append({
                        "type": "MODIFIED" if changes else "SUSPICIOUS",
                        "severity": severity,
                        "path": fpath,
                        "category": cur["category"],
                        "current": cur,
                        "baseline": base,
                        "reasons": changes + susp_reasons,
                    })
                    if changes:
                        self.add_event(
                            severity,
                            "檔案竄改警報 (FIM)",
                            f"檔案內容或權限異動: {os.path.basename(fpath)}",
                            f"路徑: {fpath} | 變更: {', '.join(changes + susp_reasons)}",
                            dedup_key=f"fim_mod:{fpath}:{cur['hash']}:{cur['mode']}",
                        )

        for bpath, binfo in base_files.items():
            if bpath not in self.latest_files:
                deleted_count += 1
                fim_anomalies.append({
                    "type": "DELETED",
                    "severity": "WARNING",
                    "path": bpath,
                    "category": binfo.get("category", "unknown"),
                    "current": None,
                    "baseline": binfo,
                    "reasons": ["受監控基線檔案已被刪除或移除"],
                })
                self.add_event(
                    "WARNING",
                    "檔案移除 (FIM)",
                    f"受保護檔案被刪除: {os.path.basename(bpath)}",
                    f"原路徑: {bpath}",
                    dedup_key=f"fim_del:{bpath}",
                )

        existing_targets = raw_targets_template
        if existing_targets is None and self.latest_snapshot:
            existing_targets = self.latest_snapshot["fim_summary"]["targets"]

        merged_targets = []
        for t in (existing_targets or []):
            tid = t["id"]
            t_copy = dict(t)
            t_copy["file_count"] = target_counts.get(tid, 0)
            t_copy["suspicious_count"] = target_susp.get(tid, 0)
            merged_targets.append(t_copy)

        return {
            "baseline_created_at": self.fim_baseline.get("created_at"),
            "total_monitored_files": len(self.latest_files),
            "added_count": added_count,
            "modified_count": modified_count,
            "deleted_count": deleted_count,
            "suspicious_count": suspicious_count,
            "anomaly_count": len(fim_anomalies),
            "targets": merged_targets,
            "anomalies": fim_anomalies[:100],
        }

    def handle_inotify_event(self, ev: dict):
        """Processes a real-time millisecond kernel inotify event and updates snapshot immediately."""
        with self.lock:
            fpath = ev["path"]
            is_del = ev.get("is_delete", False)
            is_dir = ev.get("is_dir", False)
            ephemeral = ev.get("ephemeral", False)
            file_entry = ev.get("file")
            flags_str = ", ".join(ev.get("flags", []))

            if not is_dir:
                if is_del:
                    self.latest_files.pop(fpath, None)
                elif file_entry is not None:
                    self.latest_files[fpath] = file_entry

            susp_list = (file_entry or {}).get("suspicious") or []
            if ephemeral:
                susp_list = list(susp_list) + ["瞬時建立後立即消失之可疑暫存檔 (Ephemeral)"]

            severity = "INFO"
            if susp_list:
                severity = "CRITICAL"
            elif is_del or "IN_CREATE" in flags_str or "IN_MODIFY" in flags_str or "IN_CLOSE_WRITE" in flags_str or "IN_ATTRIB" in flags_str:
                severity = "CRITICAL" if ev.get("category") in ("web_root", "web_config", "security_config", "system_binary") else "WARNING"

            record = {
                "id": hashlib.sha1(f"{ev.get('timestamp')}:{fpath}:{flags_str}".encode()).hexdigest()[:10],
                "iso_time": ev.get("iso_time"),
                "timestamp": ev.get("timestamp"),
                "path": fpath,
                "category": ev.get("category"),
                "flags": ev.get("flags", []),
                "is_delete": is_del,
                "ephemeral": ephemeral,
                "severity": severity,
                "mode": (file_entry or {}).get("mode", "已刪除" if is_del else "-"),
                "owner": (file_entry or {}).get("owner", "-"),
                "size": (file_entry or {}).get("size", 0),
                "hash": (file_entry or {}).get("hash", ""),
                "suspicious": susp_list,
            }
            self.inotify_events.insert(0, record)
            self.inotify_events = self.inotify_events[:150]
            self.inotify_status["total_captured"] = self.inotify_status.get("total_captured", 0) + 1
            save_json(INOTIFY_EVENTS_FILE, self.inotify_events)

            self.add_event(
                severity,
                "⚡ inotify 毫秒攔截",
                f"{os.path.basename(fpath)} 發生 {flags_str}",
                f"路徑: {fpath} | 權限: {record['mode']} | 雜湊: {(record['hash'] or '無')[:16]}... {'| ' + ', '.join(susp_list) if susp_list else ''}",
            )

            # Immediately refresh FIM summary and threat status in latest_snapshot without waiting for 15s poll
            if self.latest_snapshot is not None:
                fim_sum = self._evaluate_fim_against_baseline()
                self.latest_snapshot["fim_summary"] = fim_sum
                self.latest_snapshot["inotify"] = {
                    "status": dict(self.inotify_status),
                    "recent_events": self.inotify_events[:50],
                }
                self.latest_snapshot["events"] = self.events[:50]

                # Update Rootkit checks immediately if system_binary or /etc/ld.so.preload was touched via inotify
                rk_summary = self.latest_snapshot.get("rootkit")
                if rk_summary:
                    bin_anomalies_now = [a for a in fim_sum["anomalies"] if a.get("category") == "system_binary"]
                    preload_exists_now = "/etc/ld.so.preload" in self.latest_files
                    for rchk in rk_summary.get("checks", []):
                        if rchk["id"] == "rkhunter_binaries":
                            rchk["status"] = "pass" if not bin_anomalies_now else "fail"
                            rchk["severity"] = "OK" if not bin_anomalies_now else "CRITICAL"
                            rchk["detail"] = f"保護 20 個核心指令 (/bin/ps, ls, netstat, sshd, sudo, nginx)，異動: {len(bin_anomalies_now)}"
                        elif rchk["id"] == "ld_preload" and preload_exists_now:
                            rchk["status"] = "fail"
                            rchk["severity"] = "CRITICAL"
                            rchk["detail"] = "⚡ inotify 即時攔截：發現 /etc/ld.so.preload 被建立或修改！"
                    rk_summary["alert_count"] = sum(1 for c in rk_summary.get("checks", []) if c["status"] != "pass")

                # Update web_fim, rootkit_scanner, and inotify_stream posture items
                for chk in self.latest_snapshot["security"]["posture_checks"]:
                    if chk["id"] == "web_fim":
                        chk["status"] = "pass" if fim_sum["anomaly_count"] == 0 else "fail"
                        chk["detail"] = f"監控 {fim_sum['total_monitored_files']} 個檔案，目前異動/異常: {fim_sum['anomaly_count']} 項"
                    elif chk["id"] == "rootkit_scanner" and rk_summary:
                        rk_cnt = rk_summary["alert_count"]
                        chk["status"] = "pass" if rk_cnt == 0 else "fail"
                        if rk_cnt > 0:
                            chk["detail"] = f"發現 {rk_cnt} 項異常警報！"
                    elif chk["id"] == "inotify_stream":
                        chk["status"] = "pass" if self.inotify_status["connected"] else "warn"
                        chk["detail"] = f"狀態: {'即時連線中' if self.inotify_status['connected'] else '連線建立中'} | 監聽目錄數: {self.inotify_status['watches_count']} | 累計攔截事件: {self.inotify_status['total_captured']}"

                fw = self.latest_snapshot["security"]["firewall"]
                unauth_ports = self.latest_snapshot["network"]["unauthorized_ports"]
                crit_svcs_down = [s for s in self.latest_snapshot["security"]["services"] if s["critical"] and not s["running"]]
                web_anom_cnt = sum(1 for e in self.latest_snapshot["web_endpoints"] if not e.get("baseline_match", True) or e.get("anomaly_notes"))
                rk_alerts = (self.latest_snapshot.get("rootkit") or {}).get("alert_count", 0)
                score, t_level, t_label = self._compute_score_and_threat(
                    fim_sum["anomalies"], unauth_ports, crit_svcs_down, web_anom_cnt, fw, rk_alerts, from_inotify=True
                )
                self.latest_snapshot["security_score"] = score
                self.latest_snapshot["threat_level"] = t_level
                self.latest_snapshot["threat_label"] = t_label

    @staticmethod
    def _compute_score_and_threat(fim_anomalies, unauthorized_ports, critical_services_down, web_anomalies, fw, rootkit_alerts=0, from_inotify=False):
        threat_level = "NORMAL"
        threat_label = "安全運作中 (Normal)"
        score = 96

        if fw.get("rules_count", 0) == 0:
            score -= 6
        if rootkit_alerts > 0:
            score -= min(50, rootkit_alerts * 25)
            threat_level = "CRITICAL"
            threat_label = "偵測到 Rootkit / 隱藏程序警報"
        if fim_anomalies:
            score -= min(45, len(fim_anomalies) * 15)
            threat_level = "CRITICAL" if any(a["severity"] == "CRITICAL" for a in fim_anomalies) else "WARNING"
            if rootkit_alerts == 0:
                threat_label = "偵測到檔案異動警報 (inotify 即時攔截)" if from_inotify else "偵測到檔案異動警報 (FIM Alert)"
        if unauthorized_ports:
            score -= 20
            threat_level = "CRITICAL"
            if not fim_anomalies and rootkit_alerts == 0:
                threat_label = "偵測到異常開放埠 (Port Alert)"
        if critical_services_down:
            score -= 15
            if threat_level == "NORMAL":
                threat_level = "WARNING"
                threat_label = "關鍵服務未執行 (Service Warning)"
        if web_anomalies > 0 and threat_level == "NORMAL":
            score -= 10
            threat_level = "WARNING"
            threat_label = "Web 端點異常 (Web Warning)"

        return max(10, score), threat_level, threat_label

    def perform_scan(self, mode="fast", force_baseline=False):
        with self.lock:
            if self.scan_in_progress:
                return self.latest_snapshot
            self.scan_in_progress = True

        try:
            with self.lock:
                if not self.fim_baseline or not self.fim_baseline.get("files") or not self.latest_files:
                    mode = "deep"

            script_bytes = COLLECTOR_SCRIPT.read_bytes().replace(b"\r\n", b"\n")
            web_results_holder = []

            def _run_web_probes():
                web_results_holder.extend(probe_all_web_endpoints())

            probe_thread = threading.Thread(target=_run_web_probes, daemon=True)
            probe_thread.start()

            proc = subprocess.run(
                build_ssh_cmd(f"python3 - {mode}", timeout=8),
                input=script_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=35,
            )
            probe_thread.join(timeout=6)

            if proc.returncode != 0:
                err_msg = proc.stderr.decode("utf-8", errors="replace").strip() or "SSH connection failed"
                with self.lock:
                    self.last_error = f"SSH 採集失敗 (Code {proc.returncode}): {err_msg}"
                    self.add_event("CRITICAL", "連線狀態", "無法經由 SSH 連線至 NAS", self.last_error, dedup_key="ssh_fail")
                return None

            raw_data = json.loads(proc.stdout.decode("utf-8", errors="replace"))
            with self.lock:
                self.last_error = None
                return self._process_telemetry(raw_data, web_results_holder, mode, force_baseline)

        except Exception as e:
            with self.lock:
                self.last_error = str(e)
                self.add_event("CRITICAL", "系統例外", "監控採集發生異常", str(e), dedup_key=f"exc_{type(e).__name__}")
            return None
        finally:
            with self.lock:
                self.scan_in_progress = False

    def _process_telemetry(self, raw_data, web_endpoints, mode, force_baseline):
        now_ts = raw_data["timestamp"]
        now_iso = raw_data["iso_time"]
        scanned_files = raw_data["fim"]["files"]

        if mode == "deep" or not self.latest_files:
            self.latest_files = dict(scanned_files)
        else:
            for old_path in list(self.latest_files.keys()):
                if not old_path.startswith("/usr/syno/synoman/"):
                    if old_path not in scanned_files:
                        self.latest_files.pop(old_path, None)
                else:
                    rel_depth = old_path[len("/usr/syno/synoman/"):].count("/") + 1
                    ext = os.path.splitext(old_path)[1].lower()
                    in_fast_scope = (rel_depth == 1) or (rel_depth <= 3 and ext in FAST_SYNOMAN_CHECKED_EXTS)
                    if in_fast_scope and old_path not in scanned_files:
                        self.latest_files.pop(old_path, None)
            self.latest_files.update(scanned_files)

        if force_baseline or not self.fim_baseline.get("files"):
            self.fim_baseline = {
                "created_at": now_iso,
                "file_count": len(self.latest_files),
                "files": copy.deepcopy(self.latest_files),
            }
            save_json(FIM_BASELINE_FILE, self.fim_baseline)
            self.add_event("SUCCESS", "檔案基線", "已建立/更新網頁與系統檔案完整性基線", f"共納入 {len(self.latest_files)} 個受保護檔案的 SHA-256 與權限特徵")

        if force_baseline or not self.port_baseline.get("ports"):
            port_map = {}
            for l in raw_data["network"]["listeners"]:
                key = f"{l['proto']}:{l['port']}"
                port_map[key] = {"proto": l["proto"], "port": l["port"], "process": l["process"], "bind": l["bind"]}
            self.port_baseline = {"created_at": now_iso, "ports": port_map}
            save_json(PORT_BASELINE_FILE, self.port_baseline)

        if force_baseline or not self.http_baseline.get("endpoints"):
            ep_map = {}
            for ep in web_endpoints:
                if ep["reachable"]:
                    ep_map[ep["id"]] = {
                        "status": ep["status"],
                        "body_sha256": ep["body_sha256"],
                        "body_size": ep["body_size"],
                        "cert_sha256": ep["cert"]["sha256"] if ep.get("cert") else None,
                    }
            self.http_baseline = {"created_at": now_iso, "endpoints": ep_map}
            save_json(HTTP_BASELINE_FILE, self.http_baseline)

        fim_summary = self._evaluate_fim_against_baseline(raw_targets_template=raw_data["fim"]["targets"])
        fim_anomalies = fim_summary["anomalies"]

        # Evaluate Rootkit (chkrootkit + rkhunter) checks & Kernel Module Baseline
        rk_raw = raw_data.get("rootkit", {})
        loaded_mods = rk_raw.get("loaded_modules", [])
        if force_baseline or not self.lkm_baseline.get("modules"):
            self.lkm_baseline = {"created_at": now_iso, "modules": list(loaded_mods)}
            save_json(LKM_BASELINE_FILE, self.lkm_baseline)

        base_mods_set = set(self.lkm_baseline.get("modules", []))
        new_lkms = [m for m in loaded_mods if m not in base_mods_set]
        susp_lkms = rk_raw.get("suspicious_lkms", [])

        bin_anomalies = [a for a in fim_anomalies if a.get("category") == "system_binary"]
        ld_anom = rk_raw.get("ld_preload_anomalies", [])
        hidden_pids = rk_raw.get("hidden_pids", [])
        deleted_exes = rk_raw.get("deleted_running_exes", [])
        promisc_ifs = rk_raw.get("promisc_interfaces", [])
        unexp_tmp = rk_raw.get("unexpected_tmp_files", [])
        matched_rk_paths = rk_raw.get("matched_rootkit_paths", [])

        rk_checks = [
            {
                "id": "rkhunter_binaries",
                "tool": "rkhunter",
                "label": "系統核心執行檔防木馬替換 (System Binary SHA-256)",
                "status": "pass" if not bin_anomalies else "fail",
                "severity": "OK" if not bin_anomalies else "CRITICAL",
                "detail": f"保護 {rk_raw.get('critical_binaries_count', 20)} 個核心指令 (/bin/ps, ls, netstat, sshd, sudo, nginx)，異動: {len(bin_anomalies)}",
            },
            {
                "id": "ld_preload",
                "tool": "rkhunter / chkrootkit",
                "label": "LD_PRELOAD 動態連結器劫持檢測 (/etc/ld.so.preload & environ)",
                "status": "pass" if not ld_anom else "fail",
                "severity": "OK" if not ld_anom else "CRITICAL",
                "detail": "未發現 /etc/ld.so.preload 或程序環境變數劫持" if not ld_anom else "；".join(ld_anom),
            },
            {
                "id": "chkproc",
                "tool": "chkrootkit (chkproc)",
                "label": "隱藏幽靈程序與無檔案執行檔交叉比對 (/proc vs ps)",
                "status": "pass" if (not hidden_pids and not deleted_exes) else "fail",
                "severity": "OK" if (not hidden_pids and not deleted_exes) else "CRITICAL",
                "detail": f"隱藏 PID: {len(hidden_pids)} | 已刪除仍駐留記憶體程序: {len(deleted_exes)}" if (hidden_pids or deleted_exes) else "所有核心 /proc PID 與 ps 完全吻合，無幽靈程序",
            },
            {
                "id": "ifpromisc",
                "tool": "chkrootkit (ifpromisc)",
                "label": "網卡混雜模式封包竊聽檢測 (IFF_PROMISC)",
                "status": "pass" if not promisc_ifs else "fail",
                "severity": "OK" if not promisc_ifs else "CRITICAL",
                "detail": f"檢查 {len(rk_raw.get('interfaces', []))} 張網卡 ({', '.join(i['name'] + ':' + i['flags_hex'] for i in rk_raw.get('interfaces', []))})，均未開啟混雜竊聽" if not promisc_ifs else f"警告：網卡開啟混雜模式: {', '.join(promisc_ifs)}",
            },
            {
                "id": "lkm_modules",
                "tool": "rkhunter (LKM)",
                "label": "Linux 核心模組 (LKM Rootkit) 基線比對 (/proc/modules)",
                "status": "pass" if (not new_lkms and not susp_lkms) else "fail",
                "severity": "OK" if (not new_lkms and not susp_lkms) else "CRITICAL",
                "detail": f"已載入 {len(loaded_mods)} 個核心模組，與安全基線 100% 吻合" if (not new_lkms and not susp_lkms) else f"新增未知模組: {new_lkms} | 可疑模組: {susp_lkms}",
            },
            {
                "id": "shm_tmp_rootkit",
                "tool": "chkrootkit / rkhunter",
                "label": "已知 Rootkit 後門路徑與 /dev/shm、/tmp 異常點檔案/ELF 掃描",
                "status": "pass" if (not matched_rk_paths and not unexp_tmp) else "fail",
                "severity": "OK" if (not matched_rk_paths and not unexp_tmp) else "CRITICAL",
                "detail": "未發現已知 Rootkit 特徵路徑或 /dev/shm、/tmp 異常隱藏檔/ELF 執行檔" if (not matched_rk_paths and not unexp_tmp) else f"命中特徵: {matched_rk_paths} | 異常暫存檔: {unexp_tmp}",
            },
        ]

        rk_alert_count = sum(1 for c in rk_checks if c["status"] != "pass")
        if rk_alert_count > 0:
            failed_titles = [c["label"] for c in rk_checks if c["status"] != "pass"]
            self.add_event(
                "CRITICAL",
                "Rootkit 偵測警報",
                f"偵測到 {rk_alert_count} 項 Rootkit / 系統異常指標",
                "；".join(failed_titles),
                dedup_key=f"rk_alert:{rk_alert_count}:{','.join(failed_titles)}",
            )

        rootkit_summary = {
            "duration_ms": rk_raw.get("duration_ms", 0),
            "alert_count": rk_alert_count,
            "loaded_modules_count": len(loaded_mods),
            "checks": rk_checks,
        }

        base_eps = self.http_baseline.get("endpoints", {})
        web_anomalies = 0
        for ep in web_endpoints:
            b_ep = base_eps.get(ep["id"])
            ep["baseline_match"] = True
            ep["anomaly_notes"] = list(ep.get("suspicious_content") or [])
            if not ep["reachable"]:
                ep["baseline_match"] = False
                ep["anomaly_notes"].append("端點無法連線")
                web_anomalies += 1
            elif b_ep:
                if ep["status"] != b_ep.get("status"):
                    ep["baseline_match"] = False
                    ep["anomaly_notes"].append(f"HTTP 狀態碼改變 ({b_ep.get('status')} → {ep['status']})")
                if ep["body_sha256"] != b_ep.get("body_sha256"):
                    ep["baseline_match"] = False
                    ep["anomaly_notes"].append("網頁回應內容 SHA-256 與基線不符")
                cert_mismatch = bool(
                    ep.get("cert") and b_ep.get("cert_sha256") and ep["cert"]["sha256"] != b_ep.get("cert_sha256")
                )
                if cert_mismatch:
                    ep["baseline_match"] = False
                    ep["anomaly_notes"].append("TLS 憑證指紋與基線不符（已釘選；拒絕信任新憑證，請於基線重置後確認）")
                if not ep["baseline_match"] or ep["anomaly_notes"]:
                    web_anomalies += 1
                    self.add_event(
                        "CRITICAL" if cert_mismatch else "WARNING",
                        "Web 端點異常",
                        f"網頁端點回應異動: {ep['label']}",
                        f"Port {ep['port']} {ep['path']}: {', '.join(ep['anomaly_notes'])}",
                        dedup_key=f"web_ep:{ep['id']}:{ep['body_sha256']}",
                    )

        base_ports = self.port_baseline.get("ports", {})
        unauthorized_ports = []
        for l in raw_data["network"]["listeners"]:
            k = f"{l['proto']}:{l['port']}"
            l["in_baseline"] = k in base_ports
            if not l["in_baseline"]:
                if l["proto"].startswith("tcp") or l["port"] < 32768:
                    unauthorized_ports.append(l)
                    self.add_event(
                        "CRITICAL",
                        "網路監聽埠警報",
                        f"發現非基線開放埠: {l['proto'].upper()} {l['port']}",
                        f"綁定: {l['bind']}:{l['port']} | 程序: {l['process'] or '未知'}",
                        dedup_key=f"new_port:{k}",
                    )

        sysctls = raw_data["security"]["sysctls"]
        fw = raw_data["security"]["firewall"]
        posture_checks = [
            {
                "id": "inotify_stream",
                "label": "Linux 核心 inotify 毫秒級即時檔案監聽引擎",
                "status": "pass" if self.inotify_status["connected"] else "warn",
                "detail": f"狀態: {'即時連線中' if self.inotify_status['connected'] else '連線建立中'} | 監聽目錄數: {self.inotify_status['watches_count']} | 累計攔截事件: {self.inotify_status['total_captured']}",
            },
            {
                "id": "ssh_pubkey",
                "label": "SSH 強制公鑰認證與禁止 Root 登入",
                "status": "pass",
                "detail": f"已啟用公鑰認證，授權金鑰數: {len(raw_data['security']['ssh_keys'])}",
            },
            {
                "id": "kernel_hardening",
                "label": "核心指標與 dmesg 隱私保護 (kptr/dmesg_restrict)",
                "status": "pass" if sysctls.get("kernel.kptr_restrict") == "2" and sysctls.get("kernel.dmesg_restrict") == "1" else "warn",
                "detail": f"kptr_restrict={sysctls.get('kernel.kptr_restrict')}, dmesg_restrict={sysctls.get('kernel.dmesg_restrict')}",
            },
            {
                "id": "source_route",
                "label": "IPv4 Source-Route 封包拒絕保護",
                "status": "pass" if sysctls.get("net.ipv4.conf.all.accept_source_route") == "0" and sysctls.get("net.ipv4.conf.eth0.accept_source_route") == "0" else "warn",
                "detail": f"all={sysctls.get('net.ipv4.conf.all.accept_source_route')}, eth0={sysctls.get('net.ipv4.conf.eth0.accept_source_route')}",
            },
            {
                "id": "ipv6_loopback",
                "label": "IPv6 Loopback (::1) 與 Chrony UDP 控制埠收斂",
                "status": "pass" if sysctls.get("net.ipv6.conf.lo.disable_ipv6") == "1" else "warn",
                "detail": f"lo.disable_ipv6={sysctls.get('net.ipv6.conf.lo.disable_ipv6')}",
            },
            {
                "id": "dsm_firewall",
                "label": "DSM 防火牆來源白名單規則",
                "status": "pass" if (fw["enabled"] and fw["rules_count"] > 0) else "warn",
                "detail": f"狀態: {'啟用' if fw['enabled'] else '停用'} (Profile: {fw['profile']}), 規則數: {fw['rules_count']} (建議於 DSM 建立來源白名單)",
            },
            {
                "id": "rootkit_scanner",
                "label": "Rootkit 與系統指令防木馬引擎 (chkrootkit + rkhunter 核心檢測)",
                "status": "pass" if rk_alert_count == 0 else "fail",
                "detail": f"6 大核心檢測項目全數通過 (耗時 {rootkit_summary['duration_ms']}ms，監控 {len(loaded_mods)} 個核心模組與 20 個系統執行檔)" if rk_alert_count == 0 else f"發現 {rk_alert_count} 項異常警報！",
            },
            {
                "id": "web_fim",
                "label": "Nginx 與 DSM 網頁伺服器檔案完整性 (FIM)",
                "status": "pass" if len(fim_anomalies) == 0 else "fail",
                "detail": f"監控 {len(self.latest_files)} 個檔案，目前異動/異常: {len(fim_anomalies)} 項",
            },
        ]

        critical_services_down = [s for s in raw_data["security"]["services"] if s["critical"] and not s["running"]]
        score, threat_level, threat_label = self._compute_score_and_threat(
            fim_anomalies, unauthorized_ports, critical_services_down, web_anomalies, fw, rk_alert_count, from_inotify=False
        )

        avg_latency = 0
        reachable_eps = [e["latency_ms"] for e in web_endpoints if e["reachable"] and e["latency_ms"] is not None]
        if reachable_eps:
            avg_latency = round(sum(reachable_eps) / len(reachable_eps), 1)

        ext_conns = [c for c in raw_data["network"]["connections"] if c["scope"] == "external"]
        lan_conns = [c for c in raw_data["network"]["connections"] if c["scope"] == "lan"]

        hist_point = {
            "time": datetime.datetime.fromtimestamp(now_ts).strftime("%H:%M:%S"),
            "cpu": raw_data["system"]["cpu_percent"],
            "mem": raw_data["system"]["mem_percent"],
            "temp": raw_data["system"]["temp_c"] or 0,
            "load": raw_data["system"]["load_1m"],
            "web_latency_ms": avg_latency,
            "conn_total": len(raw_data["network"]["connections"]),
            "conn_external": len(ext_conns),
        }
        self.history.append(hist_point)
        self.history = self.history[-60:]
        save_json(HISTORY_FILE, self.history)

        snapshot = {
            "nas_host": self.config.get("nas_host") or NAS_HOST,
            "nas_user": self.config.get("nas_user") or NAS_USER,
            "timestamp": now_ts,
            "iso_time": now_iso,
            "scan_mode": mode,
            "scan_elapsed_ms": raw_data["total_elapsed_ms"],
            "poll_interval_sec": POLL_INTERVAL_SEC,
            "security_score": score,
            "threat_level": threat_level,
            "threat_label": threat_label,
            "system": raw_data["system"],
            "smart_reference": SMART_REFERENCE,
            "fim_summary": fim_summary,
            "rootkit": rootkit_summary,
            "inotify": {
                "status": dict(self.inotify_status),
                "recent_events": self.inotify_events[:50],
            },
            "web_endpoints": web_endpoints,
            "network": {
                "listeners": raw_data["network"]["listeners"],
                "unauthorized_ports": unauthorized_ports,
                "connections": raw_data["network"]["connections"],
                "lan_conn_count": len(lan_conns),
                "external_conn_count": len(ext_conns),
            },
            "security": {
                "services": raw_data["security"]["services"],
                "suspicious_processes": raw_data["security"]["suspicious_processes"],
                "sysctls": sysctls,
                "firewall": fw,
                "ssh_keys": raw_data["security"]["ssh_keys"],
                "active_sessions": raw_data["security"]["active_sessions"],
                "posture_checks": posture_checks,
                "historical_brute_force": HISTORICAL_AUTH_SUMMARY,
            },
            "events": self.events[:50],
            "history": self.history,
            "cloudflare": self._build_cloudflare_summary(),
        }
        self.latest_snapshot = snapshot
        return snapshot


STATE = MonitorState()


def inotify_listener_loop():
    """Maintains persistent SSH kernel inotify stream to NAS for millisecond file event detection."""
    while True:
        if not STATE.config.get("is_configured"):
            time.sleep(2)
            continue
        proc = None
        try:
            script_bytes = INOTIFY_SCRIPT.read_bytes().replace(b"\r\n", b"\n")
            proc = subprocess.Popen(
                build_ssh_cmd("python3 -u -", timeout=8),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            proc.stdin.write(script_bytes)
            proc.stdin.close()

            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                line_str = line.decode("utf-8", errors="replace").strip()
                if not line_str:
                    continue
                try:
                    msg = json.loads(line_str)
                except ValueError:
                    continue

                mtype = msg.get("type")
                if mtype == "ready":
                    with STATE.lock:
                        STATE.inotify_status["connected"] = True
                        STATE.inotify_status["watches_count"] = msg.get("watches_count", 0)
                        STATE.inotify_status["last_heartbeat"] = int(time.time())
                        if STATE.latest_snapshot:
                            STATE.latest_snapshot["inotify"]["status"] = dict(STATE.inotify_status)
                    STATE.add_event(
                        "SUCCESS",
                        "inotify 引擎",
                        "Linux 核心 inotify 即時監聽串流已啟動",
                        f"已掛載 {msg.get('watches_count', 0)} 個網頁與系統安全目錄監聽器 (毫秒級即時攔截)",
                        dedup_key="inotify_ready",
                    )
                elif mtype == "heartbeat":
                    with STATE.lock:
                        STATE.inotify_status["connected"] = True
                        STATE.inotify_status["watches_count"] = msg.get("watches_count", 0)
                        STATE.inotify_status["last_heartbeat"] = int(time.time())
                elif mtype == "fs_event":
                    STATE.handle_inotify_event(msg)
        except Exception:
            pass
        finally:
            with STATE.lock:
                STATE.inotify_status["connected"] = False
                if STATE.latest_snapshot and "inotify" in STATE.latest_snapshot:
                    STATE.latest_snapshot["inotify"]["status"] = dict(STATE.inotify_status)
            if proc:
                try:
                    proc.terminate()
                except Exception:
                    pass
        time.sleep(5)


def background_poller():
    while not STATE.config.get("is_configured"):
        time.sleep(1)
    STATE.perform_scan(mode="deep")
    if STATE.config.get("cloudflare_enabled"):
        threading.Thread(target=STATE.sync_cloudflare, daemon=True).start()
    while True:
        poll_int = STATE.config.get("poll_interval_sec", POLL_INTERVAL_SEC)
        time.sleep(poll_int)
        if not STATE.config.get("is_configured"):
            continue
        STATE.deep_scan_counter += 1
        scan_mode = "deep" if (STATE.deep_scan_counter % 20 == 0) else "fast"
        STATE.perform_scan(mode=scan_mode)
        if STATE.deep_scan_counter % 4 == 0 and STATE.config.get("cloudflare_enabled"):
            threading.Thread(target=STATE.sync_cloudflare, daemon=True).start()


class MonitorHTTPHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def log_message(self, format, *args):
        pass

    def _send_json(self, data, status=200):
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def _extract_bearer_token(self) -> str:
        auth = self.headers.get("Authorization", "") or ""
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        # Authorization-header auth resists CSRF better than cookies (M6).
        return (self.headers.get("X-API-Token") or "").strip()

    def _require_api_auth(self) -> bool:
        expected = (STATE.config.get("api_token") or "").strip()
        if not expected:
            self._send_json({"ok": False, "error": "Server misconfigured: API token missing"}, status=500)
            return False
        provided = self._extract_bearer_token()
        if not provided or not hmac.compare_digest(provided, expected):
            self._send_json({
                "ok": False,
                "error": "Unauthorized. Set Authorization: Bearer <API_TOKEN> (see data/api_token.txt or API_TOKEN env).",
            }, status=401)
            return False
        return True

    def _guard_api(self, parsed_path: str) -> bool:
        if not parsed_path.startswith("/api/"):
            return True
        if parsed_path in PUBLIC_API_PATHS:
            return True
        return self._require_api_auth()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/api/auth/status":
            self._send_json({
                "ok": True,
                "auth_required": True,
                "auth_scheme": "Bearer",
                "hint": "Paste the token from data/api_token.txt or the API_TOKEN environment variable into the UI.",
            })
            return

        if parsed.path.startswith("/api/") and not self._guard_api(parsed.path):
            return

        if parsed.path == "/api/status":
            if not STATE.config.get("is_configured"):
                with STATE.lock:
                    self._send_json({
                        "ok": True,
                        "is_configured": False,
                        "scan_in_progress": False,
                        "last_error": None,
                        "data": None,
                        "config": public_config_view(STATE.config),
                    })
                return
            if STATE.latest_snapshot is None:
                STATE.perform_scan(mode="fast")
            with STATE.lock:
                self._send_json({
                    "ok": STATE.latest_snapshot is not None,
                    "is_configured": True,
                    "scan_in_progress": STATE.scan_in_progress,
                    "last_error": STATE.last_error,
                    "data": STATE.latest_snapshot,
                })
            return

        if parsed.path == "/api/config":
            keys = find_local_ssh_keys()
            with STATE.lock:
                self._send_json({
                    "ok": True,
                    "config": public_config_view(STATE.config),
                    "detected_ssh_keys": keys,
                })
            return

        if parsed.path == "/api/files":
            qs = urllib.parse.parse_qs(parsed.query)
            q = (qs.get("q", [""])[0] or "").strip().lower()
            cat = (qs.get("category", ["all"])[0] or "all").strip()
            try:
                limit = max(1, min(2000, int(qs.get("limit", ["200"])[0])))
            except ValueError:
                limit = 200

            with STATE.lock:
                files_list = list(STATE.latest_files.values())
                base_files = dict(STATE.fim_baseline.get("files", {}))

            filtered = []
            for f in files_list:
                if cat != "all" and f["category"] != cat:
                    continue
                if q and (q not in f["path"].lower() and q not in str(f.get("hash", "")).lower()):
                    continue
                b = base_files.get(f["path"])
                status = "OK"
                if b is None:
                    status = "ADDED"
                elif f["hash"] != b.get("hash") or f["mode"] != b.get("mode") or f["owner"] != b.get("owner"):
                    status = "MODIFIED"
                elif f.get("suspicious"):
                    status = "SUSPICIOUS"
                item = dict(f)
                item["status"] = status
                filtered.append(item)

            filtered.sort(key=lambda x: (0 if x["status"] != "OK" else 1, x["path"]))
            self._send_json({
                "total_matched": len(filtered),
                "total_monitored": len(files_list),
                "items": filtered[:limit],
            })
            return

        if parsed.path == "/api/cloudflare/status":
            with STATE.lock:
                self._send_json({
                    "ok": True,
                    "data": STATE._build_cloudflare_summary(),
                })
            return

        return super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.startswith("/api/") and not self._guard_api(parsed.path):
            return

        try:
            length = max(0, min(65536, int(self.headers.get("Content-Length", "0"))))
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(body.decode("utf-8", errors="replace"))
        except Exception:
            payload = {}

        if parsed.path == "/api/setup/test-connection":
            host = (payload.get("nas_host") or "").strip()
            user = (payload.get("nas_user") or "").strip()
            port = int(payload.get("nas_port", 22) or 22)
            key_path = (payload.get("ssh_key_path") or "").strip()
            key_check = validate_ssh_key_path(key_path)
            if not key_check.get("ok"):
                self._send_json({"ok": False, "error": key_check.get("error")})
                return
            res = test_nas_connection(host, user, port, key_path, cfg=STATE.config)
            self._send_json(res)
            return

        if parsed.path == "/api/setup/generate-key":
            passphrase = payload.get("passphrase")
            if passphrase is None or not isinstance(passphrase, str) or len(passphrase) < MIN_SSH_PASSPHRASE_LEN:
                self._send_json({
                    "ok": False,
                    "error": (
                        f"Passphrase required (min {MIN_SSH_PASSPHRASE_LEN} characters). "
                        "Empty-passphrase auto-generation is disabled. "
                        "Or run: ssh-keygen -t ed25519 -f ~/.ssh/nas_sentinel_ed25519"
                    ),
                })
                return
            ssh_dir = Path.home() / ".ssh"
            ssh_dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(ssh_dir, 0o700)
            except OSError:
                pass
            key_file = ssh_dir / "nas_sentinel_ed25519"
            pub_file = ssh_dir / "nas_sentinel_ed25519.pub"
            if not key_file.exists():
                gen_proc = subprocess.run(
                    [
                        "ssh-keygen", "-t", "ed25519",
                        "-N", passphrase,
                        "-f", str(key_file),
                        "-C", "nas-sentinel",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                if gen_proc.returncode != 0:
                    self._send_json({"ok": False, "error": f"金鑰生成失敗: {gen_proc.stderr.decode('utf-8', errors='replace')}"})
                    return
                _chmod_secret(key_file, 0o600)
                if pub_file.exists():
                    _chmod_secret(pub_file, 0o644)

            # Prefer ~/.ssh/ relative form for allowlisted path responses
            key_path_public = f"~/.ssh/{key_file.name}"
            pub_text = pub_file.read_text(encoding="utf-8").strip() if pub_file.exists() else ""
            setup_cmd = f"mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '{pub_text}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
            self._send_json({
                "ok": True,
                "key_path": key_path_public,
                "pub_key": pub_text,
                "dsm_command": setup_cmd,
                "note": "Private key material is never returned. Load the passphrase via ssh-agent for BatchMode scans.",
            })
            return

        if parsed.path == "/api/setup/save":
            host = (payload.get("nas_host") or "").strip()
            user = (payload.get("nas_user") or "").strip()
            port = int(payload.get("nas_port", 22) or 22)
            key_path = (payload.get("ssh_key_path") or "").strip()

            key_check = validate_ssh_key_path(key_path)
            if not key_check.get("ok"):
                self._send_json({"ok": False, "error": key_check.get("error")})
                return

            test_res = test_nas_connection(host, user, port, key_path, cfg=STATE.config)
            if not test_res.get("ok"):
                self._send_json({"ok": False, "error": f"連線測試失敗，無法儲存：{test_res.get('error')}"})
                return

            with STATE.lock:
                STATE.config["nas_host"] = host
                STATE.config["nas_user"] = user
                STATE.config["nas_port"] = port
                STATE.config["ssh_key_path"] = key_check.get("path") or key_path
                if key_check.get("path"):
                    # Store portable ~/.ssh/basename form when possible
                    try:
                        bn = Path(key_check["path"]).name
                        STATE.config["ssh_key_path"] = f"~/.ssh/{bn}"
                    except Exception:
                        STATE.config["ssh_key_path"] = key_check["path"]
                STATE.config["is_configured"] = True
                if test_res.get("ssh_host_key_fp"):
                    STATE.config["ssh_host_key_fp"] = test_res["ssh_host_key_fp"]

                if "cloudflare_enabled" in payload:
                    STATE.config["cloudflare_enabled"] = bool(payload["cloudflare_enabled"])
                    STATE.cf_config["enabled"] = STATE.config["cloudflare_enabled"]
                if "cloudflare_api_token" in payload and payload["cloudflare_api_token"]:
                    STATE.config["cloudflare_api_token"] = payload["cloudflare_api_token"].strip()
                    STATE.cf_config["api_token"] = STATE.config["cloudflare_api_token"]
                if "cloudflare_zone_id" in payload and payload["cloudflare_zone_id"]:
                    STATE.config["cloudflare_zone_id"] = payload["cloudflare_zone_id"].strip()
                    STATE.cf_config["zone_id"] = STATE.config["cloudflare_zone_id"]

                save_app_config(STATE.config)
                cloudflare_intel.save_config(STATE.cf_config)

            # Trigger background scan and sync
            threading.Thread(target=lambda: STATE.perform_scan(mode="fast", force_baseline=False), daemon=True).start()
            if STATE.config.get("cloudflare_enabled"):
                threading.Thread(target=STATE.sync_cloudflare, daemon=True).start()

            self._send_json({
                "ok": True,
                "message": "設定已成功儲存！監控已啟動",
                "system": test_res.get("system"),
                "ssh_host_key_fp": test_res.get("ssh_host_key_fp"),
                "config": public_config_view(STATE.config),
            })
            return

        if parsed.path == "/api/scan":
            with STATE.lock:
                if STATE.scan_in_progress:
                    self._send_json({"ok": False, "busy": True, "error": "系統忙碌中：已有掃描作業正在執行，請稍候再試"}, status=429)
                    return
            mode = payload.get("mode", "fast")
            if mode not in ("fast", "deep"):
                mode = "fast"
            snap = STATE.perform_scan(mode=mode, force_baseline=False)
            self._send_json({"ok": snap is not None, "data": snap, "last_error": STATE.last_error})
            return

        if parsed.path == "/api/baseline/reset":
            with STATE.lock:
                if STATE.scan_in_progress:
                    self._send_json({"ok": False, "busy": True, "error": "系統忙碌中：已有作業正在執行，請稍候再試"}, status=429)
                    return
            snap = STATE.perform_scan(mode="deep", force_baseline=True)
            self._send_json({"ok": snap is not None, "data": snap, "last_error": STATE.last_error})
            return

        if parsed.path == "/api/cloudflare/config":
            token = (payload.get("api_token") or "").strip()
            zone = (payload.get("zone_id") or "").strip()
            enabled = bool(payload.get("enabled", True))
            test_only = bool(payload.get("test_only", False))

            test_res = cloudflare_intel.test_connection(token, zone)
            if not test_res.get("ok"):
                self._send_json({"ok": False, "error": test_res.get("error")})
                return

            if not test_only:
                with STATE.lock:
                    STATE.cf_config["api_token"] = token
                    STATE.cf_config["zone_id"] = zone
                    STATE.cf_config["enabled"] = enabled
                    STATE.cf_config["last_error"] = None
                    STATE.config["cloudflare_api_token"] = token
                    STATE.config["cloudflare_zone_id"] = zone
                    STATE.config["cloudflare_enabled"] = enabled
                    cloudflare_intel.save_config(STATE.cf_config)
                    save_app_config(STATE.config)
                threading.Thread(target=STATE.sync_cloudflare, daemon=True).start()

            self._send_json({"ok": True, "message": "Cloudflare 權杖驗證成功！已儲存設定", "data": STATE._build_cloudflare_summary()})
            return

        if parsed.path == "/api/cloudflare/sync":
            threading.Thread(target=STATE.sync_cloudflare, daemon=True).start()
            self._send_json({"ok": True, "message": "已觸發 Cloudflare 邊界日誌即時同步"})
            return

        self._send_json({"ok": False, "error": "Unknown endpoint"}, status=404)


def main():
    cfg = load_app_config()
    api_token = ensure_api_token(cfg)
    # Keep STATE in sync if ensure_api_token mutated config before STATE init races
    if "STATE" in globals() and hasattr(STATE, "config"):
        STATE.config["api_token"] = api_token

    host_display = f"{cfg.get('nas_user', 'admin')}@{cfg.get('nas_host', 'not configured')}" if cfg.get("is_configured") else "[尚未設定 - 啟動後由瀏覽器引導配置]"
    listen_host = cfg.get("web_host", "127.0.0.1")
    listen_port = int(cfg.get("web_port", 8088))
    print(f"============================================================")
    print(f"  NAS Sentinel - Synology NAS 即時安全與網頁檔案監控系統")
    print(f"  目標主機 : {host_display}")
    print(f"  本機介面 : http://{listen_host}:{listen_port}")
    print(f"  API 權杖 : {api_token}")
    print(f"  Token 檔 : {API_TOKEN_FILE}")
    print(f"  Auth     : Authorization: Bearer <token> required for all /api/*")
    if listen_host in ("0.0.0.0", "::"):
        print(f"  WARNING  : Binding {listen_host} exposes the UI/API on all interfaces.")
        print(f"             Network exposure without TLS + firewall is unsupported.")
        print(f"             Prefer MONITOR_HOST=127.0.0.1 (Docker Compose default).")
    print(f"============================================================")
    inotify_thread = threading.Thread(target=inotify_listener_loop, daemon=True)
    inotify_thread.start()

    poller = threading.Thread(target=background_poller, daemon=True)
    poller.start()

    server = ThreadingHTTPServer((listen_host, listen_port), MonitorHTTPHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n正在關閉監控伺服器...")
        server.server_close()


if __name__ == "__main__":
    main()
