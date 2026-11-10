#!/usr/bin/env python3
"""
Cloudflare Edge Threat Intelligence Client for NAS Sentinel
Fetches WAF security events, directory probing, and bot scanning logs
via Cloudflare GraphQL Analytics API using standard library urllib (zero dependencies).
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.request

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
CONFIG_FILE = DATA_DIR / "cloudflare_config.json"
EVENTS_FILE = DATA_DIR / "cloudflare_events.json"

GRAPHQL_ENDPOINT = "https://api.cloudflare.com/client/v4/graphql"

PROBE_RULES = [
    (re.compile(r"(\.env|config\.php|wp-config|database\.(ya?ml|json)|secrets?\.ya?ml|serverless\.ya?ml|\.aws/)", re.I), "敏感設定檔探測", "CRITICAL"),
    (re.compile(r"(wp-login|xmlrpc\.php|wp-admin|wp-content|wp-includes)", re.I), "WordPress / CMS 漏洞掃描", "WARNING"),
    (re.compile(r"(phpmyadmin|pma|adminer|mysqldumper|dbadmin)", re.I), "資料庫後台刺探", "CRITICAL"),
    (re.compile(r"(\.git/|\.svn/|\.hg/|\.bzr/|\.DS_Store)", re.I), "版本庫源碼洩漏掃描", "CRITICAL"),
    (re.compile(r"(shell|alfa|c99|r57|wso|b374k|cmd\.php|uploader)", re.I), "Webshell / 後門踩點", "CRITICAL"),
    (re.compile(r"(actuator|swagger-ui|api-docs|\.well-known|debug|graphql|\.next)", re.I), "API / 前端架構暴露探測", "WARNING"),
    (re.compile(r"(\.bak|\.old|\.zip|\.tar|\.sql|\.rar|\.7z)", re.I), "備份檔案下載嘗試", "WARNING"),
    (re.compile(r"(\.cgi|\.pl|\.sh|cgi-bin)", re.I), "CGI / 系統指令執行探測", "CRITICAL"),
]


def classify_probe(path: str, query: str = "", ua: str = "") -> dict:
    target = f"{path}?{query}" if query else path
    for pattern, label, severity in PROBE_RULES:
        if pattern.search(target):
            return {"label": label, "severity": severity}
    if any(bot in ua.lower() for bot in ("nmap", "sqlmap", "nikto", "masscan", "zgrab", "gobuster")):
        return {"label": "已知自動化滲透掃描器", "severity": "CRITICAL"}
    return {"label": "未明目錄刺探 / 爬蟲", "severity": "WARNING"}


def load_config() -> dict:
    default_conf = {
        "enabled": False,
        "api_token": os.environ.get("CF_API_TOKEN", ""),
        "zone_id": os.environ.get("CF_ZONE_ID", ""),
        "last_sync": None,
        "last_error": None,
    }
    if CONFIG_FILE.exists():
        try:
            stored = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            default_conf.update(stored)
        except Exception:
            pass
    return default_conf


def save_config(conf: dict):
    tmp = CONFIG_FILE.with_name(f"{CONFIG_FILE.name}.tmp")
    tmp.write_text(json.dumps(conf, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(CONFIG_FILE)
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except OSError:
        pass


def load_events() -> list:
    if EVENTS_FILE.exists():
        try:
            return json.loads(EVENTS_FILE.read_text(encoding="utf-8"))
        except Exception:
            return []
    return []


def save_events(events: list):
    tmp = EVENTS_FILE.with_name(f"{EVENTS_FILE.name}.tmp")
    tmp.write_text(json.dumps(events[:300], ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(EVENTS_FILE)


def test_connection(api_token: str, zone_id: str) -> dict:
    if not api_token or not zone_id:
        return {"ok": False, "error": "API Token 與 Zone ID 不能為空"}
    query = """
    query TestZone($zoneTag: string) {
      viewer {
        zones(filter: {zoneTag: $zoneTag}) {
          zoneTag
        }
      }
    }
    """
    req_payload = {
        "query": query,
        "variables": {"zoneTag": zone_id.strip()}
    }
    raw_data = json.dumps(req_payload).encode("utf-8")
    req = urllib.request.Request(
        GRAPHQL_ENDPOINT,
        data=raw_data,
        headers={
            "Authorization": f"Bearer {api_token.strip()}",
            "Content-Type": "application/json",
            "User-Agent": "NAS-Sentinel-Cloudflare/1.0"
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8", errors="replace"))
            if body.get("errors"):
                err_msg = "; ".join(e.get("message", "Unknown error") for e in body["errors"])
                return {"ok": False, "error": f"Cloudflare API 錯誤: {err_msg}"}
            zones = body.get("data", {}).get("viewer", {}).get("zones", [])
            if not zones:
                return {"ok": False, "error": "找不到此 Zone ID，請確認 Token 權限具備此 Zone 的存取權"}
            return {"ok": True, "message": "Cloudflare API 連線成功！"}
    except urllib.error.HTTPError as e:
        err_text = e.read().decode("utf-8", errors="replace")
        return {"ok": False, "error": f"HTTP {e.code}: {err_text[:120]}"}
    except Exception as e:
        return {"ok": False, "error": f"連線例外: {str(e)}"}


def fetch_edge_security_events(api_token: str, zone_id: str, hours: int = 24, limit: int = 100) -> dict:
    if not api_token or not zone_id:
        return {"ok": False, "error": "未設定 API Token 或 Zone ID"}

    since_iso = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=hours)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    query = """
    query GetFirewallEvents($zoneTag: string, $since: string, $limit: int) {
      viewer {
        zones(filter: {zoneTag: $zoneTag}) {
          firewallEventsAdaptive(
            filter: {datetime_geq: $since}
            limit: $limit
            orderBy: [datetime_DESC]
          ) {
            datetime
            action
            clientIP
            clientCountryName
            clientRequestHTTPHost
            clientRequestPath
            clientRequestQuery
            clientRequestHTTPMethodName
            userAgent
            edgeResponseStatus
            ruleId
            kind
            source
          }
        }
      }
    }
    """
    req_payload = {
        "query": query,
        "variables": {
            "zoneTag": zone_id.strip(),
            "since": since_iso,
            "limit": limit
        }
    }
    raw_data = json.dumps(req_payload).encode("utf-8")
    req = urllib.request.Request(
        GRAPHQL_ENDPOINT,
        data=raw_data,
        headers={
            "Authorization": f"Bearer {api_token.strip()}",
            "Content-Type": "application/json",
            "User-Agent": "NAS-Sentinel-Cloudflare/1.0"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            body = json.loads(resp.read().decode("utf-8", errors="replace"))
            if body.get("errors"):
                err_msg = "; ".join(e.get("message", "Unknown error") for e in body["errors"])
                return {"ok": False, "error": f"GraphQL Error: {err_msg}"}

            zones = body.get("data", {}).get("viewer", {}).get("zones", [])
            if not zones:
                return {"ok": True, "events": []}

            raw_events = zones[0].get("firewallEventsAdaptive", [])
            processed = []
            for ev in raw_events:
                path = ev.get("clientRequestPath") or "/"
                query_str = ev.get("clientRequestQuery") or ""
                ua = ev.get("userAgent") or ""
                ip = ev.get("clientIP") or ""
                dt = ev.get("datetime") or ""
                clf = classify_probe(path, query_str, ua)

                event_id = hashlib.sha1(f"{dt}:{ip}:{path}:{query_str}".encode()).hexdigest()[:12]
                processed.append({
                    "id": event_id,
                    "datetime": dt,
                    "action": (ev.get("action") or "log").upper(),
                    "ip": ip,
                    "country": ev.get("clientCountryName") or "Unknown",
                    "host": ev.get("clientRequestHTTPHost") or "",
                    "path": path,
                    "query": query_str,
                    "method": (ev.get("clientRequestHTTPMethodName") or "GET").upper(),
                    "user_agent": ua,
                    "status": ev.get("edgeResponseStatus") or 403,
                    "rule_id": ev.get("ruleId") or "",
                    "probe_label": clf["label"],
                    "severity": clf["severity"],
                })

            return {"ok": True, "events": processed}
    except urllib.error.HTTPError as e:
        err_text = e.read().decode("utf-8", errors="replace")
        return {"ok": False, "error": f"HTTP {e.code}: {err_text[:120]}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
