# NAS Sentinel 系統架構與設計規範 (System Architecture)

> **版本**：2.0 (整合 Linux Kernel inotify 串流與 DSM Rootkit 無套件核心引擎)  
> **最後更新**：2026-11-07  
> **適用目標**：Synology DS118 (DSM 7.4.1-90080 Update 1, Kernel 4.4.302+ aarch64)  
> **受控主機**：`shar@10.253.2.126` (Ed25519 SSH 認證)

---

## 1. 系統架構總覽

NAS Sentinel 是一套專為 Synology NAS 設計的**零足跡 (Zero Footprint)、毫秒級即時檔案完整性 (FIM) 與 Rootkit 防木馬安全監控系統**。

主控伺服器常駐於本地端 Windows 主機 (`D:\nas\nas-sentinel\`)，透過 SSH 遠端通道對 NAS 進行完全唯讀的遙測與即時核心事件攔截，提供直觀的即時 Web 儀表板 (`http://127.0.0.1:8088`)。

```
+---------------------------------------------------------------------------------+
| Windows 主機 (127.0.0.1)                                                        |
|                                                                                 |
|  [ start-nas-sentinel.bat ] -> 雙擊啟動                                         |
|                                                                                 |
|  +---------------------------------------------------------------------------+  |
|  | NAS Sentinel 本地端伺服器 (server.py) : Port 8088                           |  |
|  |  - Web UI / REST API: /api/status, /api/scan, /api/baseline/reset, ...     |  |
|  |  - MonitorState: 線程安全記憶體狀態、基線比對、安全評分計算                  |  |
|  |  - Persistent Storage: data/*.json (FIM, Ports, LKM, Events, History)    |  |
|  +---------------------------------------------------------------------------+  |
|          | (SSH 非交談式 stdin 串流)               ^ (inotify NDJSON stdout 串流)|
+----------|-----------------------------------------|----------------------------+
           v                                         |
+----------------------------------------------------+----------------------------+
| Synology DS118 NAS (10.253.2.126)                                               |
|                                                                                 |
|  1. collector_remote.py (定時 15 秒快速 / 手動深度輪詢)                           |
|     - 系統遙測: CPU、RAM、溫度、磁碟空間、SMART 狀態                             |
|     - 網頁與系統 FIM: 掃描 1,786 個關鍵檔案 SHA-256、權限、擁有者與 Webshell    |
|     - 網路與埠矩陣: netstat 連線與監聽埠比對                                     |
|     - Rootkit 檢測: 6 大核心檢測 (對標 chkrootkit + rkhunter)                    |
|                                                                                 |
|  2. inotify_stream_remote.py (Linux 核心 ctypes 毫秒級事件串流)                 |
|     - 監聽 254 個目錄 (/etc/nginx, /usr/syno/synoman, /bin, /usr/bin...)        |
|     - 攔截 CREATE, MODIFY, CLOSE_WRITE, ATTRIB, DELETE, MOVE                    |
|     - 毫秒級 SHA-256 即時重算，免 auditd、零磁碟寫入                            |
+---------------------------------------------------------------------------------+
```

---

## 2. 核心模組架構

### 2.1 主控服務器 (`nas-sentinel/server.py`)
- **Web UI & REST API**：使用 Python 內建 `http.server` 構建高效能非同步 API，支援靜態檔案伺服。
- **基線引擎**：
  - `fim_baseline.json`：儲存受保護之 1,786 個網頁伺服器與核心執行檔之 SHA-256、權限、擁有者。
  - `port_baseline.json`：核准開放之 TCP/UDP 監聽埠矩陣。
  - `http_baseline.json`：Nginx 80/443/5000/5001 端點回應 SHA-256 與 TLS 憑證指紋。
  - `lkm_baseline.json`：105 個合法載入之 Linux 核心模組白名單。
- **事件驅動雙軌制**：
  - 軌道一：15 秒自動輪詢 (`collector_remote.py`)。
  - 軌道二：後台長連線 inotify 串流線程，即時攔截檔案事件並在記憶體內毫秒級刷新快照與威脅狀態。

### 2.2 遠端遙測與 FIM 採集器 (`nas-sentinel/collector_remote.py`)
- 透過 `ssh shar@10.253.2.126 "python3 - <mode>"` 將程式碼由 stdin 注入執行，不在 NAS 硬碟遺留任何臨時檔案。
- 監控範疇：
  - `/etc/nginx`、`/usr/syno/share/nginx`（Nginx 核心設定）
  - `/usr/syno/synoman`、`/var/tmp/nginx/html`（DSM 系統網頁管理目錄）
  - `/volume1/web`（自架網站目錄）
  - `/bin`、`/usr/bin`、`/usr/sbin`、`/usr/syno/bin`、`/usr/syno/sbin`（20 個系統核心指令）
  - `/etc/sysctl.d`、`/usr/syno/etc/firewall.d`、`/etc/ssh`（安全防護設定）
  - `/volume1/public`、`/volume1/tmp`（敏感共享與暫存區）

### 2.3 DSM Rootkit 檢測引擎 (6 大檢測項目)
1. **系統核心執行檔防木馬替換**：比對 `/bin/ps`、`/bin/ls`、`/bin/netstat`、`/usr/bin/sudo` 等 20 個關鍵二進位檔之實體 SHA-256（支援 Symlink 目標本體穿透計算）。
2. **`LD_PRELOAD` 動態連結器劫持檢測**：監控 `/etc/ld.so.preload` 與全系統 `/proc/<pid>/environ`。
3. **隱藏幽靈程序與無檔案執行檔交叉比對**：比對 `/proc` 核心 PID 快照與 `ps -eo pid`，檢驗 `/proc/<pid>/exe` 指向 `(deleted)` 或從 `/dev/shm/`、`/tmp/` 執行之程序。
4. **網卡混雜模式封包竊聽檢測**：讀取 `/sys/class/net/*/flags` 驗證 `IFF_PROMISC` (`0x100`)。
5. **Linux 核心模組基線比對 (LKM Rootkit)**：動態比對 `/proc/modules` 是否載入非基線未知模組或惡意模組。
6. **已知 Rootkit 後門路徑與暫存區異常掃描**：比對常見 Rootkit 特徵目錄，並以 Magic Bytes 掃描 `/dev/shm`、`/tmp`、`/var/tmp` 是否出現非預期之 ELF 二進位執行檔。

### 2.4 核心 inotify 串流引擎 (`nas-sentinel/inotify_stream_remote.py`)
- 利用 Python 內建 `ctypes` 調用 Linux 核心 `libc.so.6` 之 `inotify_init1()`、`inotify_add_watch()` 與 `read()`。
- 監聽 254 個目錄，支援單檔父目錄過濾監聽（即使檔案遭 `vim`/`sed -i` 進行原子性置換，監聽通道依然不中斷）。
- 每當捕捉到寫入完成 (`IN_CLOSE_WRITE`) 或修改 (`IN_MODIFY`)，立即於 NAS 記憶體內計算 64KB 分塊 SHA-256 與 Webshell 滑動視窗特徵，輸出單行 JSON (NDJSON) 至 stdout 傳回本地端。

### 2.5 Cloudflare 邊界刺探情資引擎 (`nas-sentinel/cloudflare_intel.py`)
- 針對 NAS 透過 Cloudflare Tunnel 發布至公網之特性，直連 Cloudflare GraphQL Analytics API (`firewallEventsAdaptive`)。
- 零硬碟耗損、不開 DSM Nginx access log，直接從全球 Cloudflare 邊界拉取公網對網站目錄的探測掃描（包含 `/.env`、`wp-login`、`phpmyadmin`、`/.git`、Webshell 踩點與惡意爬蟲）。
- 自動分類攻擊行為（敏感設定檔探測、CMS 漏洞掃描、資料庫後台刺探、版本庫源碼洩漏等）並於 Web 儀表板實時告警。

---

## 3. 專案目錄結構

```
D:\nas\
├── start-nas-sentinel.bat       # Windows 一鍵啟動腳本
├── README.md                    # 專案說明文件
├── GEMINI.md                    # AI Agent 專案行為規則與禁止讀取過時檔案指南
├── AGENTS.md                    # 跨平台 Agent 規範
│
├── nas-sentinel/                # [核心主程式目錄]
│   ├── server.py                # 本地端 HTTP 伺服器、狀態管理與 REST API
│   ├── collector_remote.py      # NAS 遠端唯讀遙測、FIM 與 Rootkit 採集腳本
│   ├── inotify_stream_remote.py # NAS 遠端 Linux 核心 inotify 串流引擎
│   ├── cloudflare_intel.py      # Cloudflare 邊界 GraphQL 刺探情資客戶端
│   ├── static/                  # Web 前端介面
│   │   ├── index.html           # 視覺化儀表板 (Nine-Security Cyber SOC 風格)
│   │   ├── app.js               # 前端控制器與即時輪詢邏輯
│   │   ├── logo_v2.png          # Nine-Security 官方高解析度 Logo
│   │   └── favicon.png          # 官方 Favicon
│   └── data/                    # 監控資料與基線儲存區
│       ├── fim_baseline.json    # 1,786 個檔案之完整性基準
│       ├── port_baseline.json   # 網路監聽埠基準
│       ├── http_baseline.json   # Web 端點回應基準
│       ├── lkm_baseline.json    # 105 個核心模組基準
│       ├── events.json          # 安全事件日誌
│       ├── inotify_events.json  # inotify 毫秒事件日誌
│       ├── cloudflare_config.json # Cloudflare API 權杖與 Zone 設定
│       ├── cloudflare_events.json # 邊界刺探歷史情資紀錄
│       └── history.json         # 趨勢圖歷史數據
│
├── docs/                        # [專案文件目錄]
│   ├── ARCHITECTURE.md          # 系統架構與設計規範 (本文件，最新權威來源)
│   └── historical-audit-20261022/ # 歷史審計歸檔區 (2026-10-22 過時資料，僅供考古)
│       ├── README.md            # 歷史歸檔警示說明
│       ├── *.md                 # 歷史盤點報告
│       └── *.txt, *.json, *.log # 歷史原始探測日誌
│
└── scripts/                     # [輔助與歷史腳本目錄]
    └── legacy-audit-20261022/   # 2026-10-22 手動加固使用之一次性 Shell / Python 腳本
```

---

## 4. 運行與維護指引

- **背景常駐啟動**：雙擊 `D:\nas\start-nas-sentinel.bat`（採用 `pythonw.exe` 於系統純背景常駐，無黑視窗，關閉終端機或 agy 均不受影響），瀏覽器自動開啟 `http://127.0.0.1:8088`。
- **開機自啟動服務**：雙擊 `D:\nas\install-autostart-service.bat`，系統會自動在 Windows 工作排程器註冊常駐工作 `NAS-Sentinel`，開機登入 Windows 即自動運行。
- **停止背景服務**：雙擊 `D:\nas\stop-nas-sentinel.bat`，自動終止監聽 8088 埠之背景程序。
- **解除開機自啟**：雙擊 `D:\nas\uninstall-autostart-service.bat`。
- **重建基線**：當合法更新 DSM 韌體或修改 Web 設定後，點擊儀表板右上角「🛡️ 重建安全基線」按鈕或呼叫 `POST /api/baseline/reset`。
