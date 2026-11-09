# NAS Sentinel — Synology DSM 零足跡即時安全與檔案完整性監控系統

<p align="center">
  <a href="README.md">English</a> | <b>繁體中文</b>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://www.synology.com"><img src="https://img.shields.io/badge/Target-Synology%20DSM%207.x-00e5ff.svg" alt="Target: Synology DSM 7.x"></a>
  <img src="https://img.shields.io/badge/NAS%20Footprint-Zero%20(免安裝套件)-00ff41.svg" alt="Zero Footprint">
  <img src="https://img.shields.io/badge/Arch-ARM64%20%7C%20x86__64-orange.svg" alt="Architecture">
  <a href="http://127.0.0.1:8088"><img src="https://img.shields.io/badge/UI-Cyber%20SOC%20Dashboard-purple.svg" alt="UI Dashboard"></a>
</p>

NAS Sentinel 是一套專為 **Synology NAS (DSM 7.x)** 量身打造的**開源、生手友善、零足跡 (Zero Footprint)、毫秒級即時檔案完整性 (FIM) 與 Rootkit 防木馬安全監控系統**。

具備網頁版安裝引導精靈（Web Setup Wizard），不需要複雜的 Linux 技術，只要輸入 NAS IP，3 步驟即可在 3 分鐘內建立專屬的高科技 Cyberpunk 資安戰情室！

---

## 📋 事前準備 (只需 30 秒)

在啟動 NAS Sentinel 之前，請確認您的 Synology NAS 已開啟 SSH 服務：
1. 以管理員身分登入 Synology DSM 網頁桌面。
2. 前往 **「控制台」➔「終端機與 SNMP」**。
3. 勾選 **「啟用 SSH 服務」**（預設連接埠為 `22`）。
> *註：Synology DSM 7.x 系統韌體已原生內建 Python 3，NAS 端完全無需安裝任何套件！*

---

## ⚡ 3 步驟生手快速上手 (3-Minute Quickstart)

### 步驟 1：下載專案
下載本專案原始碼並解壓縮至本機任意目錄。

### 步驟 2：雙擊啟動
- **Windows 用戶**：雙擊根目錄下的 [`start-nas-sentinel.bat`](start-nas-sentinel.bat)。  
  *(系統會以純背景常駐運作，無擾人黑視窗，並自動開啟瀏覽器)*
- **macOS / Linux 用戶**：在終端機執行 `./start-nas-sentinel.sh`。
- **Docker 用戶**：執行 `docker-compose up -d`。

### 步驟 3：瀏覽器引導配置（Web Setup Wizard）
瀏覽器打開 `http://127.0.0.1:8088`，初次啟動將自動彈出 **「系統連線與安裝精靈」**：
1. **輸入主機資訊**：填入您的 NAS IP 與 SSH 帳號（系統會自動搜尋本機現存 SSH 金鑰，或點擊「🔑 自動產生新金鑰」）。
2. **點擊「⚡ 測試連線並自動探測 NAS」**：系統自動辨識 NAS 核心架構（x86_64 或 ARM64）與 DSM 韌體版本。
3. **點擊「🛡️ 儲存並進入戰情室」**：系統自動在背景建立初始 1,786 個系統檔案完整性與網路埠基線，立刻展開即時動態戰情室！

---

## 🚀 常駐服務與開機自啟動管理

NAS Sentinel 支援完全獨立於終端機/命令列的純背景常駐執行，關閉終端機或 IDE 均不會中斷：

### 1. 手動背景啟動
雙擊執行專案根目錄下的批次檔，伺服器會以 `pythonw.exe` 於系統背景運作，並自動開啟儀表板：
```bat
start-nas-sentinel.bat
```
- **儀表板網址**：`http://127.0.0.1:8088`

### 2. 開機自動啟動（最推薦）
將 NAS Sentinel 註冊為 Windows 開機登入自啟動排程，開機後系統在背景自動監控：
```bat
install-autostart-service.bat
```
- 若要移除開機自啟動排程，雙擊執行：`uninstall-autostart-service.bat`。

### 3. 一鍵停止背景服務
若需停止背景運作的 NAS Sentinel 伺服器，雙擊執行：
```bat
stop-nas-sentinel.bat
```

---

## 🌟 核心功能特色

1. **零足跡安全遙測 (Zero Footprint)**：
   - NAS 系統分割區通常僅約 2.3 GB，傳統資安 Agent（Wazuh, OSquery, Tripwire 等）過於厚重容易寫滿磁碟。
   - NAS Sentinel 所有採集均透過本機 Python 經由 SSH stdin 注入執行，輸出至 stdout，**完全不在 NAS 本地磁碟落檔、免安裝任何套件 (免 ipkg/opkg/gcc)**，記憶體與 CPU 佔用接近 0%。
2. **🕸️ 網頁伺服器與檔案完整性監控 (FIM)**：
   - 監控 Nginx 設定 (`/etc/nginx`)、DSM 網頁目錄 (`/usr/syno/synoman`)、自架網站目錄 (`/volume1/web`)、系統安全設定等 1,786 個關鍵檔案。
   - 嚴格比對 SHA-256 雜湊、Linux 權限模式、擁有者，並內建分塊滑動視窗 Webshell 特徵比對。
3. **⚡ Linux 核心 inotify 毫秒級事件串流**：
   - 使用 Python 內建 `ctypes` 調用 NAS Linux 核心 `libc.so.6` 的 inotify 系統呼叫，免安裝 auditd，零磁碟消耗。
   - 即時監聽 254 個目錄，捕捉新建、修改、寫入完成、更名、刪除與權限變更。
4. **🕵️ DSM Rootkit 與系統指令防木馬檢測**：
   - 實作對標 `chkrootkit` 與 `rkhunter` 的 6 大核心檢測：
     - 20 個系統指令 (`/bin/ps`, `ls`, `netstat`, `sshd`, `sudo`, `nginx` 等) 實體 SHA-256 驗證
     - `/etc/ld.so.preload` 與 `/proc/*/environ` 動態連結器劫持檢測
     - 隱藏幽靈程序與無檔案執行檔 (`/proc` vs `ps`) 交叉比對
     - 網卡混雜模式竊聽檢測 (`IFF_PROMISC`)
     - Linux 核心模組白名單比對 (105 個模組之 `lkm_baseline.json`)
     - 已知 Rootkit 特徵路徑與 `/dev/shm`、`/tmp` ELF 二進位執行檔偵測
5. **🌐 網路連線與監聽埠矩陣**：
   - 自動將活動網路連線分類為本機、區網 (LAN)、公網 (WAN)。
   - 即時比對監聽埠基線，任何非預期的新開放埠將立刻觸發高風險警報。
6. **🌐 Cloudflare 邊界網站刺探與 WAF 防禦情資 (Edge Threat Intelligence)**：
   - 針對 NAS 透過 Cloudflare Tunnel 發布至公網設計，直連 Cloudflare GraphQL Analytics API (`firewallEventsAdaptive`)。
   - 零硬碟耗損、不需開啟 DSM Nginx access log，即可自 Cloudflare 邊界節點拉取公網對網站目錄的探測與掃描紀錄（`/.env`、`wp-login`、`/.git`、Webshell 踩點與惡意爬蟲）。
   - 支援自動分類威脅等級（敏感設定檔探測、CMS 漏洞掃描、資料庫後台刺探等），提供 TOP 5 刺探目標與來源國家統計。
7. **🎨 Nine-Security 官方品牌 Cyber SOC 視覺系統**：
   - 採用 [Nine-Security](https://nine-security.com) 品牌高科技戰情室風格：深黑網格底圖 (`#050505`)、微環境掃描線 (Scanlines)、Terminal Matrix Green (`#00ff41`) 與 Cyber Cyan (`#00e5ff`)。
   - 引入 Google Fonts `Inter` 與 `JetBrains Mono`，搭配 DPR 銳利折線圖。
   - 內建 2 秒操作防刷冷卻、全域鎖定防呆與安全確認彈窗。

---

## 📁 目錄結構

```
nas-sentinel-project/
├── nas-sentinel/                # [主控核心程式碼]
│   ├── server.py                # 本機 HTTP 伺服器、狀態引擎、REST API 與排程
│   ├── collector_remote.py      # NAS 遠端唯讀遙測、FIM 與 Rootkit 採集腳本
│   ├── inotify_stream_remote.py # NAS 遠端 Linux 核心 inotify 毫秒串流引擎
│   ├── cloudflare_intel.py      # Cloudflare 邊界 GraphQL 刺探情資客戶端
│   ├── static/                  # Cyberpunk 戰情室 Web 前端
│   │   ├── index.html           # 儀表板與 Setup Wizard 前端介面
│   │   ├── app.js               # 前端控制器、狀態輪詢與安裝精靈
│   │   ├── logo_v2.png          # Nine-Security 品牌 Logo
│   │   └── favicon.png          # 官方 Favicon
│   └── data/                    # 基線與本機設定儲存區 (敏感設定已由 .gitignore 忽略)
│       ├── config.example.json  # 初始設定檔範本
│       ├── fim_baseline.json    # 系統檔案完整性基準
│       ├── port_baseline.json   # 網路監聽埠基準
│       └── lkm_baseline.json    # 核心模組基準
│
├── start-nas-sentinel.bat       # Windows 雙擊背景常駐啟動腳本
├── stop-nas-sentinel.bat        # Windows 一鍵停止服務腳本
├── install-autostart-service.bat# Windows 開機登入自啟動安裝檔
├── uninstall-autostart-service.bat # Windows 開機自啟動解除檔
├── start-nas-sentinel.sh        # Linux / macOS 一鍵啟動腳本
├── Dockerfile                   # Docker 容器化構建檔
├── docker-compose.yml           # Docker Compose 一鍵部署配置
├── LICENSE                      # MIT 開源授權條款
└── README.md                    # 英文版文件說明
```

---

## 📜 開源授權

本專案採用 **[MIT License](LICENSE)** 授權開源。由 **[Nine-Security.INC](https://nine-security.com)** 品牌維護與技術支援。
