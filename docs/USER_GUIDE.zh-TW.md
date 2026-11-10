# NAS Sentinel 功能操作與使用指南 (Feature & Operations Guide)

<p align="center">
  <a href="USER_GUIDE.md">English</a> | <b>繁體中文</b>
</p>

本手冊為 **NAS Sentinel** 的完整功能操作與維運指引，涵蓋系統架構原理、快速上手配置、雙遙測引擎操作、安全基準維護及常見問題排查。

---

## 1. 🚀 快速上手 (Quick Start)

### 1.1 系統運作架構
NAS Sentinel 採用**主從式無足跡架構 (Agentless Zero-Footprint)**：
* **控制端 (本機)**：本地端 Python 伺服器運行於 `http://127.0.0.1:8088`，負責儀表板呈現、基線比對、警報推播與歷史持久化。
* **受控端 (Synology NAS)**：不需在 NAS 上安裝任何套件（如 auditd, gcc 等），亦不在 NAS 磁碟或根目錄落檔。所有採集指令與腳本均透過 SSH stdin 注入記憶體中執行，輸出由 stdout 導回本地。

下方按鈕／選單名稱與應用內安裝精靈、管理選單一致。Docker、Windows 可攜式 Python、OpenSSH 用戶端等細節請見專案 [README（繁中）](../README.zh-TW.md)。

### 1.2 本機首次啟動（自動解鎖）
1. 啟動本機伺服器（Windows 雙擊 `start-nas-sentinel.bat`；macOS／Linux 執行 `./start-nas-sentinel.sh`）。瀏覽器會開啟 `http://127.0.0.1:8088`。
2. **建議路徑**：從此電腦開啟時，瀏覽器會自動取得並儲存 API Token（僅限迴路位址 `127.0.0.1` / `::1`）。正常流程不必再開 `api_token.txt`。
3. **備援**：伺服器仍會在主控台印出 Token，並寫入 `nas-sentinel/data/api_token.txt`（或使用 `.env` 的 `API_TOKEN`），供手動貼上。其餘 `/api/*` 請求仍需 `Authorization: Bearer <token>`。

### 1.3 首次連線設定（第一次連上 NAS）
**事前準備（與精靈步驟卡相同）**：在 DSM 開啟 SSH（**「控制台」➔「終端機與 SNMP」➔「終端機」**），並使用隸屬 `administrators` 的帳號。Windows 請啟用 **OpenSSH 用戶端**，以便精靈執行 `ssh`／`ssh-keygen`。

1. 點擊右上角「**⚙️ 管理 ▾**」➔「**⚙️ 系統連線與參數設定...**」（或依首次啟動的安裝精靈操作）。
2. 填寫 **NAS 區網 IP**（如 `192.168.1.100` — 勿填 `127.0.0.1`，那是本機儀表板）與 **SSH 登入帳號**（需在 `administrators`）。
3. **自訂 SSH Port**：若您的 NAS 變更過 SSH 監聽埠（例如 `2222`、`5022`），請在此填入對應埠號。
4. **SSH 金鑰配置**（精靈路徑 — 建議生手使用）：
   - 點擊「**🔑 產生專用金鑰**」，設定至少 **8 字元**的保護密碼（不允許空白密碼）。私鑰寫入本機 **`~/.ssh/nas_sentinel_ed25519`**（**不是** `data/`）。設定檔、API Token、known_hosts 則存放於 `nas-sentinel/data/`。
   - 點「**複製**」，再到 DSM **「控制台」➔「任務排程表」** → **新增 → 使用者定義的指令碼**。任務使用者選您的管理員帳號，貼上單行指令，儲存後點 **「執行」一次**。
   - 在這台電腦以 **`ssh-agent`** 解鎖金鑰一次，背景 BatchMode 掃描才能使用。
5. 點擊「**測試連線並探測 NAS**」，確認連線並取得 DSM／架構（成功時會釘選 Host Key 指紋）。失敗時介面會依錯誤類型提示接下來該怎麼做。
6. 點擊「**🛡️ 測試並上線**」寫入 `data/config.json`，SSH 成功時建立基線並進入戰情室。也可先「**儲存連線設定**」，稍後再上線。

> **可選／進階**：以電腦終端機（PowerShell／macOS）授權為備援路徑 — 見 README 方法 B。範例使用個人金鑰如 `id_ed25519`；精靈產生的專用金鑰一律為 `nas_sentinel_ed25519`。

---

## 2. 🔍 網頁與系統檔案完整性監控 (FIM & Scan)

### 2.1 掃描模式差異
* **快速掃描 (Fast Scan ~0.4 秒)**：
  - 聚焦於高危險副檔名（`.php`, `.sh`, `.cgi`, `.conf`, `.mustache` 等）以及關鍵設定檔（`/etc/passwd`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `authorized_keys`）。
  - 適合由背景排程（預設每 15 秒）高頻自動探測。
* **深度掃描 (Deep Scan ~3.5 秒)**：
  - 對 DSM 網頁樹與核心二進位執行檔進行完整的 **SHA-256 雜湊值** 計算與對比（一般 DSM 可達數千個路徑；精確數量依基線與 DSM 版本而定）。
  - 偵測檔案是否被駭客置換木馬、植入隱蔽後門或變更擁有者權限。

### 2.2 檢索監控檔案清單
- 點擊「**⚙️ 管理 ▾**」➔「**🗄️ 檢索監控檔案**」（選單可能顯示目前基線的檔案數量）。
- 可在「檔案完整性監控」分頁中即時過濾、搜尋所有受監控檔案的完整路徑、檔案大小、修改時間 (mtime) 與 SHA-256 雜湊碼。

### 2.3 何時需要「重建安全基線」？
* 當發生下列**合法維護操作**時，系統會因偵測到檔案變更而觸發警報：
  1. 剛完成 Synology DSM 官方韌體更新。
  2. 合法安裝或更新套件（如 Web Station、File Station、Python）。
  3. 管理員主動編輯了合法設定檔或更新了 SSH 公鑰。
* **操作步驟**：
  1. 點擊右上角「**⚙️ 管理 ▾**」➔「**🛡️ 重建安全基線...**」。
  2. 閱讀確認事項後點擊「**⚠️ 確認重建基準**」。
  3. 系統將以當前狀態作為全新的「安全黃金基準 (Golden Baseline)」，並清除先前的異動警報。

---

## 3. ⚡ 即時核心事件串流 (inotify Kernel Stream)

### 3.1 毫秒級事件捕捉原理
除了週期性輪詢外，NAS Sentinel 支援即時核心串流引擎：
- 透過 Linux 核心 `inotify` 機制，在檔案被 `IN_CLOSE_WRITE`（寫入完成）、`IN_MOVED_TO`（檔案移入）、`IN_CREATE`（建立）或 `IN_ATTRIB`（權限/屬性變更）的**毫秒瞬間**即時回傳告警。

### 3.2 內建即時威脅特徵庫
* **Webshell 動態啟發式偵測**：
  - 針對上傳至 `/volume1/public`、`/volume1/tmp` 或 DSM 網頁目錄的檔案，即時掃描特徵字串（如 `eval(base64_decode(...))`、`passthru`、`shell_exec`、`assert`）。
* **SUID 提權監控**：
  - 偵測是否有二進位程式被賦予 `chmod +s` 提權旗標，防止本機權限提升攻擊。
* **授權金鑰偷渡防護**：
  - 任何對 `~/.ssh/authorized_keys` 或 `/root/.ssh/authorized_keys` 的非法寫入皆會立即觸發最高危險警報。

---

## 4. 🌐 Cloudflare 邊界日誌監控 (Edge Intel)

### 4.1 邊界刺探情資價值
* 將攻擊者對您網域的「惡意路徑爆破」與「WAF 攔截事件」擋在 Cloudflare 全球 CDN 邊界，完全不耗損 NAS 本地硬碟 I/O 與 CPU 算力。
* 即時統計外部攻擊來源 IP、攻擊國家、目標惡意目錄（如 `/.git/config`、`/wp-login.php`、`/.env`）與 WAF 觸發規則。

### 4.2 設定步驟
1. 進入 Cloudflare Dashboard ➔ **My Profile** ➔ **API Tokens**。
2. 建立具備 **`Zone - Analytics - Read`** 單一唯讀權限的 API Token。
3. 進入網域主頁（Overview），從右下方複製 **Zone ID**（32 位元字串）。
4. 開啟「**⚙️ 管理 ▾**」➔「**系統連線與參數設定...**」，展開 Cloudflare 區塊填入資訊。
5. 點擊「**🧪 測試連線**」驗證無誤後勾選「啟用自動同步」，點擊儲存即可開始每 60 秒排程拉取情資。

---

## 5. 🔌 網路監聽埠與帳號安全審計

### 5.1 監聽埠矩陣 (Listening Ports Matrix)
* **基準比對機制**：系統內建受信任的網路監聽埠基準（如 SSH、DSM HTTP 5000/5001、Nginx 80/443）。
* **異常標紅**：若有未授權程序開啟了未知埠（如反向 Shell 監聽埠 4444、9999 或惡意代理），該監聽埠將立即標紅並列入告警清單。

### 5.2 活動工作階段 (utmp) 與公鑰指紋
* **目前活動登入**：解析 `/var/run/utmp`，即時呈現目前連線中的終端機 (TTY)、來源 IP 與登入時間。
* **授權公鑰指紋**：自動掃描各用戶目錄下的 `authorized_keys`，核算並列出 SHA-256 指紋前 16 碼，方便管理員隨時盤點是否有幽靈金鑰偷渡。

---

## 6. 🎨 主題切換與多語系支援

* **主題切換 (Dark / Light)**：
  - 點選右上角圖示（`🌙` / `☀️`）即時切換。
  - 深色主題採用 Cyberpunk 暗黑綠光；淺色主題對齊 Nine-Security 官方標準，透過 180° 色相翻轉技術提供清晰專業的科技商務藍視覺。
* **多語系切換 (zh-TW / EN / JP)**：
  - 點選右上角 `🌐 語系選單`，支援 **繁體中文 (TW)**、**English (EN)**、**日本語 (JP)** 三語系即時無縫切換。

---

## 7. ❓ 常見問題排查 (FAQ)

### Q1：戰情室突然跳出「🚨 偵測到檔案完整性異常」紅框警報？
1. 檢視首頁的「**檔案異動警報**」表格，確認變更檔案的路徑與修改時間。
2. **若為本人合法操作**（如剛剛升級 DSM 或編輯設定）：點選「**管理 ➔ 重建安全基線**」即可消除警報。
3. **若非本人操作**：請立即切斷 NAS 對外連線，檢查該檔案內容並檢查 utmp 登入紀錄。

### Q2：為什麼快速掃描只需 0.4 秒？會不會漏掉變更？
- 快速掃描採取目標化設計，直接比對檔案大小與修改時間 (mtime)，並針對核心 Web 執行檔比對雜湊。配合高頻輪詢與 inotify 核心串流，可維持即時偵測且對 NAS 負擔輕量。

### Q3：如何手動停止或重新啟動 NAS Sentinel 伺服器？
- **Windows：** 啟動程式會以背景常駐執行 — **關閉命令視窗並不會停止服務**。請雙擊 [`stop-nas-sentinel.bat`](../stop-nas-sentinel.bat) 結束伺服器並釋放 8088 連接埠，再雙擊 [`start-nas-sentinel.bat`](../start-nas-sentinel.bat) 重新啟動。
- **macOS／Linux：** 結束佔用 8088 連接埠的 Python 行程（例如依 `./start-nas-sentinel.sh` 啟動的 PID），再執行 `./start-nas-sentinel.sh`。
- **Docker：** 在專案根目錄執行 `docker compose down`／`docker compose up -d`（Compose 僅綁定 `127.0.0.1:8088`）。
