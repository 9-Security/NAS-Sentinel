// NAS Sentinel Frontend Controller
let autoPoll = true;
let pollInterval = 3;
let countdown = 3;
let currentSnapshot = null;
let searchTimer = null;
let currentLang = "zh-TW";

// Anti-Fooling & Concurrency Controls
let isOperationBusy = false;
let lastScanCompletedTime = 0;
let lastPollToggleTime = 0;
let toastTimeout = null;

// API auth (Authorization Bearer — CSRF-resistant; required for all /api/* except /api/auth/status)
const API_TOKEN_STORAGE_KEY = "nas_sentinel_api_token";
let apiAuthPromptOpen = false;

function getApiToken() {
  try {
    return (localStorage.getItem(API_TOKEN_STORAGE_KEY) || "").trim();
  } catch (_) {
    return "";
  }
}

function setApiToken(token) {
  const cleaned = (token || "").trim();
  try {
    if (cleaned) localStorage.setItem(API_TOKEN_STORAGE_KEY, cleaned);
    else localStorage.removeItem(API_TOKEN_STORAGE_KEY);
  } catch (_) { /* ignore quota / private mode */ }
  return cleaned;
}

function apiAuthHeaders(extra) {
  const headers = Object.assign({}, extra || {});
  const token = getApiToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;
  return headers;
}

function showApiAuthModal(reason) {
  const modal = document.getElementById("apiAuthModal");
  const input = document.getElementById("apiAuthTokenInput");
  const msg = document.getElementById("apiAuthMsg");
  if (!modal) {
    const pasted = window.prompt(
      "API token required. Paste from data/api_token.txt or server console / API_TOKEN env:",
      getApiToken()
    );
    if (pasted) setApiToken(pasted);
    return;
  }
  if (msg) {
    msg.textContent = reason || "All /api/* routes require Authorization: Bearer <token>.";
    msg.style.display = "block";
  }
  if (input) input.value = getApiToken();
  modal.style.display = "flex";
  apiAuthPromptOpen = true;
  if (input) input.focus();
}

function closeApiAuthModal() {
  const modal = document.getElementById("apiAuthModal");
  if (modal) modal.style.display = "none";
  apiAuthPromptOpen = false;
}

function saveApiAuthTokenFromModal() {
  const input = document.getElementById("apiAuthTokenInput");
  const token = input ? input.value.trim() : "";
  if (!token) {
    showToast("⚠️ Please paste a non-empty API token", "warn");
    return;
  }
  setApiToken(token);
  closeApiAuthModal();
  showToast("🔐 API token saved in this browser", "info");
  loadAppConfig();
  fetchStatus();
}

async function apiFetch(url, options) {
  const opts = Object.assign({}, options || {});
  const baseHeaders = opts.body ? { "Content-Type": "application/json" } : {};
  opts.headers = apiAuthHeaders(Object.assign(baseHeaders, opts.headers || {}));
  const res = await fetch(url, opts);
  if (res.status === 401 && !apiAuthPromptOpen) {
    showApiAuthModal("Unauthorized — enter the API token from data/api_token.txt or API_TOKEN.");
  }
  return res;
}

// ==========================================
// Multilingual Translation Dictionary (I18N)
// Compatible with Nine-Security Standards
// ==========================================
const I18N = {
  "zh-TW": {
    "brand.sub_default": "主機: NAS123 • 載入中...",
    "brand.threat_init": "連線初檢中...",
    "poll.active": "自動輪詢",
    "poll.paused": "輪詢暫停",
    "poll.toggle_title": "點擊切換 自動定時輪詢 / 暫停",
    "poll.toast_active": "⏱️ 已開啟背景自動輪詢 (每 15 秒更新一次)",
    "poll.toast_paused": "⏸️ 背景自動輪詢已暫停 (手動模式)",
    "scan.fast": "快速掃描",
    "scan.fast_title": "快速掃描：核心系統設定、關鍵網頁與開放埠 (約 0.8 秒)",
    "scan.deep": "🔍 深度",
    "scan.deep_title": "深度掃描：全量 DSM 網頁樹與 1,786 檔完整 SHA-256 (約 3.5 秒)",
    "scan.busy_toast": "⚠️ 目前已有掃描或系統作業正在進行中，請稍候...",
    "top.settings": "設定",
    "top.settings_title": "開啟連線與系統設定精靈",
    "top.admin": "⚙️ 管理 ▾",
    "admin.baseline_header": "安全基準維護",
    "admin.rebuild_baseline": "重建安全基線...",
    "admin.rebuild_desc": "將當前狀態寫入為合法基準",
    "admin.tools_header": "快速工具",
    "admin.search_files": "檢索 1,786 監控檔案",
    "admin.system_settings": "系統連線與參數設定...",
    "admin.system_settings_desc": "設定 NAS IP、SSH 金鑰與 Cloudflare",
    "admin.user_guide": "系統功能操作手冊...",
    "admin.user_guide_desc": "快速上手、FIM、inotify 與 Cloudflare 指南",
    "guide.modal_title": "NAS Sentinel 系統功能操作手冊 (Operations Guide)",
    "guide.tab_quickstart": "🚀 快速上手",
    "guide.tab_fim": "🔍 檔案完整性 (FIM)",
    "guide.tab_inotify": "⚡ 核心即時串流",
    "guide.tab_cf": "🌐 Cloudflare 邊界情資",
    "guide.tab_audit": "🔌 網路與金鑰審計",
    "guide.tab_faq": "❓ 常見問題 FAQ",
    "guide.btn_github": "在 GitHub 閱讀完整技術文檔",
    "guide.btn_gotit": "我知道了 (Got it)",
    "guide.content_quickstart": '<div class="guide-card"><div class="guide-card-title"><span class="guide-step-badge">1</span> 系統零足跡架構原理 (Zero-Footprint Architecture)</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">NAS Sentinel 採主從式無足跡架構。本機端 Python 伺服器（<code>http://127.0.0.1:8088</code>）透過 SSH 加密通道將遙測探針注入 NAS 記憶體中執行，<strong>完全不在 NAS 本地磁碟落檔、不佔用系統空間、亦不需安裝任何第三方套件</strong>。</p></div><div class="guide-card"><div class="guide-card-title"><span class="guide-step-badge">2</span> 首次連線設定與金鑰授權 (Setup & SSH Key)</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">1. 點擊右上角「⚙️ 管理 ▾」➔「系統連線與參數設定...」。<br>2. 輸入 NAS IP 與 SSH 帳號（需具備 administrators 權限）。若變更過 SSH Port（如 2222），請一併修改。<br>3. 點選「🔑 產生專用 Ed25519 金鑰」，展開快速授權指令並複製單行指令至 NAS 終端機貼上執行一次即可完成免密授權。<br>4. 點擊「🧪 測試 NAS 連線」，確認連線成功後儲存進入戰情室。</p></div><div class="guide-card"><div class="guide-card-title"><span class="guide-step-badge">3</span> 自動排程與即時推播 (Telemetry Modes)</div><p style="font-size:12.5px; color:var(--text-secondary);">- <strong>背景輪詢</strong>：預設每 15 秒自動探測一次 NAS 系統指標、網路連線與關鍵檔案異動。<br>- <strong>核心串流</strong>：利用 Linux inotify 即時捕捉檔案新增、修改與權限變更，具備毫秒級告警推播能力。</p></div>',
    "guide.content_fim": '<div class="guide-card"><div class="guide-card-title">⚡ 快速掃描 vs 深度掃描</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">- <strong>快速掃描 (Fast Scan ~0.4s)</strong>：每 15 秒自動觸發，針對 <code>.php</code>, <code>.sh</code>, <code>.cgi</code>, <code>.conf</code> 等高風險檔案與帳號設定比對修改時間 (mtime) 與檔案大小。<br>- <strong>深度掃描 (Deep Scan ~3.5s)</strong>：全量計算全系統 1,786 個 DSM 網頁核心檔案與系統二進位指令的 <strong>完整 SHA-256 雜湊碼</strong>，徹底揪出被偷換的木馬檔案。</p></div><div class="guide-card"><div class="guide-card-title">🛡️ 何時需要「重建安全基線」？</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">當您進行了下列<strong>合法維護操作</strong>時，戰情室會偵測到變更並顯示紅框警報：<br>1. 剛完成 Synology DSM 韌體升級。<br>2. 安裝或更新了官方套件（如 Web Station、Python）。<br>3. 管理員主動編輯了合法設定檔或更新了 SSH 金鑰。<br>此時請點擊「<strong>⚙️ 管理 ▾ ➔ 重建安全基線...</strong>」，系統將以目前狀態寫入為新的合法黃金基準並清除異動警報。</p></div><div class="guide-card"><div class="guide-card-title">🗄️ 檢索監控清單 (Search Monitored Files)</div><p style="font-size:12.5px; color:var(--text-secondary);">點選管理選單中的「檢索 1,786 監控檔案」，即可在 FIM 分頁搜尋過濾所有受監控檔案的完整路徑、SHA-256 雜湊碼與擁有者權限。</p></div>',
    "guide.content_inotify": '<div class="guide-card"><div class="guide-card-title">⚡ Linux inotify 核心事件串流機制</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">透過在 NAS 核心常駐之 inotify 監控程序，主動監控 <code>/usr/syno/synoman</code>, <code>/etc/nginx</code>, <code>/volume1/public</code>, <code>/volume1/tmp</code> 等敏感路徑。在檔案被寫入完成 (CLOSE_WRITE) 或屬性變更 (ATTRIB) 的毫秒瞬間，即時透過 stdout 推播回戰情室。</p></div><div class="guide-card"><div class="guide-card-title">🚨 Webshell 啟發式動態偵測</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">當任何檔案被寫入共享區或網頁目錄時，引擎自動檢查內容是否包含後門特徵：<br><code>eval(base64_decode(...))</code>, <code>passthru()</code>, <code>shell_exec()</code>, <code>assert()</code>。<br>一旦命中特徵，即時將威脅等級升至最高級別並標紅警示。</p></div><div class="guide-card"><div class="guide-card-title">🚫 SUID 提權與未授權公鑰寫入防護</div><p style="font-size:12.5px; color:var(--text-secondary);">- 嚴密防範 <code>chmod +s</code> 本機提權後門。<br>- 任何未經允許對 <code>~/.ssh/authorized_keys</code> 寫入的行為皆會被毫秒級捕捉。</p></div>',
    "guide.content_cf": '<div class="guide-card"><div class="guide-card-title">🌐 邊界刺探情資 (Edge Security Intel)</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">透過 Cloudflare GraphQL API，直接從全球邊界 CDN 節點拉取外部對您網域的「惡意目錄刺探（如 <code>/.git/config</code>, <code>/wp-login.php</code>, <code>/.env</code>）」與「WAF 攔截事件」，完全不耗損 NAS 本地硬碟 I/O。</p></div><div class="guide-card"><div class="guide-card-title">🔑 API Token 建立與權限規範</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">1. 前往 Cloudflare ➔ <strong>My Profile</strong> ➔ <strong>API Tokens</strong>。<br>2. 建立 Token，權限僅需給予單一項目：<strong><code>Zone - Analytics - Read</code></strong>。<br>3. 進入網域主頁，從右下方複製 <strong>Zone ID</strong>（32 位元字串）。</p></div><div class="guide-card"><div class="guide-card-title">🧪 測試連線功能 (Test Connection)</div><p style="font-size:12.5px; color:var(--text-secondary);">在設定精靈的 Cloudflare 區塊輸入後，可隨時點擊「<strong>🧪 測試連線 (Test)</strong>」確認 Token 與 Zone ID 的有效性，驗證通過再點擊儲存啟用。</p></div>',
    "guide.content_audit": '<div class="guide-card"><div class="guide-card-title">🔌 監聽埠矩陣與異常報警 (Port Baseline)</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">系統預設記錄合法監聽埠基準（如 SSH 22, DSM 5000/5001, Nginx 80/443）。一旦有未授權程序開啟了未知 Port（例如反向 Shell 監聽埠或未知代理服務），該埠號將立即在總覽面板標紅警報。</p></div><div class="guide-card"><div class="guide-card-title">🔑 活動工作階段 (utmp) 審計</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">即時解析 <code>/var/run/utmp</code>，呈現目前連線中的終端機 (TTY)、來源 IP 與登入時間，協助您掌握 NAS 目前是否有未預期的活動連線。</p></div><div class="guide-card"><div class="guide-card-title">🛡️ SSH 授權公鑰雜湊盤點</div><p style="font-size:12.5px; color:var(--text-secondary);">自動掃描各用戶目錄下之 <code>authorized_keys</code>，核算金鑰類型與 SHA-256 指紋前 16 碼，杜絕幽靈金鑰偷渡與持久化存取。</p></div>',
    "guide.content_faq": '<div class="guide-card"><div class="guide-card-title">Q1: 收到「🚨 偵測到檔案完整性異常」紅框警報該怎麼做？</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">1. 點擊頂部「查看檔案異動詳情」表格，確認變更檔案的路徑與修改時間。<br>2. <strong>若為您本人的合法操作</strong>（如剛升級 DSM 或修改設定）：點選「⚙️ 管理 ▾ ➔ 重建安全基線」消除警報。<br>3. <strong>若非本人操作</strong>：請立即檢查登入紀錄並將可疑檔案隔離。</p></div><div class="guide-card"><div class="guide-card-title">Q2: 為什麼 NAS Sentinel 監控不會影響 NAS 效能？</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">採集腳本由本機端注入 NAS 記憶體中執行，無磁碟 I/O 寫入負擔，單次快速掃描僅約 0.4 秒，CPU 佔用小於 1%，絕不縮短硬碟壽命。</p></div><div class="guide-card"><div class="guide-card-title">Q3: 如何重啟或關閉 NAS Sentinel？</div><p style="font-size:12.5px; color:var(--text-secondary);">本地伺服器為獨立執行程序，關閉啟動終端機即可停止；重新雙擊 <code>start-nas-sentinel.bat</code> 即可重啟。</p></div>',
    "admin.cf_settings": "Cloudflare 邊界日誌設定...",
    "admin.cf_desc": "設定 API Token 撈取刺探情報",
    "theme.toggle_title": "切換深色 / 淺色主題 (Toggle Dark/Light Mode)",
    "lang.toggle_title": "切換語系 (Select Language)",
    "alert.banner_title": "🚨 偵測到檔案完整性或安全異常！",
    "alert.banner_desc": "請立即檢視下方「檔案異動警報」或「網路監聽埠」清單。",
    "alert.btn_details": "查看檔案異動詳情",
    "kpi.fim_title": "網頁與系統檔案監控 (FIM)",
    "kpi.web_title": "Nginx 網頁端點與 HTTPS 探測",
    "kpi.net_title": "監聽埠與外部網路連線",
    "kpi.cpu_title": "CPU 負載與系統溫度",
    "kpi.mem_title": "記憶體與 Swap 使用率",
    "kpi.disk_title": "儲存空間 (/volume1) 與服務",
    "kpi.status_ok": "正常",
    "kpi.status_warn": "異常",
    "kpi.status_crit": "緊急",
    "kpi.baseline_ok": "符合基線",
    "kpi.smart_ok": "SMART 通過",
    "kpi.smart_warn": "SMART 警告",
    "tabs.overview": "📊 即時視覺化總覽與告警",
    "tabs.fim": "🕸️ 網頁伺服器與檔案完整性 (FIM)",
    "tabs.network": "🌐 網路連線與監聽埠矩陣",
    "tabs.security": "🕵️ Rootkit 偵測、登入活動與守護程序",
    "overview.trend_title": "📈 系統遙測趨勢 (CPU / 記憶體 / 溫度)",
    "overview.threat_gauge_title": "🛡️ 當前 NAS 即時威脅綜合評級",
    "overview.inotify_stream_title": "⚡ 即時檔案異動事件串流 (inotify Remote Stream)",
    "overview.http_matrix_title": "🌐 Nginx 關鍵網頁端點探測矩陣 (HTTP Baseline & Latency)",
    "overview.cf_title": "☁️ Cloudflare 邊界安全事件防護",
    "reset.title": "🛡️ 重建 NAS 安全基準確認",
    "reset.confirm_question": "您確定要將 NAS 目前的狀態重設為「受信任安全基準 (Trusted Baseline)」嗎？",
    "reset.btn_confirm": "⚠️ 確認重建基準",
    "reset.btn_cancel": "取消",
    "cf.title": "🌐 Cloudflare 邊界日誌 API 連線設定",
    "cf.btn_test": "🧪 測試連線",
    "cf.btn_save": "💾 儲存並啟用",
    "cf.btn_cancel": "取消",
    "setup.title": "NAS Sentinel // 系統連線與安裝精靈",
    "setup.sub": "Zero-Footprint Synology DSM 即時安全監控",
    "setup.quick_title": "✨ 零技術門檻快速啟用 (Quick Setup)",
    "setup.quick_desc": "輸入您的 Synology NAS 內部 IP 與 SSH 帳號，點擊「⚡ 測試連線與自動探測 NAS」，系統將自動檢測 DSM 版本、CPU 架構並在背景初始化安全基線。",
    "setup.ssh_help_header": "💡 初次使用？如何取得 Synology NAS 的 SSH 連線與金鑰權限？",
    "setup.ssh_help_show": "▶ 展開教學",
    "setup.ssh_help_hide": "▼ 收合教學",
    "setup.host_label": "NAS 主機 IP / 網址",
    "setup.user_label": "SSH 登入帳號",
    "setup.port_label": "SSH Port (可自訂)",
    "setup.key_label": "SSH 私鑰路徑 (Authentication Key)",
    "setup.keygen_link": "🔑 自動產生新金鑰與教學",
    "setup.btn_test": "測試 SSH 連線並自動探測 NAS",
    "setup.cf_header": "🌐 Cloudflare 邊界日誌監控 (選填，可稍後設定)",
    "setup.btn_save": "🛡️ 儲存並進入戰情室 (Save & Launch)",
    "setup.btn_close": "關閉",
    "setup.footnote": "🔒 密鑰僅儲存在本地端 data/ 目錄"
  },
  "en": {
    "brand.sub_default": "Host: NAS123 • Loading...",
    "brand.threat_init": "Connecting...",
    "poll.active": "Auto-Poll",
    "poll.paused": "Paused",
    "poll.toggle_title": "Toggle Periodic Auto-Poll / Pause",
    "poll.toast_active": "⏱️ Background auto-polling active (refreshes every 15s)",
    "poll.toast_paused": "⏸️ Background auto-polling paused (manual mode)",
    "scan.fast": "Fast Scan",
    "scan.fast_title": "Fast Scan: Core config, web & listening ports (~0.8s)",
    "scan.deep": "🔍 Deep",
    "scan.deep_title": "Deep Scan: Full DSM web tree & 1,786 SHA-256 checks (~3.5s)",
    "scan.busy_toast": "⚠️ A scan or operation is already in progress, please wait...",
    "top.settings": "Settings",
    "top.settings_title": "Open Connection & Settings Wizard",
    "top.admin": "⚙️ Admin ▾",
    "admin.baseline_header": "Baseline Maintenance",
    "admin.rebuild_baseline": "Rebuild Baseline...",
    "admin.rebuild_desc": "Save current NAS state as golden baseline",
    "admin.tools_header": "Quick Tools",
    "admin.search_files": "Search 1,786 Monitored Files",
    "admin.system_settings": "System Connection & Settings...",
    "admin.system_settings_desc": "Configure NAS IP, SSH Key & Cloudflare",
    "admin.user_guide": "Feature & Operations Guide...",
    "admin.user_guide_desc": "Quick start, FIM, inotify & Cloudflare guide",
    "guide.modal_title": "NAS Sentinel Operations & Feature Guide",
    "guide.tab_quickstart": "🚀 Quick Start",
    "guide.tab_fim": "🔍 File Integrity (FIM)",
    "guide.tab_inotify": "⚡ Real-Time Stream",
    "guide.tab_cf": "🌐 Cloudflare Intel",
    "guide.tab_audit": "🔌 Ports & SSH Keys",
    "guide.tab_faq": "❓ FAQ",
    "guide.btn_github": "View Full Tech Docs on GitHub",
    "guide.btn_gotit": "Got it",
    "guide.content_quickstart": '<div class="guide-card"><div class="guide-card-title"><span class="guide-step-badge">1</span> Zero-Footprint Architecture</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">NAS Sentinel operates in an agentless, zero-footprint model. The local Python server (<code>http://127.0.0.1:8088</code>) injects lightweight telemetry probes into the NAS via SSH encrypted memory execution. <strong>Zero files are written to NAS disks, zero root partition space is used, and no extra packages are required</strong>.</p></div><div class="guide-card"><div class="guide-card-title"><span class="guide-step-badge">2</span> Initial Connection & SSH Key Authorization</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">1. Open "⚙️ Admin ▾" ➔ "System Connection & Settings...".<br>2. Enter your NAS IP and SSH account (must belong to the administrators group). If using a custom SSH port (e.g. 2222), enter it here.<br>3. Click "🔑 Generate Dedicated Ed25519 Key", expand the quick authorization command, and paste it into your NAS terminal once.<br>4. Click "🧪 Test NAS Connection" to verify DSM and Linux kernel details, then click Save & Launch.</p></div><div class="guide-card"><div class="guide-card-title"><span class="guide-step-badge">3</span> Telemetry & Push Modes</div><p style="font-size:12.5px; color:var(--text-secondary);">- <strong>Background Polling</strong>: Automatically probes system metrics, network connections, and key file changes every 15 seconds.<br>- <strong>Kernel Streaming</strong>: Leverages Linux inotify to detect file creations, edits, and permission changes with sub-second alert dispatch.</p></div>',
    "guide.content_fim": '<div class="guide-card"><div class="guide-card-title">⚡ Fast Scan vs Deep Scan</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">- <strong>Fast Scan (~0.4s)</strong>: Automatically runs every 15s. Audits high-risk files (<code>.php</code>, <code>.sh</code>, <code>.cgi</code>, <code>.conf</code>) and security configs by comparing mtime and size.<br>- <strong>Deep Scan (~3.5s)</strong>: Computes full <strong>SHA-256 hashes</strong> across all 1,786 DSM web files and system binaries to expose stealthy backdoor replacements.</p></div><div class="guide-card"><div class="guide-card-title">🛡️ When to "Rebuild Baseline"?</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">When performing <strong>legitimate maintenance</strong>, an alert will be raised because files changed:<br>1. Just upgraded Synology DSM firmware.<br>2. Installed or updated official packages (e.g. Web Station, Python).<br>3. Legitimate administrator edits to configs or authorized_keys.<br>Simply click "<strong>⚙️ Admin ▾ ➔ Rebuild Baseline...</strong>" to save the clean state as the new golden reference.</p></div><div class="guide-card"><div class="guide-card-title">🗄️ Search Monitored Files</div><p style="font-size:12.5px; color:var(--text-secondary);">Click "Search 1,786 Monitored Files" in the Admin menu to filter paths, SHA-256 hashes, and permissions in the FIM tab.</p></div>',
    "guide.content_inotify": '<div class="guide-card"><div class="guide-card-title">⚡ Linux inotify Kernel Event Stream</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">A resident inotify daemon on the NAS monitors sensitive paths like <code>/usr/syno/synoman</code>, <code>/etc/nginx</code>, <code>/volume1/public</code>, and <code>/volume1/tmp</code>. As soon as a file is written (CLOSE_WRITE) or permissions change (ATTRIB), events stream to the dashboard in milliseconds.</p></div><div class="guide-card"><div class="guide-card-title">🚨 Real-Time Webshell Heuristics</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">When files are written to shared folders or web directories, the engine scans for backdoor patterns:<br><code>eval(base64_decode(...))</code>, <code>passthru()</code>, <code>shell_exec()</code>, <code>assert()</code>.<br>Matching signatures trigger immediate critical alerts.</p></div><div class="guide-card"><div class="guide-card-title">🚫 SUID Escalation & Unauthorized Key Injection</div><p style="font-size:12.5px; color:var(--text-secondary);">- Detects <code>chmod +s</code> local privilege escalation backdoors.<br>- Any unauthorized write to <code>~/.ssh/authorized_keys</code> is trapped in real time.</p></div>',
    "guide.content_cf": '<div class="guide-card"><div class="guide-card-title">🌐 Edge Security Intelligence</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">Using Cloudflare GraphQL API, pull path probing attempts (e.g. <code>/.git/config</code>, <code>/wp-login.php</code>, <code>/.env</code>) and WAF blocks directly from Cloudflare global edge with zero NAS disk I/O.</p></div><div class="guide-card"><div class="guide-card-title">🔑 API Token Setup & Permissions</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">1. Go to Cloudflare ➔ <strong>My Profile</strong> ➔ <strong>API Tokens</strong>.<br>2. Create a Token with a single read-only permission: <strong><code>Zone - Analytics - Read</code></strong>.<br>3. Go to domain overview and copy the 32-character <strong>Zone ID</strong>.</p></div><div class="guide-card"><div class="guide-card-title">🧪 Connection Verification</div><p style="font-size:12.5px; color:var(--text-secondary);">Click "<strong>🧪 Test Connection</strong>" in setup wizard to verify Token & Zone ID before saving.</p></div>',
    "guide.content_audit": '<div class="guide-card"><div class="guide-card-title">🔌 Port Baseline & Anomaly Alerts</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">The system maintains a baseline of trusted listening ports (SSH 22, DSM 5000/5001, Nginx 80/443). Any rogue port opened by unauthorized services or reverse shells is instantly flagged in red.</p></div><div class="guide-card"><div class="guide-card-title">🔑 Active Sessions (utmp) Audit</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">Parses <code>/var/run/utmp</code> to display active terminals (TTY), client IPs, and login timestamps to spot suspicious concurrent sessions.</p></div><div class="guide-card"><div class="guide-card-title">🛡️ SSH Authorized Keys SHA-256 Audit</div><p style="font-size:12.5px; color:var(--text-secondary);">Scans all <code>authorized_keys</code> across user homes and hashes keys with SHA-256 to uncover phantom backdoor keys.</p></div>',
    "guide.content_faq": '<div class="guide-card"><div class="guide-card-title">Q1: What should I do if a File Integrity Anomaly alert triggers?</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">1. Click "View File Anomaly Details" to review affected paths.<br>2. <strong>If it was your legitimate action</strong> (e.g. DSM update): Click "⚙️ Admin ▾ ➔ Rebuild Baseline" to acknowledge.<br>3. <strong>If unexpected</strong>: Isolate the NAS and inspect utmp and suspicious files immediately.</p></div><div class="guide-card"><div class="guide-card-title">Q2: Why does NAS Sentinel not impact NAS performance?</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">Telemetry runs in-memory with zero disk write overhead. Each fast scan takes ~0.4s and CPU overhead is under 1%.</p></div><div class="guide-card"><div class="guide-card-title">Q3: How do I stop or restart NAS Sentinel?</div><p style="font-size:12.5px; color:var(--text-secondary);">Close the terminal window to stop; double-click <code>start-nas-sentinel.bat</code> to relaunch.</p></div>',
    "admin.cf_settings": "Cloudflare Edge Log Settings...",
    "admin.cf_desc": "Set API Token to pull threat intel",
    "theme.toggle_title": "Toggle Dark / Light Mode",
    "lang.toggle_title": "Select Language",
    "alert.banner_title": "🚨 File Integrity or Security Anomaly Detected!",
    "alert.banner_desc": "Please inspect the File Change Alerts or Listening Ports list below immediately.",
    "alert.btn_details": "View File Anomaly Details",
    "kpi.fim_title": "File Integrity Monitoring (FIM)",
    "kpi.web_title": "Nginx Web Endpoints & HTTPS Probing",
    "kpi.net_title": "Listening Ports & Network Conns",
    "kpi.cpu_title": "CPU Load & System Temp",
    "kpi.mem_title": "Memory & Swap Utilization",
    "kpi.disk_title": "Storage (/volume1) & Services",
    "kpi.status_ok": "NORMAL",
    "kpi.status_warn": "ANOMALY",
    "kpi.status_crit": "CRITICAL",
    "kpi.baseline_ok": "MATCHED",
    "kpi.smart_ok": "SMART PASSED",
    "kpi.smart_warn": "SMART WARNING",
    "tabs.overview": "📊 Real-time Overview & Alerts",
    "tabs.fim": "🕸️ Web Server & File Integrity (FIM)",
    "tabs.network": "🌐 Network Conns & Port Matrix",
    "tabs.security": "🕵️ Rootkit, Logins & Daemons",
    "overview.trend_title": "📈 System Telemetry Trends (CPU / RAM / Temp)",
    "overview.threat_gauge_title": "🛡️ Real-time NAS Threat Rating",
    "overview.inotify_stream_title": "⚡ Real-time Inotify Stream (Remote)",
    "overview.http_matrix_title": "🌐 Nginx Web Endpoint Matrix (HTTP Baseline & Latency)",
    "overview.cf_title": "☁️ Cloudflare Edge Threat Defense",
    "reset.title": "🛡️ Rebuild Security Baseline Confirmation",
    "reset.confirm_question": "Are you sure you want to overwrite the current NAS state as the trusted baseline?",
    "reset.btn_confirm": "⚠️ Confirm Rebuild Baseline",
    "reset.btn_cancel": "Cancel",
    "cf.title": "🌐 Cloudflare Edge Log API Settings",
    "cf.btn_test": "🧪 Test Connection",
    "cf.btn_save": "💾 Save & Enable",
    "cf.btn_cancel": "Cancel",
    "setup.title": "NAS Sentinel // Setup & Connection Wizard",
    "setup.sub": "Zero-Footprint Synology DSM Real-Time Security Monitor",
    "setup.quick_title": "✨ One-Click Quick Start (Quick Setup)",
    "setup.quick_desc": "Enter your Synology NAS LAN IP and SSH user, then click '⚡ Test Connection & Probe NAS'. The system auto-detects DSM version, CPU arch, and establishes baseline.",
    "setup.ssh_help_header": "💡 First time? How to obtain Synology NAS SSH access & key authentication?",
    "setup.ssh_help_show": "▶ Show Guide",
    "setup.ssh_help_hide": "▼ Hide Guide",
    "setup.host_label": "NAS LAN IP / Hostname",
    "setup.user_label": "SSH Username",
    "setup.port_label": "SSH Port (Customizable)",
    "setup.key_label": "SSH Private Key Path",
    "setup.keygen_link": "🔑 Auto-Generate New Key & Guide",
    "setup.btn_test": "Test SSH Connection & Probe NAS",
    "setup.cf_header": "🌐 Cloudflare Edge Log Monitoring (Optional)",
    "setup.btn_save": "🛡️ Save & Launch Dashboard",
    "setup.btn_close": "Close",
    "setup.footnote": "🔒 Credentials stored strictly in local data/ directory"
  },
  "jp": {
    "brand.sub_default": "ホスト: NAS123 • 読込中...",
    "brand.threat_init": "接続確認中...",
    "poll.active": "自動更新",
    "poll.paused": "一時停止",
    "poll.toggle_title": "自動定期更新 / 一時停止の切替",
    "poll.toast_active": "⏱️ バックグラウンド自動更新を有効化 (15秒毎)",
    "poll.toast_paused": "⏸️ 自動更新を一時停止しました (手動モード)",
    "scan.fast": "クイック走査",
    "scan.fast_title": "クイック走査：中核設定、主要Web、開放ポート (~0.8秒)",
    "scan.deep": "🔍 ディープ",
    "scan.deep_title": "ディープ走査：全DSM Webツリー & 1,786ファイル完全走査 (~3.5秒)",
    "scan.busy_toast": "⚠️ 現在他の走査または処理が実行中です。少々お待ちください...",
    "top.settings": "設定",
    "top.settings_title": "接続・システム設定ウィザードを開く",
    "top.admin": "⚙️ 管理 ▾",
    "admin.baseline_header": "セキュリティ基準保守",
    "admin.rebuild_baseline": "ベースライン再構築...",
    "admin.rebuild_desc": "現在のNAS状態を正規基準として保存",
    "admin.tools_header": "クイックツール",
    "admin.search_files": "監視対象1,786ファイルを検索",
    "admin.system_settings": "システム接続・基本設定...",
    "admin.system_settings_desc": "NAS IP、SSH鍵、Cloudflareを設定",
    "admin.user_guide": "機能・操作マニュアル...",
    "admin.user_guide_desc": "クイックスタート、FIM、inotify、Cloudflareガイド",
    "guide.modal_title": "NAS Sentinel 機能・操作マニュアル (Operations Guide)",
    "guide.tab_quickstart": "🚀 クイックスタート",
    "guide.tab_fim": "🔍 ファイル整合性 (FIM)",
    "guide.tab_inotify": "⚡ リアルタイム検知",
    "guide.tab_cf": "🌐 Cloudflare脅威情報",
    "guide.tab_audit": "🔌 ポート＆SSH鍵監査",
    "guide.tab_faq": "❓ よくある質問 FAQ",
    "guide.btn_github": "GitHubで完全技術ドキュメントを表示",
    "guide.btn_gotit": "了解 (Got it)",
    "guide.content_quickstart": '<div class="guide-card"><div class="guide-card-title"><span class="guide-step-badge">1</span> ゼロフットプリント設計原理</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">NAS Sentinelは完全エージェントレスのゼロフットプリント設計を採用しています。ローカルのPythonサーバー（<code>http://127.0.0.1:8088</code>）からSSH暗号化通信経由で監視スクリプトをNASのメモリ内に直接挿入して実行するため、<strong>NASのディスク書き込みゼロ、ルートパーティション容量消費ゼロ、追加パッケージ導入不要</strong>です。</p></div><div class="guide-card"><div class="guide-card-title"><span class="guide-step-badge">2</span> 初回接続・SSH鍵設定</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">1. 右上の「⚙️ 管理 ▾」➔「システム接続・基本設定...」を開きます。<br>2. NASのIPアドレスとSSHログインユーザー（administratorsグループ必須）を入力します。ポートを変更している場合は変更後のポート（例：2222）を指定します。<br>3. 「🔑 専用Ed25519鍵を生成」をクリックし、展開されたコマンドをNASのターミナルに1回貼り付けて実行します。<br>4. 「🧪 NAS接続テスト」をクリックして正常通信を確認後、保存してダッシュボードに入ります。</p></div><div class="guide-card"><div class="guide-card-title"><span class="guide-step-badge">3</span> 監視モードとアラート</div><p style="font-size:12.5px; color:var(--text-secondary);">- <strong>定期ポーリング</strong>：15秒ごとにシステム指標、ネットワーク接続、重要ファイル変更を自動収集します。<br>- <strong>リアルタイム検知</strong>：Linux inotifyによりファイル生成や権限変更をミリ秒単位で即時通知します。</p></div>',
    "guide.content_fim": '<div class="guide-card"><div class="guide-card-title">⚡ クイック走査 vs ディープ走査</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">- <strong>クイック走査 (~0.4秒)</strong>：15秒ごとに自動実行。高リスクファイル（<code>.php</code>, <code>.sh</code>, <code>.cgi</code>, <code>.conf</code>）と主要設定のmtimeおよびサイズを高速検査します。<br>- <strong>ディープ走査 (~3.5秒)</strong>：全1,786個のDSM Web中核ファイルおよびシステムバイナリの<strong>完全SHA-256ハッシュ</strong>を計算し、改ざんやトロイの木馬を徹底検出します。</p></div><div class="guide-card"><div class="guide-card-title">🛡️ 「ベースライン再構築」の実行タイミング</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">以下の<strong>正規のメンテナンス操作</strong>を行った際、ファイル変更により赤枠アラートが発生します：<br>1. Synology DSMの正規アップデート完了直後。<br>2. 公式パッケージ（Web StationやPython等）の導入・更新直後。<br>3. 管理者自身が設定ファイルやSSH公開鍵を更新した場合。<br>「<strong>⚙️ 管理 ▾ ➔ ベースライン再構築...</strong>」をクリックして現在の正規状態を新たな基準として保存してください。</p></div><div class="guide-card"><div class="guide-card-title">🗄️ 監視ファイル一覧の検索</div><p style="font-size:12.5px; color:var(--text-secondary);">管理メニューの「監視対象1,786ファイルを検索」から、FIMタブで全ファイルのパス、SHA-256ハッシュ、所有者権限を素早く絞り込めます。</p></div>',
    "guide.content_inotify": '<div class="guide-card"><div class="guide-card-title">⚡ Linux inotify カーネルイベントストリーム</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">NAS上で常駐するinotifyデーモンが、<code>/usr/syno/synoman</code>、<code>/etc/nginx</code>、<code>/volume1/public</code>、<code>/volume1/tmp</code>などの重要ディレクトリを監視。書き込み完了(CLOSE_WRITE)や属性変更(ATTRIB)を検知した瞬間にダッシュボードへ通知します。</p></div><div class="guide-card"><div class="guide-card-title">🚨 Webshell動的ヒューリスティック検知</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">ファイルが共有フォルダ等に保存された際、内部のバックドア特徴コードを即座にスキャンします：<br><code>eval(base64_decode(...))</code>, <code>passthru()</code>, <code>shell_exec()</code>, <code>assert()</code>。<br>一致した場合、脅威レベルを最高に引き上げて警告します。</p></div><div class="guide-card"><div class="guide-card-title">🚫 SUID権限昇格・不正SSH鍵の侵入阻止</div><p style="font-size:12.5px; color:var(--text-secondary);">- <code>chmod +s</code>によるローカル特権昇格を厳密に遮断します。<br>- <code>~/.ssh/authorized_keys</code>への不正な書き込みはミリ秒単位で捕捉されます。</p></div>',
    "guide.content_cf": '<div class="guide-card"><div class="guide-card-title">🌐 エッジ脅威インテリジェンス (Cloudflare Intel)</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">Cloudflare GraphQL APIを利用し、外部からのパス探索試行（<code>/.git/config</code>, <code>/wp-login.php</code>, <code>/.env</code>）やWAF遮断イベントをエッジ側から取得します。NASのディスクI/O負荷はゼロです。</p></div><div class="guide-card"><div class="guide-card-title">🔑 APIトークンの権限設定</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">1. Cloudflare ➔ <strong>My Profile</strong> ➔ <strong>API Tokens</strong>にアクセスします。<br>2. <strong><code>Zone - Analytics - Read</code></strong>の単一権限を持つトークンを作成します。<br>3. ドメイン概要画面の右下から32文字の<strong>Zone ID</strong>をコピーします。</p></div><div class="guide-card"><div class="guide-card-title">🧪 接続テスト機能 (Test Connection)</div><p style="font-size:12.5px; color:var(--text-secondary);">設定画面で入力後、「<strong>🧪 接続テスト</strong>」をクリックしてトークンとZone IDの有効性を事前に確認できます。</p></div>',
    "guide.content_audit": '<div class="guide-card"><div class="guide-card-title">🔌 監視ポートベースラインと異常通知</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">信頼されたポート一覧（SSH 22, DSM 5000/5001, Nginx 80/443等）を保持します。不正なリバースシェルや未知のサービスがポートを開いた場合、赤色で即時警告されます。</p></div><div class="guide-card"><div class="guide-card-title">🔑 アクティブセッション(utmp)監査</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;"><code>/var/run/utmp</code>を解析し、現在接続中の端末(TTY)、接続元IP、ログイン時刻を表示して不正な同時セッションを監視します。</p></div><div class="guide-card"><div class="guide-card-title">🛡️ SSH認可公開鍵のSHA-256監査</div><p style="font-size:12.5px; color:var(--text-secondary);">全ユーザーの<code>authorized_keys</code>をスキャンし、SHA-256フィンガープリントを照合して不正なバックドア鍵の潜伏を防ぎます。</p></div>',
    "guide.content_faq": '<div class="guide-card"><div class="guide-card-title">Q1: ファイル整合性アラートが発生した場合は？</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">1. 「詳細を表示」から対象ファイルのパスを確認してください。<br>2. <strong>自身が行った正規の変更の場合</strong>：「⚙️ 管理 ▾ ➔ ベースライン再構築」を実行してアラートをクリアします。<br>3. <strong>心当たりがない場合</strong>：直ちにネットワークを遮断し、ログイン履歴と不審ファイルを調査してください。</p></div><div class="guide-card"><div class="guide-card-title">Q2: NASのパフォーマンスに影響はありませんか？</div><p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:8px;">監視スクリプトはメモリ内実行され、ディスク書き込みはありません。クイック走査は約0.4秒、CPU負荷は1%未満です。</p></div><div class="guide-card"><div class="guide-card-title">Q3: NAS Sentinelの停止・再起動方法は？</div><p style="font-size:12.5px; color:var(--text-secondary);">コマンドウィンドウを閉じると停止します。<code>start-nas-sentinel.bat</code>を再度ダブルクリックすると再起動します。</p></div>',
    "admin.cf_settings": "Cloudflare エッジログ設定...",
    "admin.cf_desc": "APIトークンを設定して脅威情報を取得",
    "theme.toggle_title": "ダーク/ライトテーマ切替",
    "lang.toggle_title": "言語を選択",
    "alert.banner_title": "🚨 ファイル整合性またはセキュリティ異常を検知しました！",
    "alert.banner_desc": "直ちに下の「ファイル変更アラート」または「監視ポート」リストを確認してください。",
    "alert.btn_details": "ファイル変更の詳細を表示",
    "kpi.fim_title": "ファイル整合性監視 (FIM)",
    "kpi.web_title": "Nginx Webエンドポイント & HTTPSプローブ",
    "kpi.net_title": "監視ポート & ネットワーク接続",
    "kpi.cpu_title": "CPU負荷 & システム温度",
    "kpi.mem_title": "メモリ & Swap 使用率",
    "kpi.disk_title": "ストレージ (/volume1) & サービス",
    "kpi.status_ok": "正常",
    "kpi.status_warn": "異常",
    "kpi.status_crit": "緊急",
    "kpi.baseline_ok": "基準合致",
    "kpi.smart_ok": "SMART 正常",
    "kpi.smart_warn": "SMART 警告",
    "tabs.overview": "📊 リアルタイム概要とアラート",
    "tabs.fim": "🕸️ Webサーバー & ファイル整合性 (FIM)",
    "tabs.network": "🌐 ネットワーク接続 & ポートマトリクス",
    "tabs.security": "🕵️ Rootkit検知・ログイン活動・デーモン",
    "overview.trend_title": "📈 システムテレメトリ傾向 (CPU / RAM / 温度)",
    "overview.threat_gauge_title": "🛡️ リアルタイムNAS総合脅威評価",
    "overview.inotify_stream_title": "⚡ リアルタイムファイル変更ストリーム (inotify)",
    "overview.http_matrix_title": "🌐 Nginx Webエンドポイントプローブ (HTTP基準 & 応答遅延)",
    "overview.cf_title": "☁️ Cloudflare エッジセキュリティ保護",
    "reset.title": "🛡️ NAS セキュリティ基準の再構築確認",
    "reset.confirm_question": "現在のNAS状態を正規のセキュリティ基準として上書きしますか？",
    "reset.btn_confirm": "⚠️ 基準再構築を実行",
    "reset.btn_cancel": "キャンセル",
    "cf.title": "🌐 Cloudflare エッジログ API 接続設定",
    "cf.btn_test": "🧪 接続テスト",
    "cf.btn_save": "💾 保存して有効化",
    "cf.btn_cancel": "キャンセル",
    "setup.title": "NAS Sentinel // システム接続・初期設定ウィザード",
    "setup.sub": "Zero-Footprint Synology DSM リアルタイムセキュリティ監視",
    "setup.quick_title": "✨ ワンクリック簡単スタート (Quick Setup)",
    "setup.quick_desc": "Synology NASの内部IPとSSHユーザー名を入力し「⚡ SSH接続テスト & NAS自動検出」をクリックすると、DSMバージョン等を自動検出し基準を作成します。",
    "setup.ssh_help_header": "💡 初めての方へ：Synology NASのSSH接続と鍵認証を設定する方法",
    "setup.ssh_help_show": "▶ ガイドを開く",
    "setup.ssh_help_hide": "▼ ガイドを閉じる",
    "setup.host_label": "NAS ホスト IP / ホスト名",
    "setup.user_label": "SSH ログインユーザー",
    "setup.port_label": "SSH ポート (変更可)",
    "setup.key_label": "SSH 秘密鍵パス (認証鍵)",
    "setup.keygen_link": "🔑 新規鍵の自動生成とガイド",
    "setup.btn_test": "SSH接続テスト & NAS自動検出",
    "setup.cf_header": "🌐 Cloudflare エッジログ監視 (任意・後で設定可)",
    "setup.btn_save": "🛡️ 保存してダッシュボードを開く",
    "setup.btn_close": "閉じる",
    "setup.footnote": "🔒 認証情報はローカルの data/ ディレクトリのみに保存されます"
  }
};

function t(key, fallback = "") {
  if (I18N[currentLang] && I18N[currentLang][key] !== undefined) {
    return I18N[currentLang][key];
  }
  if (I18N["zh-TW"] && I18N["zh-TW"][key] !== undefined) {
    return I18N["zh-TW"][key];
  }
  return fallback || key;
}

function initLanguage() {
  let saved = localStorage.getItem("9sec_lang");
  if (saved === "tw") saved = "zh-TW";
  if (saved && I18N[saved]) {
    currentLang = saved;
  } else {
    const nav = (navigator.language || navigator.userLanguage || "").toLowerCase();
    if (nav.startsWith("ja")) currentLang = "jp";
    else if (nav.startsWith("en")) currentLang = "en";
    else currentLang = "zh-TW";
  }
  applyLanguage(currentLang, false);
}

function selectLanguage(lang) {
  if (!I18N[lang]) return;
  currentLang = lang;
  localStorage.setItem("9sec_lang", lang);
  closeLangMenu();
  applyLanguage(lang, true);
}

function applyLanguage(lang, notify = false) {
  document.documentElement.setAttribute("lang", lang === "zh-TW" ? "zh-Hant" : (lang === "jp" ? "ja" : "en"));

  const labelEl = document.getElementById("currentLangLabel");
  if (labelEl) {
    labelEl.textContent = lang === "zh-TW" ? "TW" : lang.toUpperCase();
  }

  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    const val = t(key);
    if (val) el.innerHTML = val;
  });

  document.querySelectorAll("[data-i18n-title]").forEach((el) => {
    const key = el.getAttribute("data-i18n-title");
    const val = t(key);
    if (val) el.setAttribute("title", val);
  });

  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    const key = el.getAttribute("data-i18n-placeholder");
    const val = t(key);
    if (val) el.setAttribute("placeholder", val);
  });

  if (currentSnapshot) {
    renderDashboard(currentSnapshot);
  } else {
    updateAutoPollUI();
  }

  if (notify) {
    const msgs = {
      "zh-TW": "語系已切換為：繁體中文 (TW)",
      "en": "Language switched to: English (EN)",
      "jp": "言語を日本語に切り替えました (JP)"
    };
    showToast(msgs[lang] || "Language updated", "info");
  }
}

function toggleLangMenu(e) {
  if (e) e.stopPropagation();
  const dropdown = document.getElementById("langDropdown");
  const adminDropdown = document.getElementById("adminDropdown");
  if (adminDropdown) adminDropdown.classList.remove("show");
  if (dropdown) dropdown.classList.toggle("show");
}

function closeLangMenu() {
  const dropdown = document.getElementById("langDropdown");
  if (dropdown) dropdown.classList.remove("show");
}

// ==========================================
// Theme Controller (Dark / Light Mode)
// Nine-Security Cyber SOC Standards
// ==========================================
function initTheme() {
  const saved = localStorage.getItem("9sec_theme") || "dark";
  document.documentElement.setAttribute("data-theme", saved);
  updateThemeButtonUI(saved);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme") || "dark";
  const newTheme = current === "light" ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", newTheme);
  localStorage.setItem("9sec_theme", newTheme);
  updateThemeButtonUI(newTheme);

  if (currentSnapshot && currentSnapshot.history) {
    drawCharts(currentSnapshot.history);
  }

  const msgs = {
    "zh-TW": newTheme === "light" ? "已切換為淺色主題 (Light Mode)" : "已切換為深色主題 (Dark Mode)",
    "en": newTheme === "light" ? "Switched to Light Mode" : "Switched to Dark Mode",
    "jp": newTheme === "light" ? "ライトモードに切り替えました" : "ダークモードに切り替えました"
  };
  showToast(msgs[currentLang] || msgs["zh-TW"], "info");
}

function updateThemeButtonUI(theme) {
  const icon = document.getElementById("theme-icon");
  const text = document.getElementById("theme-text");
  const btn = document.getElementById("theme-toggle");
  if (icon) icon.textContent = theme === "light" ? "☀️" : "🌙";
  if (text) text.textContent = theme.toUpperCase();
  if (btn) {
    const titles = {
      "zh-TW": theme === "light" ? "切換至深色主題 (Dark Mode)" : "切換至淺色主題 (Light Mode)",
      "en": theme === "light" ? "Switch to Dark Mode" : "Switch to Light Mode",
      "jp": theme === "light" ? "ダークモードに切り替える" : "ライトモードに切り替える"
    };
    btn.title = titles[currentLang] || titles["zh-TW"];
  }
}

function showToast(msg, type = "info") {
  const toast = document.getElementById("toastNotice");
  const icon = document.getElementById("toastIcon");
  const text = document.getElementById("toastMsg");
  if (!toast) return;

  clearTimeout(toastTimeout);
  icon.textContent = type === "crit" ? "🚨" : type === "warn" ? "⚠️" : "ℹ️";
  text.textContent = msg;
  toast.className = `toast-notice show ${type}`;

  toastTimeout = setTimeout(() => {
    toast.className = "toast-notice";
  }, 2600);
}

function setControlsBusy(busy, actionMessage) {
  isOperationBusy = busy;
  const btnFast = document.getElementById("btnFastScan");
  const btnDeep = document.getElementById("btnDeepScan");
  const btnAdmin = document.getElementById("btnAdminMenu");
  const pillPoll = document.getElementById("btnTogglePoll");
  const primaryIcon = document.getElementById("scanPrimaryIcon");
  const primaryText = document.getElementById("scanPrimaryText");
  const btnConfirmReset = document.getElementById("btnConfirmResetBaseline");

  if (btnFast) btnFast.disabled = busy;
  if (btnDeep) btnDeep.disabled = busy;
  if (btnAdmin) btnAdmin.disabled = busy;
  if (btnConfirmReset) btnConfirmReset.disabled = busy;
  if (pillPoll) pillPoll.classList.toggle("disabled", busy);

  if (busy) {
    if (primaryIcon) primaryIcon.textContent = "⏳";
    if (primaryText && actionMessage) primaryText.textContent = actionMessage;
  }
}

const PORT_DESCRIPTIONS = {
  "zh-TW": {
    22: "OpenSSH 遠端安全管理 (僅公鑰)",
    53: "Synology DNS Server (named)",
    80: "Nginx HTTP 入口導向服務",
    111: "RPCbind (NFS 遠端程序呼叫)",
    123: "Chrony NTP 時間同步服務",
    137: "NetBIOS 名稱服務 (nmbd)",
    138: "NetBIOS 資料報服務 (nmbd)",
    161: "SNMP 系統監控代理 (僅 Loopback)",
    323: "Chrony 本機控制埠",
    443: "Nginx HTTPS 反向代理與安全入口",
    662: "NFS statd 狀態監聽",
    892: "NFS mountd 掛載服務",
    953: "DNS Server 本機控制通道 (rndc)",
    1900: "SSDP / UPnP 區網裝置探索",
    2049: "NFS 主檔案服務",
    3261: "iSCSI Target 儲存服務",
    3263: "iSCSI / LUN 儲存服務",
    3264: "iSCSI / VMM 儲存服務",
    4045: "NFS lockd 鎖定管理",
    5000: "DSM HTTP 管理介面 (導向 HTTPS 5001)",
    5001: "DSM HTTPS 網頁管理主介面 (Nginx)",
    5432: "PostgreSQL 系統資料庫 (僅 Loopback)",
    6690: "Synology Drive 檔案同步服務 (syncd)",
    9997: "Synology Assistant 搜尋服務 (findhostd)",
    9998: "Synology Assistant 搜尋服務 (findhostd)",
    9999: "Synology Assistant 搜尋服務 (findhostd)",
    20241: "Cloudflare Tunnel 本機指標端點 (Loopback)",
    33304: "Synology MIB 本機服務 (Loopback)",
  },
  "en": {
    22: "OpenSSH Remote Admin (Key-Auth Only)",
    53: "Synology DNS Server (named)",
    80: "Nginx HTTP Redirect Service",
    111: "RPCbind (NFS Remote Procedure Call)",
    123: "Chrony NTP Time Synchronization",
    137: "NetBIOS Name Service (nmbd)",
    138: "NetBIOS Datagram Service (nmbd)",
    161: "SNMP Monitoring Agent (Loopback Only)",
    323: "Chrony Local Control Port",
    443: "Nginx HTTPS Reverse Proxy & Entry",
    662: "NFS statd Status Monitor",
    892: "NFS mountd Mount Daemon",
    953: "DNS Server Local Control (rndc)",
    1900: "SSDP / UPnP Device Discovery",
    2049: "NFS Main File Service",
    3261: "iSCSI Target Storage Service",
    3263: "iSCSI / LUN Storage Service",
    3264: "iSCSI / VMM Storage Service",
    4045: "NFS lockd Lock Management",
    5000: "DSM HTTP Web Admin (Redirects to 5001)",
    5001: "DSM HTTPS Web Admin Interface (Nginx)",
    5432: "PostgreSQL System DB (Loopback Only)",
    6690: "Synology Drive File Sync (syncd)",
    9997: "Synology Assistant Discovery (findhostd)",
    9998: "Synology Assistant Discovery (findhostd)",
    9999: "Synology Assistant Discovery (findhostd)",
    20241: "Cloudflare Tunnel Local Metrics",
    33304: "Synology MIB Local Service (Loopback)",
  },
  "jp": {
    22: "OpenSSH リモート安全管理 (鍵認証専用)",
    53: "Synology DNS サーバー (named)",
    80: "Nginx HTTP リダイレクトサービス",
    111: "RPCbind (NFS リモートプロシージャ呼出)",
    123: "Chrony NTP 時刻同期サービス",
    137: "NetBIOS ネームサービス (nmbd)",
    138: "NetBIOS データグラムサービス (nmbd)",
    161: "SNMP 監視エージェント (Loopback専用)",
    323: "Chrony ローカル制御ポート",
    443: "Nginx HTTPS リバースプロキシ・安全入口",
    662: "NFS statd 状態監視",
    892: "NFS mountd マウントサービス",
    953: "DNS サーバーローカル制御 (rndc)",
    1900: "SSDP / UPnP デバイス探索",
    2049: "NFS メインファイルサービス",
    3261: "iSCSI ターゲットストレージサービス",
    3263: "iSCSI / LUN ストレージサービス",
    3264: "iSCSI / VMM ストレージサービス",
    4045: "NFS lockd ロック管理",
    5000: "DSM HTTP 管理画面 (HTTPS 5001へ転送)",
    5001: "DSM HTTPS Web管理インターフェース (Nginx)",
    5432: "PostgreSQL システムDB (Loopback専用)",
    6690: "Synology Drive ファイル同期 (syncd)",
    9997: "Synology Assistant 探索 (findhostd)",
    9998: "Synology Assistant 探索 (findhostd)",
    9999: "Synology Assistant 探索 (findhostd)",
    20241: "Cloudflare Tunnel メトリクス端点",
    33304: "Synology MIB ローカルサービス",
  }
};

function getPortDescription(port) {
  const dict = PORT_DESCRIPTIONS[currentLang] || PORT_DESCRIPTIONS["zh-TW"];
  if (dict && dict[port]) return dict[port];
  if (PORT_DESCRIPTIONS["zh-TW"] && PORT_DESCRIPTIONS["zh-TW"][port]) return PORT_DESCRIPTIONS["zh-TW"][port];
  if (port >= 32768) {
    return currentLang === "en" ? "Dynamic RPC / Outbound QUIC Port" : currentLang === "jp" ? "動的 RPC / 送信 QUIC ポート" : "動態 RPC / 出站 QUIC 埠";
  }
  return currentLang === "en" ? "System Service Port" : currentLang === "jp" ? "システムサービスポート" : "系統服務埠";
}

function formatUptime(sec) {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (currentLang === "en") return `${d}d ${h}h ${m}m`;
  if (currentLang === "jp") return `${d}日 ${h}時間 ${m}分`;
  return `${d}天 ${h}小時 ${m}分`;
}

function formatTimeTs(ts) {
  if (!ts) return "--";
  const d = new Date(ts * 1000);
  const loc = currentLang === "en" ? "en-US" : currentLang === "jp" ? "ja-JP" : "zh-TW";
  return d.toLocaleString(loc, { hour12: false });
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function switchTab(tabId) {
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === tabId);
  });
  document.querySelectorAll(".tab-panel").forEach((panel) => {
    panel.classList.toggle("active", panel.id === `tab-${tabId}`);
  });
  if (tabId === "fim") {
    loadFilesExplorer();
  }
  if (tabId === "overview" && currentSnapshot) {
    drawCharts(currentSnapshot.history || []);
  }
}

function updateAutoPollUI() {
  const pill = document.getElementById("btnTogglePoll");
  const label = document.getElementById("pollStatusLabel");
  const icon = document.getElementById("pollIcon");
  const countEl = document.getElementById("countdownText");
  if (!pill || !label) return;
  if (autoPoll) {
    pill.className = "poll-pill active";
    label.textContent = t("poll.active", "自動輪詢");
    if (icon) icon.textContent = "⏸️";
    if (countEl) countEl.style.display = "inline";
  } else {
    pill.className = "poll-pill paused";
    label.textContent = t("poll.paused", "輪詢暫停");
    if (icon) icon.textContent = "▶️";
    if (countEl) countEl.style.display = "none";
  }
}

function toggleAutoPoll() {
  if (isOperationBusy) {
    showToast(t("scan.busy_toast", "⚠️ 目前已有掃描或系統作業正在進行中，請稍候..."), "warn");
    return;
  }

  const now = Date.now();
  if (now - lastPollToggleTime < 600) {
    return;
  }
  lastPollToggleTime = now;

  autoPoll = !autoPoll;
  updateAutoPollUI();

  if (autoPoll) {
    countdown = pollInterval;
    const countEl = document.getElementById("countdownText");
    if (countEl) countEl.textContent = `${countdown}s`;
    showToast(t("poll.toast_active", "⏱️ 已開啟背景自動輪詢 (每 15 秒更新一次)"), "info");
  } else {
    showToast(t("poll.toast_paused", "⏸️ 背景自動輪詢已暫停 (手動模式)"), "warn");
  }
}

async function fetchStatus() {
  if (isOperationBusy) return; // Prevent concurrent polling collisions
  try {
    if (!getApiToken()) {
      showApiAuthModal("Enter API token to unlock the dashboard (from data/api_token.txt).");
      return;
    }
    const res = await apiFetch("/api/status");
    if (res.status === 401) return;
    const json = await res.json();
    if (json.is_configured === false) {
      const badge = document.getElementById("threatBadge");
      if (badge) {
        badge.className = "badge badge-warn";
        badge.textContent = "尚未設定";
      }
      const idEl = document.getElementById("nasIdentity");
      if (idEl) idEl.textContent = "請透過安裝精靈完成 NAS 連線與基線配置";
      openSetupModal(true);
      return;
    }
    if (json.ok && json.data) {
      currentSnapshot = json.data;
      renderDashboard(json.data);
    } else if (json.last_error) {
      const badge = document.getElementById("threatBadge");
      badge.className = "badge badge-crit";
      badge.textContent = "SSH 連線異常";
      document.getElementById("nasIdentity").textContent = json.last_error;
    }
  } catch (err) {
    console.error("Failed to fetch status:", err);
  }
}

async function triggerScan(mode) {
  // Anti-Fooling Check 1: Already busy
  if (isOperationBusy) {
    showToast("⚠️ 目前已有掃描或系統作業正在進行中，請稍候...", "warn");
    return;
  }

  // Anti-Fooling Check 2: 2-second anti-spam cooldown window
  const now = Date.now();
  if (now - lastScanCompletedTime < 2000) {
    const remainSec = Math.ceil((2000 - (now - lastScanCompletedTime)) / 1000);
    showToast(`⏳ 系統防刷冷卻中，請等待 ${remainSec} 秒後再執行`, "warn");
    return;
  }

  const primaryText = mode === "deep" ? "全量深度比對中..." : "快速掃描中...";
  setControlsBusy(true, primaryText);
  if (mode === "deep") {
    const btnDeep = document.getElementById("btnDeepScan");
    if (btnDeep) btnDeep.textContent = "⏳ 深度比對中 (~3.5s)...";
  }

  try {
    const res = await apiFetch("/api/scan", {
      method: "POST",
      body: JSON.stringify({ mode }),
    });

    if (res.status === 429) {
      showToast("⚠️ 後端回報：系統已有其他作業正在執行，請稍候", "warn");
      return;
    }

    const json = await res.json();
    if (json.ok && json.data) {
      currentSnapshot = json.data;
      renderDashboard(json.data);
      if (document.getElementById("tab-fim").classList.contains("active")) {
        loadFilesExplorer();
      }
      showToast(mode === "deep" ? "✅ 深度檔案雜湊掃描完成" : "⚡ 快速掃描完成", "info");
    } else {
      showToast(`❌ 掃描失敗: ${json.error || json.last_error || "未明錯誤"}`, "crit");
    }
  } catch (err) {
    showToast(`❌ 連線或執行例外: ${err.message || err}`, "crit");
  } finally {
    lastScanCompletedTime = Date.now();

    // 2-Second Cooldown Visual Feedback (Anti-Fooling)
    const primaryIcon = document.getElementById("scanPrimaryIcon");
    const primaryTxt = document.getElementById("scanPrimaryText");
    const btnDeep = document.getElementById("btnDeepScan");

    if (primaryIcon) primaryIcon.textContent = "✅";
    if (primaryTxt) primaryTxt.textContent = "完成 (冷卻中)";
    if (btnDeep) btnDeep.textContent = "🔍 深度";

    setTimeout(() => {
      setControlsBusy(false);
      if (primaryIcon) primaryIcon.textContent = "⚡";
      if (primaryTxt) primaryTxt.textContent = "快速掃描";
      countdown = pollInterval;
    }, 2000);
  }
}

function toggleAdminMenu(event) {
  if (isOperationBusy) {
    showToast("⚠️ 系統作業執行中，無法開啟管理選單", "warn");
    return;
  }
  if (event) event.stopPropagation();
  const dropdown = document.getElementById("adminDropdown");
  if (dropdown) dropdown.classList.toggle("show");
}

function closeAdminMenu() {
  const dropdown = document.getElementById("adminDropdown");
  if (dropdown) dropdown.classList.remove("show");
}

function openResetBaselineModal() {
  if (isOperationBusy) {
    showToast("⚠️ 系統作業執行中，無法進行基線重設", "warn");
    return;
  }
  closeAdminMenu();
  const modal = document.getElementById("resetBaselineModal");
  if (modal) modal.classList.add("show");
}

function closeResetBaselineModal() {
  const modal = document.getElementById("resetBaselineModal");
  if (modal) modal.classList.remove("show");
}

function onModalOverlayClick(event) {
  if (isOperationBusy) return;
  if (event.target && event.target.id === "resetBaselineModal") {
    closeResetBaselineModal();
  }
}

function openGuideModal() {
  closeAdminMenu();
  const modal = document.getElementById("userGuideModal");
  if (modal) modal.classList.add("show");
}

function closeGuideModal() {
  const modal = document.getElementById("userGuideModal");
  if (modal) modal.classList.remove("show");
}

function onGuideModalOverlayClick(event) {
  if (event.target && event.target.id === "userGuideModal") {
    closeGuideModal();
  }
}

function switchGuideTab(tabId) {
  const modal = document.getElementById("userGuideModal");
  if (!modal) return;
  modal.querySelectorAll(".guide-tab-btn").forEach(btn => {
    btn.classList.toggle("active", btn.getAttribute("data-guide-tab") === tabId);
  });
  modal.querySelectorAll(".guide-tab-panel").forEach(panel => {
    panel.classList.toggle("active", panel.id === `guidePanel-${tabId}`);
  });
}

async function confirmResetBaseline() {
  if (isOperationBusy) {
    showToast("⚠️ 目前已有作業正在執行，請稍候", "warn");
    return;
  }

  setControlsBusy(true, "正在重設基線...");
  const btn = document.getElementById("btnConfirmResetBaseline");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "⏳ 正在重建基線中...";
  }

  try {
    const res = await apiFetch("/api/baseline/reset", { method: "POST" });
    if (res.status === 429) {
      showToast("⚠️ 後端回報：系統忙碌中，請稍候再試", "warn");
      return;
    }
    const json = await res.json();
    if (json.ok && json.data) {
      currentSnapshot = json.data;
      renderDashboard(json.data);
      loadFilesExplorer();
      closeResetBaselineModal();
      showToast("🛡️ 安全基準重建成功！所有檔案與埠已設為新基線", "info");
    } else {
      showToast("❌ 重建基線失敗: " + (json.error || json.last_error), "crit");
    }
  } catch (err) {
    showToast("❌ 重建基線例外: " + err, "crit");
  } finally {
    lastScanCompletedTime = Date.now();
    if (btn) {
      btn.disabled = false;
      btn.textContent = "⚠️ 確認重建基準";
    }
    setTimeout(() => {
      setControlsBusy(false);
      const primaryIcon = document.getElementById("scanPrimaryIcon");
      const primaryTxt = document.getElementById("scanPrimaryText");
      if (primaryIcon) primaryIcon.textContent = "⚡";
      if (primaryTxt) primaryTxt.textContent = "快速掃描";
      countdown = pollInterval;
    }, 2000);
  }
}

function renderDashboard(data) {
  const sys = data.system;
  const fim = data.fim_summary;
  const net = data.network;
  const sec = data.security;

  // Header status
  const threatBadge = document.getElementById("threatBadge");
  if (data.threat_level === "CRITICAL") {
    threatBadge.className = "badge badge-crit";
  } else if (data.threat_level === "WARNING") {
    threatBadge.className = "badge badge-warn";
  } else {
    threatBadge.className = "badge badge-ok";
  }
  const levelLabels = {
    "CRITICAL": { "zh-TW": "🚨 緊急威脅", "en": "🚨 CRITICAL", "jp": "🚨 緊急異常" },
    "WARNING": { "zh-TW": "⚠️ 注意警戒", "en": "⚠️ WARNING", "jp": "⚠️ 警戒中" },
    "SECURE": { "zh-TW": "🛡️ 系統正常", "en": "🛡️ SYSTEM SECURE", "jp": "🛡️ システム正常" }
  };
  const labelKey = data.threat_level || "SECURE";
  const localizedLabel = (levelLabels[labelKey] && levelLabels[labelKey][currentLang]) || data.threat_label;
  const scoreText = currentLang === "en" ? `Score ${data.security_score}` : currentLang === "jp" ? `スコア ${data.security_score}` : `評分 ${data.security_score}`;
  threatBadge.textContent = `${localizedLabel} | ${scoreText}`;

  // inotify status badge
  const inotify = data.inotify || { status: {}, recent_events: [] };
  const inoStat = inotify.status || {};
  const inoBadge = document.getElementById("inotifyBadge");
  if (inoBadge) {
    if (inoStat.connected) {
      inoBadge.className = "badge badge-ok";
      inoBadge.textContent = currentLang === "en"
        ? `⚡ inotify Live: ${inoStat.watches_count || 0} dirs`
        : currentLang === "jp"
        ? `⚡ inotify 監視中: ${inoStat.watches_count || 0} ディレクトリ`
        : `⚡ inotify 即時監聽: ${inoStat.watches_count || 0} 目錄`;
    } else {
      inoBadge.className = "badge badge-warn";
      inoBadge.textContent = currentLang === "en" ? `⚡ inotify reconnecting...` : currentLang === "jp" ? `⚡ inotify 再接続中...` : `⚡ inotify 重連中...`;
    }
  }

  const inoSub = document.getElementById("inotifyPanelSub");
  if (inoSub) {
    inoSub.textContent = inoStat.connected
      ? (currentLang === "en"
          ? `🟢 Stream connected | Monitored dirs: ${inoStat.watches_count} | Captured events: ${inoStat.total_captured || 0}`
          : currentLang === "jp"
          ? `🟢 ストリーム正常 | 監視ディレクトリ数: ${inoStat.watches_count} | キャプチャ総数: ${inoStat.total_captured || 0}`
          : `🟢 核心串流連線正常 | 監聽目錄數: ${inoStat.watches_count} | 累計攔截事件: ${inoStat.total_captured || 0}`)
      : (currentLang === "en" ? `🟡 Establishing SSH inotify stream...` : currentLang === "jp" ? `🟡 SSH inotify ストリームを確立中...` : `🟡 正在建立 SSH inotify 串流...`);
  }

  const inoBody = document.getElementById("inotifyEventsBody");
  if (inoBody) {
    const inoEvents = inotify.recent_events || [];
    if (inoEvents.length === 0) {
      inoBody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:18px; color:var(--text-muted);">${currentLang === "en" ? "⚡ No file change events captured currently (standby)." : currentLang === "jp" ? "⚡ 現在ファイル変更イベントは検知されていません (待機中)。" : "⚡ 目前受監控之 250 個網頁與安全目錄尚無任何即時檔案寫入/修改/刪除事件 (毫秒級監聽待命中)。"}</td></tr>`;
    } else {
      inoBody.innerHTML = inoEvents.map((ev) => {
        const bCls = ev.severity === "CRITICAL" ? "badge-crit" : ev.severity === "WARNING" ? "badge-warn" : "badge-ok";
        const suspText = (ev.suspicious && ev.suspicious.length > 0)
          ? `<div style="color:#ff3377; font-weight:600; margin-top:2px;">⚠️ ${escapeHtml(ev.suspicious.join("；"))}</div>`
          : "";
        return `<tr>
          <td class="mono">${escapeHtml(ev.iso_time)}</td>
          <td><span class="badge ${bCls}">${escapeHtml(ev.severity)}</span></td>
          <td class="mono" style="color:#fbbf24;">${escapeHtml((ev.flags || []).join(", "))}</td>
          <td class="mono" style="color:#ff6699;">${escapeHtml(ev.path)}</td>
          <td class="mono">${escapeHtml(ev.mode)} (${escapeHtml(ev.owner)})</td>
          <td class="mono">${escapeHtml((ev.hash || "無/已刪除").slice(0, 20))}... ${suspText}</td>
        </tr>`;
      }).join("");
    }
  }

  const hostPrefix = currentLang === "en" ? "Host: " : currentLang === "jp" ? "ホスト: " : "主機: ";
  const upPrefix = currentLang === "en" ? "Uptime: " : currentLang === "jp" ? "稼働: " : "連續運作: ";
  document.getElementById("nasIdentity").textContent =
    `${hostPrefix}${sys.hostname || "NAS123"} • ${sys.dsm_version ? sys.dsm_version.split("-")[0] : "DSM 7.4.1"} • ${upPrefix}${formatUptime(sys.uptime_seconds)}`;

  const updPrefix = currentLang === "en" ? "Updated: " : currentLang === "jp" ? "更新: " : "更新: ";
  const timeLoc = currentLang === "en" ? "en-US" : currentLang === "jp" ? "ja-JP" : "zh-TW";
  document.getElementById("lastScanTime").textContent =
    `${updPrefix}${new Date(data.timestamp * 1000).toLocaleTimeString(timeLoc, { hour12: false })} (${data.scan_elapsed_ms}ms)`;

  // Alert Banner
  const rk = data.rootkit || { checks: [], alert_count: 0 };
  const banner = document.getElementById("alertBanner");
  if (fim.anomaly_count > 0 || net.unauthorized_ports.length > 0 || (rk.alert_count || 0) > 0) {
    banner.style.display = "flex";
    if (currentLang === "en") {
      document.getElementById("alertBannerTitle").textContent =
        `🚨 Security Alert: Detected ${fim.anomaly_count} file anomalies, ${net.unauthorized_ports.length} unapproved ports, ${rk.alert_count || 0} rootkit flags!`;
    } else if (currentLang === "jp") {
      document.getElementById("alertBannerTitle").textContent =
        `🚨 セキュリティ警告：${fim.anomaly_count} 件のファイル変更、${net.unauthorized_ports.length} 件の未承認ポート、${rk.alert_count || 0} 件のRootkit異常を検知！`;
    } else {
      document.getElementById("alertBannerTitle").textContent =
        `🚨 安全警報：偵測到 ${fim.anomaly_count} 項檔案異動、${net.unauthorized_ports.length} 個非基線埠、${rk.alert_count || 0} 項 Rootkit 異常！`;
    }
    const firstReasons = (fim.anomalies || []).slice(0, 2).map((a) => `${a.path} (${a.reasons.join(", ")})`).join(" ； ");
    document.getElementById("alertBannerDesc").textContent = firstReasons || (currentLang === "en" ? "Please inspect file integrity, rootkit checks, or listening port lists immediately." : currentLang === "jp" ? "直ちにファイル整合性、Rootkit検知、監視ポートリストを確認してください。" : "請立即檢查檔案完整性、Rootkit 檢測或監聽埠異動清單。");
  } else {
    banner.style.display = "none";
  }

  // KPI 1: FIM
  const fileUnit = currentLang === "en" ? " files" : currentLang === "jp" ? " ファイル" : " 檔";
  document.getElementById("kpiFimTotal").textContent = `${fim.total_monitored_files.toLocaleString()}${fileUnit}`;
  if (currentLang === "en") {
    document.getElementById("kpiFimDiff").textContent =
      `Modified: ${fim.modified_count} | Added: ${fim.added_count} | Deleted: ${fim.deleted_count}`;
  } else if (currentLang === "jp") {
    document.getElementById("kpiFimDiff").textContent =
      `変更: ${fim.modified_count} | 追加: ${fim.added_count} | 削除: ${fim.deleted_count}`;
  } else {
    document.getElementById("kpiFimDiff").textContent =
      `異動: ${fim.modified_count} | 新增: ${fim.added_count} | 刪除: ${fim.deleted_count}`;
  }
  document.getElementById("kpiFimDuration").textContent = `${data.scan_elapsed_ms} ms`;
  const kpiFimBadge = document.getElementById("kpiFimBadge");
  const tabFimCount = document.getElementById("tabFimCount");
  const kpiFimBar = document.getElementById("kpiFimBar");
  tabFimCount.textContent = fim.anomaly_count;
  if (fim.anomaly_count > 0) {
    kpiFimBadge.className = "badge badge-crit";
    kpiFimBadge.textContent = currentLang === "en" ? `${fim.anomaly_count} Anomaly` : currentLang === "jp" ? `${fim.anomaly_count} 異常` : `${fim.anomaly_count} 異常`;
    tabFimCount.className = "badge badge-crit";
    kpiFimBar.style.background = "var(--crit)";
  } else {
    kpiFimBadge.className = "badge badge-ok";
    kpiFimBadge.textContent = currentLang === "en" ? "100% Intact" : currentLang === "jp" ? "100% 正常" : "100% 完整";
    tabFimCount.className = "badge badge-ok";
    kpiFimBar.style.background = "var(--ok)";
  }

  // KPI 2: Web Endpoints
  const eps = data.web_endpoints || [];
  const okEps = eps.filter((e) => e.reachable && e.baseline_match).length;
  const okUnit = currentLang === "en" ? " OK" : currentLang === "jp" ? " 正常" : " 正常";
  document.getElementById("kpiWebStatus").textContent = `${okEps} / ${eps.length}${okUnit}`;
  const avgLat = eps.filter((e) => e.latency_ms).reduce((a, b) => a + b.latency_ms, 0) / Math.max(1, eps.length);
  const latPrefix = currentLang === "en" ? "Avg Latency: " : currentLang === "jp" ? "平均遅延: " : "平均延遲: ";
  document.getElementById("kpiWebLatency").textContent = `${latPrefix}${Math.round(avgLat)} ms`;
  const kpiWebBadge = document.getElementById("kpiWebBadge");
  if (okEps === eps.length) {
    kpiWebBadge.className = "badge badge-ok";
    kpiWebBadge.textContent = currentLang === "en" ? "Hash Matched" : currentLang === "jp" ? "ハッシュ合致" : "雜湊吻合";
  } else {
    kpiWebBadge.className = "badge badge-warn";
    kpiWebBadge.textContent = currentLang === "en" ? "Endpoints Changed" : currentLang === "jp" ? "変更あり" : "端點異動";
  }

  // KPI 3: Network
  const connsUnit = currentLang === "en" ? " conns" : currentLang === "jp" ? " 接続" : " 條連線";
  document.getElementById("kpiNetConns").textContent = `${net.connections.length}${connsUnit}`;
  document.getElementById("kpiNetDetail").textContent = `LAN: ${net.lan_conn_count} | WAN: ${net.external_conn_count}`;
  const unauthPrefix = currentLang === "en" ? "Unauth: " : currentLang === "jp" ? "未承認: " : "非授權埠: ";
  document.getElementById("kpiPortUnauth").textContent = `${unauthPrefix}${net.unauthorized_ports.length}`;
  const kpiNetBadge = document.getElementById("kpiNetBadge");
  if (net.unauthorized_ports.length > 0) {
    kpiNetBadge.className = "badge badge-crit";
    kpiNetBadge.textContent = currentLang === "en" ? "New Ports!" : currentLang === "jp" ? "新規開放!" : "新開放埠!";
  } else {
    kpiNetBadge.className = "badge badge-ok";
    kpiNetBadge.textContent = currentLang === "en" ? `${net.listeners.length} Ports OK` : currentLang === "jp" ? `${net.listeners.length} 正常` : `${net.listeners.length} 監聽埠正常`;
  }

  // KPI 4: CPU & Temp
  document.getElementById("kpiCpuVal").textContent = `${sys.cpu_percent}%`;
  document.getElementById("kpiLoadVal").textContent = `Load: ${sys.load_1m} / ${sys.load_5m} / ${sys.load_15m}`;
  document.getElementById("kpiTempVal").textContent = `🌡️ ${sys.temp_c ?? "--"}°C`;
  document.getElementById("kpiCpuBar").style.width = `${Math.min(100, sys.cpu_percent)}%`;
  const kpiCpuBadge = document.getElementById("kpiCpuBadge");
  if ((sys.temp_c || 0) >= 70 || sys.cpu_percent >= 85) {
    kpiCpuBadge.className = "badge badge-warn";
    kpiCpuBadge.textContent = currentLang === "en" ? "High Load" : currentLang === "jp" ? "高負荷" : "高負載/高溫";
  } else {
    kpiCpuBadge.className = "badge badge-ok";
    kpiCpuBadge.textContent = currentLang === "en" ? "NORMAL" : currentLang === "jp" ? "正常" : "正常";
  }

  // KPI 5: Memory
  document.getElementById("kpiMemVal").textContent = `${sys.mem_percent}%`;
  document.getElementById("kpiMemMb").textContent = `${sys.mem_used_mb} / ${sys.mem_total_mb} MB`;
  document.getElementById("kpiSwapVal").textContent = `Swap: ${sys.swap_percent}% (${sys.swap_used_mb} MB)`;
  document.getElementById("kpiMemBar").style.width = `${Math.min(100, sys.mem_percent)}%`;

  // KPI 6: Disk & Services
  const vol1 = (sys.disks || []).find((d) => d.mount === "/volume1") || (sys.disks || [])[0] || {};
  document.getElementById("kpiDiskVal").textContent = `${vol1.percent ?? "--"}%`;
  const availPrefix = currentLang === "en" ? "Avail: " : currentLang === "jp" ? "空き: " : "可用: ";
  document.getElementById("kpiDiskGb").textContent = `${availPrefix}${vol1.avail_gb ?? "--"} / ${vol1.total_gb ?? "--"} GB`;
  document.getElementById("kpiDiskBar").style.width = `${Math.min(100, vol1.percent || 0)}%`;
  const runningSvcs = (sec.services || []).filter((s) => s.running).length;
  const svcPrefix = currentLang === "en" ? "Services: " : currentLang === "jp" ? "サービス: " : "服務: ";
  document.getElementById("kpiSvcCount").textContent = `${svcPrefix}${runningSvcs}/${(sec.services || []).length}`;

  // Render Overview Anomalies Panel
  const ovPanel = document.getElementById("overviewAnomaliesPanel");
  const ovBody = document.getElementById("overviewAnomaliesBody");
  if (fim.anomalies && fim.anomalies.length > 0) {
    ovPanel.style.display = "block";
    ovBody.innerHTML = fim.anomalies.map((a) => {
      const cur = a.current || {};
      const badgeCls = a.severity === "CRITICAL" ? "badge-crit" : "badge-warn";
      return `<tr>
        <td><span class="badge ${badgeCls}">${escapeHtml(a.type)}</span></td>
        <td><span class="badge ${badgeCls}">${escapeHtml(a.severity)}</span></td>
        <td class="mono" style="color:#ff6699;">${escapeHtml(a.path)}</td>
        <td>${escapeHtml((a.reasons || []).join("；"))}</td>
        <td class="mono">${escapeHtml(cur.mode || "已刪除")} (${escapeHtml(cur.owner || "-")})</td>
        <td class="mono">${escapeHtml((cur.hash || "").slice(0, 20))}...</td>
      </tr>`;
    }).join("");
  } else {
    ovPanel.style.display = "none";
  }

  // Render Posture Checklist
  document.getElementById("securityScoreText").textContent = `安全評分: ${data.security_score} / 100`;
  document.getElementById("postureList").innerHTML = (sec.posture_checks || []).map((c) => {
    const bCls = c.status === "pass" ? "badge-ok" : c.status === "warn" ? "badge-warn" : "badge-crit";
    const bTxt = c.status === "pass" ? "通過" : c.status === "warn" ? "注意" : "警報";
    return `<div class="check-item">
      <div>
        <div style="font-weight:600; font-size:13.5px;">${escapeHtml(c.label)}</div>
        <div style="font-size:12px; color:var(--text-muted); margin-top:2px;">${escapeHtml(c.detail)}</div>
      </div>
      <span class="badge ${bCls}">${bTxt}</span>
    </div>`;
  }).join("");

  // Render Events
  document.getElementById("eventList").innerHTML = (data.events || []).map((ev) => {
    return `<div class="event-item ${escapeHtml(ev.level)}">
      <div style="display:flex; justify-content:space-between; margin-bottom:2px;">
        <span style="font-weight:700;">[${escapeHtml(ev.category)}] ${escapeHtml(ev.title)}</span>
        <span class="mono" style="color:var(--text-muted); font-size:11.5px;">${escapeHtml(ev.time)}</span>
      </div>
      <div style="color:var(--text-muted); font-size:12px;">${escapeHtml(ev.detail)}</div>
    </div>`;
  }).join("");

  // Render Tab 2: FIM Targets Grid
  document.getElementById("fimBaselineTimestamp").textContent = `基線建立時間: ${fim.baseline_created_at || "--"}`;
  document.getElementById("fimTargetsGrid").innerHTML = (fim.targets || []).map((t) => {
    const bCls = t.suspicious_count > 0 ? "badge-crit" : t.exists ? "badge-ok" : "badge-warn";
    const bTxt = t.suspicious_count > 0 ? `${t.suspicious_count} 可疑` : t.exists ? "受保護中" : "目錄未啟用";
    return `<div class="target-card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
        <span style="font-weight:600; font-size:13.5px;">${escapeHtml(t.label)}</span>
        <span class="badge ${bCls}">${bTxt}</span>
      </div>
      <div class="mono" style="font-size:12px; color:var(--text-muted);">檔案數: ${t.file_count} | 路徑: ${escapeHtml((t.paths || []).join(", "))}</div>
    </div>`;
  }).join("");

  // Render Tab 2: FIM Anomalies Table
  const fimAnomBody = document.getElementById("fimAnomaliesBody");
  if (!fim.anomalies || fim.anomalies.length === 0) {
    fimAnomBody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:22px; color:#00ff41; font-family:var(--font-mono);">✅ 目前所有受監控之網頁伺服器與系統設定檔案均與安全基線 100% 吻合，未發現竄改或可疑 Webshell。</td></tr>`;
  } else {
    fimAnomBody.innerHTML = fim.anomalies.map((a) => {
      const cur = a.current || {};
      const base = a.baseline || {};
      const bCls = a.severity === "CRITICAL" ? "badge-crit" : "badge-warn";
      const modeDiff = base.mode ? `${base.mode} → ${cur.mode || "刪除"}` : `${cur.mode || "-"} (新增)`;
      const hashDiff = `${(base.hash || "無基線").slice(0, 12)}... → ${(cur.hash || "已刪除").slice(0, 12)}...`;
      return `<tr>
        <td><span class="badge ${bCls}">${escapeHtml(a.type)}</span></td>
        <td><span class="badge ${bCls}">${escapeHtml(a.severity)}</span></td>
        <td class="mono" style="color:#ff6699;">${escapeHtml(a.path)}</td>
        <td>${escapeHtml((a.reasons || []).join("；"))}</td>
        <td class="mono">${escapeHtml(modeDiff)}</td>
        <td class="mono">${escapeHtml(hashDiff)}</td>
      </tr>`;
    }).join("");
  }

  // Render Tab 2: Web Endpoints Table
  document.getElementById("webEndpointsBody").innerHTML = (data.web_endpoints || []).map((ep) => {
    const scheme = ep.https ? "https" : "http";
    const url = `${scheme}://${data.nas_host}:${ep.port}${ep.path}`;
    const statusBadge = ep.reachable
      ? `<span class="badge badge-ok">HTTP ${ep.status}</span>`
      : `<span class="badge badge-crit">連線失敗</span>`;
    const matchBadge = ep.baseline_match && (!ep.anomaly_notes || ep.anomaly_notes.length === 0)
      ? `<span class="badge badge-ok">基線吻合</span>`
      : `<span class="badge badge-warn">${escapeHtml((ep.anomaly_notes || []).join(", ") || "異動")}</span>`;
    const tlsInfo = ep.cert
      ? `${escapeHtml(ep.cert.tls_version)} (${escapeHtml(ep.cert.sha256.slice(0, 14))}...)`
      : ep.redirects_to_https ? "自動導向 HTTPS" : "HTTP 明文";
    return `<tr>
      <td style="font-weight:600;">${escapeHtml(ep.label)}</td>
      <td class="mono"><a href="${escapeHtml(url)}" target="_blank" style="color:#00e5ff; text-decoration:none;">${escapeHtml(url)}</a></td>
      <td>${statusBadge}</td>
      <td class="mono">${ep.latency_ms ?? "--"} ms</td>
      <td class="mono">${ep.body_size} B</td>
      <td class="mono">${escapeHtml((ep.body_sha256 || "--").slice(0, 24))}...</td>
      <td class="mono">${tlsInfo}</td>
      <td>${matchBadge}</td>
    </tr>`;
  }).join("");

  // Render Tab 3: Active Connections
  document.getElementById("activeConnsBody").innerHTML = (net.connections || []).map((c) => {
    const scopeBadge = c.scope === "external"
      ? `<span class="badge badge-warn">EXTERNAL (外網)</span>`
      : c.scope === "lan"
      ? `<span class="badge badge-ok">LAN (區網)</span>`
      : `<span class="badge">LOOPBACK</span>`;
    return `<tr>
      <td>${scopeBadge}</td>
      <td class="mono">${escapeHtml(c.proto.toUpperCase())}</td>
      <td class="mono">${escapeHtml(c.local_ip)}:${escapeHtml(c.local_port)}</td>
      <td class="mono" style="font-weight:600;">${escapeHtml(c.remote_ip)}:${escapeHtml(c.remote_port)}</td>
      <td class="mono">${escapeHtml(c.state)}</td>
      <td class="mono">${escapeHtml(c.process || "系統核心/無權限讀取 PID")}</td>
    </tr>`;
  }).join("");

  // Render Tab 3: Listening Ports
  document.getElementById("listeningPortsBody").innerHTML = (net.listeners || []).map((l) => {
    const bBadge = l.in_baseline
      ? `<span class="badge badge-ok">${currentLang === "en" ? "BASELINE" : currentLang === "jp" ? "承認済" : "核准基線"}</span>`
      : `<span class="badge badge-crit">${currentLang === "en" ? "UNAUTH PORT" : currentLang === "jp" ? "未承認ポート" : "非基線新埠"}</span>`;
    const desc = getPortDescription(l.port);
    return `<tr>
      <td>${bBadge}</td>
      <td class="mono">${escapeHtml(l.proto.toUpperCase())}</td>
      <td class="mono">${escapeHtml(l.bind)}</td>
      <td class="mono" style="font-weight:700; color:#00e5ff;">${escapeHtml(l.port)}</td>
      <td class="mono">${escapeHtml(l.state)}</td>
      <td>${escapeHtml(l.process ? `${l.process} — ${desc}` : desc)}</td>
    </tr>`;
  }).join("");

  // Render Tab 3: Cloudflare Edge Threat Intelligence
  renderCloudflareIntel(data.cloudflare);

  // Render Tab 4: Rootkit (chkrootkit + rkhunter), Services, Sessions, SSH Keys, Brute-Force, Disk SMART
  const rkBadge = document.getElementById("rootkitSummaryBadge");
  if (rkBadge) {
    if ((rk.alert_count || 0) > 0) {
      rkBadge.className = "badge badge-crit";
      rkBadge.textContent = `🚨 ${rk.alert_count} 項異常 (${rk.duration_ms || 0} ms)`;
    } else {
      rkBadge.className = "badge badge-ok";
      rkBadge.textContent = `✅ 6 項核心檢測全數通過 | LKM 模組基線: ${rk.loaded_modules_count || 0} 個 (${rk.duration_ms || 0} ms)`;
    }
  }

  const rkBody = document.getElementById("rootkitChecksBody");
  if (rkBody) {
    rkBody.innerHTML = (rk.checks || []).map((c) => {
      const bCls = c.status === "pass" ? "badge-ok" : c.severity === "CRITICAL" ? "badge-crit" : "badge-warn";
      const bTxt = c.status === "pass" ? "通過 (PASS)" : "警報 (CRITICAL)";
      return `<tr>
        <td><span class="badge ${bCls}">${bTxt}</span></td>
        <td class="mono"><span class="badge">${escapeHtml(c.tool || "rkhunter")}</span></td>
        <td style="font-weight:600;">${escapeHtml(c.label)}</td>
        <td class="mono">${escapeHtml(c.detail)}</td>
      </tr>`;
    }).join("");
  }

  document.getElementById("servicesBody").innerHTML = (sec.services || []).map((s) => {
    const sBadge = s.running
      ? `<span class="badge badge-ok">執行中</span>`
      : s.critical
      ? `<span class="badge badge-crit">已停止!</span>`
      : `<span class="badge">未啟用</span>`;
    return `<tr>
      <td>${sBadge}</td>
      <td class="mono" style="font-weight:700;">${escapeHtml(s.name)}</td>
      <td>${escapeHtml(s.label)}</td>
      <td class="mono">${s.process_count}</td>
      <td class="mono">${escapeHtml((s.users || []).join(", ") || "-")}</td>
      <td class="mono">${escapeHtml((s.pids || []).join(", ") || "-")}</td>
    </tr>`;
  }).join("");

  const sessBody = document.getElementById("activeSessionsBody");
  if (!sec.active_sessions || sec.active_sessions.length === 0) {
    sessBody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:var(--text-muted);">目前無互動式 TTY 登入工作階段 (監控採集使用非互動式 SSH 通道)</td></tr>`;
  } else {
    sessBody.innerHTML = sec.active_sessions.map((s) => `<tr>
      <td class="mono" style="font-weight:600;">${escapeHtml(s.user)}</td>
      <td class="mono">${escapeHtml(s.tty)}</td>
      <td class="mono">${escapeHtml(s.host)}</td>
      <td class="mono">${formatTimeTs(s.login_ts)}</td>
    </tr>`).join("");
  }

  document.getElementById("sshKeysBody").innerHTML = (sec.ssh_keys || []).map((k) => `<tr>
    <td class="mono">${escapeHtml(k.type)}</td>
    <td class="mono" style="color:#00ff41;">${escapeHtml(k.comment)}</td>
    <td class="mono">${escapeHtml(k.id)}</td>
  </tr>`).join("");

  const bruteRows = sec.historical_brute_force || [];
  const bruteBody = document.getElementById("bruteForceBody");
  const bruteBadge = document.getElementById("bruteForceBadge");
  if (bruteBody) {
    if (bruteRows.length === 0) {
      bruteBody.innerHTML = `<tr><td colspan="4" style="text-align:center; padding:18px; color:var(--text-secondary); font-family:var(--font-mono); font-size:12px;">
        No auth-log intelligence loaded. Live auth logs are not shipped by default.
        Demo sample rows appear only when <code>NAS_SENTINEL_DEMO_AUTH_INTEL=1</code>.
      </td></tr>`;
    } else {
      bruteBody.innerHTML = bruteRows.map((b) => `<tr>
        <td class="mono" style="color:#ff6699; font-weight:600;">${escapeHtml(b.ip)}</td>
        <td class="mono">${escapeHtml(String(b.attempts))} 次</td>
        <td class="mono">${escapeHtml(b.last_seen)}</td>
        <td>${escapeHtml(b.note)}</td>
      </tr>`).join("");
    }
  }
  if (bruteBadge) {
    if (sec.historical_brute_force_is_demo) {
      bruteBadge.className = "badge badge-warn";
      bruteBadge.textContent = "SAMPLE / DEMO DATA ONLY";
    } else {
      bruteBadge.className = "badge";
      bruteBadge.textContent = "No live auth-log feed";
    }
  }

  const sm = data.smart_reference || {};
  const disksHtml = (sys.disks || []).map((d) => `<div class="check-item">
    <div>
      <div style="font-weight:600;">${escapeHtml(d.label)} (${escapeHtml(d.mount)})</div>
      <div class="mono" style="font-size:12px; color:var(--text-muted);">已用: ${d.used_gb} GB / 總計: ${d.total_gb} GB (可用: ${d.avail_gb} GB)</div>
    </div>
    <span class="badge badge-ok">${d.percent}%</span>
  </div>`).join("");

  document.getElementById("diskSmartBox").innerHTML = `
    ${disksHtml}
    <div class="check-item">
      <div>
        <div style="font-weight:600;">實體硬碟型號：${escapeHtml(sm.model)}</div>
        <div style="font-size:12px; color:var(--text-muted);">通電時數: ${sm.power_on_hours?.toLocaleString()} 小時 | Reallocated: ${sm.reallocated_sectors} | Pending: ${sm.pending_sectors}</div>
        <div style="font-size:12px; color:#fbbf24; margin-top:3px;">💡 ${escapeHtml(sm.note)}</div>
      </div>
      <span class="badge badge-ok">${escapeHtml(sm.status)}</span>
    </div>
  `;

  drawCharts(data.history || []);
}

function debouncedLoadFiles() {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(loadFilesExplorer, 250);
}

async function loadFilesExplorer() {
  const q = document.getElementById("fileSearchInput").value.trim();
  const cat = document.getElementById("fileCategorySelect").value;
  const res = await apiFetch(`/api/files?q=${encodeURIComponent(q)}&category=${encodeURIComponent(cat)}&limit=250`);
  const json = await res.json();
  document.getElementById("fileExplorerCount").textContent =
    `顯示前 ${json.items.length} 筆 (符合: ${json.total_matched} / 總監控: ${json.total_monitored} 檔)`;

  document.getElementById("fileExplorerBody").innerHTML = (json.items || []).map((f) => {
    const bCls = f.status === "OK" ? "badge-ok" : "badge-crit";
    return `<tr>
      <td><span class="badge ${bCls}">${escapeHtml(f.status)}</span></td>
      <td class="mono">${escapeHtml(f.category)}</td>
      <td class="mono" style="word-break:break-all;">${escapeHtml(f.path)}</td>
      <td class="mono">${f.size.toLocaleString()}</td>
      <td class="mono">${escapeHtml(f.mode)}</td>
      <td class="mono">${escapeHtml(f.owner)}</td>
      <td class="mono">${formatTimeTs(f.mtime)}</td>
      <td class="mono" title="${escapeHtml(f.hash)}">${escapeHtml((f.hash || "").slice(0, 24))}...</td>
    </tr>`;
  }).join("");
}

function drawMultiLineChart(canvasId, history, seriesConfig, maxValOverride) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  if (rect.width === 0 || rect.height === 0) return;

  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  ctx.scale(dpr, dpr);

  const w = rect.width;
  const h = rect.height;
  const padL = 38, padR = 14, padT = 14, padB = 26;
  const plotW = w - padL - padR;
  const plotH = h - padT - padB;

  ctx.clearRect(0, 0, w, h);

  let maxVal = maxValOverride || 100;
  if (!maxValOverride) {
    maxVal = 10;
    history.forEach((pt) => {
      seriesConfig.forEach((s) => {
        if ((pt[s.key] || 0) > maxVal) maxVal = pt[s.key];
      });
    });
    maxVal = Math.ceil(maxVal * 1.15);
  }

  const isLight = document.documentElement.getAttribute("data-theme") === "light";

  // Nine-Security Cyber Grid lines
  ctx.strokeStyle = isLight ? "rgba(0, 86, 179, 0.15)" : "rgba(0, 229, 255, 0.12)";
  ctx.lineWidth = 1;
  ctx.fillStyle = isLight ? "#475569" : "#8b949e";
  ctx.font = "10.5px 'JetBrains Mono', Consolas, monospace";
  for (let i = 0; i <= 4; i++) {
    const y = padT + (plotH * i) / 4;
    const val = Math.round(maxVal * (1 - i / 4));
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(w - padR, y);
    ctx.stroke();
    ctx.fillText(String(val), 4, y + 4);
  }

  if (history.length === 0) return;

  // Time labels
  const stepX = plotW / Math.max(1, history.length - 1);
  history.forEach((pt, idx) => {
    if (idx === 0 || idx === history.length - 1 || idx % Math.max(1, Math.floor(history.length / 5)) === 0) {
      const x = padL + idx * stepX;
      ctx.fillText(pt.time, Math.max(padL, x - 22), h - 6);
    }
  });

  // Series lines
  seriesConfig.forEach((s) => {
    ctx.strokeStyle = s.color;
    ctx.lineWidth = 2.2;
    ctx.lineJoin = "round";
    ctx.lineCap = "round";
    ctx.beginPath();
    history.forEach((pt, idx) => {
      const val = pt[s.key] || 0;
      const x = padL + (history.length === 1 ? plotW / 2 : idx * stepX);
      const y = padT + plotH * (1 - Math.min(maxVal, val) / maxVal);
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();
  });
}

function drawCharts(history) {
  drawMultiLineChart(
    "chartSystem",
    history,
    [
      { key: "cpu", color: "#00e5ff" },
      { key: "mem", color: "#00ff41" },
      { key: "temp", color: "#fbbf24" },
    ],
    100
  );

  drawMultiLineChart(
    "chartWeb",
    history,
    [
      { key: "web_latency_ms", color: "#e879f9" },
      { key: "conn_total", color: "#38bdf8" },
    ],
    null
  );
}

// Periodic countdown timer
setInterval(() => {
  if (!autoPoll || isOperationBusy) return;
  countdown--;
  if (countdown <= 0) {
    countdown = pollInterval;
    fetchStatus();
  }
  const el = document.getElementById("countdownText");
  if (el) el.textContent = `${countdown}s`;
}, 1000);

window.addEventListener("resize", () => {
  if (currentSnapshot) drawCharts(currentSnapshot.history || []);
});

window.addEventListener("click", (e) => {
  if (!e.target.closest(".admin-menu-wrap")) {
    closeAdminMenu();
  }
  if (!e.target.closest(".lang-selector-wrap")) {
    closeLangMenu();
  }
});

window.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    closeResetBaselineModal();
    closeAdminMenu();
    closeLangMenu();
  }
});

// ==========================================
// Cloudflare Edge Threat Intelligence Frontend
// ==========================================
function renderCloudflareIntel(cf) {
  const cfBadge = document.getElementById("cfStatusBadge");
  const totalEl = document.getElementById("cfTotalEvents");
  const countriesEl = document.getElementById("cfCountriesCount");
  const lastSyncEl = document.getElementById("cfLastSync");
  const topPathsEl = document.getElementById("cfTopPaths");
  const eventsBody = document.getElementById("cfEventsBody");

  if (!cf || !cf.configured) {
    if (cfBadge) {
      cfBadge.className = "badge badge-warn";
      cfBadge.textContent = "⚠️ 未設定 API 權杖";
    }
    if (totalEl) totalEl.textContent = "0 次";
    if (countriesEl) countriesEl.textContent = "0 國";
    if (lastSyncEl) lastSyncEl.textContent = "未配置";
    if (topPathsEl) {
      topPathsEl.innerHTML = `<span class="badge" style="color:var(--text-secondary); cursor:pointer;" onclick="openCfConfigModal()">點擊此處設定 Cloudflare API 權杖 ➔</span>`;
    }
    if (eventsBody) {
      eventsBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:24px; color:var(--text-secondary); font-family:var(--font-mono);">
        尚未配置 Cloudflare API Token。點擊右上角「⚙️ 設定 API 權杖」即可免安裝套件、免寫 NAS 磁碟直接從 Cloudflare 邊界即時拉取刺探日誌。
      </td></tr>`;
    }
    return;
  }

  // Configured
  if (cfBadge) {
    if (cf.last_error) {
      cfBadge.className = "badge badge-crit";
      cfBadge.textContent = `❌ 同步錯誤: ${(cf.last_error || "").slice(0, 24)}...`;
    } else if (cf.sync_in_progress) {
      cfBadge.className = "badge badge-warn";
      cfBadge.textContent = "⏳ 邊界同步中...";
    } else {
      cfBadge.className = "badge badge-ok";
      cfBadge.textContent = `✅ 已連線 9SEC Edge WAF (${cf.total_events_24h || 0} 筆刺探)`;
    }
  }

  if (totalEl) totalEl.textContent = `${cf.total_events_24h || 0} 次`;
  if (countriesEl) countriesEl.textContent = `${cf.distinct_countries_count || 0} 國`;
  if (lastSyncEl) lastSyncEl.textContent = cf.last_sync ? formatTimeTs(cf.last_sync) : "同步中...";

  if (topPathsEl) {
    const top = cf.top_probed_paths || [];
    if (top.length === 0) {
      topPathsEl.innerHTML = `<span class="badge badge-ok">過去 24H 無異常刺探路徑</span>`;
    } else {
      topPathsEl.innerHTML = top.map(p => `
        <span class="badge badge-warn" style="font-family:var(--font-mono); font-size:11.5px;">
          ${escapeHtml(p.path)} <strong style="color:var(--accent); margin-left:4px;">${p.count}次</strong>
        </span>
      `).join("");
    }
  }

  if (eventsBody) {
    const evs = cf.recent_events || [];
    if (evs.length === 0) {
      eventsBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:22px; color:#00ff41; font-family:var(--font-mono);">
        ✅ 過去 24 小時內 Cloudflare 邊界節點未觀測到異常目錄掃描或 WAF 阻擋事件。
      </td></tr>`;
    } else {
      eventsBody.innerHTML = evs.map(ev => {
        const actionBadge = ev.action === "BLOCK"
          ? `<span class="badge badge-crit">BLOCK 阻擋</span>`
          : ev.action.includes("CHALLENGE")
          ? `<span class="badge badge-warn">CHALLENGE 驗證</span>`
          : `<span class="badge">${escapeHtml(ev.action)}</span>`;

        const sevBadge = ev.severity === "CRITICAL"
          ? `<span class="badge badge-crit">${escapeHtml(ev.probe_label)}</span>`
          : `<span class="badge badge-warn">${escapeHtml(ev.probe_label)}</span>`;

        const queryStr = ev.query ? `?${escapeHtml(ev.query)}` : "";
        const uaShort = (ev.user_agent || "").slice(0, 36) + (ev.user_agent && ev.user_agent.length > 36 ? "..." : "");

        return `<tr>
          <td class="mono" style="font-size:11.5px; white-space:nowrap;">${escapeHtml(ev.datetime ? ev.datetime.replace("T", " ").replace("Z", "") : "--")}</td>
          <td>${actionBadge}</td>
          <td>
            <span class="mono" style="font-weight:700; color:var(--accent);">${escapeHtml(ev.ip)}</span>
            <span class="badge" style="margin-left:4px; font-size:10px;">${escapeHtml(ev.country)}</span>
          </td>
          <td class="mono" style="color:#ff6699; font-weight:600; word-break:break-all;">
            <span style="color:var(--accent-secondary); font-size:11px;">[${escapeHtml(ev.method)}]</span> ${escapeHtml(ev.path)}${queryStr}
          </td>
          <td>${sevBadge}</td>
          <td class="mono">${escapeHtml(String(ev.status))}</td>
          <td class="mono" style="font-size:11px; color:var(--text-secondary);" title="${escapeHtml(ev.user_agent)}">${escapeHtml(uaShort)}</td>
        </tr>`;
      }).join("");
    }
  }
}

function openCfConfigModal() {
  const modal = document.getElementById("cfConfigModal");
  const msg = document.getElementById("cfModalMsg");
  if (msg) msg.style.display = "none";

  apiFetch("/api/cloudflare/status")
    .then(r => r.json())
    .then(res => {
      if (res.ok && res.data) {
        const d = res.data;
        const cb = document.getElementById("cfEnabledCheckbox");
        if (cb) cb.checked = d.enabled;
      }
    })
    .catch(() => {});

  if (modal) modal.classList.add("show");
}

function closeCfConfigModal() {
  const modal = document.getElementById("cfConfigModal");
  if (modal) modal.classList.remove("show");
}

function onCfModalOverlayClick(event) {
  if (event.target && event.target.id === "cfConfigModal") {
    closeCfConfigModal();
  }
}

async function submitCfConfig(testOnly = false) {
  const token = document.getElementById("cfApiTokenInput").value.trim();
  const zone = document.getElementById("cfZoneIdInput").value.trim();
  const enabled = document.getElementById("cfEnabledCheckbox").checked;
  const msg = document.getElementById("cfModalMsg");
  const btnTest = document.getElementById("btnTestCf");
  const btnSave = document.getElementById("btnSaveCf");

  if (!token || !zone) {
    if (msg) {
      msg.style.display = "block";
      msg.style.background = "rgba(255, 0, 85, 0.15)";
      msg.style.color = "#ff6699";
      msg.style.border = "1px solid #ff0055";
      msg.textContent = "⚠️ 請填寫 Cloudflare API Token 與 Zone ID";
    }
    return;
  }

  if (btnTest) btnTest.disabled = true;
  if (btnSave) btnSave.disabled = true;
  if (msg) {
    msg.style.display = "block";
    msg.style.background = "rgba(0, 229, 255, 0.1)";
    msg.style.color = "#00e5ff";
    msg.style.border = "1px solid #00e5ff";
    msg.textContent = testOnly ? "⏳ 正在向 Cloudflare 驗證 Token..." : "⏳ 正在驗證並儲存設定...";
  }

  try {
    const res = await apiFetch("/api/cloudflare/config", {
      method: "POST",
      body: JSON.stringify({ api_token: token, zone_id: zone, enabled, test_only: testOnly }),
    });
    const json = await res.json();
    if (json.ok) {
      if (msg) {
        msg.style.background = "rgba(0, 255, 65, 0.15)";
        msg.style.color = "#00ff41";
        msg.style.border = "1px solid #00ff41";
        msg.textContent = testOnly ? "✅ Cloudflare API 連線與權限驗證成功！" : "✅ 設定已儲存！已開始背景即時同步邊界安全情報。";
      }
      if (!testOnly) {
        showToast("✅ Cloudflare 邊界情報已啟用", "info");
        setTimeout(() => {
          closeCfConfigModal();
          fetchStatus();
        }, 1200);
      }
    } else {
      if (msg) {
        msg.style.background = "rgba(255, 0, 85, 0.15)";
        msg.style.color = "#ff6699";
        msg.style.border = "1px solid #ff0055";
        msg.textContent = `❌ ${json.error || "驗證失敗"}`;
      }
    }
  } catch (err) {
    if (msg) {
      msg.style.background = "rgba(255, 0, 85, 0.15)";
      msg.style.color = "#ff6699";
      msg.style.border = "1px solid #ff0055";
      msg.textContent = `❌ 連線例外: ${err.message || err}`;
    }
  } finally {
    if (btnTest) btnTest.disabled = false;
    if (btnSave) btnSave.disabled = false;
  }
}

async function triggerCfSync() {
  showToast("🔄 正在向 Cloudflare 邊界同步最新刺探日誌...", "info");
  try {
    const res = await apiFetch("/api/cloudflare/sync", { method: "POST" });
    const json = await res.json();
    setTimeout(() => {
      fetchStatus();
      showToast("✅ Cloudflare 邊界情報同步完成", "info");
    }, 1500);
  } catch (err) {
    showToast(`❌ 同步失敗: ${err.message || err}`, "crit");
  }
}

// Initial load
initTheme();
initLanguage();
loadAppConfig();
fetchStatus();

// ==========================================
// Setup Wizard & System Settings Controller
// ==========================================
let appConfig = null;
let isSetupInitial = false;

async function loadAppConfig() {
  try {
    if (!getApiToken()) {
      showApiAuthModal("Enter API token to load configuration (data/api_token.txt).");
      return;
    }
    const res = await apiFetch("/api/config");
    if (res.status === 401) return;
    const json = await res.json();
    if (json.ok && json.config) {
      appConfig = json.config;
      populateSetupForm(json.config, json.detected_ssh_keys || []);
      if (!appConfig.is_configured) {
        openSetupModal(true);
      }
    }
  } catch (err) {
    console.error("Failed to load config:", err);
  }
}

function populateSetupForm(cfg, detectedKeys) {
  const hostInput = document.getElementById("setupNasHost");
  const userInput = document.getElementById("setupNasUser");
  const portInput = document.getElementById("setupNasPort");
  const keySelect = document.getElementById("setupSshKeySelect");
  const keyCustom = document.getElementById("setupSshKeyCustom");
  const cfToken = document.getElementById("setupCfToken");
  const cfZone = document.getElementById("setupCfZone");
  const cfEnabled = document.getElementById("setupCfEnabled");

  if (hostInput && cfg.nas_host) hostInput.value = cfg.nas_host;
  if (userInput && cfg.nas_user) userInput.value = cfg.nas_user;
  if (portInput) portInput.value = cfg.nas_port || 22;
  if (keyCustom) keyCustom.value = cfg.ssh_key_path || "";

  if (keySelect) {
    keySelect.innerHTML = '<option value="">(系統預設金鑰 / ~/.ssh/ 自動解析)</option>';
    detectedKeys.forEach(k => {
      const opt = document.createElement("option");
      opt.value = k;
      opt.textContent = k;
      if (cfg.ssh_key_path === k) opt.selected = true;
      keySelect.appendChild(opt);
    });
  }

  // Never echo raw Cloudflare tokens (server strips them). Keep field empty; show presence hint.
  if (cfToken) {
    cfToken.value = "";
    cfToken.placeholder = cfg.cloudflare_api_token_set
      ? `Token on file (${cfg.cloudflare_api_token_masked || "***"}) — leave blank to keep`
      : "具備 Zone.Analytics:Read 權限之 Token";
  }
  if (cfZone && cfg.cloudflare_zone_id) cfZone.value = cfg.cloudflare_zone_id;
  if (cfEnabled) cfEnabled.checked = Boolean(cfg.cloudflare_enabled);
}

function openSetupModal(isInitial = false) {
  isSetupInitial = isInitial;
  const modal = document.getElementById("setupWizardModal");
  const btnCloseX = document.getElementById("btnSetupCloseX");
  const btnCancel = document.getElementById("btnCancelSetup");
  if (!modal) return;

  if (isInitial) {
    if (btnCloseX) btnCloseX.style.display = "none";
    if (btnCancel) btnCancel.style.display = "none";
  } else {
    if (btnCloseX) btnCloseX.style.display = "block";
    if (btnCancel) btnCancel.style.display = "inline-block";
  }

  modal.style.display = "flex";
  if (!appConfig) {
    loadAppConfig();
  }
}

function closeSetupModal() {
  if (isSetupInitial && (!appConfig || !appConfig.is_configured)) {
    showToast("⚠️ 請先完成 NAS 連線與基線配置以啟用戰情室", "warn");
    return;
  }
  const modal = document.getElementById("setupWizardModal");
  if (modal) modal.style.display = "none";
}

function onSetupModalOverlayClick(e) {
  if (e.target && e.target.id === "setupWizardModal") {
    if (!isSetupInitial && appConfig && appConfig.is_configured) {
      closeSetupModal();
    }
  }
}

function toggleSetupSshHelp() {
  const content = document.getElementById("setupSshHelpContent");
  const toggle = document.getElementById("setupSshHelpToggle");
  if (!content) return;
  const isHidden = content.style.display === "none" || !content.style.display;
  content.style.display = isHidden ? "block" : "none";
  if (toggle) {
    toggle.textContent = isHidden ? t("setup.ssh_help_hide", "▼ 收合教學") : t("setup.ssh_help_show", "▶ 展開教學");
  }
}

function onSshKeySelectChange() {
  const select = document.getElementById("setupSshKeySelect");
  const custom = document.getElementById("setupSshKeyCustom");
  if (select && custom) {
    custom.value = select.value;
  }
}

function toggleSetupCfSection() {
  const sec = document.getElementById("setupCfSection");
  const icon = document.getElementById("setupCfToggleIcon");
  if (!sec) return;
  const isHidden = sec.style.display === "none" || !sec.style.display;
  sec.style.display = isHidden ? "flex" : "none";
  if (icon) icon.textContent = isHidden ? "▼ 收合" : "▶ 展開";
}

async function testSetupCfConnection() {
  const token = (document.getElementById("setupCfToken").value || "").trim();
  const zone = (document.getElementById("setupCfZone").value || "").trim();
  const msg = document.getElementById("setupCfMsg");
  const btn = document.getElementById("btnTestSetupCf");

  if (!token || !zone) {
    if (msg) {
      msg.style.display = "block";
      msg.style.background = "rgba(255, 0, 85, 0.15)";
      msg.style.color = "#ff6699";
      msg.style.border = "1px solid #ff0055";
      msg.textContent = "⚠️ 請填寫 Cloudflare API Token 與 Zone ID";
    }
    return;
  }

  if (btn) {
    btn.disabled = true;
    btn.textContent = "⏳ 測試中...";
  }
  if (msg) {
    msg.style.display = "block";
    msg.style.background = "rgba(0, 229, 255, 0.1)";
    msg.style.color = "#00e5ff";
    msg.style.border = "1px solid #00e5ff";
    msg.textContent = "⏳ 正在向 Cloudflare GraphQL API 驗證 Token 權限...";
  }

  try {
    const res = await apiFetch("/api/cloudflare/config", {
      method: "POST",
      body: JSON.stringify({ api_token: token, zone_id: zone, enabled: true, test_only: true }),
    });
    const json = await res.json();
    if (json.ok) {
      if (msg) {
        msg.style.background = "rgba(0, 255, 65, 0.15)";
        msg.style.color = "#00ff41";
        msg.style.border = "1px solid #00ff41";
        msg.textContent = "✅ Cloudflare API 連線與權限驗證成功！";
      }
      showToast("✅ Cloudflare API 驗證成功", "ok");
    } else {
      if (msg) {
        msg.style.background = "rgba(255, 0, 85, 0.15)";
        msg.style.color = "#ff6699";
        msg.style.border = "1px solid #ff0055";
        msg.textContent = "❌ 驗證失敗: " + (json.error || "無法連線至 Cloudflare");
      }
      showToast("❌ Cloudflare 驗證失敗", "danger");
    }
  } catch (e) {
    if (msg) {
      msg.style.background = "rgba(255, 0, 85, 0.15)";
      msg.style.color = "#ff6699";
      msg.style.border = "1px solid #ff0055";
      msg.textContent = "❌ 網路異常: " + e.message;
    }
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = "🧪 測試連線 (Test)";
    }
  }
}

async function testNasConnection() {
  const host = (document.getElementById("setupNasHost").value || "").trim();
  const user = (document.getElementById("setupNasUser").value || "").trim();
  const port = parseInt(document.getElementById("setupNasPort").value || "22", 10);
  const key = (document.getElementById("setupSshKeyCustom").value || "").trim();

  const btn = document.getElementById("btnTestNasConnect");
  const icon = document.getElementById("btnTestNasIcon");
  const text = document.getElementById("btnTestNasText");
  const resBox = document.getElementById("setupProbeResult");

  if (!host || !user) {
    showToast("⚠️ 請先填寫 NAS IP 與 SSH 帳號", "warn");
    return;
  }

  if (btn) btn.disabled = true;
  if (icon) icon.textContent = "⏳";
  if (text) text.textContent = "正在透過 SSH 探測 NAS 核心與 DSM...";
  if (resBox) resBox.style.display = "none";

  try {
    const res = await apiFetch("/api/setup/test-connection", {
      method: "POST",
      body: JSON.stringify({ nas_host: host, nas_user: user, nas_port: port, ssh_key_path: key }),
    });
    const json = await res.json();
    if (resBox) {
      resBox.style.display = "block";
      if (json.ok && json.system) {
        resBox.style.background = "rgba(0, 255, 65, 0.12)";
        resBox.style.border = "1px solid #00ff41";
        resBox.style.color = "#00ff41";
        const fp = json.ssh_host_key_fp ? `<br>• SSH Host Key：<strong>${escapeHtml(json.ssh_host_key_fp)}</strong>` : "";
        resBox.innerHTML = `
          <div style="font-weight:700; font-size:13px; margin-bottom:4px;">✅ SSH 連線測試成功！NAS 系統探測完成</div>
          <div style="color:#d1fae5; font-size:12px;">
            • 系統版本：<strong>${escapeHtml(json.system.dsm_version)}</strong><br>
            • 核心架構：<strong>${escapeHtml(json.system.kernel)} (${escapeHtml(json.system.arch)})</strong><br>
            • Python 環境：<strong>${escapeHtml(json.system.python)}</strong>${fp}
          </div>
        `;
        showToast("✅ NAS 連線與探測成功！", "info");
      } else {
        resBox.style.background = "rgba(255, 0, 85, 0.12)";
        resBox.style.border = "1px solid #ff0055";
        resBox.style.color = "#ff4d88";
        resBox.innerHTML = `
          <div style="font-weight:700; font-size:13px; margin-bottom:4px;">❌ 連線失敗</div>
          <div style="color:#ffccd7; font-size:12px;">${escapeHtml(json.error || "未知連線錯誤")}</div>
        `;
      }
    }
  } catch (err) {
    if (resBox) {
      resBox.style.display = "block";
      resBox.style.background = "rgba(255, 0, 85, 0.12)";
      resBox.style.border = "1px solid #ff0055";
      resBox.style.color = "#ff4d88";
      resBox.textContent = `❌ 連線請求例外: ${err.message || err}`;
    }
  } finally {
    if (btn) btn.disabled = false;
    if (icon) icon.textContent = "⚡";
    if (text) text.textContent = "測試 SSH 連線並自動探測 NAS";
  }
}

async function generateNewSshKey() {
  const passInput = document.getElementById("setupKeyPassphrase");
  let passphrase = passInput ? passInput.value : "";
  if (!passphrase || passphrase.length < 8) {
    passphrase = window.prompt("Enter a passphrase for the new Ed25519 key (min 8 characters). Empty passphrases are not allowed:") || "";
  }
  if (!passphrase || passphrase.length < 8) {
    showToast("⚠️ Passphrase required (min 8 chars). Empty-passphrase keygen is disabled.", "warn");
    return;
  }
  if (passInput) passInput.value = passphrase;
  showToast("🔑 正在產生受密碼保護的 Ed25519 金鑰對...", "info");
  try {
    const res = await apiFetch("/api/setup/generate-key", {
      method: "POST",
      body: JSON.stringify({ passphrase }),
    });
    const json = await res.json();
    if (json.ok) {
      const customInput = document.getElementById("setupSshKeyCustom");
      if (customInput) customInput.value = json.key_path;

      const helperPanel = document.getElementById("setupKeyHelperPanel");
      const cmdText = document.getElementById("setupKeyCommandText");
      if (cmdText) cmdText.value = json.dsm_command;
      if (helperPanel) helperPanel.style.display = "block";
      showToast("✅ 新金鑰已生成（請用 ssh-agent 載入密碼）。複製授權指令至 NAS。", "info");
    } else {
      showToast(`❌ 生成失敗: ${json.error}`, "crit");
    }
  } catch (err) {
    showToast(`❌ 請求異常: ${err.message || err}`, "crit");
  }
}

function copySetupKeyCmd() {
  const cmdText = document.getElementById("setupKeyCommandText");
  if (!cmdText || !cmdText.value) return;
  navigator.clipboard.writeText(cmdText.value).then(() => {
    showToast("📋 已複製授權指令到剪貼簿！", "info");
  }).catch(() => {
    cmdText.select();
    document.execCommand("copy");
    showToast("📋 已複製！", "info");
  });
}

async function saveSetupConfig() {
  const host = (document.getElementById("setupNasHost").value || "").trim();
  const user = (document.getElementById("setupNasUser").value || "").trim();
  const port = parseInt(document.getElementById("setupNasPort").value || "22", 10);
  const key = (document.getElementById("setupSshKeyCustom").value || "").trim();
  const cfToken = (document.getElementById("setupCfToken").value || "").trim();
  const cfZone = (document.getElementById("setupCfZone").value || "").trim();
  const cfEnabled = document.getElementById("setupCfEnabled").checked;

  const btnSave = document.getElementById("btnSaveSetup");
  const msgBox = document.getElementById("setupSaveMsg");

  if (!host || !user) {
    showToast("⚠️ 請輸入 NAS 主機 IP 與 SSH 帳號", "warn");
    return;
  }

  if (btnSave) {
    btnSave.disabled = true;
    btnSave.textContent = "⏳ 正在驗證連線並建立初始基線...";
  }
  if (msgBox) msgBox.style.display = "none";

  try {
    const payload = {
      nas_host: host,
      nas_user: user,
      nas_port: port,
      ssh_key_path: key,
      cloudflare_enabled: cfEnabled,
      cloudflare_zone_id: cfZone,
    };
    // Only send Cloudflare token when the user entered a new value (blank = keep existing).
    if (cfToken) payload.cloudflare_api_token = cfToken;
    const res = await apiFetch("/api/setup/save", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    const json = await res.json();
    if (json.ok) {
      if (msgBox) {
        msgBox.style.display = "block";
        msgBox.style.background = "rgba(0, 255, 65, 0.15)";
        msgBox.style.border = "1px solid #00ff41";
        msgBox.style.color = "#00ff41";
        msgBox.textContent = "✅ " + (json.message || "設定已成功儲存！");
      }
      showToast("🛡️ 設定已儲存！進入戰情室...", "info");
      appConfig = json.config || { is_configured: true };
      isSetupInitial = false;
      setTimeout(() => {
        closeSetupModal();
        fetchStatus();
      }, 1200);
    } else {
      if (msgBox) {
        msgBox.style.display = "block";
        msgBox.style.background = "rgba(255, 0, 85, 0.15)";
        msgBox.style.border = "1px solid #ff0055";
        msgBox.style.color = "#ff6699";
        msgBox.textContent = "❌ " + (json.error || "儲存失敗");
      }
    }
  } catch (err) {
    if (msgBox) {
      msgBox.style.display = "block";
      msgBox.style.background = "rgba(255, 0, 85, 0.15)";
      msgBox.style.border = "1px solid #ff0055";
      msgBox.style.color = "#ff6699";
      msgBox.textContent = `❌ 儲存例外錯誤: ${err.message || err}`;
    }
  } finally {
    if (btnSave) {
      btnSave.disabled = false;
      btnSave.textContent = "🛡️ 儲存並進入戰情室 (Save & Launch)";
    }
  }
}

