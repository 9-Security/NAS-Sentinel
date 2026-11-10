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
    "lang.toggle_title": "切換語系",
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
    "setup.keygen_link": "🔑 產生受密碼保護的新金鑰",
    "setup.btn_test": "測試 SSH 連線並自動探測 NAS",
    "setup.cf_header": "🌐 Cloudflare 邊界日誌監控 (選填，可稍後設定)",
    "setup.btn_save": "🛡️ 測試並上線 (Test & go live)",
    "setup.btn_close": "關閉",
    "setup.footnote": "🔒 密鑰僅儲存在本地端 data/ 目錄",
    "page.title": "Nine-Security | NAS Sentinel - Synology DSM 即時安全監控中心",
    "toast.placeholder": "系統提示訊息",
    "overview.chart_temp_legend": "溫度°C",
    "overview.web_latency_title": "⚡ Nginx 網頁回應延遲 (ms) 與網路連線數",
    "overview.web_latency_legend": "延遲 (ms)",
    "overview.web_conns_legend": "連線數",
    "overview.anom_title": "🚨 偵測到網頁或系統檔案異動 / 可疑檔案 (即時比對結果)",
    "overview.anom_goto": "前往完整檔案檢視器 →",
    "overview.posture_title": "🛡️ NAS 安全防禦態勢即時檢核 (Security Posture)",
    "overview.score_prefix": "安全評分:",
    "overview.events_title": "🔔 即時安全與系統事件日誌 (Event Stream)",
    "overview.events_sub": "自動保存最近 150 筆",
    "th.status": "狀態",
    "th.severity": "嚴重度",
    "th.file_path": "檔案完整路徑",
    "th.reason": "異動原因 / 偵測特徵",
    "th.perms_owner": "目前權限 / 擁有者",
    "th.sha256": "目前 SHA-256 雜湊",
    "th.change_type": "異動類型",
    "th.trigger": "觸發原因",
    "th.perm_change": "權限變更",
    "th.hash_diff": "基線 SHA-256 → 目前 SHA-256",
    "th.ms_ts": "毫秒時間戳記",
    "th.level": "等級",
    "th.inotify_mask": "核心事件旗標 (inotify Mask)",
    "th.trigger_path": "觸發檔案路徑",
    "th.live_perms": "當下權限 / 擁有者",
    "th.live_hash": "即時計算 SHA-256 / 威脅判定",
    "th.endpoint": "端點名稱",
    "th.url_path": "網址路徑",
    "th.conn_status": "連線狀態",
    "th.latency": "回應延遲",
    "th.size": "內容大小",
    "th.resp_hash": "回應內容 SHA-256 雜湊",
    "th.tls": "TLS 協定 / 憑證指紋",
    "th.baseline_cmp": "基線比對",
    "th.category": "類別",
    "th.bytes": "大小 (Bytes)",
    "th.mode": "權限 (Mode)",
    "th.owner": "擁有者",
    "th.mtime": "最後修改時間",
    "th.fingerprint": "SHA-256 / 特徵指紋",
    "th.scope": "連線範圍",
    "th.proto": "協定",
    "th.local_addr": "本機位址與埠號",
    "th.remote_addr": "遠端 IP 與埠號",
    "th.process": "關聯程序 (PID/Name)",
    "th.baseline_status": "基線狀態",
    "th.bind": "綁定位址",
    "th.port": "埠號 (Port)",
    "th.proc_desc": "執行程序 / 服務說明",
    "th.time": "時間",
    "th.action": "處置動作",
    "th.src_ip_country": "來源 IP 與國家",
    "th.probe_path": "刺探目標路徑 (Path & Query)",
    "th.threat_class": "威脅判定分類",
    "th.status_code": "狀態碼",
    "th.ua": "客戶端特徵 (User-Agent)",
    "th.engine": "對應工具引擎",
    "th.module": "檢測模組 (對標 chkrootkit / rkhunter)",
    "th.result": "即時核心與記憶體比對結果",
    "th.service": "服務名稱",
    "th.svc_desc": "功能說明",
    "th.proc_count": "程序數",
    "th.run_as": "執行帳號",
    "th.account": "帳號",
    "th.tty": "終端機 (TTY)",
    "th.src_host": "來源主機 IP",
    "th.login_time": "登入時間",
    "th.key_type": "金鑰類型",
    "th.key_comment": "金鑰備註 / 身分",
    "th.key_hash": "雜湊識別碼 (SHA-256 前 16 碼)",
    "th.attacker_ip": "攻擊來源 IP",
    "th.fail_count": "失敗嘗試次數",
    "th.last_seen": "最後觀測日期",
    "th.defense_note": "防禦狀態與備註",
    "fim.targets_title": "📂 受保護之網頁伺服器與關鍵系統目錄範疇",
    "fim.baseline_prefix": "基線建立時間:",
    "fim.rebuild_btn": "🛡️ 重建/維護基準",
    "fim.inotify_title": "⚡ Linux 核心 inotify 毫秒級即時檔案事件流 (取代 auditd 檔案監控)",
    "fim.inotify_sub": "即時監聽中：250 個網頁與系統目錄",
    "fim.diff_title": "🔍 檔案完整性異動與可疑 Webshell 告警清單 (FIM Diff)",
    "fim.diff_sub": "比對項目：SHA-256 內容雜湊、Linux 權限模式、擁有者、新增/刪除、Webshell 特徵",
    "fim.web_title": "🌐 Nginx / DSM 網頁伺服器端點即時探測與回應雜湊驗證",
    "fim.web_sub": "從本機直接對 NAS 80 / 443 / 5000 / 5001 進行內容防竄改與憑證檢驗",
    "fim.explorer_title": "🗄️ 網頁伺服器與系統檔案 SHA-256 基線檢索器",
    "fim.explorer_count": "顯示 -- / -- 個檔案",
    "fim.search_ph": "輸入檔名、路徑 (如 login.cgi, nginx.conf, .php) 或 SHA-256 雜湊搜尋...",
    "fim.cat_all": "所有監控類別 (All Categories)",
    "fim.cat_web_root": "DSM 網頁根目錄 (/usr/syno/synoman, html)",
    "fim.cat_web_config": "Nginx 設定與樣板 (/etc/nginx, share/nginx)",
    "fim.cat_user_web": "自架網站目錄 (/volume1/web)",
    "fim.cat_security": "系統安全與防火牆設定 (sshd, sysctl, firewall)",
    "fim.cat_binary": "核心系統執行檔防木馬 (/bin, /usr/bin, /usr/sbin)",
    "fim.cat_shared": "共享與暫存敏感區 (/volume1/public, tmp)",
    "fim.refresh": "🔄 重新整理清單",
    "net.conns_title": "🔌 活動中網路連線即時監控 (Active TCP/UDP Connections)",
    "net.conns_sub": "自動標示外部公網 (WAN) 連線與內網管理連線",
    "net.ports_title": "📡 NAS 監聽埠盤點與安全基線比對 (Listening Ports Matrix)",
    "net.ports_sub": "若出現未在核准基線內的開放埠號，系統將自動發起高風險警報",
    "cf.panel_title": "🌐 Cloudflare 邊界網站刺探與 WAF 防禦情資 (Edge Threat Intelligence)",
    "cf.checking": "檢查中...",
    "cf.sync_btn": "🔄 即時同步",
    "cf.config_btn": "⚙️ 設定 API 權杖",
    "cf.stats_title": "邊界防禦與刺探統計 (24H STATS)",
    "cf.stat_total": "攔截刺探總量",
    "cf.stat_total_unit": "0 次",
    "cf.stat_countries": "刺探來源國家數",
    "cf.stat_countries_unit": "0 國",
    "cf.stat_last_sync": "最近邊界同步時間",
    "cf.never_synced": "尚未同步",
    "cf.top_paths": "最常被刺探之敏感目錄 TOP 5 (MOST PROBED TARGETS)",
    "cf.no_paths": "暫無刺探路徑紀錄",
    "sec.rootkit_title": "🕵️ DSM Rootkit 與系統指令防木馬即時檢測 (chkrootkit + rkhunter 無套件核心引擎)",
    "sec.detecting": "檢測中...",
    "sec.daemons_title": "⚙️ 核心守護程序存活狀態 (Core Daemons)",
    "sec.daemons_sub": "即時監測 Nginx、SSH、Cloudflared 等服務",
    "sec.sessions_title": "🔑 目前登入工作階段 (utmp) 與授權 SSH 公鑰",
    "sec.utmp_header": "目前活動登入階段 (/var/run/utmp)：",
    "sec.keys_header": "已授權 SSH 公鑰清單 (~/.ssh/authorized_keys)：",
    "sec.disk_title": "💽 硬碟儲存空間與 SMART 健康監控",
    "sec.smart_badge": "PASSED (0 壞軌)",
    "reset.warning_title": "⚠️ 注意：此操作將會：",
    "reset.li1": "將目前 1,786 個系統與網頁檔案的 SHA-256 視為合法基準並清空異動警報",
    "reset.li2": "將目前開放之網路監聽埠與 105 個核心模組記錄為核准清單",
    "reset.li3": "此操作僅適用於您剛完成合法 DSM 韌體更新或明確修改設定後",
    "reset.footer": "若您並未主動變更 NAS 設定，請勿執行此操作，以免掩蓋潛在的未授權竄改！",
    "cf.desc": "透過 Cloudflare GraphQL API，直接從 Cloudflare 全球邊界節點拉取外部對您網域的「惡意目錄刺探」與「WAF 攔截事件」，完全不耗損 NAS 本地硬碟 I/O。",
    "cf.token_label": "Cloudflare API Token (權杖)",
    "cf.token_ph": "具有 Zone.Analytics:Read 權限的 API Token",
    "cf.token_help": "至 Cloudflare ➔ My Profile ➔ API Tokens 建立具備「Zone - Analytics - Read」權限之 Token",
    "cf.zone_label": "Zone ID (區域標籤)",
    "cf.zone_ph": "例如：42a1b7... (32 位元十六進位字串)",
    "cf.zone_help": "在 Cloudflare 點入網域 ➔ 右下方 Overview 即可複製 Zone ID",
    "cf.enable_label": "啟用邊界安全情報自動排程同步 (每 60 秒)",
    "setup.ssh_help_body_1": "<strong>1. 開啟 DSM SSH 服務</strong>：登入 DSM 桌面 ➔ 控制台 ➔ 終端機與 SNMP ➔ 勾選「啟用 SSH 服務」(Port 22)。",
    "setup.ssh_help_body_2": "<strong>2. 確認管理員權限</strong>：Synology 規定僅管理員群組 (`administrators`) 使用者可透過 SSH 登入。",
    "setup.ssh_help_body_3": "<strong>3. 授權 SSH 金鑰</strong>：點擊下方「🔑 產生受密碼保護的新金鑰」（需設定 Passphrase），將公鑰授權指令貼至 DSM「任務排程表」執行一次。監控掃描使用 <code>BatchMode</code>，請以 <code>ssh-agent</code> 載入私鑰密碼。",
    "setup.host_ph": "例如：192.168.1.100",
    "setup.user_ph": "例如：admin 或 root",
    "setup.port_hint": "(可自訂)",
    "setup.port_title": "若您的 NAS 修改過 SSH Port（例如 2222、5022），請在此修改",
    "setup.keygen_link": "🔑 產生受密碼保護的新金鑰",
    "setup.key_default_opt": "(系統預設金鑰 / ~/.ssh/ 自動解析)",
    "setup.key_custom_ph": "例如：~/.ssh/id_ed25519（僅允許 ~/.ssh 內檔案）",
    "setup.passphrase_ph": "新金鑰 Passphrase（至少 8 字元；禁止空白密碼）",
    "setup.key_auth_title": "🔑 快速授權此金鑰至 Synology NAS",
    "setup.key_auth_desc": "登入 NAS 終端機一次，貼上下列單行指令即可完成免密碼公鑰授權：",
    "setup.copy_btn": "📋 複製",
    "setup.cf_expand": "▶ 展開",
    "setup.cf_collapse": "▼ 收合",
    "setup.cf_token_ph": "具備 Zone.Analytics:Read 權限之 Token",
    "setup.cf_zone_ph": "32 位元 Zone Tag",
    "setup.cf_enable": "啟用 Cloudflare 邊界安全情報自動排程同步",
    "setup.btn_test_cf": "🧪 測試連線 (Test)",
    "setup.btn_skip": "🚪 稍後設定，先進入戰情室",
    "setup.btn_persist": "💾 儲存連線設定",
    "setup.btn_golive": "🛡️ 測試並上線 (Test & go live)",
    "setup.btn_skip_busy": "⏳ 進入離線戰情室...",
    "setup.btn_save_busy": "⏳ 儲存並測試 SSH...",
    "setup.btn_persist_busy": "⏳ 儲存參數中...",
    "kpi.diff_init": "異動: 0 | 新增: 0 | 刪除: 0",
    "kpi.latency_init": "平均回應延遲: -- ms",
    "kpi.net_detail_init": "區網: -- | 外網: --",
    "kpi.unauth_init": "非授權埠: 0",
    "kpi.disk_gb_init": "可用: -- GB / -- GB",
    "kpi.svc_init": "服務: --/--",
    "status.not_configured": "尚未設定",
    "status.need_setup": "請透過安裝精靈完成 NAS 連線與基線配置",
    "status.offline": "離線模式",
    "status.ssh_error": "SSH 連線異常",
    "toast.busy": "⚠️ 目前已有掃描或系統作業正在進行中，請稍候...",
    "toast.cooldown": "⏳ 系統防刷冷卻中，請等待 {n} 秒後再執行",
    "scan.fast_busy": "快速掃描中...",
    "scan.deep_busy": "全量深度比對中...",
    "scan.deep_btn_busy": "⏳ 深度比對中 (~3.5s)...",
    "toast.backend_busy": "⚠️ 後端回報：系統已有其他作業正在執行，請稍候",
    "toast.scan_deep_done": "✅ 深度檔案雜湊掃描完成",
    "toast.scan_fast_done": "⚡ 快速掃描完成",
    "toast.scan_fail": "❌ 掃描失敗:",
    "toast.unknown_err": "未明錯誤",
    "toast.conn_ex": "❌ 連線或執行例外:",
    "scan.done_cooldown": "完成 (冷卻中)",
    "toast.admin_busy": "⚠️ 系統作業執行中，無法開啟管理選單",
    "toast.reset_busy": "⚠️ 系統作業執行中，無法進行基線重設",
    "toast.job_busy": "⚠️ 目前已有作業正在執行，請稍候",
    "reset.busy_msg": "正在重設基線...",
    "reset.btn_busy": "⏳ 正在重建基線中...",
    "toast.backend_busy2": "⚠️ 後端回報：系統忙碌中，請稍候再試",
    "toast.reset_ok": "🛡️ 安全基準重建成功！所有檔案與埠已設為新基線",
    "toast.reset_fail": "❌ 重建基線失敗:",
    "toast.reset_ex": "❌ 重建基線例外:",
    "posture.score": "安全評分: {n} / 100",
    "posture.pass": "通過",
    "posture.warn": "注意",
    "posture.alert": "警報",
    "fim.files_count": "檔案數:",
    "fim.path_label": "路徑:",
    "fim.suspicious": "{n} 可疑",
    "fim.protected": "受保護中",
    "fim.dir_off": "目錄未啟用",
    "fim.clean": "✅ 目前所有受監控之網頁伺服器與系統設定檔案均與安全基線 100% 吻合，未發現竄改或可疑 Webshell。",
    "fim.deleted": "已刪除",
    "fim.no_baseline": "無基線",
    "fim.added": "新增",
    "web.conn_fail": "連線失敗",
    "web.hash_ok": "基線吻合",
    "web.changed": "異動",
    "web.redirect_https": "自動導向 HTTPS",
    "web.http_plain": "HTTP 明文",
    "net.external": "EXTERNAL (外網)",
    "net.lan": "LAN (區網)",
    "net.proc_unknown": "系統核心/無權限讀取 PID",
    "rk.alerts": "🚨 {n} 項異常 ({ms} ms)",
    "rk.all_pass": "✅ 6 項核心檢測全數通過 | LKM 模組基線: {n} 個 ({ms} ms)",
    "rk.pass": "通過 (PASS)",
    "rk.crit": "警報 (CRITICAL)",
    "svc.running": "執行中",
    "svc.stopped": "已停止!",
    "svc.inactive": "未啟用",
    "sess.empty": "目前無互動式 TTY 登入工作階段 (監控採集使用非互動式 SSH 通道)",
    "auth.attempts": "{n} 次",
    "disk.used": "已用: {u} GB / 總計: {t} GB (可用: {a} GB)",
    "disk.model": "實體硬碟型號：",
    "disk.hours": "通電時數:",
    "disk.hours_unit": "小時",
    "files.showing": "顯示前 {shown} 筆 (符合: {matched} / 總監控: {total} 檔)",
    "cf.unset_token": "⚠️ 未設定 API 權杖",
    "cf.not_configured": "未配置",
    "cf.click_config": "點擊此處設定 Cloudflare API 權杖 ➔",
    "cf.unset_hint": "尚未配置 Cloudflare API Token。點擊右上角「⚙️ 設定 API 權杖」即可免安裝套件、免寫 NAS 磁碟直接從 Cloudflare 邊界即時拉取刺探日誌。",
    "cf.sync_err": "❌ 同步錯誤:",
    "cf.syncing": "⏳ 邊界同步中...",
    "cf.connected": "✅ 已連線 9SEC Edge WAF ({n} 筆刺探)",
    "cf.hits_unit": "{n} 次",
    "cf.countries_unit": "{n} 國",
    "cf.sync_pending": "同步中...",
    "cf.no_probe_24h": "過去 24H 無異常刺探路徑",
    "cf.path_hits": "{n}次",
    "cf.empty_events": "✅ 過去 24 小時內 Cloudflare 邊界節點未觀測到異常目錄掃描或 WAF 阻擋事件。",
    "cf.block": "BLOCK 阻擋",
    "cf.challenge": "CHALLENGE 驗證",
    "cf.need_fields": "⚠️ 請填寫 Cloudflare API Token 與 Zone ID",
    "cf.testing": "⏳ 正在向 Cloudflare 驗證 Token...",
    "cf.saving": "⏳ 正在驗證並儲存設定...",
    "cf.test_ok": "✅ Cloudflare API 連線與權限驗證成功！",
    "cf.save_ok": "✅ 設定已儲存！已開始背景即時同步邊界安全情報。",
    "cf.enabled_toast": "✅ Cloudflare 邊界情報已啟用",
    "cf.verify_fail": "驗證失敗",
    "cf.ex": "❌ 連線例外:",
    "cf.sync_toast": "🔄 正在向 Cloudflare 邊界同步最新刺探日誌...",
    "cf.sync_done": "✅ Cloudflare 邊界情報同步完成",
    "cf.sync_fail": "❌ 同步失敗:",
    "setup.need_host_user": "⚠️ 請先填寫 NAS IP 與 SSH 帳號",
    "setup.probing": "正在透過 SSH 探測 NAS 核心與 DSM...",
    "setup.probe_ok_title": "✅ SSH 連線測試成功！NAS 系統探測完成",
    "setup.probe_sys": "系統版本：",
    "setup.probe_arch": "核心架構：",
    "setup.probe_py": "Python 環境：",
    "setup.probe_ok_toast": "✅ NAS 連線與探測成功！",
    "setup.probe_fail_title": "❌ 連線失敗",
    "setup.unknown_conn": "未知連線錯誤",
    "setup.probe_ex": "❌ 連線請求例外:",
    "setup.keygen_toast": "🔑 正在產生受密碼保護的 Ed25519 金鑰對...",
    "setup.keygen_ok": "✅ 新金鑰已生成（請用 ssh-agent 載入密碼）。複製授權指令至 NAS。",
    "setup.keygen_fail": "❌ 生成失敗:",
    "setup.req_ex": "❌ 請求異常:",
    "setup.copied": "📋 已複製授權指令到剪貼簿！",
    "setup.copied_short": "📋 已複製！",
    "setup.skip_ok": "🚪 已進入離線戰情室（既有主機／金鑰未變更）",
    "setup.skip_fail": "無法略過設定",
    "setup.need_fields": "⚠️ 請輸入 NAS 主機 IP 與 SSH 帳號",
    "setup.reject_localhost": "⚠️ nas_host 不可為 127.0.0.1（那是本機 UI）。請填實際 NAS IP。",
    "setup.saved_default": "設定已儲存",
    "setup.saved_live": "🛡️ 設定已儲存，監控已上線",
    "setup.saved_warn": "💾 設定已儲存（SSH 未上線：{w}）",
    "setup.saved_offline": "💾 連線設定已儲存（離線）",
    "setup.save_fail": "儲存失敗",
    "setup.save_ex": "❌ 儲存例外錯誤:",
    "setup.need_config_toast": "⚠️ 請先完成 NAS 連線與基線配置以啟用戰情室",
    "setup.cf_testing": "⏳ 正在向 Cloudflare GraphQL API 驗證 Token 權限...",
    "setup.cf_ok_toast": "✅ Cloudflare API 驗證成功",
    "setup.cf_fail": "❌ 驗證失敗:",
    "setup.cf_fail_toast": "❌ Cloudflare 驗證失敗",
    "setup.cf_net": "❌ 網路異常:",
    "setup.cf_unreachable": "無法連線至 Cloudflare",
    "hash.none_deleted": "無/已刪除",
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
    "setup.keygen_link": "🔑 Generate Passphrase-Protected Key",
    "setup.btn_test": "Test SSH Connection & Probe NAS",
    "setup.cf_header": "🌐 Cloudflare Edge Log Monitoring (Optional)",
    "setup.btn_save": "🛡️ Test & go live",
    "setup.btn_close": "Close",
    "setup.footnote": "🔒 Credentials stored strictly in local data/ directory",
    "page.title": "Nine-Security | NAS Sentinel - Synology DSM Real-Time Security SOC",
    "toast.placeholder": "System notification",
    "overview.chart_temp_legend": "Temp °C",
    "overview.web_latency_title": "⚡ Nginx Latency (ms) & Connection Count",
    "overview.web_latency_legend": "Latency (ms)",
    "overview.web_conns_legend": "Connections",
    "overview.anom_title": "🚨 Web/System File Changes / Suspicious Files Detected",
    "overview.anom_goto": "Open Full File Viewer →",
    "overview.posture_title": "🛡️ NAS Security Posture Live Check",
    "overview.score_prefix": "Security Score:",
    "overview.events_title": "🔔 Live Security & System Event Stream",
    "overview.events_sub": "Keeps the latest 150 events",
    "th.status": "Status",
    "th.severity": "Severity",
    "th.file_path": "Full File Path",
    "th.reason": "Change Reason / Signature",
    "th.perms_owner": "Current Mode / Owner",
    "th.sha256": "Current SHA-256 Hash",
    "th.change_type": "Change Type",
    "th.trigger": "Trigger Reason",
    "th.perm_change": "Permission Change",
    "th.hash_diff": "Baseline SHA-256 → Current",
    "th.ms_ts": "Millisecond Timestamp",
    "th.level": "Level",
    "th.inotify_mask": "Kernel Event Mask (inotify)",
    "th.trigger_path": "Triggered File Path",
    "th.live_perms": "Live Mode / Owner",
    "th.live_hash": "Live SHA-256 / Threat Verdict",
    "th.endpoint": "Endpoint",
    "th.url_path": "URL Path",
    "th.conn_status": "Connection Status",
    "th.latency": "Latency",
    "th.size": "Content Size",
    "th.resp_hash": "Response SHA-256",
    "th.tls": "TLS / Cert Fingerprint",
    "th.baseline_cmp": "Baseline Compare",
    "th.category": "Category",
    "th.bytes": "Size (Bytes)",
    "th.mode": "Mode",
    "th.owner": "Owner",
    "th.mtime": "Last Modified",
    "th.fingerprint": "SHA-256 / Fingerprint",
    "th.scope": "Scope",
    "th.proto": "Protocol",
    "th.local_addr": "Local Address:Port",
    "th.remote_addr": "Remote IP:Port",
    "th.process": "Process (PID/Name)",
    "th.baseline_status": "Baseline Status",
    "th.bind": "Bind Address",
    "th.port": "Port",
    "th.proc_desc": "Process / Service Description",
    "th.time": "Time",
    "th.action": "Action",
    "th.src_ip_country": "Source IP & Country",
    "th.probe_path": "Probed Path & Query",
    "th.threat_class": "Threat Classification",
    "th.status_code": "Status Code",
    "th.ua": "Client Fingerprint (User-Agent)",
    "th.engine": "Tool Engine",
    "th.module": "Detection Module (chkrootkit / rkhunter)",
    "th.result": "Live Kernel/Memory Result",
    "th.service": "Service Name",
    "th.svc_desc": "Description",
    "th.proc_count": "Process Count",
    "th.run_as": "Run As",
    "th.account": "Account",
    "th.tty": "Terminal (TTY)",
    "th.src_host": "Source Host IP",
    "th.login_time": "Login Time",
    "th.key_type": "Key Type",
    "th.key_comment": "Key Comment / Identity",
    "th.key_hash": "Hash ID (SHA-256 first 16)",
    "th.attacker_ip": "Attacker IP",
    "th.fail_count": "Failed Attempts",
    "th.last_seen": "Last Observed",
    "th.defense_note": "Defense Status & Notes",
    "fim.targets_title": "📂 Protected Web & Critical System Directories",
    "fim.baseline_prefix": "Baseline created:",
    "fim.rebuild_btn": "🛡️ Rebuild / Maintain Baseline",
    "fim.inotify_title": "⚡ Linux inotify Millisecond File Event Stream",
    "fim.inotify_sub": "Live watching: 250 web & system directories",
    "fim.diff_title": "🔍 File Integrity Diff & Suspicious Webshell Alerts",
    "fim.diff_sub": "Compares: SHA-256, mode, owner, add/delete, webshell signatures",
    "fim.web_title": "🌐 Nginx / DSM Endpoint Probe & Response Hash Verify",
    "fim.web_sub": "Probes NAS 80/443/5000/5001 from this host for integrity & cert checks",
    "fim.explorer_title": "🗄️ Web & System File SHA-256 Baseline Explorer",
    "fim.explorer_count": "Showing -- / -- files",
    "fim.search_ph": "Search by name, path (e.g. login.cgi, nginx.conf, .php) or SHA-256...",
    "fim.cat_all": "All Categories",
    "fim.cat_web_root": "DSM Web Root (/usr/syno/synoman, html)",
    "fim.cat_web_config": "Nginx Config & Templates (/etc/nginx, share/nginx)",
    "fim.cat_user_web": "User Web Directory (/volume1/web)",
    "fim.cat_security": "Security Configs (sshd, sysctl, firewall)",
    "fim.cat_binary": "System Binaries Anti-Trojan (/bin, /usr/bin, /usr/sbin)",
    "fim.cat_shared": "Shared & Temp Watch (/volume1/public, tmp)",
    "fim.refresh": "🔄 Refresh List",
    "net.conns_title": "🔌 Active TCP/UDP Connections",
    "net.conns_sub": "Auto-labels WAN vs LAN management connections",
    "net.ports_title": "📡 Listening Ports Matrix vs Baseline",
    "net.ports_sub": "Unauthorized open ports trigger high-risk alerts automatically",
    "cf.panel_title": "🌐 Cloudflare Edge Probe & WAF Intel",
    "cf.checking": "Checking...",
    "cf.sync_btn": "🔄 Sync Now",
    "cf.config_btn": "⚙️ Configure API Token",
    "cf.stats_title": "Edge Defense & Probe Stats (24H)",
    "cf.stat_total": "Blocked Probes Total",
    "cf.stat_total_unit": "0 hits",
    "cf.stat_countries": "Source Countries",
    "cf.stat_countries_unit": "0 countries",
    "cf.stat_last_sync": "Last Edge Sync",
    "cf.never_synced": "Not synced yet",
    "cf.top_paths": "Most Probed Sensitive Paths TOP 5",
    "cf.no_paths": "No probed paths yet",
    "sec.rootkit_title": "🕵️ DSM Rootkit & Binary Integrity (chkrootkit + rkhunter core)",
    "sec.detecting": "Detecting...",
    "sec.daemons_title": "⚙️ Core Daemon Liveness",
    "sec.daemons_sub": "Monitors Nginx, SSH, Cloudflared, etc.",
    "sec.sessions_title": "🔑 Active Sessions (utmp) & Authorized SSH Keys",
    "sec.utmp_header": "Active login sessions (/var/run/utmp):",
    "sec.keys_header": "Authorized SSH keys (~/.ssh/authorized_keys):",
    "sec.disk_title": "💽 Disk Storage & SMART Health",
    "sec.smart_badge": "PASSED (0 bad sectors)",
    "reset.warning_title": "⚠️ Warning — this will:",
    "reset.li1": "Treat current 1,786 system/web file SHA-256 values as trusted and clear alerts",
    "reset.li2": "Record current listening ports and 105 kernel modules as approved",
    "reset.li3": "Only use after legitimate DSM updates or intentional config changes",
    "reset.footer": "If you did not change the NAS yourself, do not run this — it may hide unauthorized tampering!",
    "cf.desc": "Pull malicious path probes and WAF blocks from Cloudflare's global edge via GraphQL — zero NAS disk I/O.",
    "cf.token_label": "Cloudflare API Token",
    "cf.token_ph": "API Token with Zone.Analytics:Read",
    "cf.token_help": "Create a Token with Zone - Analytics - Read at Cloudflare ➔ My Profile ➔ API Tokens",
    "cf.zone_label": "Zone ID",
    "cf.zone_ph": "e.g. 42a1b7... (32-char hex)",
    "cf.zone_help": "Open the domain in Cloudflare ➔ Overview (bottom-right) to copy Zone ID",
    "cf.enable_label": "Enable edge intel auto-sync (every 60s)",
    "setup.ssh_help_body_1": "<strong>1. Enable DSM SSH</strong>: DSM Desktop ➔ Control Panel ➔ Terminal & SNMP ➔ Enable SSH service (Port 22).",
    "setup.ssh_help_body_2": "<strong>2. Admin required</strong>: Only users in the `administrators` group may SSH in.",
    "setup.ssh_help_body_3": "<strong>3. Authorize SSH key</strong>: Click “🔑 Generate passphrase-protected key”, paste the auth command into DSM Task Scheduler once. Scans use <code>BatchMode</code> — load the key via <code>ssh-agent</code>.",
    "setup.host_ph": "e.g. 192.168.1.100",
    "setup.user_ph": "e.g. admin or root",
    "setup.port_hint": "(customizable)",
    "setup.port_title": "If your NAS uses a custom SSH port (e.g. 2222, 5022), set it here",
    "setup.keygen_link": "🔑 Generate Passphrase-Protected Key",
    "setup.key_default_opt": "(Default key / auto-resolve ~/.ssh/)",
    "setup.key_custom_ph": "e.g. ~/.ssh/id_ed25519 (must be under ~/.ssh)",
    "setup.passphrase_ph": "New key passphrase (min 8 chars; empty not allowed)",
    "setup.key_auth_title": "🔑 Quickly authorize this key on Synology NAS",
    "setup.key_auth_desc": "Log into the NAS terminal once and paste this one-liner to authorize the public key:",
    "setup.copy_btn": "📋 Copy",
    "setup.cf_expand": "▶ Expand",
    "setup.cf_collapse": "▼ Collapse",
    "setup.cf_token_ph": "Token with Zone.Analytics:Read",
    "setup.cf_zone_ph": "32-char Zone Tag",
    "setup.cf_enable": "Enable Cloudflare edge intel auto-sync",
    "setup.btn_test_cf": "🧪 Test Connection",
    "setup.btn_skip": "🚪 Skip for now — open SOC offline",
    "setup.btn_persist": "💾 Save connection settings",
    "setup.btn_golive": "🛡️ Test & go live",
    "setup.btn_skip_busy": "⏳ Opening offline SOC...",
    "setup.btn_save_busy": "⏳ Saving & testing SSH...",
    "setup.btn_persist_busy": "⏳ Saving settings...",
    "kpi.diff_init": "Mod: 0 | Add: 0 | Del: 0",
    "kpi.latency_init": "Avg Latency: -- ms",
    "kpi.net_detail_init": "LAN: -- | WAN: --",
    "kpi.unauth_init": "Unauth ports: 0",
    "kpi.disk_gb_init": "Avail: -- GB / -- GB",
    "kpi.svc_init": "Services: --/--",
    "status.not_configured": "Not configured",
    "status.need_setup": "Complete NAS connection & baseline via the setup wizard",
    "status.offline": "Offline mode",
    "status.ssh_error": "SSH connection error",
    "toast.busy": "⚠️ A scan or operation is already running, please wait...",
    "toast.cooldown": "⏳ Cooldown active — wait {n}s before retrying",
    "scan.fast_busy": "Fast scanning...",
    "scan.deep_busy": "Deep comparing...",
    "scan.deep_btn_busy": "⏳ Deep compare (~3.5s)...",
    "toast.backend_busy": "⚠️ Backend busy: another job is running",
    "toast.scan_deep_done": "✅ Deep file-hash scan complete",
    "toast.scan_fast_done": "⚡ Fast scan complete",
    "toast.scan_fail": "❌ Scan failed:",
    "toast.unknown_err": "Unknown error",
    "toast.conn_ex": "❌ Connection/runtime exception:",
    "scan.done_cooldown": "Done (cooling down)",
    "toast.admin_busy": "⚠️ System busy — cannot open admin menu",
    "toast.reset_busy": "⚠️ System busy — cannot rebuild baseline",
    "toast.job_busy": "⚠️ Another job is running, please wait",
    "reset.busy_msg": "Rebuilding baseline...",
    "reset.btn_busy": "⏳ Rebuilding baseline...",
    "toast.backend_busy2": "⚠️ Backend busy — try again shortly",
    "toast.reset_ok": "🛡️ Baseline rebuilt — files & ports are the new golden reference",
    "toast.reset_fail": "❌ Baseline rebuild failed:",
    "toast.reset_ex": "❌ Baseline rebuild exception:",
    "posture.score": "Security Score: {n} / 100",
    "posture.pass": "PASS",
    "posture.warn": "WARN",
    "posture.alert": "ALERT",
    "fim.files_count": "Files:",
    "fim.path_label": "Paths:",
    "fim.suspicious": "{n} suspicious",
    "fim.protected": "Protected",
    "fim.dir_off": "Directory inactive",
    "fim.clean": "✅ All monitored web/system files match the baseline 100%. No tampering or webshell signatures.",
    "fim.deleted": "Deleted",
    "fim.no_baseline": "No baseline",
    "fim.added": "Added",
    "web.conn_fail": "Connection failed",
    "web.hash_ok": "Baseline match",
    "web.changed": "Changed",
    "web.redirect_https": "Auto-redirect to HTTPS",
    "web.http_plain": "Plain HTTP",
    "net.external": "EXTERNAL (WAN)",
    "net.lan": "LAN",
    "net.proc_unknown": "Kernel / PID unreadable",
    "rk.alerts": "🚨 {n} anomalies ({ms} ms)",
    "rk.all_pass": "✅ All 6 core checks passed | LKM baseline: {n} ({ms} ms)",
    "rk.pass": "PASS",
    "rk.crit": "CRITICAL",
    "svc.running": "Running",
    "svc.stopped": "Stopped!",
    "svc.inactive": "Inactive",
    "sess.empty": "No interactive TTY sessions (collector uses non-interactive SSH)",
    "auth.attempts": "{n} attempts",
    "disk.used": "Used: {u} GB / Total: {t} GB (Avail: {a} GB)",
    "disk.model": "Disk model: ",
    "disk.hours": "Power-on hours:",
    "disk.hours_unit": "hours",
    "files.showing": "Showing first {shown} (matched: {matched} / monitored: {total})",
    "cf.unset_token": "⚠️ API token not set",
    "cf.not_configured": "Not configured",
    "cf.click_config": "Click to configure Cloudflare API token ➔",
    "cf.unset_hint": "Cloudflare API Token not configured. Click “⚙️ Configure API Token” to pull edge probe logs with zero NAS disk I/O.",
    "cf.sync_err": "❌ Sync error:",
    "cf.syncing": "⏳ Edge syncing...",
    "cf.connected": "✅ Connected to 9SEC Edge WAF ({n} probes)",
    "cf.hits_unit": "{n} hits",
    "cf.countries_unit": "{n} countries",
    "cf.sync_pending": "Syncing...",
    "cf.no_probe_24h": "No anomalous probe paths in 24h",
    "cf.path_hits": "{n}x",
    "cf.empty_events": "✅ No anomalous directory scans or WAF blocks observed at Cloudflare edge in the last 24 hours.",
    "cf.block": "BLOCK",
    "cf.challenge": "CHALLENGE",
    "cf.need_fields": "⚠️ Enter Cloudflare API Token and Zone ID",
    "cf.testing": "⏳ Validating token with Cloudflare...",
    "cf.saving": "⏳ Validating and saving settings...",
    "cf.test_ok": "✅ Cloudflare API connection & permissions verified!",
    "cf.save_ok": "✅ Settings saved! Background edge intel sync started.",
    "cf.enabled_toast": "✅ Cloudflare edge intel enabled",
    "cf.verify_fail": "Verification failed",
    "cf.ex": "❌ Connection exception:",
    "cf.sync_toast": "🔄 Syncing latest probe logs from Cloudflare edge...",
    "cf.sync_done": "✅ Cloudflare edge intel sync complete",
    "cf.sync_fail": "❌ Sync failed:",
    "setup.need_host_user": "⚠️ Enter NAS IP and SSH username first",
    "setup.probing": "Probing NAS kernel & DSM over SSH...",
    "setup.probe_ok_title": "✅ SSH test succeeded! NAS probe complete",
    "setup.probe_sys": "System version: ",
    "setup.probe_arch": "Kernel / arch: ",
    "setup.probe_py": "Python: ",
    "setup.probe_ok_toast": "✅ NAS connection & probe succeeded!",
    "setup.probe_fail_title": "❌ Connection failed",
    "setup.unknown_conn": "Unknown connection error",
    "setup.probe_ex": "❌ Connection request exception:",
    "setup.keygen_toast": "🔑 Generating passphrase-protected Ed25519 key pair...",
    "setup.keygen_ok": "✅ New key generated (load passphrase via ssh-agent). Copy the auth command to the NAS.",
    "setup.keygen_fail": "❌ Generation failed:",
    "setup.req_ex": "❌ Request error:",
    "setup.copied": "📋 Auth command copied to clipboard!",
    "setup.copied_short": "📋 Copied!",
    "setup.skip_ok": "🚪 Opened offline SOC (existing host/key unchanged)",
    "setup.skip_fail": "Unable to skip setup",
    "setup.need_fields": "⚠️ Enter NAS host IP and SSH username",
    "setup.reject_localhost": "⚠️ nas_host cannot be 127.0.0.1 (that is the local UI). Use the real NAS IP.",
    "setup.saved_default": "Settings saved",
    "setup.saved_live": "🛡️ Settings saved — monitoring is live",
    "setup.saved_warn": "💾 Settings saved (SSH not live: {w})",
    "setup.saved_offline": "💾 Connection settings saved (offline)",
    "setup.save_fail": "Save failed",
    "setup.save_ex": "❌ Save exception:",
    "setup.need_config_toast": "⚠️ Complete NAS connection & baseline setup to enable the SOC",
    "setup.cf_testing": "⏳ Validating token permissions via Cloudflare GraphQL API...",
    "setup.cf_ok_toast": "✅ Cloudflare API verified",
    "setup.cf_fail": "❌ Verification failed:",
    "setup.cf_fail_toast": "❌ Cloudflare verification failed",
    "setup.cf_net": "❌ Network error:",
    "setup.cf_unreachable": "Unable to reach Cloudflare",
    "hash.none_deleted": "n/a / deleted",
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
    "setup.keygen_link": "🔑 パスフレーズ付き鍵を生成",
    "setup.btn_test": "SSH接続テスト & NAS自動検出",
    "setup.cf_header": "🌐 Cloudflare エッジログ監視 (任意・後で設定可)",
    "setup.btn_save": "🛡️ テストしてオンライン化",
    "setup.btn_close": "閉じる",
    "setup.footnote": "🔒 認証情報はローカルの data/ ディレクトリのみに保存されます",
    "page.title": "Nine-Security | NAS Sentinel - Synology DSM リアルタイムセキュリティSOC",
    "toast.placeholder": "システム通知",
    "overview.chart_temp_legend": "温度°C",
    "overview.web_latency_title": "⚡ Nginx応答遅延 (ms) と接続数",
    "overview.web_latency_legend": "遅延 (ms)",
    "overview.web_conns_legend": "接続数",
    "overview.anom_title": "🚨 Web/システムファイル変更・不審ファイルを検知",
    "overview.anom_goto": "完全ファイルビューアへ →",
    "overview.posture_title": "🛡️ NASセキュリティ態勢リアルタイム検査",
    "overview.score_prefix": "セキュリティスコア:",
    "overview.events_title": "🔔 リアルタイムセキュリティ/システムイベント",
    "overview.events_sub": "直近150件を自動保存",
    "th.status": "状態",
    "th.severity": "重大度",
    "th.file_path": "ファイル完全パス",
    "th.reason": "変更理由 / 検知特徴",
    "th.perms_owner": "現在の権限 / 所有者",
    "th.sha256": "現在の SHA-256 ハッシュ",
    "th.change_type": "変更タイプ",
    "th.trigger": "トリガー理由",
    "th.perm_change": "権限変更",
    "th.hash_diff": "基準 SHA-256 → 現在",
    "th.ms_ts": "ミリ秒タイムスタンプ",
    "th.level": "レベル",
    "th.inotify_mask": "カーネルイベントフラグ (inotify)",
    "th.trigger_path": "トリガーファイルパス",
    "th.live_perms": "現在の権限 / 所有者",
    "th.live_hash": "即時SHA-256 / 脅威判定",
    "th.endpoint": "エンドポイント",
    "th.url_path": "URLパス",
    "th.conn_status": "接続状態",
    "th.latency": "応答遅延",
    "th.size": "コンテンツサイズ",
    "th.resp_hash": "応答 SHA-256",
    "th.tls": "TLS / 証明書指紋",
    "th.baseline_cmp": "基準比較",
    "th.category": "カテゴリ",
    "th.bytes": "サイズ (Bytes)",
    "th.mode": "権限 (Mode)",
    "th.owner": "所有者",
    "th.mtime": "最終更新時刻",
    "th.fingerprint": "SHA-256 / 指紋",
    "th.scope": "接続範囲",
    "th.proto": "プロトコル",
    "th.local_addr": "ローカルアドレス:ポート",
    "th.remote_addr": "リモートIP:ポート",
    "th.process": "関連プロセス (PID/Name)",
    "th.baseline_status": "基準状態",
    "th.bind": "バインドアドレス",
    "th.port": "ポート",
    "th.proc_desc": "プロセス / サービス説明",
    "th.time": "時刻",
    "th.action": "処置",
    "th.src_ip_country": "送信元IPと国",
    "th.probe_path": "探査パス (Path & Query)",
    "th.threat_class": "脅威分類",
    "th.status_code": "ステータスコード",
    "th.ua": "クライアント特徴 (User-Agent)",
    "th.engine": "対応ツールエンジン",
    "th.module": "検出モジュール (chkrootkit / rkhunter)",
    "th.result": "リアルタイムカーネル/メモリ比較結果",
    "th.service": "サービス名",
    "th.svc_desc": "機能説明",
    "th.proc_count": "プロセス数",
    "th.run_as": "実行アカウント",
    "th.account": "アカウント",
    "th.tty": "端末 (TTY)",
    "th.src_host": "接続元ホストIP",
    "th.login_time": "ログイン時刻",
    "th.key_type": "鍵タイプ",
    "th.key_comment": "鍵コメント / 識別",
    "th.key_hash": "ハッシュ識別 (SHA-256 先頭16)",
    "th.attacker_ip": "攻撃元IP",
    "th.fail_count": "失敗試行回数",
    "th.last_seen": "最終観測日",
    "th.defense_note": "防御状態と備考",
    "fim.targets_title": "📂 保護対象Web/重要システムディレクトリ",
    "fim.baseline_prefix": "ベースライン作成:",
    "fim.rebuild_btn": "🛡️ 基準の再構築/保守",
    "fim.inotify_title": "⚡ Linux inotify ミリ秒級リアルタイムファイルイベント",
    "fim.inotify_sub": "リアルタイム監視中：250のWeb/システムディレクトリ",
    "fim.diff_title": "🔍 ファイル整合性差分と不審Webshellアラート",
    "fim.diff_sub": "比較項目：SHA-256、権限、所有者、追加/削除、Webshell特徴",
    "fim.web_title": "🌐 Nginx / DSM エンドポイント即時プローブと応答ハッシュ検証",
    "fim.web_sub": "本機から NAS 80/443/5000/5001 の改ざん・証明書を検査",
    "fim.explorer_title": "🗄️ Web/システムファイル SHA-256 ベースライン検索",
    "fim.explorer_count": "表示 -- / -- ファイル",
    "fim.search_ph": "ファイル名、パス、またはSHA-256で検索...",
    "fim.cat_all": "すべての監視カテゴリ",
    "fim.cat_web_root": "DSM Webルート (/usr/syno/synoman, html)",
    "fim.cat_web_config": "Nginx設定とテンプレート (/etc/nginx, share/nginx)",
    "fim.cat_user_web": "ユーザーWebディレクトリ (/volume1/web)",
    "fim.cat_security": "セキュリティ設定 (sshd, sysctl, firewall)",
    "fim.cat_binary": "システムバイナリ (/bin, /usr/bin, /usr/sbin)",
    "fim.cat_shared": "共有・一時領域 (/volume1/public, tmp)",
    "fim.refresh": "🔄 リストを更新",
    "net.conns_title": "🔌 アクティブTCP/UDP接続の監視",
    "net.conns_sub": "WAN外部接続とLAN管理接続を自動表示",
    "net.ports_title": "📡 監視ポート棚卸と基準比較",
    "net.ports_sub": "未承認の開放ポートは高リスク警報を自動発行",
    "cf.panel_title": "🌐 Cloudflare エッジ探査とWAF防御情報",
    "cf.checking": "確認中...",
    "cf.sync_btn": "🔄 即時同期",
    "cf.config_btn": "⚙️ APIトークン設定",
    "cf.stats_title": "エッジ防御と探査統計 (24H)",
    "cf.stat_total": "遮断探査総数",
    "cf.stat_total_unit": "0 回",
    "cf.stat_countries": "探査元の国数",
    "cf.stat_countries_unit": "0 カ国",
    "cf.stat_last_sync": "最終エッジ同期",
    "cf.never_synced": "未同期",
    "cf.top_paths": "最も探査された機密パス TOP 5",
    "cf.no_paths": "探査パス記録なし",
    "sec.rootkit_title": "🕵️ DSM Rootkit・バイナリ検知 (chkrootkit + rkhunter)",
    "sec.detecting": "検出中...",
    "sec.daemons_title": "⚙️ コアデーモン稼働状態",
    "sec.daemons_sub": "Nginx、SSH、Cloudflared等を監視",
    "sec.sessions_title": "🔑 アクティブセッション(utmp)と認可SSH鍵",
    "sec.utmp_header": "アクティブログインセッション (/var/run/utmp)：",
    "sec.keys_header": "認可済みSSH公開鍵 (~/.ssh/authorized_keys)：",
    "sec.disk_title": "💽 ディスク容量とSMART健康監視",
    "sec.smart_badge": "PASSED (不良セクタ 0)",
    "reset.warning_title": "⚠️ 注意：この操作では：",
    "reset.li1": "現在の1,786個のシステム/WebファイルSHA-256を正規基準としアラートをクリア",
    "reset.li2": "現在の監視ポートと105のカーネルモジュールを承認リストに記録",
    "reset.li3": "正規のDSM更新や意図的な設定変更後にのみ実行してください",
    "reset.footer": "自身で変更していない場合は実行しないでください。不正改ざんを隠す恐れがあります！",
    "cf.desc": "Cloudflare GraphQL APIでエッジから悪意あるパス探査とWAF遮断を取得。NASのディスクI/Oはゼロです。",
    "cf.token_label": "Cloudflare API Token",
    "cf.token_ph": "Zone.Analytics:Read 権限の API Token",
    "cf.token_help": "Cloudflare ➔ My Profile ➔ API Tokens で Zone - Analytics - Read 権限のトークンを作成",
    "cf.zone_label": "Zone ID",
    "cf.zone_ph": "例：42a1b7... (32桁の16進数)",
    "cf.zone_help": "Cloudflareでドメイン Overview 右下から Zone ID をコピー",
    "cf.enable_label": "エッジ脅威情報の自動同期を有効化 (60秒毎)",
    "setup.ssh_help_body_1": "<strong>1. DSM SSHを有効化</strong>：DSMデスクトップ ➔ コントロールパネル ➔ ターミナルとSNMP ➔ 「SSHサービスを有効にする」(Port 22)。",
    "setup.ssh_help_body_2": "<strong>2. 管理者権限を確認</strong>：`administrators` グループのユーザーのみSSH可能です。",
    "setup.ssh_help_body_3": "<strong>3. SSH鍵を認可</strong>：下の「🔑 パスフレーズ付き鍵を生成」をクリックし、認可コマンドをDSMのタスクスケジューラで1回実行。監視は<code>BatchMode</code>のため<code>ssh-agent</code>で鍵を読み込んでください。",
    "setup.host_ph": "例：192.168.1.100",
    "setup.user_ph": "例：admin または root",
    "setup.port_hint": "(変更可)",
    "setup.port_title": "NASのSSHポートを変更している場合（例：2222、5022）はここに入力",
    "setup.keygen_link": "🔑 パスフレーズ付き鍵を生成",
    "setup.key_default_opt": "(システム既定鍵 / ~/.ssh/ 自動解決)",
    "setup.key_custom_ph": "例：~/.ssh/id_ed25519（~/.ssh内のみ）",
    "setup.passphrase_ph": "新しい鍵のパスフレーズ（8文字以上・空白不可）",
    "setup.key_auth_title": "🔑 この鍵をSynology NASへ素早く認可",
    "setup.key_auth_desc": "NAS端末に1回ログインし、次の1行コマンドを貼り付けて公開鍵を認可：",
    "setup.copy_btn": "📋 コピー",
    "setup.cf_expand": "▶ 展開",
    "setup.cf_collapse": "▼ 閉じる",
    "setup.cf_token_ph": "Zone.Analytics:Read 権限のToken",
    "setup.cf_zone_ph": "32桁の Zone Tag",
    "setup.cf_enable": "Cloudflareエッジ脅威情報の自動同期を有効化",
    "setup.btn_test_cf": "🧪 接続テスト",
    "setup.btn_skip": "🚪 後で設定・先にSOCを開く",
    "setup.btn_persist": "💾 接続設定を保存",
    "setup.btn_golive": "🛡️ テストしてオンライン化",
    "setup.btn_skip_busy": "⏳ オフラインSOCを開いています...",
    "setup.btn_save_busy": "⏳ 保存してSSHテスト中...",
    "setup.btn_persist_busy": "⏳ 設定を保存中...",
    "kpi.diff_init": "変更: 0 | 追加: 0 | 削除: 0",
    "kpi.latency_init": "平均遅延: -- ms",
    "kpi.net_detail_init": "LAN: -- | WAN: --",
    "kpi.unauth_init": "未承認ポート: 0",
    "kpi.disk_gb_init": "空き: -- GB / -- GB",
    "kpi.svc_init": "サービス: --/--",
    "status.not_configured": "未設定",
    "status.need_setup": "セットアップウィザードでNAS接続と基準設定を完了してください",
    "status.offline": "オフラインモード",
    "status.ssh_error": "SSH接続異常",
    "toast.busy": "⚠️ 他の走査/処理が実行中です。少々お待ちください...",
    "toast.cooldown": "⏳ クールダウン中です。{n}秒後に再実行してください",
    "scan.fast_busy": "クイック走査中...",
    "scan.deep_busy": "ディープ比較中...",
    "scan.deep_btn_busy": "⏳ ディープ比較中 (~3.5秒)...",
    "toast.backend_busy": "⚠️ バックエンド処理中です。少々お待ちください",
    "toast.scan_deep_done": "✅ ディープハッシュ走査完了",
    "toast.scan_fast_done": "⚡ クイック走査完了",
    "toast.scan_fail": "❌ 走査失敗:",
    "toast.unknown_err": "不明なエラー",
    "toast.conn_ex": "❌ 接続または実行例外:",
    "scan.done_cooldown": "完了 (クールダウン中)",
    "toast.admin_busy": "⚠️ 処理中のため管理メニューを開けません",
    "toast.reset_busy": "⚠️ 処理中のためベースライン再構築できません",
    "toast.job_busy": "⚠️ 他の処理が実行中です。少々お待ちください",
    "reset.busy_msg": "ベースライン再構築中...",
    "reset.btn_busy": "⏳ ベースライン再構築中...",
    "toast.backend_busy2": "⚠️ バックエンドがビジーです。後でもう一度",
    "toast.reset_ok": "🛡️ 基準再構築成功。ファイルとポートを新基準に設定しました",
    "toast.reset_fail": "❌ 基準再構築失敗:",
    "toast.reset_ex": "❌ 基準再構築例外:",
    "posture.score": "セキュリティスコア: {n} / 100",
    "posture.pass": "合格",
    "posture.warn": "注意",
    "posture.alert": "警報",
    "fim.files_count": "ファイル数:",
    "fim.path_label": "パス:",
    "fim.suspicious": "{n} 不審",
    "fim.protected": "保護中",
    "fim.dir_off": "ディレクトリ未使用",
    "fim.clean": "✅ 監視中のWeb/システムファイルは基準と100%一致。改ざんやWebshellは検知されていません。",
    "fim.deleted": "削除済み",
    "fim.no_baseline": "基準なし",
    "fim.added": "追加",
    "web.conn_fail": "接続失敗",
    "web.hash_ok": "基準一致",
    "web.changed": "変更",
    "web.redirect_https": "HTTPSへ自動転送",
    "web.http_plain": "平文HTTP",
    "net.external": "EXTERNAL (外部)",
    "net.lan": "LAN (内部)",
    "net.proc_unknown": "カーネル / PID読取不可",
    "rk.alerts": "🚨 {n} 件の異常 ({ms} ms)",
    "rk.all_pass": "✅ 6項目すべて合格 | LKM基準: {n} ({ms} ms)",
    "rk.pass": "合格 (PASS)",
    "rk.crit": "警報 (CRITICAL)",
    "svc.running": "実行中",
    "svc.stopped": "停止!",
    "svc.inactive": "未使用",
    "sess.empty": "対話型TTYセッションなし（監視は非対話SSHを使用）",
    "auth.attempts": "{n} 回",
    "disk.used": "使用: {u} GB / 合計: {t} GB (空き: {a} GB)",
    "disk.model": "物理ディスク型番：",
    "disk.hours": "通電時間:",
    "disk.hours_unit": "時間",
    "files.showing": "先頭 {shown} 件表示 (一致: {matched} / 監視総数: {total})",
    "cf.unset_token": "⚠️ APIトークン未設定",
    "cf.not_configured": "未設定",
    "cf.click_config": "ここをクリックしてCloudflare APIトークンを設定 ➔",
    "cf.unset_hint": "Cloudflare API Token未設定。「⚙️ APIトークン設定」からNASディスクI/Oゼロでエッジ探査ログを取得できます。",
    "cf.sync_err": "❌ 同期エラー:",
    "cf.syncing": "⏳ エッジ同期中...",
    "cf.connected": "✅ 9SEC Edge WAF 接続中 ({n} 件の探査)",
    "cf.hits_unit": "{n} 回",
    "cf.countries_unit": "{n} カ国",
    "cf.sync_pending": "同期中...",
    "cf.no_probe_24h": "過去24時間に異常探査パスなし",
    "cf.path_hits": "{n}回",
    "cf.empty_events": "✅ 過去24時間、Cloudflareエッジで異常なディレクトリスキャンやWAF遮断は観測されていません。",
    "cf.block": "BLOCK 遮断",
    "cf.challenge": "CHALLENGE 検証",
    "cf.need_fields": "⚠️ Cloudflare API Token と Zone ID を入力してください",
    "cf.testing": "⏳ CloudflareでTokenを検証中...",
    "cf.saving": "⏳ 検証して設定を保存中...",
    "cf.test_ok": "✅ Cloudflare API接続と権限の検証に成功！",
    "cf.save_ok": "✅ 設定を保存しました。エッジ脅威情報のバックグラウンド同期を開始しました。",
    "cf.enabled_toast": "✅ Cloudflareエッジ情報を有効化しました",
    "cf.verify_fail": "検証失敗",
    "cf.ex": "❌ 接続例外:",
    "cf.sync_toast": "🔄 Cloudflareエッジから最新探査ログを同期中...",
    "cf.sync_done": "✅ Cloudflareエッジ情報の同期完了",
    "cf.sync_fail": "❌ 同期失敗:",
    "setup.need_host_user": "⚠️ 先にNAS IPとSSHユーザー名を入力してください",
    "setup.probing": "SSH経由でNASカーネルとDSMを検出中...",
    "setup.probe_ok_title": "✅ SSH接続テスト成功！NASシステム検出完了",
    "setup.probe_sys": "システム版：",
    "setup.probe_arch": "カーネル/アーキテクチャ：",
    "setup.probe_py": "Python環境：",
    "setup.probe_ok_toast": "✅ NAS接続と検出に成功！",
    "setup.probe_fail_title": "❌ 接続失敗",
    "setup.unknown_conn": "不明な接続エラー",
    "setup.probe_ex": "❌ 接続リクエスト例外:",
    "setup.keygen_toast": "🔑 パスフレーズ付きEd25519鍵ペアを生成中...",
    "setup.keygen_ok": "✅ 新しい鍵を生成しました（ssh-agentでパスフレーズを読込）。認可コマンドをNASへコピー。",
    "setup.keygen_fail": "❌ 生成失敗:",
    "setup.req_ex": "❌ リクエスト異常:",
    "setup.copied": "📋 認可コマンドをクリップボードにコピーしました！",
    "setup.copied_short": "📋 コピーしました！",
    "setup.skip_ok": "🚪 オフラインSOCを開きました（既存ホスト/鍵は未変更）",
    "setup.skip_fail": "セットアップをスキップできません",
    "setup.need_fields": "⚠️ NASホストIPとSSHユーザー名を入力してください",
    "setup.reject_localhost": "⚠️ nas_host に 127.0.0.1 は使えません（ローカルUI用）。実際のNAS IPを入力してください。",
    "setup.saved_default": "設定を保存しました",
    "setup.saved_live": "🛡️ 設定を保存し、監視をオンライン化しました",
    "setup.saved_warn": "💾 設定を保存しました（SSH未オンライン：{w}）",
    "setup.saved_offline": "💾 接続設定を保存しました（オフライン）",
    "setup.save_fail": "保存失敗",
    "setup.save_ex": "❌ 保存例外:",
    "setup.need_config_toast": "⚠️ 先にNAS接続と基準設定を完了してSOCを有効化してください",
    "setup.cf_testing": "⏳ Cloudflare GraphQL APIでToken権限を検証中...",
    "setup.cf_ok_toast": "✅ Cloudflare API検証成功",
    "setup.cf_fail": "❌ 検証失敗:",
    "setup.cf_fail_toast": "❌ Cloudflare検証失敗",
    "setup.cf_net": "❌ ネットワーク異常:",
    "setup.cf_unreachable": "Cloudflareに接続できません",
    "hash.none_deleted": "なし/削除済み",
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

function tf(key, vars = {}, fallback = "") {
  let s = t(key, fallback);
  Object.keys(vars).forEach((k) => {
    s = s.replaceAll("{" + k + "}", String(vars[k]));
  });
  return s;
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
  document.title = t("page.title");

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
      "zh-TW": "語系已切換為：繁體中文",
      "en": "Language switched to: English",
      "jp": "言語を日本語に切り替えました"
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
        badge.textContent = t("status.not_configured");
      }
      const idEl = document.getElementById("nasIdentity");
      if (idEl) idEl.textContent = t("status.need_setup");
      openSetupModal(true);
      return;
    }
    if (json.offline_mode && !json.data) {
      const badge = document.getElementById("threatBadge");
      if (badge) {
        badge.className = "badge badge-warn";
        badge.textContent = t("status.offline");
      }
      const idEl = document.getElementById("nasIdentity");
      if (idEl) {
        idEl.textContent = json.last_error
          || "Offline mode — finish NAS SSH setup from Admin when ready";
      }
      return;
    }
    if (json.ok && json.data) {
      currentSnapshot = json.data;
      renderDashboard(json.data);
    } else if (json.last_error) {
      const badge = document.getElementById("threatBadge");
      badge.className = "badge badge-crit";
      badge.textContent = t("status.ssh_error");
      document.getElementById("nasIdentity").textContent = json.last_error;
    }
  } catch (err) {
    console.error("Failed to fetch status:", err);
  }
}

async function triggerScan(mode) {
  // Anti-Fooling Check 1: Already busy
  if (isOperationBusy) {
    showToast(t("toast.busy"), "warn");
    return;
  }

  // Anti-Fooling Check 2: 2-second anti-spam cooldown window
  const now = Date.now();
  if (now - lastScanCompletedTime < 2000) {
    const remainSec = Math.ceil((2000 - (now - lastScanCompletedTime)) / 1000);
    showToast(tf("toast.cooldown", { n: remainSec }), "warn");
    return;
  }

  const primaryText = mode === "deep" ? t("scan.deep_busy") : t("scan.fast_busy");
  setControlsBusy(true, primaryText);
  if (mode === "deep") {
    const btnDeep = document.getElementById("btnDeepScan");
    if (btnDeep) btnDeep.textContent = t("scan.deep_btn_busy");
  }

  try {
    const res = await apiFetch("/api/scan", {
      method: "POST",
      body: JSON.stringify({ mode }),
    });

    if (res.status === 429) {
      showToast(t("toast.backend_busy"), "warn");
      return;
    }

    const json = await res.json();
    if (json.ok && json.data) {
      currentSnapshot = json.data;
      renderDashboard(json.data);
      if (document.getElementById("tab-fim").classList.contains("active")) {
        loadFilesExplorer();
      }
      showToast(mode === "deep" ? t("toast.scan_deep_done") : t("toast.scan_fast_done"), "info");
    } else {
      showToast(`${t("toast.scan_fail")} ${json.error || json.last_error || t("toast.unknown_err")}`, "crit");
    }
  } catch (err) {
    showToast(`${t("toast.conn_ex")} ${err.message || err}`, "crit");
  } finally {
    lastScanCompletedTime = Date.now();

    // 2-Second Cooldown Visual Feedback (Anti-Fooling)
    const primaryIcon = document.getElementById("scanPrimaryIcon");
    const primaryTxt = document.getElementById("scanPrimaryText");
    const btnDeep = document.getElementById("btnDeepScan");

    if (primaryIcon) primaryIcon.textContent = "✅";
    if (primaryTxt) primaryTxt.textContent = t("scan.done_cooldown");
    if (btnDeep) btnDeep.textContent = t("scan.deep");

    setTimeout(() => {
      setControlsBusy(false);
      if (primaryIcon) primaryIcon.textContent = "⚡";
      if (primaryTxt) primaryTxt.textContent = t("scan.fast");
      countdown = pollInterval;
    }, 2000);
  }
}

function toggleAdminMenu(event) {
  if (isOperationBusy) {
    showToast(t("toast.admin_busy"), "warn");
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
    showToast(t("toast.reset_busy"), "warn");
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
    showToast(t("toast.job_busy"), "warn");
    return;
  }

  setControlsBusy(true, t("reset.busy_msg"));
  const btn = document.getElementById("btnConfirmResetBaseline");
  if (btn) {
    btn.disabled = true;
    btn.textContent = t("reset.btn_busy");
  }

  try {
    const res = await apiFetch("/api/baseline/reset", { method: "POST" });
    if (res.status === 429) {
      showToast(t("toast.backend_busy2"), "warn");
      return;
    }
    const json = await res.json();
    if (json.ok && json.data) {
      currentSnapshot = json.data;
      renderDashboard(json.data);
      loadFilesExplorer();
      closeResetBaselineModal();
      showToast(t("toast.reset_ok"), "info");
    } else {
      showToast(t("toast.reset_fail") + " " + (json.error || json.last_error), "crit");
    }
  } catch (err) {
    showToast(t("toast.reset_ex") + " " + err, "crit");
  } finally {
    lastScanCompletedTime = Date.now();
    if (btn) {
      btn.disabled = false;
      btn.textContent = t("reset.btn_confirm");
    }
    setTimeout(() => {
      setControlsBusy(false);
      const primaryIcon = document.getElementById("scanPrimaryIcon");
      const primaryTxt = document.getElementById("scanPrimaryText");
      if (primaryIcon) primaryIcon.textContent = "⚡";
      if (primaryTxt) primaryTxt.textContent = t("scan.fast");
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
          <td class="mono">${escapeHtml((ev.hash || t("hash.none_deleted")).slice(0, 20))}... ${suspText}</td>
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
        <td class="mono">${escapeHtml(cur.mode || t("fim.deleted"))} (${escapeHtml(cur.owner || "-")})</td>
        <td class="mono">${escapeHtml((cur.hash || "").slice(0, 20))}...</td>
      </tr>`;
    }).join("");
  } else {
    ovPanel.style.display = "none";
  }

  // Render Posture Checklist
  document.getElementById("securityScoreText").textContent = tf("posture.score", { n: data.security_score });
  document.getElementById("postureList").innerHTML = (sec.posture_checks || []).map((c) => {
    const bCls = c.status === "pass" ? "badge-ok" : c.status === "warn" ? "badge-warn" : "badge-crit";
    const bTxt = c.status === "pass" ? t("posture.pass") : c.status === "warn" ? t("posture.warn") : t("posture.alert");
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
  document.getElementById("fimBaselineTimestamp").textContent = `${t("fim.baseline_prefix")} ${fim.baseline_created_at || "--"}`;
  document.getElementById("fimTargetsGrid").innerHTML = (fim.targets || []).map((tgt) => {
    const bCls = tgt.suspicious_count > 0 ? "badge-crit" : tgt.exists ? "badge-ok" : "badge-warn";
    const bTxt = tgt.suspicious_count > 0 ? tf("fim.suspicious", { n: tgt.suspicious_count }) : tgt.exists ? t("fim.protected") : t("fim.dir_off");
    return `<div class="target-card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
        <span style="font-weight:600; font-size:13.5px;">${escapeHtml(tgt.label)}</span>
        <span class="badge ${bCls}">${bTxt}</span>
      </div>
      <div class="mono" style="font-size:12px; color:var(--text-muted);">${t("fim.files_count")} ${tgt.file_count} | ${t("fim.path_label")} ${escapeHtml((tgt.paths || []).join(", "))}</div>
    </div>`;
  }).join("");

  // Render Tab 2: FIM Anomalies Table
  const fimAnomBody = document.getElementById("fimAnomaliesBody");
  if (!fim.anomalies || fim.anomalies.length === 0) {
    fimAnomBody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:22px; color:#00ff41; font-family:var(--font-mono);">${t("fim.clean")}</td></tr>`;
  } else {
    fimAnomBody.innerHTML = fim.anomalies.map((a) => {
      const cur = a.current || {};
      const base = a.baseline || {};
      const bCls = a.severity === "CRITICAL" ? "badge-crit" : "badge-warn";
      const modeDiff = base.mode ? `${base.mode} → ${cur.mode || t("fim.deleted")}` : `${cur.mode || "-"} (${t("fim.added")})`;
      const hashDiff = `${(base.hash || t("fim.no_baseline")).slice(0, 12)}... → ${(cur.hash || t("fim.deleted")).slice(0, 12)}...`;
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
      : `<span class="badge badge-crit">${t("web.conn_fail")}</span>`;
    const matchBadge = ep.baseline_match && (!ep.anomaly_notes || ep.anomaly_notes.length === 0)
      ? `<span class="badge badge-ok">${t("web.hash_ok")}</span>`
      : `<span class="badge badge-warn">${escapeHtml((ep.anomaly_notes || []).join(", ") || t("web.changed"))}</span>`;
    const tlsInfo = ep.cert
      ? `${escapeHtml(ep.cert.tls_version)} (${escapeHtml(ep.cert.sha256.slice(0, 14))}...)`
      : ep.redirects_to_https ? t("web.redirect_https") : t("web.http_plain");
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
      ? `<span class="badge badge-warn">${t("net.external")}</span>`
      : c.scope === "lan"
      ? `<span class="badge badge-ok">${t("net.lan")}</span>`
      : `<span class="badge">LOOPBACK</span>`;
    return `<tr>
      <td>${scopeBadge}</td>
      <td class="mono">${escapeHtml(c.proto.toUpperCase())}</td>
      <td class="mono">${escapeHtml(c.local_ip)}:${escapeHtml(c.local_port)}</td>
      <td class="mono" style="font-weight:600;">${escapeHtml(c.remote_ip)}:${escapeHtml(c.remote_port)}</td>
      <td class="mono">${escapeHtml(c.state)}</td>
      <td class="mono">${escapeHtml(c.process || t("net.proc_unknown"))}</td>
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
      rkBadge.textContent = tf("rk.alerts", { n: rk.alert_count, ms: rk.duration_ms || 0 });
    } else {
      rkBadge.className = "badge badge-ok";
      rkBadge.textContent = tf("rk.all_pass", { n: rk.loaded_modules_count || 0, ms: rk.duration_ms || 0 });
    }
  }

  const rkBody = document.getElementById("rootkitChecksBody");
  if (rkBody) {
    rkBody.innerHTML = (rk.checks || []).map((c) => {
      const bCls = c.status === "pass" ? "badge-ok" : c.severity === "CRITICAL" ? "badge-crit" : "badge-warn";
      const bTxt = c.status === "pass" ? t("rk.pass") : t("rk.crit");
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
      ? `<span class="badge badge-ok">${t("svc.running")}</span>`
      : s.critical
      ? `<span class="badge badge-crit">${t("svc.stopped")}</span>`
      : `<span class="badge">${t("svc.inactive")}</span>`;
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
    sessBody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:var(--text-muted);">${t("sess.empty")}</td></tr>`;
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
        <td class="mono">${tf("auth.attempts", { n: b.attempts })}</td>
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
      <div class="mono" style="font-size:12px; color:var(--text-muted);">${tf("disk.used", { u: d.used_gb, t: d.total_gb, a: d.avail_gb })}</div>
    </div>
    <span class="badge badge-ok">${d.percent}%</span>
  </div>`).join("");

  document.getElementById("diskSmartBox").innerHTML = `
    ${disksHtml}
    <div class="check-item">
      <div>
        <div style="font-weight:600;">${t("disk.model")}${escapeHtml(sm.model)}</div>
        <div style="font-size:12px; color:var(--text-muted);">${t("disk.hours")} ${sm.power_on_hours?.toLocaleString()} ${t("disk.hours_unit")} | Reallocated: ${sm.reallocated_sectors} | Pending: ${sm.pending_sectors}</div>
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
    tf("files.showing", { shown: json.items.length, matched: json.total_matched, total: json.total_monitored });

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
      cfBadge.textContent = t("cf.unset_token");
    }
    if (totalEl) totalEl.textContent = t("cf.stat_total_unit");
    if (countriesEl) countriesEl.textContent = t("cf.stat_countries_unit");
    if (lastSyncEl) lastSyncEl.textContent = t("cf.not_configured");
    if (topPathsEl) {
      topPathsEl.innerHTML = `<span class="badge" style="color:var(--text-secondary); cursor:pointer;" onclick="openCfConfigModal()">${t("cf.click_config")}</span>`;
    }
    if (eventsBody) {
      eventsBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:24px; color:var(--text-secondary); font-family:var(--font-mono);">
        ${t("cf.unset_hint")}
      </td></tr>`;
    }
    return;
  }

  // Configured
  if (cfBadge) {
    if (cf.last_error) {
      cfBadge.className = "badge badge-crit";
      cfBadge.textContent = `${t("cf.sync_err")} ${(cf.last_error || "").slice(0, 24)}...`;
    } else if (cf.sync_in_progress) {
      cfBadge.className = "badge badge-warn";
      cfBadge.textContent = t("cf.syncing");
    } else {
      cfBadge.className = "badge badge-ok";
      cfBadge.textContent = tf("cf.connected", { n: cf.total_events_24h || 0 });
    }
  }

  if (totalEl) totalEl.textContent = tf("cf.hits_unit", { n: cf.total_events_24h || 0 });
  if (countriesEl) countriesEl.textContent = tf("cf.countries_unit", { n: cf.distinct_countries_count || 0 });
  if (lastSyncEl) lastSyncEl.textContent = cf.last_sync ? formatTimeTs(cf.last_sync) : t("cf.sync_pending");

  if (topPathsEl) {
    const top = cf.top_probed_paths || [];
    if (top.length === 0) {
      topPathsEl.innerHTML = `<span class="badge badge-ok">${t("cf.no_probe_24h")}</span>`;
    } else {
      topPathsEl.innerHTML = top.map(p => `
        <span class="badge badge-warn" style="font-family:var(--font-mono); font-size:11.5px;">
          ${escapeHtml(p.path)} <strong style="color:var(--accent); margin-left:4px;">${tf("cf.path_hits", { n: p.count })}</strong>
        </span>
      `).join("");
    }
  }

  if (eventsBody) {
    const evs = cf.recent_events || [];
    if (evs.length === 0) {
      eventsBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:22px; color:#00ff41; font-family:var(--font-mono);">
        ${t("cf.empty_events")}
      </td></tr>`;
    } else {
      eventsBody.innerHTML = evs.map(ev => {
        const actionBadge = ev.action === "BLOCK"
          ? `<span class="badge badge-crit">${t("cf.block")}</span>`
          : ev.action.includes("CHALLENGE")
          ? `<span class="badge badge-warn">${t("cf.challenge")}</span>`
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
      msg.textContent = t("cf.need_fields");
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
    msg.textContent = testOnly ? t("cf.testing") : t("cf.saving");
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
        msg.textContent = testOnly ? t("cf.test_ok") : t("cf.save_ok");
      }
      if (!testOnly) {
        showToast(t("cf.enabled_toast"), "info");
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
        msg.textContent = `❌ ${json.error || t("cf.verify_fail")}`;
      }
    }
  } catch (err) {
    if (msg) {
      msg.style.background = "rgba(255, 0, 85, 0.15)";
      msg.style.color = "#ff6699";
      msg.style.border = "1px solid #ff0055";
      msg.textContent = `${t("cf.ex")} ${err.message || err}`;
    }
  } finally {
    if (btnTest) btnTest.disabled = false;
    if (btnSave) btnSave.disabled = false;
  }
}

async function triggerCfSync() {
  showToast(t("cf.sync_toast"), "info");
  try {
    const res = await apiFetch("/api/cloudflare/sync", { method: "POST" });
    const json = await res.json();
    setTimeout(() => {
      fetchStatus();
      showToast(t("cf.sync_done"), "info");
    }, 1500);
  } catch (err) {
    showToast(`${t("cf.sync_fail")} ${err.message || err}`, "crit");
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
    keySelect.innerHTML = `<option value="">${t("setup.key_default_opt")}</option>`;
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
      : t("setup.cf_token_ph");
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
    showToast(t("setup.need_config_toast"), "warn");
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
  if (icon) icon.textContent = isHidden ? t("setup.cf_collapse") : t("setup.cf_expand");
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
      msg.textContent = t("cf.need_fields");
    }
    return;
  }

  if (btn) {
    btn.disabled = true;
    btn.textContent = t("cf.testing");
  }
  if (msg) {
    msg.style.display = "block";
    msg.style.background = "rgba(0, 229, 255, 0.1)";
    msg.style.color = "#00e5ff";
    msg.style.border = "1px solid #00e5ff";
    msg.textContent = t("setup.cf_testing");
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
        msg.textContent = t("cf.test_ok");
      }
      showToast(t("setup.cf_ok_toast"), "ok");
    } else {
      if (msg) {
        msg.style.background = "rgba(255, 0, 85, 0.15)";
        msg.style.color = "#ff6699";
        msg.style.border = "1px solid #ff0055";
        msg.textContent = t("setup.cf_fail") + " " + (json.error || t("setup.cf_unreachable"));
      }
      showToast(t("setup.cf_fail_toast"), "danger");
    }
  } catch (e) {
    if (msg) {
      msg.style.background = "rgba(255, 0, 85, 0.15)";
      msg.style.color = "#ff6699";
      msg.style.border = "1px solid #ff0055";
      msg.textContent = t("setup.cf_net") + " " + e.message;
    }
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = t("setup.btn_test_cf");
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
    showToast(t("setup.need_host_user"), "warn");
    return;
  }

  if (btn) btn.disabled = true;
  if (icon) icon.textContent = "⏳";
  if (text) text.textContent = t("setup.probing");
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
          <div style="font-weight:700; font-size:13px; margin-bottom:4px;">${t("setup.probe_ok_title")}</div>
          <div style="color:#d1fae5; font-size:12px;">
            • ${t("setup.probe_sys")}<strong>${escapeHtml(json.system.dsm_version)}</strong><br>
            • ${t("setup.probe_arch")}<strong>${escapeHtml(json.system.kernel)} (${escapeHtml(json.system.arch)})</strong><br>
            • ${t("setup.probe_py")}<strong>${escapeHtml(json.system.python)}</strong>${fp}
          </div>
        `;
        showToast(t("setup.probe_ok_toast"), "info");
      } else {
        resBox.style.background = "rgba(255, 0, 85, 0.12)";
        resBox.style.border = "1px solid #ff0055";
        resBox.style.color = "#ff4d88";
        resBox.innerHTML = `
          <div style="font-weight:700; font-size:13px; margin-bottom:4px;">${t("setup.probe_fail_title")}</div>
          <div style="color:#ffccd7; font-size:12px;">${escapeHtml(json.error || t("setup.unknown_conn"))}</div>
        `;
      }
    }
  } catch (err) {
    if (resBox) {
      resBox.style.display = "block";
      resBox.style.background = "rgba(255, 0, 85, 0.12)";
      resBox.style.border = "1px solid #ff0055";
      resBox.style.color = "#ff4d88";
      resBox.textContent = `${t("setup.probe_ex")} ${err.message || err}`;
    }
  } finally {
    if (btn) btn.disabled = false;
    if (icon) icon.textContent = "⚡";
    if (text) text.textContent = t("setup.btn_test");
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
  showToast(t("setup.keygen_toast"), "info");
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
      showToast(t("setup.keygen_ok"), "info");
    } else {
      showToast(`${t("setup.keygen_fail")} ${json.error}`, "crit");
    }
  } catch (err) {
    showToast(`${t("setup.req_ex")} ${err.message || err}`, "crit");
  }
}

function copySetupKeyCmd() {
  const cmdText = document.getElementById("setupKeyCommandText");
  if (!cmdText || !cmdText.value) return;
  navigator.clipboard.writeText(cmdText.value).then(() => {
    showToast(t("setup.copied"), "info");
  }).catch(() => {
    cmdText.select();
    document.execCommand("copy");
    showToast(t("setup.copied_short"), "info");
  });
}

async function skipSetupOffline() {
  const btnSkip = document.getElementById("btnSkipSetupOffline");
  const msgBox = document.getElementById("setupSaveMsg");

  if (!getApiToken()) {
    showApiAuthModal("Enter API token before skipping setup (data/api_token.txt).");
    return;
  }
  if (btnSkip) {
    btnSkip.disabled = true;
    btnSkip.textContent = t("setup.btn_skip_busy");
  }
  try {
    // Empty body on purpose: server must NOT rewrite nas_host / key from form defaults.
    const res = await apiFetch("/api/setup/skip-offline", {
      method: "POST",
      body: JSON.stringify({}),
    });
    if (res.status === 401) return;
    const json = await res.json();
    if (json.ok) {
      appConfig = json.config || { is_configured: true, offline_mode: true };
      isSetupInitial = false;
      if (msgBox) {
        msgBox.style.display = "block";
        msgBox.style.background = "rgba(251, 191, 36, 0.12)";
        msgBox.style.border = "1px solid rgba(251, 191, 36, 0.45)";
        msgBox.style.color = "#fbbf24";
        msgBox.textContent = "✅ " + (json.message || "Offline SOC unlocked (SSH fields unchanged)");
      }
      showToast(t("setup.skip_ok"), "info");
      setTimeout(() => {
        closeSetupModal();
        fetchStatus();
      }, 600);
    } else {
      showToast("❌ " + (json.error || t("setup.skip_fail")), "crit");
    }
  } catch (err) {
    showToast(`❌ ${err.message || err}`, "crit");
  } finally {
    if (btnSkip) {
      btnSkip.disabled = false;
      btnSkip.textContent = t("setup.btn_skip");
    }
  }
}

async function saveSetupConfig(options) {
  // Backward-compatible: saveSetupConfig(true) => persist only; saveSetupConfig(false) => try go live.
  const opts = (typeof options === "boolean")
    ? { persistOnly: options, goLive: !options }
    : Object.assign({ persistOnly: false, goLive: true }, options || {});
  const persistOnly = Boolean(opts.persistOnly);
  const goLive = Boolean(opts.goLive) && !persistOnly;

  const host = (document.getElementById("setupNasHost").value || "").trim();
  const user = (document.getElementById("setupNasUser").value || "").trim();
  const port = parseInt(document.getElementById("setupNasPort").value || "22", 10);
  const key = (document.getElementById("setupSshKeyCustom").value || "").trim();
  const cfToken = (document.getElementById("setupCfToken").value || "").trim();
  const cfZone = (document.getElementById("setupCfZone").value || "").trim();
  const cfEnabled = document.getElementById("setupCfEnabled").checked;

  const btnSave = document.getElementById("btnSaveSetup");
  const btnPersist = document.getElementById("btnPersistSetupOffline");
  const msgBox = document.getElementById("setupSaveMsg");

  if (!host || !user) {
    showToast(t("setup.need_fields"), "warn");
    return;
  }
  if (["127.0.0.1", "localhost", "::1", "0.0.0.0"].includes(host.toLowerCase())) {
    showToast(t("setup.reject_localhost"), "warn");
    return;
  }

  if (!getApiToken()) {
    showApiAuthModal("Enter API token before saving settings (data/api_token.txt).");
    return;
  }

  if (btnSave) {
    btnSave.disabled = true;
    if (goLive) btnSave.textContent = t("setup.btn_save_busy");
  }
  if (btnPersist) {
    btnPersist.disabled = true;
    if (persistOnly) btnPersist.textContent = t("setup.btn_persist_busy");
  }
  if (msgBox) msgBox.style.display = "none";

  try {
    const payload = {
      nas_host: host,
      nas_user: user,
      nas_port: port,
      cloudflare_enabled: cfEnabled,
      cloudflare_zone_id: cfZone,
      persist_without_connect: persistOnly,
      go_live: goLive,
    };
    // Blank key = keep existing server-side; only send when the user typed/selected one.
    if (key) payload.ssh_key_path = key;
    // Only send Cloudflare token when the user entered a new value (blank = keep existing).
    if (cfToken) payload.cloudflare_api_token = cfToken;
    const res = await apiFetch("/api/setup/save", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (res.status === 401) {
      showApiAuthModal("Unauthorized — paste API token, then save again.");
      return;
    }
    const json = await res.json();
    if (json.ok) {
      const live = Boolean(json.live);
      const offline = !live;
      if (msgBox) {
        msgBox.style.display = "block";
        msgBox.style.background = offline ? "rgba(251, 191, 36, 0.12)" : "rgba(0, 255, 65, 0.15)";
        msgBox.style.border = offline ? "1px solid rgba(251, 191, 36, 0.45)" : "1px solid #00ff41";
        msgBox.style.color = offline ? "#fbbf24" : "#00ff41";
        msgBox.textContent = (offline ? "⚠️ " : "✅ ") + (json.message || t("setup.saved_default"));
      }
      showToast(
        live
          ? t("setup.saved_live")
          : (json.warning
            ? tf("setup.saved_warn", { w: json.warning })
            : t("setup.saved_offline")),
        live ? "info" : "warn"
      );
      appConfig = json.config || { is_configured: true, offline_mode: offline };
      isSetupInitial = false;
      setTimeout(() => {
        closeSetupModal();
        fetchStatus();
      }, offline ? 900 : 1200);
    } else {
      if (msgBox) {
        msgBox.style.display = "block";
        msgBox.style.background = "rgba(255, 0, 85, 0.15)";
        msgBox.style.border = "1px solid #ff0055";
        msgBox.style.color = "#ff6699";
        const hint = json.hint ? ` — ${json.hint}` : "";
        msgBox.textContent = "❌ " + (json.error || t("setup.save_fail")) + hint;
      }
    }
  } catch (err) {
    if (msgBox) {
      msgBox.style.display = "block";
      msgBox.style.background = "rgba(255, 0, 85, 0.15)";
      msgBox.style.border = "1px solid #ff0055";
      msgBox.style.color = "#ff6699";
      msgBox.textContent = `${t("setup.save_ex")} ${err.message || err}`;
    }
  } finally {
    if (btnSave) {
      btnSave.disabled = false;
      btnSave.textContent = t("setup.btn_golive");
    }
    if (btnPersist) {
      btnPersist.disabled = false;
      btnPersist.textContent = t("setup.btn_persist");
    }
  }
}

