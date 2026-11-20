"use strict";
// Everything rendered here comes from captured network traffic, i.e. it is
// attacker-controlled. Only ever insert it as text (el() / textContent).

const SEV = {
  critical: "嚴重",
  high: "高",
  medium: "中",
  info: "資訊",
};
const KIND = {
  credential: "帳號密碼",
  session: "Cookie",
  token: "存取權杖",
  url: "瀏覽網址",
  dns: "DNS 查詢",
  sni: "TLS 網域",
  email: "電子郵件",
  command: "遠端指令",
  file: "檔案傳輸",
  form: "表單資料",
  upgrade: "升級加密",
};
const SECRET_LABEL = {
  username: "帳號",
  password: "密碼",
  encoded: "線路上的原文",
  encoded_user: "帳號（Base64）",
  encoded_password: "密碼（Base64）",
  token: "權杖",
  cookie: "Cookie 值",
  body: "信件內文",
};
const ENCRYPTED_PROTOCOLS = new Set(["TLS", "HTTPS"]);

const LESSONS = {
  credential: {
    why: "帳號密碼以明文（或只是 Base64 編碼）在網路上傳送。同一個 Wi-Fi 的人、被設定成鏡像埠的電腦，或任何中繼節點（路由器、代理伺服器、惡意熱點）都能直接讀出來。",
    fix: [
      "只在網址是 HTTPS 的網站輸入密碼",
      "網站管理者：全站強制 HTTPS 並啟用 HSTS",
      "停用 FTP / Telnet / POP3 / IMAP 明文登入，改用 SFTP、SSH、IMAPS 或 STARTTLS",
      "每個網站使用不同密碼，並開啟多因素驗證（MFA）",
    ],
  },
  session: {
    why: "Cookie 通常就是你的「登入狀態」。攻擊者不需要密碼，只要把這串值放進自己的瀏覽器，就能冒用你的身分（Session Hijacking）。",
    fix: [
      "Cookie 設定 Secure 旗標，只透過 HTTPS 傳送",
      "同時設定 HttpOnly 與 SameSite",
      "全站 HTTPS + HSTS，避免第一個請求走 HTTP",
    ],
  },
  token: {
    why: "API 權杖等同於帳號密碼。拿到它的人可以用你的身分呼叫 API，而且很多權杖效期很長。",
    fix: ["API 一律走 HTTPS", "權杖設定短效期並可撤銷", "不要把權杖或密碼放在網址參數裡"],
  },
  url: {
    why: "未加密的 HTTP 連線中，完整網址（含路徑與參數）、送出的內容、伺服器回傳的網頁全部一覽無遺。中間人甚至可以竄改網頁，植入惡意程式碼。",
    fix: ["網站全面改用 HTTPS", "瀏覽器開啟「僅限 HTTPS」模式"],
  },
  dns: {
    why: "傳統 DNS 查詢沒有加密：網路上的人知道你正要連去哪些網站，也可能偽造回應把你導向釣魚網站。",
    fix: ["啟用 DNS over HTTPS（DoH）或 DNS over TLS（DoT）", "使用有 DNSSEC 驗證的解析器"],
  },
  sni: {
    why: "內容已由 TLS 加密，攻擊者看不到網頁和密碼——但 TLS 握手的 ClientHello 裡，SNI 欄位仍以明文寫出你要連的網域。HTTPS 保護的是「內容」，不一定隱藏「你去了哪裡」。",
    fix: [
      "這是相對安全的連線，內容無法被讀取",
      "支援 Encrypted Client Hello（ECH）的瀏覽器與網站可以隱藏 SNI",
      "需要更高隱私時，使用可信任的 VPN 或 Tor",
    ],
  },
  email: {
    why: "SMTP 沒有加密時，寄件者、收件者、主旨和內文全部可讀——包含信裡附帶的帳號密碼。",
    fix: [
      "郵件軟體使用 SMTPS（465）或 587 + STARTTLS",
      "郵件伺服器之間啟用 MTA-STS，避免被降級",
      "機密內容使用端對端加密（S/MIME、PGP）",
      "不要在信件中傳送密碼",
    ],
  },
  command: {
    why: "Telnet 的每一個按鍵都以明文送出，包含你輸入的指令與設備回傳的設定（裡面常有 SNMP community、其他密碼）。",
    fix: ["改用 SSH", "網路設備關閉 Telnet 服務"],
  },
  file: {
    why: "FTP 傳輸的檔名與檔案內容全部是明文，攻擊者可以從封包中直接還原整個檔案。",
    fix: ["改用 SFTP 或 FTPS", "使用 HTTPS 的檔案分享服務"],
  },
  form: {
    why: "表單內容（搜尋關鍵字、個人資料、留言）以明文傳送，任何中間節點都能讀取與記錄。",
    fix: ["網站全面改用 HTTPS"],
  },
  upgrade: {
    why: "好消息：這條連線在登入前就用 STARTTLS 升級為加密，後續內容攻擊者看不到。但若用戶端不是「強制」加密，中間人可以刪掉 STARTTLS 指令把連線降級（STRIPTLS）。",
    fix: ["郵件軟體設定為「必須使用 TLS」而非「可用時使用」", "優先使用一開始就加密的連接埠（993 / 995 / 465）"],
  },
};
const MITM_LESSON = {
  why: "這筆資料原本走 HTTPS，卻被中間人解密了！原因是受害裝置信任了攻擊者的根憑證（或使用者無視了瀏覽器的憑證警告）。一旦信任了惡意憑證，HTTPS 的保護就完全失效。",
  fix: [
    "絕對不要安裝來路不明的根憑證或描述檔",
    "看到瀏覽器憑證警告時，不要按「繼續前往」",
    "網站啟用 HSTS（瀏覽器會禁止略過憑證警告）",
    "行動 App 實作 Certificate Pinning",
  ],
};

// ------------------------------------------------------------------ helpers
function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "style") node.style.cssText = v; // CSSOM: allowed by our CSP
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    node.append(c instanceof Node ? c : String(c));
  }
  return node;
}
const $ = (id) => document.getElementById(id);
const sevKey = (s) => (s in SEV ? s : "info");
const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString("zh-TW", { hour12: false });
function fmtBytes(n) {
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
}

// ------------------------------------------------------------------ state
const state = {
  items: [],
  byId: new Map(),
  hiddenBefore: 0, // ids <= this were cleared by the user
  selectedId: null,
  paused: false,
  pendingWhilePaused: 0,
  sev: new Set(Object.keys(SEV)),
  proto: "",
  q: "",
  protos: new Set(),
};
const MAX_CARDS = 600;

function matches(f) {
  if (!state.sev.has(sevKey(f.severity))) return false;
  if (state.proto && f.protocol !== state.proto) return false;
  if (state.q) {
    const hay = `${f.title} ${f.src} ${f.dst} ${f.protocol} ${Object.values(f.details).join(" ")}`.toLowerCase();
    if (!hay.includes(state.q)) return false;
  }
  return true;
}

function addFinding(f, live) {
  if (f.id <= state.hiddenBefore || state.byId.has(f.id)) return;
  state.items.push(f);
  state.byId.set(f.id, f);
  if (!state.protos.has(f.protocol)) {
    state.protos.add(f.protocol);
    $("proto").append(el("option", { value: f.protocol }, f.protocol));
  }
  updateCounts();
  if (state.paused) {
    state.pendingWhilePaused++;
    updatePauseLabel();
    return;
  }
  if (matches(f)) {
    const feed = $("feed");
    feed.prepend(card(f, live));
    while (feed.childElementCount > MAX_CARDS) feed.lastElementChild.remove();
    $("empty").hidden = true;
  }
  if (state.selectedId == null && live && (f.severity === "critical" || f.severity === "high")) {
    select(f.id);
  }
}

function card(f, live) {
  const s = sevKey(f.severity);
  return el("button", {
      type: "button",
      class: `card sev-${s}${live ? " fresh" : ""}${f.id === state.selectedId ? " selected" : ""}`,
      "data-id": String(f.id),
      onclick: () => select(f.id),
    },
    el("div", { class: "card-top" },
      el("span", { class: `sev sev-${s}` }, SEV[s]),
      el("span", { class: "proto" }, f.protocol),
      f.encrypted_channel ? el("span", { class: "badge mitm" }, "MITM 解密") : null,
      el("span", {}, KIND[f.kind] || f.kind),
      el("time", {}, fmtTime(f.ts)),
    ),
    el("div", { class: "card-title", title: f.title }, f.title),
    el("div", { class: "card-flow" }, `${f.src} → ${f.dst}`),
  );
}

function renderFeed() {
  const feed = $("feed");
  const visible = state.items.filter(matches).slice(-MAX_CARDS).reverse();
  feed.replaceChildren(...visible.map((f) => card(f, false)));
  $("empty").hidden = visible.length > 0;
  $("empty").textContent = state.items.length ? "沒有符合篩選條件的項目" : "等待流量中…";
}

function updateCounts() {
  let cred = 0, sess = 0;
  const domains = new Set();
  for (const f of state.items) {
    if (f.kind === "credential") cred++;
    else if (f.kind === "session" || f.kind === "token") sess++;
    else if (f.kind === "dns") domains.add(f.details["查詢網域"]);
    else if (f.kind === "sni") domains.add(f.details["SNI 網域"]);
  }
  $("k-cred").textContent = cred;
  $("k-session").textContent = sess;
  $("k-domains").textContent = domains.size;
  $("feed-count").textContent = `${state.items.length} 筆`;
}

// ------------------------------------------------------------------ detail
function select(id) {
  state.selectedId = id;
  for (const c of document.querySelectorAll(".card.selected")) c.classList.remove("selected");
  const c = document.querySelector(`.card[data-id="${id}"]`);
  if (c) c.classList.add("selected");
  const f = state.byId.get(id);
  if (f) renderDetail(f);
}

// Form bodies carry values URL-encoded ("p@ss!" is "p%40ss%21" on the wire).
function wireForms(v) {
  const strict = encodeURIComponent(v).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
  return [v, encodeURIComponent(v), strict, strict.replace(/%20/g, "+")];
}

function highlight(text, needles) {
  needles = [...new Set(needles.flatMap(wireForms))].filter((n) => n && n.length >= 3)
    .sort((a, b) => b.length - a.length);
  const out = [];
  let i = 0;
  while (i < text.length) {
    let best = -1, bestN = "";
    for (const n of needles) {
      const j = text.indexOf(n, i);
      if (j >= 0 && (best < 0 || j < best)) { best = j; bestN = n; }
    }
    if (best < 0) { out.push(text.slice(i)); break; }
    if (best > i) out.push(text.slice(i, best));
    out.push(el("mark", {}, bestN));
    i = best + bestN.length;
  }
  return out;
}

function kvTable(obj, valueFn) {
  return el("table", { class: "kv" },
    el("tbody", {}, Object.entries(obj).map(([k, v]) =>
      el("tr", {}, el("th", { scope: "row" }, SECRET_LABEL[k] || k), el("td", {}, valueFn(v))))));
}

function renderDetail(f) {
  const s = sevKey(f.severity);
  const lesson = LESSONS[f.kind];
  const secrets = Object.entries(f.secrets).filter(([, v]) => v);
  const details = Object.fromEntries(Object.entries(f.details).filter(([, v]) => v));
  $("detail").replaceChildren(el("div", {},
    el("div", { class: "detail-head" },
      el("div", { class: "tags" },
        el("span", { class: `sev sev-${s}` }, SEV[s]),
        el("span", { class: "proto" }, f.protocol),
        el("span", { class: "sev sev-info" }, KIND[f.kind] || f.kind),
        f.encrypted_channel ? el("span", { class: "badge mitm" }, "HTTPS 被 MITM 解密") : null,
      ),
      el("h2", {}, f.title),
      el("div", { class: "flowline" },
        el("span", { class: "node", title: "用戶端" }, f.src),
        el("span", { class: "wire" }, "──", el("span", { class: "eye" }, " 👁 中間人 "), "──▶"),
        el("span", { class: "node", title: "伺服器" }, f.dst),
        el("span", { class: "muted small" }, new Date(f.ts * 1000).toLocaleString("zh-TW", { hour12: false })),
      ),
    ),
    secrets.length ? [
      el("h3", {}, "被讀出的機密"),
      kvTable(Object.fromEntries(secrets), (v) => el("code", { class: "secret" }, v)),
    ] : null,
    Object.keys(details).length ? [el("h3", {}, "詳細資訊"), kvTable(details, (v) => v)] : null,
    f.excerpt ? [
      el("h3", {}, "封包原文（中間人看到的樣子）"),
      el("pre", { class: "excerpt" }, highlight(f.excerpt, secrets.map(([, v]) => v))),
    ] : null,
    el("div", { class: "lesson" },
      f.encrypted_channel ? lessonBox("mitm-why", "HTTPS 為什麼被解密了？", MITM_LESSON.why, MITM_LESSON.fix) : null,
      lesson ? [
        el("div", { class: "why" }, el("h4", {}, "為什麼危險"), el("p", {}, lesson.why)),
        el("div", { class: "fix" }, el("h4", {}, "怎麼防護"), el("ul", {}, lesson.fix.map((t) => el("li", {}, t)))),
      ] : null,
    ),
  ));
}

function lessonBox(cls, title, why, fix) {
  return el("div", { class: cls },
    el("h4", {}, title), el("p", {}, why),
    el("ul", {}, fix.map((t) => el("li", {}, t))));
}

// ------------------------------------------------------------------ stats
let metaShown = false;
function renderStats(s) {
  $("k-packets").textContent = s.packets.toLocaleString();
  $("k-bytes").textContent = `${fmtBytes(s.bytes)} 應用層資料`;
  const enc = s.encrypted_sessions, plain = s.plaintext_sessions, total = enc + plain;
  $("r-enc").style.width = total ? `${(enc / total) * 100}%` : "0";
  $("r-plain").style.width = total ? `${(plain / total) * 100}%` : "0";
  $("r-enc-t").textContent = `加密 ${enc}`;
  $("r-plain-t").textContent = `明文 ${plain}`;

  const entries = Object.entries(s.sessions).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(([, n]) => n));
  $("protos").replaceChildren(...entries.map(([name, n]) =>
    el("li", { class: ENCRYPTED_PROTOCOLS.has(name) ? "enc" : name === "其他" ? "unknown" : "plain" },
      el("span", {}, name, ENCRYPTED_PROTOCOLS.has(name) ? " 🔒" : ""),
      el("span", { class: "n" }, n),
      el("div", { class: "bar" }, el("span", { style: `width:${(n / max) * 100}%` })),
    )));
  if (!entries.length) $("protos").replaceChildren(el("li", { class: "muted small" }, "尚無連線"));

  if (!metaShown) {
    metaShown = true;
    $("mode").textContent = `${s.mode_label}${s.source ? "・" + s.source : ""}`;
    $("addon-cmd").textContent = `mitmdump -s "${s.addon_path}" --listen-port 8080`;
  }
}

async function pollStats() {
  try {
    const r = await fetch("/api/stats", { cache: "no-store" });
    if (r.ok) renderStats(await r.json());
  } catch { /* the stream indicator shows connectivity */ }
}

// ------------------------------------------------------------------ stream
function setConn(on) {
  const c = $("conn");
  c.className = `pill conn ${on ? "on" : "off"}`;
  c.querySelector("b").textContent = on ? "即時連線中" : "連線中斷，重試中…";
}

function connect() {
  const es = new EventSource("/events");
  es.onopen = () => setConn(true);
  es.onerror = () => setConn(false);
  es.onmessage = (e) => {
    try { addFinding(JSON.parse(e.data), true); } catch { /* ignore malformed */ }
  };
}

// ------------------------------------------------------------------ controls
function updatePauseLabel() {
  const b = $("btn-pause");
  b.textContent = state.paused ? `繼續（+${state.pendingWhilePaused}）` : "暫停";
  b.classList.toggle("active", state.paused);
}

function setupControls() {
  const chips = $("sev-chips");
  for (const [key, label] of Object.entries(SEV)) {
    const chip = el("button", { type: "button", class: `chip sev-${key}`, "aria-pressed": "true" }, label);
    chip.addEventListener("click", () => {
      const on = !state.sev.has(key);
      if (on) state.sev.add(key); else state.sev.delete(key);
      chip.setAttribute("aria-pressed", String(on));
      renderFeed();
    });
    chips.append(chip);
  }
  $("proto").addEventListener("change", (e) => { state.proto = e.target.value; renderFeed(); });
  $("search").addEventListener("input", (e) => { state.q = e.target.value.trim().toLowerCase(); renderFeed(); });
  $("btn-pause").addEventListener("click", () => {
    state.paused = !state.paused;
    if (!state.paused) { state.pendingWhilePaused = 0; renderFeed(); }
    updatePauseLabel();
  });
  $("btn-clear").addEventListener("click", () => {
    state.hiddenBefore = Math.max(state.hiddenBefore, ...state.items.map((f) => f.id));
    state.items = [];
    state.byId.clear();
    state.selectedId = null;
    renderFeed();
    updateCounts();
    $("detail").replaceChildren(el("div", { class: "placeholder" }, el("h2", {}, "畫面已清除"), el("p", {}, "新的流量會繼續出現在左側。")));
  });
  $("btn-export").addEventListener("click", () => {
    const blob = new Blob([JSON.stringify(state.items, null, 2)], { type: "application/json" });
    const a = el("a", { href: URL.createObjectURL(blob), download: `plainsight-${Date.now()}.json` });
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });
  $("btn-help").addEventListener("click", () => $("help").showModal());
}

setupControls();
connect();
pollStats();
setInterval(pollStats, 1000);
