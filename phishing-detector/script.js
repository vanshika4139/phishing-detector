const scanHistory = [];

const SHORTENERS = ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","adf.ly","tiny.cc","rb.gy","cutt.ly","shorte.st"];
const SUSPICIOUS_TLDS = [".xyz",".tk",".ml",".ga",".cf",".gq",".top",".click",".link",".work",".party",".loan",".download",".racing"];
const BRANDS = ["paypal","netflix","amazon","google","facebook","apple","microsoft","instagram","twitter","whatsapp","sbi","hdfc","icici","paytm","flipkart","snapdeal"];
const SUSP_WORDS = ["login","verify","secure","update","account","bank","confirm","password","signin","wallet","otp","kyc","suspended","unusual","activity","claim","prize","winner","free","urgent"];

function analyzeURL() {
  const input = document.getElementById("urlInput");
  const url = input.value.trim();
  if (!url) { input.focus(); return; }

  document.getElementById("loading").style.display = "block";
  document.getElementById("resultArea").innerHTML = "";

  setTimeout(() => {
    const result = fullCheck(url);
    result.url = url;
    scanHistory.unshift(result);
    if (scanHistory.length > 5) scanHistory.pop();
    document.getElementById("loading").style.display = "none";
    renderResult(result);
    renderHistory();
  }, 900);
}

function fullCheck(url) {
  const lower = url.toLowerCase();
  let hostname = "";
  try { hostname = new URL(url).hostname.toLowerCase(); } catch(e) { hostname = lower; }
  const tld = "." + hostname.split(".").pop();

  const flags = [];
  let score = 0;

  const hasHTTPS = lower.startsWith("https://");
  flags.push({ label: "HTTPS Protocol", status: hasHTTPS ? "ok" : "danger", detail: hasHTTPS ? "Secure connection" : "Not secure — HTTP only!" });
  if (!hasHTTPS) score += 20;

  const hasIP = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname);
  flags.push({ label: "Domain Legitimacy", status: hasIP ? "danger" : "ok", detail: hasIP ? "IP address used instead of domain — suspicious!" : "Domain looks normal" });
  if (hasIP) score += 35;

  const found = SUSP_WORDS.filter(w => lower.includes(w));
  flags.push({ label: "Suspicious Keywords", status: found.length > 1 ? "danger" : found.length === 1 ? "warn" : "ok", detail: found.length ? `Found: ${found.join(", ")}` : "No suspicious keywords found" });
  score += Math.min(found.length * 10, 30);

  const longURL = url.length > 100;
  flags.push({ label: "URL Length & Structure", status: longURL ? "warn" : "ok", detail: longURL ? `Very long URL (${url.length} chars)` : "URL length looks normal" });
  if (longURL) score += 15;

  const hasRedirect = lower.includes("redirect") || lower.includes("url=") || lower.includes("return=") || lower.includes("next=");
  flags.push({ label: "Redirect Patterns", status: hasRedirect ? "danger" : "ok", detail: hasRedirect ? "Redirect parameter found — suspicious!" : "No redirects found" });
  if (hasRedirect) score += 20;

  const fakeBrand = BRANDS.find(b => lower.includes(b) && !hostname.endsWith(b + ".com") && !hostname.endsWith(b + ".in") && !hostname.endsWith(b + ".net") && !hostname.endsWith(b + ".org"));
  flags.push({ label: "Brand Impersonation", status: fakeBrand ? "danger" : "ok", detail: fakeBrand ? `"${fakeBrand}" brand name used in fake domain!` : "No brand impersonation detected" });
  if (fakeBrand) score += 35;

  const isShortener = SHORTENERS.some(s => hostname.includes(s));
  flags.push({ label: "URL Shortener", status: isShortener ? "warn" : "ok", detail: isShortener ? "Shortened URL — real destination is hidden!" : "Not a shortened URL" });
  if (isShortener) score += 20;

  const badTLD = SUSPICIOUS_TLDS.includes(tld);
  flags.push({ label: "Suspicious Domain Extension", status: badTLD ? "warn" : "ok", detail: badTLD ? `"${tld}" extension is commonly used in phishing` : "Domain extension looks normal" });
  if (badTLD) score += 20;

  const hasUnicode = /[^\x00-\x7F]/.test(hostname);
  const homoglyphs = detectHomoglyphs(hostname);
  flags.push({ label: "Unicode / Character Trick", status: (hasUnicode || homoglyphs) ? "danger" : "ok", detail: (hasUnicode || homoglyphs) ? "Fake lookalike characters detected!" : "No character tricks detected" });
  if (hasUnicode || homoglyphs) score += 40;

  const subdomainCount = hostname.split(".").length - 2;
  const tooManySubs = subdomainCount > 2;
  flags.push({ label: "Subdomain Structure", status: tooManySubs ? "warn" : "ok", detail: tooManySubs ? `${subdomainCount} subdomains found — possible phishing trick` : "Subdomain structure looks normal" });
  if (tooManySubs) score += 15;

  score = Math.min(score, 100);
  const risk_level = score >= 55 ? "high" : score >= 25 ? "medium" : "safe";
  const summary = {
    safe: "This URL looks safe. No major red flags detected. Still be cautious with unknown sources.",
    medium: "This URL looks suspicious. Verify the source and do not enter personal information.",
    high: "DANGEROUS! This URL may be a phishing attempt. Do not open it, enter any details, or forward it to others!"
  }[risk_level];

  return { risk_level, risk_score: score, summary, flags };
}

function detectHomoglyphs(hostname) {
  const homoglyphMap = { 'a':'а', 'e':'е', 'o':'о', 'p':'р', 'c':'с', 'x':'х', 'i':'і' };
  return Object.keys(homoglyphMap).some(k => hostname.includes(homoglyphMap[k]));
}

function renderResult(r) {
  const lvl = r.risk_level;
  const label = { safe: "✅ Safe", medium: "⚠️ Suspicious", high: "🚨 Phishing!" }[lvl];
  const flagIcons = { ok: "✅", warn: "⚠️", danger: "🚨" };
  const flagsHTML = (r.flags || []).map(f =>
    `<div class="check-item">
      <div class="check-label">${f.label}</div>
      <div class="check-detail">${flagIcons[f.status] || ""} ${f.detail}</div>
    </div>`
  ).join("");

  const shareBtn = `<button onclick="copyResult()" style="margin-top:12px;padding:8px 16px;border:1px solid #ddd;border-radius:8px;background:#fff;cursor:pointer;font-size:13px;">📋 Copy Result</button>`;

  document.getElementById("resultArea").innerHTML = `
    <div class="result-card">
      <div class="result-header">
        <div>
          <div class="url-text">${esc(r.url)}</div>
          <span class="badge badge-${lvl}">${label}</span>
        </div>
        <div class="score score-${lvl}">${Math.round(r.risk_score)}<span style="font-size:14px;color:#999">/100</span></div>
      </div>
      <div class="checks-grid">${flagsHTML}</div>
      <div class="ai-box">
        <div class="ai-label">🔍 Analysis</div>
        <div class="ai-text">${esc(r.summary)}</div>
      </div>
      ${shareBtn}
    </div>`;
}

function copyResult() {
  const r = scanHistory[0];
  if (!r) return;
  const lvl = { safe: "✅ Safe", medium: "⚠️ Suspicious", high: "🚨 Phishing!" }[r.risk_level];
  const text = `🛡️ Phishing Link Detector Result\n\nURL: ${r.url}\nStatus: ${lvl}\nRisk Score: ${Math.round(r.risk_score)}/100\n\nAnalysis: ${r.summary}`;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.querySelector("[onclick='copyResult()']");
    if (btn) { btn.textContent = "✅ Copied!"; setTimeout(() => { btn.textContent = "📋 Copy Result"; }, 2000); }
  });
}

function renderHistory() {
  if (!scanHistory.length) return;
  const items = scanHistory.map((h, i) =>
    `<div class="history-item" onclick="showHistory(${i})">
      <div class="dot dot-${h.risk_level}"></div>
      <div class="history-url">${esc(h.url)}</div>
      <span style="font-size:12px;color:#999">${Math.round(h.risk_score)}/100</span>
    </div>`
  ).join("");
  document.getElementById("historyArea").innerHTML =
    `<div class="history-section"><div class="history-title">Recent Scans</div>${items}</div>`;
}

function showHistory(i) { renderResult(scanHistory[i]); }
function esc(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("urlInput").addEventListener("keydown", e => {
    if (e.key === "Enter") analyzeURL();
  });
});