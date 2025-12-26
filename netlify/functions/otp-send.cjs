// netlify/functions/otp-send.cjs
// ✅ 合併版：IP 寄送限流 + Upstash OTP 儲存 + Resend 寄信 + CORS 白名單
// ✅ 反枚舉：不論 email 是否有效/是否寄信成功，對外一律回 200 {ok:true}
// ✅ 保留：403(非白名單 Origin)、405(Method)、429(限流)

const crypto = require("crypto");

const DEFAULT_ALLOWED_ORIGINS = [
  "https://xinghuoad.xyz",
  "https://www.xinghuoad.xyz",
];

function getAllowedOrigins() {
  const env = String(process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return env.length ? env : DEFAULT_ALLOWED_ORIGINS;
}

function getRequestOrigin(headers = {}) {
  return headers.origin || headers.Origin || "";
}

function isOriginAllowed(origin) {
  if (!origin) return true; // 非瀏覽器/無 Origin（例如 curl）視為允許
  return getAllowedOrigins().includes(origin);
}

function corsHeaders(origin) {
  const allowOrigin = origin && isOriginAllowed(origin) ? origin : getAllowedOrigins()[0];
  return {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Vary": "Origin",
  };
}

function reply(statusCode, data, origin) {
  return {
    statusCode,
    headers: corsHeaders(origin),
    body: JSON.stringify(data),
  };
}

function isEmail(s) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s || "").trim());
}

function getClientIp(headers = {}) {
  const h = {};
  for (const [k, v] of Object.entries(headers || {})) h[String(k).toLowerCase()] = v;

  const nf = h["x-nf-client-connection-ip"];
  const xff = h["x-forwarded-for"];
  const ip = (nf || (xff ? String(xff).split(",")[0] : "") || "").trim();

  return ip || "unknown";
}

// ---------- Upstash REST helpers ----------
function requireUpstash() {
  const base = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!base || !token) throw new Error("Missing UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN");
  return { base, token };
}

async function upstashSet(key, value, exSeconds) {
  const { base, token } = requireUpstash();
  const url = `${base}/set/${encodeURIComponent(key)}/${encodeURIComponent(value)}?EX=${exSeconds}`;
  const res = await fetch(url, { method: "POST", headers: { Authorization: `Bearer ${token}` } });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Upstash set failed: ${res.status} ${JSON.stringify(json)}`);
}

async function upstashIncr(key) {
  const { base, token } = requireUpstash();
  const url = `${base}/incr/${encodeURIComponent(key)}`;
  const res = await fetch(url, { method: "POST", headers: { Authorization: `Bearer ${token}` } });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Upstash incr failed: ${res.status} ${JSON.stringify(json)}`);
  return Number(json?.result ?? 0);
}

async function upstashExpire(key, seconds) {
  const { base, token } = requireUpstash();
  const url = `${base}/expire/${encodeURIComponent(key)}/${seconds}`;
  const res = await fetch(url, { method: "POST", headers: { Authorization: `Bearer ${token}` } });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Upstash expire failed: ${res.status} ${JSON.stringify(json)}`);
}

// ---------- Resend ----------
async function resendSend(to, code) {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.RESEND_FROM; // e.g. "星火廣告 <no-reply@xinghuoad.xyz>"
  if (!apiKey) throw new Error("Missing RESEND_API_KEY");
  if (!from) throw new Error("Missing RESEND_FROM");

  const subject = "星火廣告｜Email 驗證碼";
  const text = `你的驗證碼是：${code}\n有效時間：10 分鐘\n\n若非本人操作請忽略此信。`;
  const html = `
    <div style="font-family: Arial, sans-serif; line-height:1.7">
      <h2>星火廣告 Email 驗證碼</h2>
      <p>你的驗證碼是：</p>
      <div style="font-size:28px;font-weight:800;letter-spacing:4px;margin:12px 0">${code}</div>
      <p>有效時間：10 分鐘</p>
      <p style="color:#666">若非本人操作請忽略此信。</p>
    </div>
  `;

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({ from, to: [to], subject, html, text }),
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Resend error: ${res.status} ${JSON.stringify(data)}`);
}

exports.handler = async (event) => {
  const origin = getRequestOrigin(event.headers || {});

  try {
    if (event.httpMethod === "OPTIONS") {
      // 對 OPTIONS 不硬擋，避免瀏覽器 preflight 卡死
      return reply(200, { ok: true }, origin);
    }
    if (event.httpMethod !== "POST") return reply(405, { error: "Method not allowed" }, origin);

    // 有 Origin 但不在白名單 → 直接拒絕（更嚴格）
    if (origin && !isOriginAllowed(origin)) return reply(403, { ok: false, error: "origin_not_allowed" }, origin);

    const { email } = JSON.parse(event.body || "{}");
    const e = String(email || "").trim().toLowerCase();

    // ✅ 反枚舉：email 格式不合法也回 ok:true（不讓外部用 400/200 當訊號）
    if (!isEmail(e)) return reply(200, { ok: true }, origin);

    // --- Rate limit: 同 IP 10 分鐘最多 20 次寄 OTP ---
    const ip = getClientIp(event.headers || {});
    const WINDOW_SECONDS = 10 * 60;
    const LIMIT = 20;

    const rlKey = `rl:otp_send:ip:${ip}`;
    const hit = await upstashIncr(rlKey);
    if (hit === 1) await upstashExpire(rlKey, WINDOW_SECONDS);
    if (hit > LIMIT) return reply(429, { ok: false, error: "rate_limited" }, origin);

    // 6 位數 OTP
    const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");

    // 存 OTP 10 分鐘
    await upstashSet(`otp:${e}`, code, 600);

    // ✅ 反枚舉：寄信失敗也不回錯（避免被用來判斷狀態）
    try {
      await resendSend(e, code);
    } catch (err) {
      console.error("otp-send resend error:", err);
      // 仍然回 ok:true
    }

    return reply(200, { ok: true }, origin);
  } catch (err) {
    console.error("otp-send error:", err);
    // ✅ 反枚舉：任何內部錯誤也回 ok:true（不暴露訊號）
    return reply(200, { ok: true }, origin);
  }
};
