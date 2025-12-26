// netlify/functions/otp-verify.cjs
// ✅ 合併版：驗證嘗試限流（Email/IP）+ 刪 OTP + 設 otp_verified TTL + CORS 白名單 + 不回傳內部錯誤細節

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
  if (!origin) return true;
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
  return { statusCode, headers: corsHeaders(origin), body: JSON.stringify(data) };
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

async function upstashGet(key) {
  const { base, token } = requireUpstash();
  const url = `${base}/get/${encodeURIComponent(key)}`;
  const res = await fetch(url, { method: "GET", headers: { Authorization: `Bearer ${token}` } });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Upstash get failed: ${res.status} ${JSON.stringify(json)}`);
  return json.result ?? null;
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

async function upstashDel(key) {
  const base = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!base || !token) return;
  const url = `${base}/del/${encodeURIComponent(key)}`;
  await fetch(url, { method: "POST", headers: { Authorization: `Bearer ${token}` } });
}

exports.handler = async (event) => {
  const origin = getRequestOrigin(event.headers || {});

  try {
    if (event.httpMethod === "OPTIONS") return reply(200, { ok: true }, origin);
    if (event.httpMethod !== "POST") return reply(405, { error: "Method not allowed" }, origin);
    if (origin && !isOriginAllowed(origin)) return reply(403, { ok: false, error: "origin_not_allowed" }, origin);

    const { email, code } = JSON.parse(event.body || "{}");
    const e = String(email || "").trim().toLowerCase();
    const c = String(code || "").trim();

    if (!isEmail(e)) return reply(400, { ok: false, error: "invalid_email" }, origin);
    if (!/^\d{6}$/.test(c)) return reply(400, { ok: false, error: "invalid_code" }, origin);

    // --- Rate limit: 10 分鐘內
    const ip = getClientIp(event.headers || {});
    const WINDOW_SECONDS = 10 * 60;

    const LIMIT_EMAIL = 8; // 同 email 最多 8 次
    const LIMIT_IP = 60;   // 同 IP 最多 60 次

    const rlEmailKey = `rl:otp_verify:email:${e}`;
    const rlIpKey = `rl:otp_verify:ip:${ip}`;

    const emailHit = await upstashIncr(rlEmailKey);
    if (emailHit === 1) await upstashExpire(rlEmailKey, WINDOW_SECONDS);

    const ipHit = await upstashIncr(rlIpKey);
    if (ipHit === 1) await upstashExpire(rlIpKey, WINDOW_SECONDS);

    if (emailHit > LIMIT_EMAIL || ipHit > LIMIT_IP) {
      return reply(429, { ok: false, error: "rate_limited" }, origin);
    }

    const saved = await upstashGet(`otp:${e}`);
    if (!saved) return reply(400, { ok: false, error: "code_expired_or_not_found" }, origin);
    if (String(saved) !== c) return reply(400, { ok: false, error: "code_mismatch" }, origin);

    // 成功：刪 OTP，寫入 otp_verified（TTL 30 分鐘），清掉限流 key（讓使用者不卡在上限）
    await upstashDel(`otp:${e}`);

    const OTP_VERIFIED_TTL_SECONDS = 30 * 60;
    await upstashSet(`otp_verified:${e}`, "1", OTP_VERIFIED_TTL_SECONDS);

    await upstashDel(rlEmailKey);
    await upstashDel(rlIpKey);

    return reply(200, { ok: true }, origin);
  } catch (err) {
    console.error("otp-verify error:", err);
    return reply(500, { ok: false, error: "server_error" }, origin);
  }
};
