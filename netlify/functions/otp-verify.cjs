// netlify/functions/otp-verify.cjs
function reply(statusCode, data) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Methods": "POST,OPTIONS",
    },
    body: JSON.stringify(data),
  };
}

function isEmail(s) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s || "").trim());
}

async function upstashGet(key) {
  const base = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!base || !token) throw new Error("Missing UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN");

  const url = `${base}/get/${encodeURIComponent(key)}`;
  const res = await fetch(url, {
    method: "GET",
    headers: { Authorization: `Bearer ${token}` },
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Upstash get failed: ${res.status} ${JSON.stringify(json)}`);

  return json.result ?? null;
}

async function upstashDel(key) {
  const base = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  const url = `${base}/del/${encodeURIComponent(key)}`;
  await fetch(url, { method: "POST", headers: { Authorization: `Bearer ${token}` } });
}

async function upstashSet(key, value, exSeconds) {
  const base = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!base || !token) throw new Error("Missing UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN");

  // Upstash REST: /set/<key>/<value>?EX=600
  const url = `${base}/set/${encodeURIComponent(key)}/${encodeURIComponent(value)}?EX=${exSeconds}`;
  const res = await fetch(url, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Upstash set failed: ${res.status} ${JSON.stringify(json)}`);
}

exports.handler = async (event) => {
  try {
    if (event.httpMethod === "OPTIONS") return reply(200, { ok: true });
    if (event.httpMethod !== "POST") return reply(405, { error: "Method not allowed" });

    const { email, code } = JSON.parse(event.body || "{}");
    const e = String(email || "").trim().toLowerCase();
    const c = String(code || "").trim();

    if (!isEmail(e)) return reply(400, { error: "invalid email" });
    if (!/^\d{6}$/.test(c)) return reply(400, { error: "invalid code (6 digits)" });

    const key = `otp:${e}`;
    const saved = await upstashGet(key);

    if (!saved) return reply(400, { ok: false, error: "code_expired_or_not_found" });
    if (String(saved) !== c) return reply(400, { ok: false, error: "code_mismatch" });

    // 通過後刪掉 OTP，避免重複使用
    await upstashDel(key);

    // ✅ 新增：寫入「已驗證」旗標（10 分鐘）
    await upstashSet(`otp_verified:${e}`, "1", 600);

    return reply(200, { ok: true });
  } catch (err) {
    return reply(500, { error: "server_error", detail: String(err?.message || err) });
  }
};
