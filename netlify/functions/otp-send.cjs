// netlify/functions/otp-send.cjs
const crypto = require("crypto");

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
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ from, to: [to], subject, html, text }),
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Resend error: ${res.status} ${JSON.stringify(data)}`);
}

exports.handler = async (event) => {
  try {
    if (event.httpMethod === "OPTIONS") return reply(200, { ok: true });
    if (event.httpMethod !== "POST") return reply(405, { error: "Method not allowed" });

    const { email } = JSON.parse(event.body || "{}");
    const e = String(email || "").trim().toLowerCase();

    if (!isEmail(e)) return reply(400, { error: "invalid email" });

    // 6 位數驗證碼
    const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");

    // 存到 Upstash (10 分鐘)
    const key = `otp:${e}`;
    await upstashSet(key, code, 600);

    // 寄信
    await resendSend(e, code);

    return reply(200, { ok: true });
  } catch (err) {
    return reply(500, { error: "server_error", detail: String(err?.message || err) });
  }
};
