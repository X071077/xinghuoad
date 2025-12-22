// netlify/functions/auth.cjs
const { google } = require("googleapis");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

// Node 18+ on Netlify has global fetch; if you are on older runtime, you may need node-fetch.
const RESEND_API_URL = "https://api.resend.com/emails";

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

function colToA1(n) {
  let s = "";
  n = n + 1;
  while (n > 0) {
    const m = (n - 1) % 26;
    s = String.fromCharCode(65 + m) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
}

function nowISO() {
  return new Date().toISOString();
}

function makeUserId() {
  return "u_" + crypto.randomBytes(12).toString("hex");
}

function normalizeHeader(h) {
  return String(h || "").trim();
}

function makePasswordHash(password, pepper) {
  const salt = crypto.randomBytes(16).toString("hex");
  const key = crypto.scryptSync(password + pepper, salt, 64).toString("hex");
  return `scrypt$${salt}$${key}`;
}

function verifyPassword(password, pepper, stored) {
  const parts = String(stored || "").split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") return false;
  const salt = parts[1];
  const hash = parts[2];
  const key = crypto.scryptSync(password + pepper, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(key, "hex"), Buffer.from(hash, "hex"));
}

function isValidEmail(email) {
  const e = String(email || "").trim().toLowerCase();
  // 簡單但夠用的格式檢查
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
}

function random6Digits() {
  // 000000 - 999999
  return String(Math.floor(Math.random() * 1000000)).padStart(6, "0");
}

function sha256(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
}

// -------------------- Upstash REST helpers --------------------
function getUpstashEnv() {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) {
    throw new Error("Missing env vars: UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN");
  }
  return { url: url.replace(/\/+$/, ""), token };
}

async function upstashPost(path) {
  const { url, token } = getUpstashEnv();
  const res = await fetch(`${url}/${path}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(`Upstash error (${res.status}): ${JSON.stringify(data)}`);
  }
  return data; // { result: ... }
}

async function upstashGet(key) {
  const data = await upstashPost(`get/${encodeURIComponent(key)}`);
  return data?.result ?? null;
}

async function upstashSetEx(key, ttlSeconds, value) {
  // SETEX key ttl value
  const data = await upstashPost(`setex/${encodeURIComponent(key)}/${ttlSeconds}/${encodeURIComponent(value)}`);
  return data?.result ?? null;
}

async function upstashDel(key) {
  const data = await upstashPost(`del/${encodeURIComponent(key)}`);
  return data?.result ?? null;
}

async function upstashIncr(key, ttlSecondsIfNew) {
  // 先 INCR，再用 SETEX 方式補 TTL（簡化處理：每次 incr 都重設 TTL）
  const data = await upstashPost(`incr/${encodeURIComponent(key)}`);
  const v = data?.result ?? 0;
  // 重設 TTL，避免 attempts 永久存在
  await upstashSetEx(key, ttlSecondsIfNew, String(v));
  return Number(v);
}

// -------------------- Resend helper --------------------
function getResendEnv() {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) throw new Error("Missing env var: RESEND_API_KEY");

  // 建議你在 Netlify 也加一個 RESEND_FROM，例如：no-reply@xinghuoad.xyz
  // 若沒設定，就用 onboarding@resend.dev（但是否能寄給任意收件人取決於 Resend 帳號/設定）
  const from = process.env.RESEND_FROM || "onboarding@resend.dev";
  return { apiKey, from };
}

async function sendEmailViaResend({ to, subject, text, html }) {
  const { apiKey, from } = getResendEnv();

  const res = await fetch(RESEND_API_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from,
      to,
      subject,
      text,
      html,
    }),
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = data?.message || data?.error || JSON.stringify(data);
    throw new Error(`Resend send failed: ${msg}`);
  }
  return data;
}

// -------------------- Google Sheets --------------------
async function getSheets() {
  const sheetId = process.env.GOOGLE_SHEET_ID;
  const tab = process.env.GOOGLE_SHEET_TAB;
  const saJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;

  if (!sheetId || !tab || !saJson) {
    throw new Error("Missing env vars: GOOGLE_SHEET_ID / GOOGLE_SHEET_TAB / GOOGLE_SERVICE_ACCOUNT_JSON");
  }

  const credentials = JSON.parse(saJson);

  const auth = new google.auth.JWT({
    email: credentials.client_email,
    key: credentials.private_key,
    scopes: ["https://www.googleapis.com/auth/spreadsheets"],
  });

  const sheets = google.sheets({ version: "v4", auth });
  return { sheets, sheetId, tab };
}

async function loadAllRows(sheets, sheetId, tab) {
  const res = await sheets.spreadsheets.values.get({
    spreadsheetId: sheetId,
    range: `${tab}!A:Z`,
  });
  const values = res.data.values || [];
  if (values.length === 0) return { headers: [], rows: [] };

  const headers = values[0].map(normalizeHeader);
  const rows = values.slice(1);
  return { headers, rows };
}

function buildHeaderIndex(headers) {
  const idx = {};
  headers.forEach((h, i) => {
    if (h) idx[h] = i;
  });
  return idx;
}

// -------------------- Main handler --------------------
exports.handler = async (event) => {
  try {
    if (event.httpMethod === "OPTIONS") return reply(200, { ok: true });
    if (event.httpMethod !== "POST") return reply(405, { error: "Method not allowed" });

    const body = JSON.parse(event.body || "{}");
    const action = body?.action;

    // 支援 actions: register / login / send_email_code
    if (!action || !["register", "login", "send_email_code"].includes(action)) {
      return reply(400, { error: "Invalid action. Use register, login, or send_email_code." });
    }

    const pepper = process.env.AUTH_PEPPER || "";
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) return reply(500, { error: "Missing JWT_SECRET" });

    // ---------- send_email_code ----------
    if (action === "send_email_code") {
      const email = String(body?.email || "").trim().toLowerCase();
      if (!isValidEmail(email)) return reply(400, { error: "invalid email" });

      // 60 秒冷卻，避免濫用
      const coolKey = `emailcode:cool:${email}`;
      const cool = await upstashGet(coolKey);
      if (cool) return reply(429, { error: "請稍等 60 秒再重新發送驗證碼" });

      const code = random6Digits();
      const codeHash = sha256(code + pepper);
      const ttl = 10 * 60; // 10 分鐘

      const codeKey = `emailcode:code:${email}`;
      const attemptsKey = `emailcode:attempts:${email}`;

      await upstashSetEx(codeKey, ttl, codeHash);
      await upstashSetEx(coolKey, 60, "1");
      await upstashSetEx(attemptsKey, ttl, "0");

      const subject = "星火廣告｜Email 驗證碼";
      const text = `你的驗證碼是：${code}\n有效時間：10 分鐘\n若非本人操作請忽略此信。`;
      const html = `
        <div style="font-family:Arial,sans-serif;line-height:1.7">
          <h2>星火廣告 Email 驗證碼</h2>
          <p>你的驗證碼是：</p>
          <div style="font-size:28px;font-weight:800;letter-spacing:4px;margin:12px 0">${code}</div>
          <p>有效時間：<b>10 分鐘</b></p>
          <p style="color:#666">若非本人操作請忽略此信。</p>
        </div>
      `;

      await sendEmailViaResend({ to: email, subject, text, html });
      return reply(200, { ok: true, message: "驗證碼已寄出（10 分鐘內有效）" });
    }

    // ---------- register / login 共同檢查 ----------
    const username = String(body?.username || "").trim();
    const password = String(body?.password || "");

    if (!username || username.length < 3) return reply(400, { error: "username too short (>=3)" });
    if (!password || password.length < 6) return reply(400, { error: "password too short (>=6)" });

    const { sheets, sheetId, tab } = await getSheets();
    const { headers, rows } = await loadAllRows(sheets, sheetId, tab);
    const headerIdx = buildHeaderIndex(headers);

    // 必要欄位
    const mustHave = ["username", "password_hash", "user_id"];
    for (const k of mustHave) {
      if (headerIdx[k] === undefined) return reply(500, { error: `Sheet missing header: ${k}` });
    }

    const uCol = headerIdx["username"];
    const pCol = headerIdx["password_hash"];
    const u = username;

    let foundRowIndex = -1;
    for (let i = 0; i < rows.length; i++) {
      const cell = (rows[i][uCol] || "").trim();
      if (cell === u) { foundRowIndex = i; break; }
    }

    // ---------- register ----------
    if (action === "register") {
      const name = String(body?.name || "").trim();
      const email = String(body?.email || "").trim().toLowerCase();
      const code = String(body?.code || "").trim();

      if (!isValidEmail(email)) return reply(400, { error: "invalid email" });
      if (!/^\d{6}$/.test(code)) return reply(400, { error: "invalid code (need 6 digits)" });

      // Google Sheet 必須要有 email 欄
      if (headerIdx["email"] === undefined) {
        return reply(500, { error: "Sheet missing header: email（請在 users Sheet 加一欄表頭 email）" });
      }

      if (foundRowIndex !== -1) return reply(409, { error: "username already exists" });

      // 驗證碼校驗
      const emailKey = `emailcode:code:${email}`;
      const attemptsKey = `emailcode:attempts:${email}`;

      const storedHash = await upstashGet(emailKey);
      if (!storedHash) return reply(400, { error: "驗證碼不存在或已過期，請重新取得驗證碼" });

      const attempts = await upstashIncr(attemptsKey, 10 * 60);
      if (attempts > 5) {
        await upstashDel(emailKey);
        return reply(429, { error: "驗證失敗次數過多，請重新取得驗證碼" });
      }

      const ok = sha256(code + pepper) === String(storedHash);
      if (!ok) return reply(400, { error: "驗證碼錯誤" });

      // 驗證成功 → 刪掉驗證碼
      await upstashDel(emailKey);
      await upstashDel(attemptsKey);

      const user_id = makeUserId();
      const password_hash = makePasswordHash(password, pepper);

      const newRow = new Array(headers.length).fill("");
      if (headerIdx["name"] !== undefined) newRow[headerIdx["name"]] = name;
      newRow[headerIdx["username"]] = u;
      newRow[headerIdx["password_hash"]] = password_hash;
      newRow[headerIdx["email"]] = email;

      if (headerIdx["create_at"] !== undefined) newRow[headerIdx["create_at"]] = nowISO();
      if (headerIdx["last_login_at"] !== undefined) newRow[headerIdx["last_login_at"]] = "";
      newRow[headerIdx["user_id"]] = user_id;

      await sheets.spreadsheets.values.append({
        spreadsheetId: sheetId,
        range: `${tab}!A:Z`,
        valueInputOption: "RAW",
        insertDataOption: "INSERT_ROWS",
        requestBody: { values: [newRow] },
      });

      const token = jwt.sign({ user_id, username: u }, jwtSecret, { expiresIn: "30d" });
      return reply(200, { ok: true, user: { user_id, username: u, email }, token });
    }

    // ---------- login ----------
    if (foundRowIndex === -1) return reply(401, { error: "invalid username or password" });

    const row = rows[foundRowIndex];
    const storedHash = row[pCol] || "";
    const passOk = verifyPassword(password, pepper, storedHash);
    if (!passOk) return reply(401, { error: "invalid username or password" });

    if (headerIdx["last_login_at"] !== undefined) {
      const sheetRowNumber = foundRowIndex + 2;
      const colLetter = colToA1(headerIdx["last_login_at"]);
      const a1 = `${tab}!${colLetter}${sheetRowNumber}`;
      await sheets.spreadsheets.values.update({
        spreadsheetId: sheetId,
        range: a1,
        valueInputOption: "RAW",
        requestBody: { values: [[nowISO()]] },
      });
    }

    const uid = row[headerIdx["user_id"]] || "";
    const token = jwt.sign({ user_id: uid, username: u }, jwtSecret, { expiresIn: "30d" });
    return reply(200, { ok: true, user: { user_id: uid, username: u }, token });
  } catch (err) {
    return reply(500, { error: "server_error", detail: String(err && err.message ? err.message : err) });
  }
};
