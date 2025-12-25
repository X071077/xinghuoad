// netlify/functions/auth.cjs
const { google } = require("googleapis");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

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
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
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
  if (!res.ok) throw new Error(`Upstash error (${res.status}): ${JSON.stringify(data)}`);
  return data;
}

async function upstashGet(key) {
  const data = await upstashPost(`get/${encodeURIComponent(key)}`);
  return data?.result ?? null;
}

async function upstashDel(key) {
  const data = await upstashPost(`del/${encodeURIComponent(key)}`);
  return data?.result ?? null;
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


function norm(s) {
  return String(s || "").trim().toLowerCase();
}

async function getUserRoleById(sheets, sheetId, user_id) {
  const rolesTab = process.env.USER_ROLES_SHEET_NAME; // e.g. "user_roles"
  if (!rolesTab) return "";

  const res = await sheets.spreadsheets.values.get({
    spreadsheetId: sheetId,
    range: `${rolesTab}!A:Z`,
  });

  const values = res.data.values || [];
  if (values.length < 2) return "";

  const headers = (values[0] || []).map(norm);
  const rows = values.slice(1);

  const idIdx = headers.indexOf("user_id");
  const roleIdx = headers.indexOf("role");
  if (idIdx === -1 || roleIdx === -1) {
    throw new Error("USER_ROLES sheet missing headers: user_id / role");
  }

  const target = String(user_id || "").trim();
  for (const r of rows) {
    const rid = String(r[idIdx] || "").trim();
    if (rid === target) return norm(r[roleIdx]);
  }
  return "";
}

// -------------------- Main handler --------------------
exports.handler = async (event) => {
  try {
    if (event.httpMethod === "OPTIONS") return reply(200, { ok: true });
    if (event.httpMethod !== "POST") return reply(405, { error: "Method not allowed" });

    const body = JSON.parse(event.body || "{}");
    const action = body?.action;

    if (!action || !["register", "login"].includes(action)) {
      return reply(400, { error: "Invalid action. Use register or login." });
    }

    const pepper = process.env.AUTH_PEPPER || "";
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) return reply(500, { error: "Missing JWT_SECRET" });

    // ---------- register / login 共同檢查 ----------
    const username = String(body?.username || "").trim();
    const password = String(body?.password || "");

    if (!username || username.length < 3) return reply(400, { error: "username too short (>=3)" });
    if (!password || password.length < 6) return reply(400, { error: "password too short (>=6)" });

    const { sheets, sheetId, tab } = await getSheets();
    const { headers, rows } = await loadAllRows(sheets, sheetId, tab);
    const headerIdx = buildHeaderIndex(headers);

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

      if (!isValidEmail(email)) return reply(400, { error: "invalid email" });

      if (headerIdx["email"] === undefined) {
        return reply(500, { error: "Sheet missing header: email（請在 users Sheet 加一欄表頭 email）" });
      }

      if (foundRowIndex !== -1) return reply(409, { error: "username already exists" });

      // ✅ 改成：檢查 otp-verify 成功後寫入的旗標
      const verifiedKey = `otp_verified:${email}`;
      const verified = await upstashGet(verifiedKey);
      if (!verified) return reply(400, { error: "請先完成 Email 驗證" });

      // 用過就刪，避免重複利用
      await upstashDel(verifiedKey);

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

      const role = "partner";
      const token = jwt.sign({ user_id, username: u, role }, jwtSecret, { expiresIn: "30d" });
      return reply(200, { ok: true, user: { user_id, username: u, email, role }, token });
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
    const role = (await getUserRoleById(sheets, sheetId, uid)) || "partner";
    const token = jwt.sign({ user_id: uid, username: u, role }, jwtSecret, { expiresIn: "30d" });
    return reply(200, { ok: true, user: { user_id: uid, username: u, role }, token });
  } catch (err) {
    return reply(500, { error: "server_error", detail: String(err?.message || err) });
  }
};
