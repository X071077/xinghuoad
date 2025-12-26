// netlify/functions/auth.cjs
// ✅ 合併版：CORS 白名單 + Sheet 公式注入防護 + 不回傳 err.detail + login/register
// ✅ 密碼 hash：兼容舊格式（scrypt$$salt$$key）與新格式（scrypt$salt$key）

const { google } = require("googleapis");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

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

function nowISO() {
  return new Date().toISOString();
}

function safeStr(v) {
  return String(v == null ? "" : v).trim();
}

// ✅ 防公式注入：若以 = + - @ 開頭，前面加 ' 讓 Google Sheet 當純文字
function sanitizeForSheet(v) {
  const s = safeStr(v);
  if (!s) return "";
  return /^[=+\-@]/.test(s) ? `'${s}` : s;
}

function makeUserId() {
  return `u_${crypto.randomBytes(10).toString("hex")}`;
}

function isEmail(s) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s || "").trim());
}

function normalizeEmail(s) {
  return String(s || "").trim().toLowerCase();
}

function normalizeUsername(s) {
  return String(s || "").trim();
}

function normalizeName(s) {
  return String(s || "").trim();
}

function normalizePassword(s) {
  return String(s || "");
}

function parseServiceAccountJson() {
  const raw = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
  if (!raw) throw new Error("Missing GOOGLE_SERVICE_ACCOUNT_JSON");
  return JSON.parse(raw);
}

function getSpreadsheetId() {
  const id = process.env.GOOGLE_SHEET_ID || process.env.SPREADSHEET_ID;
  if (!id) throw new Error("Missing GOOGLE_SHEET_ID (or SPREADSHEET_ID)");
  return id;
}

function getUsersSheetName() {
  return process.env.USERS_SHEET_NAME || "users";
}

function getJwtSecret() {
  const s = process.env.JWT_SECRET;
  if (!s) throw new Error("Missing JWT_SECRET");
  return s;
}

async function getSheetsClient() {
  const sa = parseServiceAccountJson();
  const auth = new google.auth.GoogleAuth({
    credentials: sa,
    scopes: ["https://www.googleapis.com/auth/spreadsheets"],
  });
  return google.sheets({ version: "v4", auth });
}

async function readAllRows(sheets, spreadsheetId, sheetName) {
  const res = await sheets.spreadsheets.values.get({
    spreadsheetId,
    range: `${sheetName}!A:Z`,
  });
  const values = res.data.values || [];
  if (!values.length) return { headers: [], rows: [] };
  const headers = values[0].map((h) => String(h || "").trim());
  const rows = values.slice(1);
  return { headers, rows };
}

function buildHeaderIndex(headers) {
  const idx = {};
  headers.forEach((h, i) => (idx[h] = i));
  return idx;
}

function ensureHeader(headers, want) {
  const missing = want.filter((h) => !headers.includes(h));
  if (missing.length) throw new Error(`Users sheet missing columns: ${missing.join(", ")}`);
}

// ✅ 新格式：scrypt$salt$key
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const key = crypto.scryptSync(password, salt, 64).toString("hex");
  return `scrypt$${salt}$${key}`; // 保留你原本格式（避免影響既有資料）
}

// ✅ 兼容：
// - scrypt$salt$key  → split("$") = ["scrypt","salt","key"]
// - scrypt$$salt$$key → split("$") = ["scrypt","","salt","","key"]
function verifyPassword(password, stored) {
  try {
    const parts = String(stored || "").split("$");
    if (parts[0] !== "scrypt") return false;

    let salt = "";
    let key = "";

    if (parts.length === 3) {
      salt = parts[1];
      key = parts[2];
    } else if (parts.length === 5 && parts[1] === "" && parts[3] === "") {
      salt = parts[2];
      key = parts[4];
    } else {
      return false;
    }

    const derived = crypto.scryptSync(password, salt, 64).toString("hex");
    return crypto.timingSafeEqual(Buffer.from(key, "hex"), Buffer.from(derived, "hex"));
  } catch {
    return false;
  }
}

function findRowByEmail(rows, headerIdx, email) {
  const emailIdx = headerIdx["email"];
  if (emailIdx === undefined) return null;
  const target = normalizeEmail(email);
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const e = normalizeEmail(row[emailIdx] || "");
    if (e && e === target) return { row, rowIndex: i };
  }
  return null;
}

function findRowByUsername(rows, headerIdx, username) {
  const uIdx = headerIdx["username"];
  if (uIdx === undefined) return null;
  const target = normalizeUsername(username);
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const u = normalizeUsername(row[uIdx] || "");
    if (u && u === target) return { row, rowIndex: i };
  }
  return null;
}

async function appendRow(sheets, spreadsheetId, sheetName, values) {
  await sheets.spreadsheets.values.append({
    spreadsheetId,
    range: `${sheetName}!A:Z`,
    valueInputOption: "RAW",
    insertDataOption: "INSERT_ROWS",
    requestBody: { values: [values] },
  });
}

async function updateCell(sheets, spreadsheetId, sheetName, rowNumber1Based, colLetter, value) {
  const a1 = `${sheetName}!${colLetter}${rowNumber1Based}`;
  await sheets.spreadsheets.values.update({
    spreadsheetId,
    range: a1,
    valueInputOption: "RAW",
    requestBody: { values: [[value]] },
  });
}

function colToLetter(n1Based) {
  let n = n1Based;
  let s = "";
  while (n > 0) {
    const mod = (n - 1) % 26;
    s = String.fromCharCode(65 + mod) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
}

exports.handler = async (event) => {
  const origin = getRequestOrigin(event.headers || {});

  try {
    if (event.httpMethod === "OPTIONS") return reply(200, { ok: true }, origin);
    if (event.httpMethod !== "POST") return reply(405, { error: "Method not allowed" }, origin);
    if (origin && !isOriginAllowed(origin)) return reply(403, { ok: false, error: "origin_not_allowed" }, origin);

    const body = JSON.parse(event.body || "{}");
    const action = String(body.action || "").trim();

    const spreadsheetId = getSpreadsheetId();
    const usersSheet = getUsersSheetName();
    const jwtSecret = getJwtSecret();
    const sheets = await getSheetsClient();

    const { headers, rows } = await readAllRows(sheets, spreadsheetId, usersSheet);
    ensureHeader(headers, ["username", "password_hash", "create_at", "last_login_at", "user_id", "email", "name"]);
    const headerIdx = buildHeaderIndex(headers);

    if (action === "register") {
      const username = sanitizeForSheet(normalizeUsername(body.username));
      const name = sanitizeForSheet(normalizeName(body.name));
      const email = sanitizeForSheet(normalizeEmail(body.email));
      const password = normalizePassword(body.password);

      if (!username) return reply(400, { ok: false, error: "username_required" }, origin);
      if (!name) return reply(400, { ok: false, error: "name_required" }, origin);

      const emailRaw = email.startsWith("'") ? email.slice(1) : email;
      if (!isEmail(emailRaw)) return reply(400, { ok: false, error: "email_invalid" }, origin);

      if (!password || password.length < 6) return reply(400, { ok: false, error: "password_too_short" }, origin);

      const usernameRaw = username.startsWith("'") ? username.slice(1) : username;

      const existsEmail = findRowByEmail(rows, headerIdx, emailRaw);
      if (existsEmail) return reply(409, { ok: false, error: "email_exists" }, origin);

      const existsUser = findRowByUsername(rows, headerIdx, usernameRaw);
      if (existsUser) return reply(409, { ok: false, error: "username_exists" }, origin);

      const uid = makeUserId();
      const pwHash = hashPassword(password);
      const createAt = nowISO();
      const lastLoginAt = "";

      const rowValues = [];
      rowValues[headerIdx["name"]] = name;
      rowValues[headerIdx["username"]] = username;
      rowValues[headerIdx["password_hash"]] = pwHash;
      rowValues[headerIdx["create_at"]] = createAt;
      rowValues[headerIdx["last_login_at"]] = lastLoginAt;
      rowValues[headerIdx["user_id"]] = uid;
      rowValues[headerIdx["email"]] = email;

      const maxLen = Math.max(...Object.values(headerIdx)) + 1;
      const finalRow = Array.from({ length: maxLen }, (_, i) => safeStr(rowValues[i] || ""));

      await appendRow(sheets, spreadsheetId, usersSheet, finalRow);
      return reply(200, { ok: true }, origin);
    }

    if (action === "login") {
      const usernameOrEmail = safeStr(body.username || body.email || body.usernameOrEmail);
      const password = normalizePassword(body.password);

      if (!usernameOrEmail) return reply(400, { ok: false, error: "username_or_email_required" }, origin);
      if (!password) return reply(400, { ok: false, error: "password_required" }, origin);

      let found = null;
      if (isEmail(usernameOrEmail)) found = findRowByEmail(rows, headerIdx, usernameOrEmail);
      if (!found) found = findRowByUsername(rows, headerIdx, usernameOrEmail);
      if (!found) return reply(401, { ok: false, error: "invalid_credentials" }, origin);

      const { row, rowIndex } = found;
      const storedHash = row[headerIdx["password_hash"]] || "";
      if (!verifyPassword(password, storedHash)) return reply(401, { ok: false, error: "invalid_credentials" }, origin);

      if (headerIdx["last_login_at"] !== undefined) {
        const rowNumber1Based = rowIndex + 2; // header=1, 第一筆資料=2
        const colLetter = colToLetter(headerIdx["last_login_at"] + 1);
        await updateCell(sheets, spreadsheetId, usersSheet, rowNumber1Based, colLetter, nowISO());
      }

      const u = safeStr(row[headerIdx["username"]] || "");
      const uid = safeStr(row[headerIdx["user_id"]] || "");
      const role =
        (headerIdx["role"] !== undefined
          ? String(row[headerIdx["role"]] || "").trim().toLowerCase()
          : "") || "partner";

      const token = jwt.sign({ user_id: uid, username: u, role }, jwtSecret, { expiresIn: "30d" });
      return reply(200, { ok: true, user: { user_id: uid, username: u, role }, token }, origin);
    }

    return reply(400, { ok: false, error: "unknown_action" }, origin);
  } catch (err) {
    console.error("auth.cjs error:", err);
    return reply(500, { ok: false, error: "server_error" }, origin);
  }
};
