// netlify/functions/user-profile.cjs
// ✅ 合併版：CORS 白名單 + JWT 驗證 + 不回傳內部錯誤細節

const { google } = require("googleapis");
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
  const allowOrigin =
    origin && isOriginAllowed(origin) ? origin : getAllowedOrigins()[0];
  return {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    Vary: "Origin",
  };
}

function reply(statusCode, data, origin) {
  return { statusCode, headers: corsHeaders(origin), body: JSON.stringify(data) };
}

function getBearerToken(event) {
  const h = event.headers || {};
  const auth = h.authorization || h.Authorization || "";
  const s = String(auth);
  if (!s.toLowerCase().startsWith("bearer ")) return "";
  return s.slice(7).trim();
}

function requireAuth(event) {
  const token = getBearerToken(event);
  if (!token) return null;
  const secret = process.env.JWT_SECRET;
  if (!secret) return null;
  try {
    return jwt.verify(token, secret);
  } catch {
    return null;
  }
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

async function updateCell(sheets, spreadsheetId, sheetName, rowNumber1Based, colLetter, value) {
  const a1 = `${sheetName}!${colLetter}${rowNumber1Based}`;
  await sheets.spreadsheets.values.update({
    spreadsheetId,
    range: a1,
    valueInputOption: "RAW",
    requestBody: { values: [[value]] },
  });
}

// ---- v1 欄位解析 helpers ----
function safeStr(v) {
  return String(v == null ? "" : v).trim();
}

function toIntOrDefault(v, d = 0) {
  const n = parseInt(String(v ?? "").trim(), 10);
  return Number.isFinite(n) ? n : d;
}

function toBoolOrDefault(v, d = false) {
  const s = String(v ?? "").trim().toLowerCase();
  if (s === "true" || s === "1" || s === "yes" || s === "y") return true;
  if (s === "false" || s === "0" || s === "no" || s === "n") return false;
  return d;
}

function getCell(row, headerIdx, key) {
  const i = headerIdx[key];
  if (i === undefined) return "";
  return row[i];
}

exports.handler = async (event) => {
  const origin = getRequestOrigin(event.headers || {});

  try {
    if (event.httpMethod === "OPTIONS") return reply(200, { ok: true }, origin);
    if (event.httpMethod !== "POST") return reply(405, { error: "Method not allowed" }, origin);
    if (origin && !isOriginAllowed(origin)) return reply(403, { ok: false, error: "origin_not_allowed" }, origin);

    const authPayload = requireAuth(event);
    if (!authPayload?.user_id) return reply(401, { ok: false, error: "unauthorized" }, origin);

    const body = JSON.parse(event.body || "{}");
    const action = String(body.action || "").trim();

    const sheets = await getSheetsClient();
    const spreadsheetId = getSpreadsheetId();
    const usersSheet = getUsersSheetName();

    const { headers, rows } = await readAllRows(sheets, spreadsheetId, usersSheet);

    // ✅ 必備欄位（含 v1 任務/等級/風控欄位）
    ensureHeader(headers, [
      "user_id",
      "name",
      "email",

      "level",
      "xp_total",
      "social_status",
      "influence_tier",
      "primary_platform",
      "can_take_tasks",
      "can_withdraw",
    ]);

    const headerIdx = buildHeaderIndex(headers);

    const uid = String(authPayload.user_id);
    const uidIdx = headerIdx["user_id"];

    let foundRowIndex = -1;
    for (let i = 0; i < rows.length; i++) {
      const cell = String(rows[i][uidIdx] || "").trim();
      if (cell === uid) {
        foundRowIndex = i;
        break;
      }
    }
    if (foundRowIndex === -1) return reply(404, { ok: false, error: "user_not_found" }, origin);

    const rowNumber1Based = foundRowIndex + 2;

    if (action === "get") {
      const row = rows[foundRowIndex];

      const name = safeStr(row[headerIdx["name"]] || "");
      const email = safeStr(row[headerIdx["email"]] || "");

      const level = toIntOrDefault(getCell(row, headerIdx, "level"), 0);
      const xp_total = toIntOrDefault(getCell(row, headerIdx, "xp_total"), 0);
      const social_status = safeStr(getCell(row, headerIdx, "social_status")) || "unsubmitted";
      const influence_tier = safeStr(getCell(row, headerIdx, "influence_tier")) || "C";
      const primary_platform = safeStr(getCell(row, headerIdx, "primary_platform")) || "";
      const can_take_tasks = toBoolOrDefault(getCell(row, headerIdx, "can_take_tasks"), false);
      const can_withdraw = toBoolOrDefault(getCell(row, headerIdx, "can_withdraw"), false);

      return reply(
        200,
        {
          ok: true,
          profile: {
            name,
            email,
            user_id: uid,

            level,
            xp_total,
            social_status,
            influence_tier,
            primary_platform,
            can_take_tasks,
            can_withdraw,
          },
        },
        origin
      );
    }

    if (action === "update") {
      const name = String(body.name || "").trim();
      const email = String(body.email || "").trim();
      if (!name) return reply(400, { ok: false, error: "name_required" }, origin);
      if (!email) return reply(400, { ok: false, error: "email_required" }, origin);

      const colName = colToLetter(headerIdx["name"] + 1);
      const colEmail = colToLetter(headerIdx["email"] + 1);

      await updateCell(sheets, spreadsheetId, usersSheet, rowNumber1Based, colName, name);
      await updateCell(sheets, spreadsheetId, usersSheet, rowNumber1Based, colEmail, email);

      return reply(200, { ok: true }, origin);
    }

    return reply(400, { ok: false, error: "unknown_action" }, origin);
  } catch (err) {
    console.error("user-profile.cjs error:", err);
    return reply(500, { ok: false, error: "server_error" }, origin);
  }
};
