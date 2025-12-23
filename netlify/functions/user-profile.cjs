// netlify/functions/user-profile.cjs
const { google } = require("googleapis");
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

function safeParse(json, fallback) {
  try { return JSON.parse(json); } catch { return fallback; }
}

function normalizeHeader(h) {
  return String(h || "").trim();
}

function buildHeaderIndex(headers) {
  const idx = {};
  headers.forEach((h, i) => { if (h) idx[h] = i; });
  return idx;
}

function getBearerToken(event) {
  const auth = event.headers?.authorization || event.headers?.Authorization || "";
  const m = String(auth).match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : "";
}

function requireAuth(event) {
  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) throw new Error("Missing JWT_SECRET");
  const token = getBearerToken(event);
  if (!token) return null;
  try {
    return jwt.verify(token, jwtSecret); // { user_id, username, iat, exp }
  } catch {
    return null;
  }
}

async function getSheetsUsers() {
  const sheetId = process.env.GOOGLE_SHEET_ID;
  const tab = process.env.GOOGLE_SHEET_TAB; // users 分頁
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

exports.handler = async (event) => {
  try {
    if (event.httpMethod === "OPTIONS") return reply(200, { ok: true });
    if (event.httpMethod !== "POST") return reply(405, { error: "Method not allowed" });

    const authPayload = requireAuth(event);
    if (!authPayload?.user_id) return reply(401, { error: "unauthorized" });

    const { sheets, sheetId, tab } = await getSheetsUsers();
    const { headers, rows } = await loadAllRows(sheets, sheetId, tab);
    const headerIdx = buildHeaderIndex(headers);

    // user_id 必須要有，name/email 若缺就回空字串
    if (headerIdx["user_id"] === undefined) {
      return reply(500, { error: "users sheet missing header: user_id" });
    }

    const uid = String(authPayload.user_id);
    const uidCol = headerIdx["user_id"];

    let foundRowIndex = -1;
    for (let i = 0; i < rows.length; i++) {
      const cell = String(rows[i][uidCol] || "").trim();
      if (cell === uid) { foundRowIndex = i; break; }
    }

    if (foundRowIndex === -1) {
      return reply(404, { error: "user_not_found" });
    }

    const row = rows[foundRowIndex];
    const username = headerIdx["username"] !== undefined ? String(row[headerIdx["username"]] || "").trim() : (authPayload.username || "");
    const name = headerIdx["name"] !== undefined ? String(row[headerIdx["name"]] || "").trim() : "";
    const email = headerIdx["email"] !== undefined ? String(row[headerIdx["email"]] || "").trim() : "";

    return reply(200, {
      ok: true,
      user: { user_id: uid, username, name, email },
    });
  } catch (err) {
    return reply(500, { error: "server_error", detail: String(err?.message || err) });
  }
};
