// netlify/functions/_lib.js
const jwt = require("jsonwebtoken");
const { google } = require("googleapis");

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};

function resJson(statusCode, obj) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json; charset=utf-8", ...corsHeaders },
    body: JSON.stringify(obj),
  };
}

function getBearerToken(headers) {
  const h = headers?.authorization || headers?.Authorization || "";
  const m = String(h).match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

function requireUser(event) {
  const secret = process.env.JWT_SECRET;
  if (!secret) return { ok: false, status: 500, error: "Missing JWT_SECRET" };

  const token = getBearerToken(event.headers);
  if (!token) return { ok: false, status: 401, error: "Missing Authorization token" };

  try {
    const payload = jwt.verify(token, secret);
    const user_id = payload.user_id || payload.id || payload.uid;
    if (!user_id) return { ok: false, status: 401, error: "Token missing user_id" };
    return { ok: true, payload, user_id };
  } catch {
    return { ok: false, status: 401, error: "Invalid token" };
  }
}

function env(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env: ${name}`);
  return v;
}

function getSheetsClient() {
  const clientEmail = env("GOOGLE_CLIENT_EMAIL");
  const privateKey = env("GOOGLE_PRIVATE_KEY").replace(/\\n/g, "\n");
  const auth = new google.auth.JWT({
    email: clientEmail,
    key: privateKey,
    scopes: ["https://www.googleapis.com/auth/spreadsheets"],
  });
  return google.sheets({ version: "v4", auth });
}

async function getSheetValues(sheetName) {
  const sheets = getSheetsClient();
  const spreadsheetId = env("GOOGLE_SHEET_ID");
  const range = `${sheetName}!A:Z`;
  const { data } = await sheets.spreadsheets.values.get({ spreadsheetId, range });
  const values = data.values || [];
  const header = values[0] || [];
  const rows = values.slice(1);
  return { header, rows };
}

async function appendRow(sheetName, row) {
  const sheets = getSheetsClient();
  const spreadsheetId = env("GOOGLE_SHEET_ID");
  const range = `${sheetName}!A:Z`;
  await sheets.spreadsheets.values.append({
    spreadsheetId,
    range,
    valueInputOption: "RAW",
    insertDataOption: "INSERT_ROWS",
    requestBody: { values: [row] },
  });
}

async function updateRowById(sheetName, idColName, idValue, patchObj) {
  const sheets = getSheetsClient();
  const spreadsheetId = env("GOOGLE_SHEET_ID");

  const { header, rows } = await getSheetValues(sheetName);
  const idIdx = header.indexOf(idColName);
  if (idIdx === -1) throw new Error(`Missing column ${idColName} in ${sheetName}`);

  const rowIndex0 = rows.findIndex(r => String(r[idIdx] || "") === String(idValue));
  if (rowIndex0 === -1) throw new Error(`Row not found in ${sheetName}: ${idValue}`);

  const row = rows[rowIndex0].slice();
  // pad
  while (row.length < header.length) row.push("");

  for (const [k, v] of Object.entries(patchObj)) {
    const idx = header.indexOf(k);
    if (idx === -1) continue; // 忽略未知欄位
    row[idx] = v;
  }

  const a1Row = rowIndex0 + 2; // header=1
  const range = `${sheetName}!A${a1Row}:${String.fromCharCode(65 + header.length - 1)}${a1Row}`;

  await sheets.spreadsheets.values.update({
    spreadsheetId,
    range,
    valueInputOption: "RAW",
    requestBody: { values: [row] },
  });

  return { header, rowIndex0, row };
}

async function getRolesByUserId(user_id) {
  const { header, rows } = await getSheetValues("user_roles");
  const uidIdx = header.indexOf("user_id");
  const roleIdx = header.indexOf("role");
  if (uidIdx === -1 || roleIdx === -1) return [];
  return rows
    .filter(r => String(r[uidIdx] || "") === String(user_id))
    .map(r => String(r[roleIdx] || "").trim())
    .filter(Boolean);
}

async function requireRole(user_id, role) {
  const roles = await getRolesByUserId(user_id);
  return roles.includes(role);
}

function nowIso() {
  return new Date().toISOString();
}

function addDaysIso(days) {
  const d = new Date();
  d.setDate(d.getDate() + Number(days || 0));
  return d.toISOString();
}

function genId(prefix) {
  return `${prefix}_${Date.now()}_${Math.random().toString(16).slice(2)}`;
}

module.exports = {
  corsHeaders,
  resJson,
  requireUser,
  getSheetValues,
  appendRow,
  updateRowById,
  getRolesByUserId,
  requireRole,
  nowIso,
  addDaysIso,
  genId,
};
