// netlify/functions/economy-ledger.cjs
// ✅ 金幣總帳（economy_ledger）寫入 API（含防重複發幣：同一 ref_type + ref_id 只能 approved 一次）

const { google } = require("googleapis");
const jwt = require("jsonwebtoken");
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

function getRequestOrigin(headers) {
  const h = headers || {};
  return h.origin || h.Origin || "";
}

function isOriginAllowed(origin) {
  if (!origin) return true; // allow server-to-server
  return getAllowedOrigins().includes(origin);
}

function corsHeaders(origin) {
  const allowOrigin = origin && isOriginAllowed(origin) ? origin : getAllowedOrigins()[0];
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Credentials": "true",
    "Content-Type": "application/json; charset=utf-8",
  };
}

function reply(statusCode, body, origin) {
  return {
    statusCode,
    headers: corsHeaders(origin),
    body: JSON.stringify(body),
  };
}

function nowISO() {
  return new Date().toISOString();
}

function getBearerToken(event) {
  const h = event.headers || {};
  const auth = h.authorization || h.Authorization || "";
  const m = String(auth).match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : "";
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

function normalizeHeader(s) {
  return String(s || "").trim().toLowerCase();
}

function toNumber(v) {
  const n = Number(String(v || "").replace(/,/g, "").trim());
  return Number.isFinite(n) ? n : 0;
}

async function getSheets() {
  const saJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
  const sheetId = process.env.GOOGLE_SHEET_ID || process.env.SPREADSHEET_ID;
  const tab = process.env.LEDGER_TAB || "economy_ledger";

  if (!saJson) throw new Error("Missing GOOGLE_SERVICE_ACCOUNT_JSON");
  if (!sheetId) throw new Error("Missing GOOGLE_SHEET_ID (or SPREADSHEET_ID)");

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

function idx(headers, name) {
  return headers.indexOf(String(name).toLowerCase());
}

function cell(row, i) {
  return i >= 0 ? (row[i] ?? "") : "";
}

function genLedgerId() {
  return "l_" + crypto.randomBytes(10).toString("hex");
}

/**
 * 防重複：同一 (ref_type, ref_id, user_id) 只能有一筆 approved
 * （你也可以把 user_id 從條件拿掉，改成整張表唯一；目前選擇較保守，避免不同 user 共享同 ref）
 */
function findApprovedByRef(rows, headers, { user_id, ref_type, ref_id }) {
  const iUser = idx(headers, "user_id");
  const iRefType = idx(headers, "ref_type");
  const iRefId = idx(headers, "ref_id");
  const iStatus = idx(headers, "status");
  const iLedger = idx(headers, "ledger_id");
  const iDelta = idx(headers, "delta");

  for (const r of rows) {
    const ru = String(cell(r, iUser)).trim();
    const rt = String(cell(r, iRefType)).trim();
    const rid = String(cell(r, iRefId)).trim();
    const st = String(cell(r, iStatus)).trim().toLowerCase();
    if (ru === user_id && rt === ref_type && rid === ref_id && st === "approved") {
      return {
        ledger_id: String(cell(r, iLedger)).trim(),
        delta: toNumber(cell(r, iDelta)),
        status: "approved",
      };
    }
  }
  return null;
}

exports.handler = async (event) => {
  const origin = getRequestOrigin(event.headers || {});
  try {
    if (event.httpMethod === "OPTIONS") return reply(200, { ok: true }, origin);
    if (event.httpMethod !== "POST") return reply(405, { ok: false, error: "Method not allowed" }, origin);
    if (origin && !isOriginAllowed(origin)) return reply(403, { ok: false, error: "origin_not_allowed" }, origin);

    const authPayload = requireAuth(event);
    if (!authPayload?.user_id) return reply(401, { ok: false, error: "unauthorized" }, origin);

    const body = JSON.parse(event.body || "{}");
    const action = String(body.action || "").trim();

    const { sheets, sheetId, tab } = await getSheets();
    const { headers, rows } = await loadAllRows(sheets, sheetId, tab);

    if (!headers.length) return reply(500, { ok: false, error: "ledger_sheet_empty" }, origin);

    // required headers
    const required = [
      "ledger_id","user_id","delta","reason","ref_type","ref_id","status",
      "created_at","created_by","approved_at","approved_by","notes",
    ];
    for (const h of required) {
      if (idx(headers, h) === -1) {
        return reply(500, { ok: false, error: "ledger_header_missing", missing: h }, origin);
      }
    }

    if (action === "award_once") {
      // admin only
      if (String(authPayload.role || "").toLowerCase() !== "admin") {
        return reply(403, { ok: false, error: "forbidden" }, origin);
      }

      const user_id = String(body.user_id || "").trim();
      const delta = toNumber(body.delta);
      const reason = String(body.reason || "").trim() || "manual_award";
      const ref_type = String(body.ref_type || "").trim();
      const ref_id = String(body.ref_id || "").trim();
      const notes = String(body.notes || "").trim();

      if (!user_id || !ref_type || !ref_id) {
        return reply(400, { ok: false, error: "missing_fields", need: ["user_id","ref_type","ref_id"] }, origin);
      }
      if (!Number.isFinite(delta) || delta === 0) {
        return reply(400, { ok: false, error: "invalid_delta" }, origin);
      }

      // 防重複發幣：同 ref 只允許一筆 approved
      const existed = findApprovedByRef(rows, headers, { user_id, ref_type, ref_id });
      if (existed) {
        return reply(200, {
          ok: true,
          deduped: true,
          ledger_id: existed.ledger_id,
          user_id,
          delta: existed.delta,
          status: "approved",
          ref_type,
          ref_id,
        }, origin);
      }

      const ledger_id = genLedgerId();
      const now = nowISO();

      const i = (name) => idx(headers, name);

      const newRow = Array(headers.length).fill("");
      newRow[i("ledger_id")] = ledger_id;
      newRow[i("user_id")] = user_id;
      newRow[i("delta")] = String(delta);
      newRow[i("reason")] = reason;
      newRow[i("ref_type")] = ref_type;
      newRow[i("ref_id")] = ref_id;
      newRow[i("status")] = "approved";
      newRow[i("created_at")] = now;
      newRow[i("created_by")] = authPayload.user_id;
      newRow[i("approved_at")] = now;
      newRow[i("approved_by")] = authPayload.user_id;
      newRow[i("notes")] = notes;

      await sheets.spreadsheets.values.append({
        spreadsheetId: sheetId,
        range: `${tab}!A:Z`,
        valueInputOption: "RAW",
        insertDataOption: "INSERT_ROWS",
        requestBody: { values: [newRow] },
      });

      return reply(200, {
        ok: true,
        deduped: false,
        ledger_id,
        user_id,
        delta,
        status: "approved",
        ref_type,
        ref_id,
      }, origin);
    }

    if (action === "check_dedup") {
      // 允許任何登入使用者查詢某 ref 是否已發幣（不回傳內部欄位）
      const user_id = String(body.user_id || authPayload.user_id || "").trim();
      const ref_type = String(body.ref_type || "").trim();
      const ref_id = String(body.ref_id || "").trim();
      if (!user_id || !ref_type || !ref_id) {
        return reply(400, { ok: false, error: "missing_fields", need: ["user_id","ref_type","ref_id"] }, origin);
      }
      const existed = findApprovedByRef(rows, headers, { user_id, ref_type, ref_id });
      return reply(200, { ok: true, exists: !!existed, ledger_id: existed?.ledger_id || "" }, origin);
    }

    return reply(400, { ok: false, error: "unknown_action" }, origin);
  } catch (e) {
    return reply(500, { ok: false, error: "internal_error" }, origin);
  }
};
