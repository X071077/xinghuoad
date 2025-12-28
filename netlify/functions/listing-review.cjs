// netlify/functions/listing-review.cjs
// ✅ Admin 審核 dealer_listings → 產生 quests
// - list_pending: 列出待審（status=submitted）
// - approve: 審核通過 → 建立 quest（quests）+ 回寫 dealer_listings 狀態與 quest_id
// - reject: 退件/需補件 → 回寫 dealer_listings 狀態與 review_note
//
// 注意：此 function 僅允許 role=admin 使用（JWT 內含 role）

const { google } = require("googleapis");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const DEFAULT_ALLOWED_ORIGINS = [
  "https://xinghuoad.xyz",
  "https://www.xinghuoad.xyz",
];

function json(statusCode, obj, extraHeaders = {}) {
  return {
    statusCode,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...extraHeaders,
    },
    body: JSON.stringify(obj),
  };
}

function getAllowedOrigins() {
  const env = String(process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return env.length ? env : DEFAULT_ALLOWED_ORIGINS;
}

function corsHeaders(event) {
  const origin = event.headers?.origin || event.headers?.Origin || "";
  const allow = getAllowedOrigins();
  const ok = allow.includes(origin);
  return {
    "access-control-allow-origin": ok ? origin : allow[0],
    "access-control-allow-headers": "content-type, authorization",
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-credentials": "true",
  };
}

function safeStr(v) {
  return (v === null || v === undefined) ? "" : String(v);
}

function safeNum(v, d = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
}

function nowIso() {
  return new Date().toISOString();
}

function getBearerToken(event) {
  const h = event.headers?.authorization || event.headers?.Authorization || "";
  const m = String(h).match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : "";
}

function requireAuth(event) {
  const token = getBearerToken(event);
  if (!token) return null;
  const secret = process.env.JWT_SECRET || "";
  if (!secret) throw new Error("JWT_SECRET missing");
  try {
    return jwt.verify(token, secret);
  } catch (e) {
    return null;
  }
}

function isAdmin(payload) {
  const role = safeStr(payload?.role).toLowerCase();
  return role === "admin";
}

function rid(prefix) {
  const suffix = crypto.randomBytes(10).toString("hex");
  return `${prefix}_${suffix}`;
}

function parseServiceAccountJson() {
  const raw = process.env.GOOGLE_SERVICE_ACCOUNT_JSON || "";
  if (!raw) throw new Error("GOOGLE_SERVICE_ACCOUNT_JSON missing");
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error("Invalid GOOGLE_SERVICE_ACCOUNT_JSON");
  }
}

async function getSheetsClient() {
  const sa = parseServiceAccountJson();
  const auth = new google.auth.JWT({
    email: sa.client_email,
    key: sa.private_key,
    scopes: ["https://www.googleapis.com/auth/spreadsheets"],
  });
  const sheets = google.sheets({ version: "v4", auth });
  const spreadsheetId = process.env.GOOGLE_SHEET_ID || process.env.SPREADSHEET_ID;
  if (!spreadsheetId) throw new Error("Missing GOOGLE_SHEET_ID (or SPREADSHEET_ID)");
  return { sheets, spreadsheetId };
}

async function getAllValues(sheets, spreadsheetId, tab) {
  const res = await sheets.spreadsheets.values.get({
    spreadsheetId,
    range: `${tab}!A:ZZ`,
    valueRenderOption: "UNFORMATTED_VALUE",
  });
  return res.data.values || [];
}

function buildHeaderIndex(headerRow) {
  const idx = {};
  headerRow.forEach((h, i) => {
    const key = safeStr(h).trim();
    if (key) idx[key] = i;
  });
  return idx;
}

function getCell(row, idx, key) {
  const i = idx[key];
  if (i === undefined) return "";
  return row[i] === undefined ? "" : row[i];
}

function setCell(row, idx, key, val) {
  const i = idx[key];
  if (i === undefined) return;
  while (row.length <= i) row.push("");
  row[i] = val;
}

function ensureColumns(idx, required, sheetName) {
  const missing = required.filter((k) => idx[k] === undefined);
  if (missing.length) {
    throw new Error(`${sheetName} missing columns: ${missing.join(", ")}`);
  }
}

function clampInt(n, min, max) {
  const x = Math.trunc(n);
  return Math.max(min, Math.min(max, x));
}

async function updateRowByA1(sheets, spreadsheetId, tab, rowNumber, rowValues) {
  await sheets.spreadsheets.values.update({
    spreadsheetId,
    range: `${tab}!A${rowNumber}:ZZ${rowNumber}`,
    valueInputOption: "RAW",
    requestBody: { values: [rowValues] },
  });
}

async function appendRow(sheets, spreadsheetId, tab, rowValues) {
  const res = await sheets.spreadsheets.values.append({
    spreadsheetId,
    range: `${tab}!A:ZZ`,
    valueInputOption: "RAW",
    insertDataOption: "INSERT_ROWS",
    requestBody: { values: [rowValues] },
  });
  return res.data;
}

exports.handler = async (event) => {
  const headers = corsHeaders(event);
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers, body: "" };
  }
  if (event.httpMethod !== "POST") {
    return json(405, { ok: false, error: "Method not allowed" }, headers);
  }

  try {
    const payload = requireAuth(event);
    if (!payload) return json(401, { ok: false, error: "Unauthorized" }, headers);
    if (!isAdmin(payload)) return json(403, { ok: false, error: "Forbidden" }, headers);

    const body = JSON.parse(event.body || "{}");
    const action = safeStr(body.action).toLowerCase();

    const LISTINGS_TAB = process.env.LISTINGS_TAB || "dealer_listings";
    const QUESTS_TAB = process.env.QUESTS_TAB || "quests";

    const { sheets, spreadsheetId } = await getSheetsClient();

    const listings = await getAllValues(sheets, spreadsheetId, LISTINGS_TAB);
    if (listings.length < 1) return json(500, { ok: false, error: "dealer_listings empty" }, headers);

    const lh = listings[0];
    const lidx = buildHeaderIndex(lh);

    ensureColumns(
      lidx,
      ["listing_id","dealer_id","user_id","title","car_info_json","budget_total","reward_min","reward_max","status","submitted_at","reviewed_at","reviewed_by","review_note","quest_id","updated_at"],
      "dealer_listings"
    );

    const quests = await getAllValues(sheets, spreadsheetId, QUESTS_TAB);
    if (quests.length < 1) return json(500, { ok: false, error: "quests empty" }, headers);
    const qh = quests[0];
    const qidx = buildHeaderIndex(qh);

    ensureColumns(
      qidx,
      ["quest_id","title","description","status","start_at","end_at","reward_min","reward_max","quota_total","quota_per_user","require_level","require_social_status","require_role","region_filter","created_at","created_by","updated_at","updated_by"],
      "quests"
    );

    // --- actions ---
    if (action === "list_pending") {
      const items = [];
      for (let r = 1; r < listings.length; r++) {
        const row = listings[r];
        const st = safeStr(getCell(row, lidx, "status")).toLowerCase();
        if (st === "submitted") {
          items.push({
            listing_id: safeStr(getCell(row, lidx, "listing_id")).trim(),
            dealer_id: getCell(row, lidx, "dealer_id"),
            user_id: getCell(row, lidx, "user_id"),
            title: getCell(row, lidx, "title"),
            budget_total: getCell(row, lidx, "budget_total"),
            reward_min: getCell(row, lidx, "reward_min"),
            reward_max: getCell(row, lidx, "reward_max"),
            submitted_at: getCell(row, lidx, "submitted_at"),
          });
        }
      }
      return json(200, { ok: true, listings: items }, headers);
    }

    const listing_id = safeStr(body.listing_id).trim();
    if (!listing_id) return json(400, { ok: false, error: "listing_id required" }, headers);

    let rowNumber = -1;
    let row = null;
    for (let r = 1; r < listings.length; r++) {
      const id = safeStr(getCell(listings[r], lidx, "listing_id")).trim();
      if (id === listing_id) {
        rowNumber = r + 1; // 1-based with header
        row = listings[r];
        break;
      }
    }
    if (!row) return json(404, { ok: false, error: "listing not found" }, headers);

    const currentStatus = safeStr(getCell(row, lidx, "status")).toLowerCase();

    if (action === "reject") {
      const review_note = safeStr(body.review_note || "need fix");
      const status = safeStr(body.status || "need_fix"); // allow "rejected" if you want
      setCell(row, lidx, "status", status);
      setCell(row, lidx, "review_note", review_note);
      setCell(row, lidx, "reviewed_at", nowIso());
      setCell(row, lidx, "reviewed_by", safeStr(payload.user_id || "admin"));
      setCell(row, lidx, "updated_at", nowIso());

      await updateRowByA1(sheets, spreadsheetId, LISTINGS_TAB, rowNumber, row);
      return json(200, { ok: true, listing_id, status }, headers);
    }

    if (action !== "approve") {
      return json(400, { ok: false, error: "Unknown action" }, headers);
    }

    // approve
    if (currentStatus !== "submitted") {
      return json(409, { ok: false, error: `Cannot approve status=${currentStatus}` }, headers);
    }

    const title = safeStr(getCell(row, lidx, "title")).trim();
    const car_info_json = safeStr(getCell(row, lidx, "car_info_json"));
    const budget_total = safeNum(getCell(row, lidx, "budget_total"), 0);
    const reward_min = safeNum(getCell(row, lidx, "reward_min"), 0);
    const reward_max = safeNum(getCell(row, lidx, "reward_max"), 0);

    if (!title) return json(400, { ok: false, error: "title empty" }, headers);
    if (!(budget_total > 0)) return json(400, { ok: false, error: "budget_total must be > 0" }, headers);
    if (!(reward_min >= 0 && reward_max > 0 && reward_min <= reward_max)) {
      return json(400, { ok: false, error: "invalid reward range" }, headers);
    }
    if (budget_total < reward_max) {
      return json(400, { ok: false, error: "budget_total < reward_max (insufficient budget)" }, headers);
    }

    const quota_total = clampInt(Math.floor(budget_total / reward_max), 1, 1000000);

    const quest_id = rid("q");
    const admin_uid = safeStr(payload.user_id || "admin");
    const ts = nowIso();

    const description = `來源刊登：${listing_id}\n車源資料：${car_info_json}`;

    // build quest row based on header
    const qrow = new Array(qh.length).fill("");
    setCell(qrow, qidx, "quest_id", quest_id);
    setCell(qrow, qidx, "title", title);
    setCell(qrow, qidx, "description", description);
    setCell(qrow, qidx, "status", "active");
    setCell(qrow, qidx, "start_at", ts);
    setCell(qrow, qidx, "end_at", "");
    setCell(qrow, qidx, "reward_min", reward_min);
    setCell(qrow, qidx, "reward_max", reward_max);
    setCell(qrow, qidx, "quota_total", quota_total);
    setCell(qrow, qidx, "quota_per_user", 1);
    setCell(qrow, qidx, "require_level", 0);
    setCell(qrow, qidx, "require_social_status", "approved");
    setCell(qrow, qidx, "require_role", "");
    setCell(qrow, qidx, "region_filter", "");
    setCell(qrow, qidx, "created_at", ts);
    setCell(qrow, qidx, "created_by", admin_uid);
    setCell(qrow, qidx, "updated_at", ts);
    setCell(qrow, qidx, "updated_by", admin_uid);

    await appendRow(sheets, spreadsheetId, QUESTS_TAB, qrow);

    // update listing row
    setCell(row, lidx, "status", "approved");
    setCell(row, lidx, "review_note", safeStr(body.review_note || "approved"));
    setCell(row, lidx, "reviewed_at", ts);
    setCell(row, lidx, "reviewed_by", admin_uid);
    setCell(row, lidx, "quest_id", quest_id);
    setCell(row, lidx, "updated_at", ts);

    await updateRowByA1(sheets, spreadsheetId, LISTINGS_TAB, rowNumber, row);

    return json(200, { ok: true, listing_id, quest_id, quota_total }, headers);
  } catch (e) {
    // 不回傳內部細節
    return json(500, { ok: false, error: "Server error" }, corsHeaders(event));
  }
};
