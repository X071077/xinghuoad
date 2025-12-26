// netlify/functions/social-verify.cjs
// ✅ 社群驗證提交：JWT 驗證 + CORS 白名單 + Sheet 公式注入防護 + A:ZZ
// action:
// - submit: 使用者提交社群驗證資料（寫回 users，並 social_status=submitted）
// - get:    讀取自己的社群驗證資料（從 users 取回）
// - approve:(admin only) 審核通過：social_status=approved + verified_at/by + Lv0->Lv1 + 開權限 + 設定 tier/platform
// - reject: (admin only) 審核拒絕：social_status=rejected + verified_at/by + 關權限

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

function toIntOrNull(v) {
  const s = safeStr(v);
  if (!s) return null;
  if (!/^\d+$/.test(s)) return NaN;
  const n = parseInt(s, 10);
  return Number.isFinite(n) ? n : NaN;
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

function isAdmin(authPayload) {
  const role = String(authPayload?.role || "").trim().toLowerCase();
  return role === "admin";
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
    range: `${sheetName}!A:ZZ`,
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

async function updateRowRange(sheets, spreadsheetId, sheetName, rowNumber1Based, headersLen, valuesRow) {
  const lastCol = colToLetter(headersLen);
  const range = `${sheetName}!A${rowNumber1Based}:${lastCol}${rowNumber1Based}`;
  await sheets.spreadsheets.values.update({
    spreadsheetId,
    range,
    valueInputOption: "RAW",
    requestBody: { values: [valuesRow] },
  });
}

function getCell(row, headerIdx, key) {
  const i = headerIdx[key];
  if (i === undefined) return "";
  return row[i];
}

function normalizePrimaryPlatform(v) {
  const s = safeStr(v).toLowerCase();
  if (!s) return "";
  if (s === "ig" || s === "instagram") return "ig";
  if (s === "fb" || s === "facebook") return "fb";
  // 允許你之後擴充平台，不在這裡擋死：先原樣回
  return s;
}

function normalizeTier(v) {
  const s = safeStr(v).toUpperCase();
  if (!s) return "";
  if (!["C", "B", "A", "S"].includes(s)) return "";
  return s;
}

function findRowIndexByUserId(rows, uidIdx, userId) {
  const target = String(userId || "").trim();
  if (!target) return -1;
  for (let i = 0; i < rows.length; i++) {
    const cell = String(rows[i][uidIdx] || "").trim();
    if (cell === target) return i;
  }
  return -1;
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
    const action = safeStr(body.action || "submit").toLowerCase();

    // submit/get：使用者自己的資料
    // approve/reject：admin 對 target_user_id 操作
    const target_user_id =
      safeStr(body.target_user_id) ||
      safeStr(body.targetUserId) ||
      safeStr(body.user_id) ||
      "";

    const data = (body && typeof body === "object" ? body.data : {}) || {};

    const sheets = await getSheetsClient();
    const spreadsheetId = getSpreadsheetId();
    const usersSheet = getUsersSheetName();

    const { headers, rows } = await readAllRows(sheets, spreadsheetId, usersSheet);

    // ✅ 社群驗證欄位 + Step4 審核需要欄位（全部都在 users）
    ensureHeader(headers, [
      "user_id",

      // social verify payload
      "social_status",
      "ig_url",
      "fb_url",
      "followers_count",
      "avg_views_7d",
      "social_screenshot_url",
      "user_type",
      "region",
      "brand_desc",
      "audience_desc",
      "social_submitted_at",
      "verified_at",
      "verified_by",

      // Step4 審核後要寫入/影響權限
      "level",
      "influence_tier",
      "primary_platform",
      "can_take_tasks",
      "can_withdraw",
    ]);

    const headerIdx = buildHeaderIndex(headers);

    const uidIdx = headerIdx["user_id"];

    // ===== action: approve/reject (admin only) =====
    if (action === "approve" || action === "reject") {
      if (!isAdmin(authPayload)) return reply(403, { ok: false, error: "forbidden" }, origin);

      const tUid = safeStr(target_user_id);
      if (!tUid) return reply(400, { ok: false, error: "target_user_id_required" }, origin);

      const foundRowIndex = findRowIndexByUserId(rows, uidIdx, tUid);
      if (foundRowIndex === -1) return reply(404, { ok: false, error: "user_not_found" }, origin);

      const rowNumber1Based = foundRowIndex + 2;
      const row = rows[foundRowIndex] || [];
      const headersLen = headers.length;

      const fullRow = Array.from({ length: headersLen }, (_, i) => safeStr(row[i] || ""));

      const currentStatus = safeStr(getCell(fullRow, headerIdx, "social_status")) || "unsubmitted";
      if (currentStatus !== "submitted") {
        // 避免未提交就被審核通過/拒絕
        return reply(409, { ok: false, error: "not_submitted" }, origin);
      }

      const adminTag = safeStr(authPayload.username) || safeStr(authPayload.user_id) || "admin";

      // 審核共通欄位
      fullRow[headerIdx["verified_at"]] = nowISO();
      fullRow[headerIdx["verified_by"]] = sanitizeForSheet(adminTag);

      if (action === "reject") {
        fullRow[headerIdx["social_status"]] = "rejected";
        fullRow[headerIdx["level"]] = "0";
        fullRow[headerIdx["can_take_tasks"]] = "false";
        fullRow[headerIdx["can_withdraw"]] = "false";

        await updateRowRange(sheets, spreadsheetId, usersSheet, rowNumber1Based, headersLen, fullRow);
        return reply(
          200,
          { ok: true, social_status: "rejected", target_user_id: tUid, verified_at: fullRow[headerIdx["verified_at"]] },
          origin
        );
      }

      // approve：必須給 primary_platform / influence_tier（可以覆寫）
      const nextPlatform = normalizePrimaryPlatform(data.primary_platform);
      const nextTier = normalizeTier(data.influence_tier);

      const currentPlatform = safeStr(getCell(fullRow, headerIdx, "primary_platform"));
      const currentTier = safeStr(getCell(fullRow, headerIdx, "influence_tier")).toUpperCase();

      const finalPlatform = nextPlatform || currentPlatform;
      const finalTier = nextTier || (["C", "B", "A", "S"].includes(currentTier) ? currentTier : "");

      if (!finalPlatform) return reply(400, { ok: false, error: "primary_platform_required" }, origin);
      if (!finalTier) return reply(400, { ok: false, error: "influence_tier_required" }, origin);

      fullRow[headerIdx["social_status"]] = "approved";
      fullRow[headerIdx["primary_platform"]] = sanitizeForSheet(finalPlatform);
      fullRow[headerIdx["influence_tier"]] = sanitizeForSheet(finalTier);

      // Lv0 -> Lv1 + 開權限
      fullRow[headerIdx["level"]] = "1";
      fullRow[headerIdx["can_take_tasks"]] = "true";
      fullRow[headerIdx["can_withdraw"]] = "true";

      await updateRowRange(sheets, spreadsheetId, usersSheet, rowNumber1Based, headersLen, fullRow);

      return reply(
        200,
        {
          ok: true,
          social_status: "approved",
          target_user_id: tUid,
          verified_at: fullRow[headerIdx["verified_at"]],
          primary_platform: finalPlatform,
          influence_tier: finalTier,
          level: 1,
          can_take_tasks: true,
          can_withdraw: true,
        },
        origin
      );
    }

    // ===== submit/get：使用者自己的 row =====
    const uid = String(authPayload.user_id);
    const foundRowIndex = findRowIndexByUserId(rows, uidIdx, uid);
    if (foundRowIndex === -1) return reply(404, { ok: false, error: "user_not_found" }, origin);

    const rowNumber1Based = foundRowIndex + 2;
    const row = rows[foundRowIndex] || [];
    const headersLen = headers.length;

    // 補齊 row 長度，避免 update 時欄位位移
    const fullRow = Array.from({ length: headersLen }, (_, i) => safeStr(row[i] || ""));

    if (action === "get") {
      return reply(
        200,
        {
          ok: true,
          social: {
            social_status: safeStr(getCell(fullRow, headerIdx, "social_status")) || "unsubmitted",
            ig_url: safeStr(getCell(fullRow, headerIdx, "ig_url")),
            fb_url: safeStr(getCell(fullRow, headerIdx, "fb_url")),
            followers_count: safeStr(getCell(fullRow, headerIdx, "followers_count")),
            avg_views_7d: safeStr(getCell(fullRow, headerIdx, "avg_views_7d")),
            social_screenshot_url: safeStr(getCell(fullRow, headerIdx, "social_screenshot_url")),
            user_type: safeStr(getCell(fullRow, headerIdx, "user_type")),
            region: safeStr(getCell(fullRow, headerIdx, "region")),
            brand_desc: safeStr(getCell(fullRow, headerIdx, "brand_desc")),
            audience_desc: safeStr(getCell(fullRow, headerIdx, "audience_desc")),
            social_submitted_at: safeStr(getCell(fullRow, headerIdx, "social_submitted_at")),
            verified_at: safeStr(getCell(fullRow, headerIdx, "verified_at")),
            verified_by: safeStr(getCell(fullRow, headerIdx, "verified_by")),
          },
        },
        origin
      );
    }

    if (action !== "submit") {
      return reply(400, { ok: false, error: "unknown_action" }, origin);
    }

    // ===== submit validation (v1) =====
    const ig_url = sanitizeForSheet(data.ig_url);
    const fb_url = sanitizeForSheet(data.fb_url);
    const screenshot = sanitizeForSheet(data.social_screenshot_url);

    const followers = toIntOrNull(data.followers_count);
    const views7d = toIntOrNull(data.avg_views_7d);

    const user_type = safeStr(data.user_type).toLowerCase(); // normal | creator
    const region = sanitizeForSheet(data.region);
    const brand_desc = sanitizeForSheet(data.brand_desc);
    const audience_desc = sanitizeForSheet(data.audience_desc);

    if (!ig_url && !fb_url) return reply(400, { ok: false, error: "platform_url_required" }, origin);
    if (!screenshot) return reply(400, { ok: false, error: "screenshot_required" }, origin);

    if (followers == null || Number.isNaN(followers) || followers < 0) {
      return reply(400, { ok: false, error: "followers_count_invalid" }, origin);
    }
    if (views7d == null || Number.isNaN(views7d) || views7d < 0) {
      return reply(400, { ok: false, error: "avg_views_7d_invalid" }, origin);
    }

    if (user_type !== "normal" && user_type !== "creator") {
      return reply(400, { ok: false, error: "user_type_invalid" }, origin);
    }

    if (user_type === "normal") {
      if (!region) return reply(400, { ok: false, error: "region_required" }, origin);
    } else {
      if (!brand_desc) return reply(400, { ok: false, error: "brand_desc_required" }, origin);
      if (!audience_desc) return reply(400, { ok: false, error: "audience_desc_required" }, origin);
    }

    // ===== write back to users =====
    fullRow[headerIdx["ig_url"]] = ig_url;
    fullRow[headerIdx["fb_url"]] = fb_url;
    fullRow[headerIdx["followers_count"]] = String(followers);
    fullRow[headerIdx["avg_views_7d"]] = String(views7d);
    fullRow[headerIdx["social_screenshot_url"]] = screenshot;
    fullRow[headerIdx["user_type"]] = user_type;
    fullRow[headerIdx["region"]] = region;
    fullRow[headerIdx["brand_desc"]] = brand_desc;
    fullRow[headerIdx["audience_desc"]] = audience_desc;

    fullRow[headerIdx["social_status"]] = "submitted";
    fullRow[headerIdx["social_submitted_at"]] = nowISO();

    // 注意：verified_at / verified_by 由管理員審核時寫入，submit 不動它

    await updateRowRange(sheets, spreadsheetId, usersSheet, rowNumber1Based, headersLen, fullRow);

    return reply(
      200,
      {
        ok: true,
        social_status: "submitted",
        social_submitted_at: fullRow[headerIdx["social_submitted_at"]],
      },
      origin
    );
  } catch (err) {
    console.error("social-verify.cjs error:", err);
    return reply(500, { ok: false, error: "server_error" }, origin);
  }
};
