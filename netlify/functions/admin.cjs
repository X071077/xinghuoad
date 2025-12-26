// netlify/functions/admin.cjs
// ✅ Admin API：JWT 驗證 + CORS 白名單 + Sheet 公式注入防護 + 讀取範圍 A:ZZ
// action:
// - snapshot:              後台總覽（目前回傳 users 總數 + social submitted 待審數）
// - social_list_submitted: 列出 users 中 social_status=submitted 的待審清單
// - social_get:            讀取指定 target_user_id 的社群驗證資料
// - social_approve:        (admin only) 僅能審核 submitted → approved + verified_at/by + level=1 + 開權限 + 設定 tier/platform
// - social_reject:         (admin only) 僅能審核 submitted → rejected + verified_at/by + level=0 + 關權限

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

function getCell(row, headerIdx, key) {
  const i = headerIdx[key];
  if (i === undefined) return "";
  return row[i];
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

function normalizePrimaryPlatform(v) {
  const s = safeStr(v).toLowerCase();
  if (!s) return "";
  if (s === "ig" || s === "instagram") return "ig";
  if (s === "fb" || s === "facebook") return "fb";
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

function inferSuggestPlatform(ig_url, fb_url) {
  const ig = safeStr(ig_url);
  const fb = safeStr(fb_url);
  if (ig) return "ig";
  if (fb) return "fb";
  return "";
}

exports.handler = async (event) => {
  const origin = getRequestOrigin(event.headers || {});

  try {
    if (event.httpMethod === "OPTIONS") return reply(200, { ok: true }, origin);
    if (event.httpMethod !== "POST") return reply(405, { error: "Method not allowed" }, origin);
    if (origin && !isOriginAllowed(origin)) return reply(403, { ok: false, error: "origin_not_allowed" }, origin);

    const authPayload = requireAuth(event);
    if (!authPayload?.user_id) return reply(401, { ok: false, error: "unauthorized" }, origin);
    if (!isAdmin(authPayload)) return reply(403, { ok: false, error: "forbidden" }, origin);

    const body = JSON.parse(event.body || "{}");
    const action = safeStr(body.action || "snapshot").toLowerCase();

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

    ensureHeader(headers, [
      "user_id",
      "username",
      "email",
      "role",

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

      "level",
      "influence_tier",
      "primary_platform",
      "can_take_tasks",
      "can_withdraw",
    ]);

    const headerIdx = buildHeaderIndex(headers);
    const uidIdx = headerIdx["user_id"];
    const headersLen = headers.length;

    // ===== snapshot =====
    if (action === "snapshot") {
      const totalUsers = rows.length;
      const pending = rows.filter((r) => safeStr(r[headerIdx["social_status"]]).toLowerCase() === "submitted").length;

      return reply(
        200,
        {
          ok: true,
          stats: {
            users: totalUsers,
            dealers: 0,
            pending,
            payouts: 0,
            todayUsers: 0,
            pendingDealers: 0,
            activeQuests: 0,
            todayPayouts: 0,
          },
          users: [],   // 目前先留空：UI 已備妥，後續可擴充
          dealers: [], // 目前先留空：UI 已備妥，後續可擴充
        },
        origin
      );
    }

    // ===== social list submitted =====
    if (action === "social_list_submitted") {
      const items = [];

      for (let i = 0; i < rows.length; i++) {
        const row = rows[i] || [];
        const status = safeStr(row[headerIdx["social_status"]]).toLowerCase();
        if (status !== "submitted") continue;

        const user_id = safeStr(row[headerIdx["user_id"]]);
        const username = safeStr(row[headerIdx["username"]]);
        const email = safeStr(row[headerIdx["email"]]);

        const ig_url = safeStr(row[headerIdx["ig_url"]]);
        const fb_url = safeStr(row[headerIdx["fb_url"]]);
        const followers_count = safeStr(row[headerIdx["followers_count"]]);
        const avg_views_7d = safeStr(row[headerIdx["avg_views_7d"]]);
        const social_submitted_at = safeStr(row[headerIdx["social_submitted_at"]]);

        const primary_platform = safeStr(row[headerIdx["primary_platform"]]);
        const influence_tier = safeStr(row[headerIdx["influence_tier"]]);

        const suggest_platform = inferSuggestPlatform(ig_url, fb_url);

        items.push({
          user_id,
          username,
          email,
          social_status: "submitted",
          followers_count,
          avg_views_7d,
          social_submitted_at,
          primary_platform,
          influence_tier,
          suggest_platform,
        });
      }

      // sort by submitted time desc if possible
      items.sort((a, b) => {
        const ta = Date.parse(a.social_submitted_at || "") || 0;
        const tb = Date.parse(b.social_submitted_at || "") || 0;
        return tb - ta;
      });

      return reply(200, { ok: true, items }, origin);
    }

    // ===== social get / approve / reject need target_user_id =====
    if (action === "social_get" || action === "social_approve" || action === "social_reject") {
      const tUid = safeStr(target_user_id);
      if (!tUid) return reply(400, { ok: false, error: "target_user_id_required" }, origin);

      const foundRowIndex = findRowIndexByUserId(rows, uidIdx, tUid);
      if (foundRowIndex === -1) return reply(404, { ok: false, error: "user_not_found" }, origin);

      const rowNumber1Based = foundRowIndex + 2;
      const row = rows[foundRowIndex] || [];
      const fullRow = Array.from({ length: headersLen }, (_, j) => safeStr(row[j] || ""));

      const currentStatus = safeStr(getCell(fullRow, headerIdx, "social_status")) || "unsubmitted";

      if (action === "social_get") {
        const ig_url = safeStr(getCell(fullRow, headerIdx, "ig_url"));
        const fb_url = safeStr(getCell(fullRow, headerIdx, "fb_url"));

        return reply(
          200,
          {
            ok: true,
            user_id: tUid,
            username: safeStr(getCell(fullRow, headerIdx, "username")),
            email: safeStr(getCell(fullRow, headerIdx, "email")),
            social: {
              social_status: currentStatus,
              ig_url,
              fb_url,
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
              suggest_platform: inferSuggestPlatform(ig_url, fb_url),
            },
          },
          origin
        );
      }

      // approve / reject: only allow when submitted
      if (currentStatus !== "submitted") {
        return reply(409, { ok: false, error: "not_submitted" }, origin);
      }

      const adminTag = safeStr(authPayload.username) || safeStr(authPayload.user_id) || "admin";
      fullRow[headerIdx["verified_at"]] = nowISO();
      fullRow[headerIdx["verified_by"]] = sanitizeForSheet(adminTag);

      if (action === "social_reject") {
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

      // social_approve
      const nextPlatform = normalizePrimaryPlatform(data.primary_platform);
      const nextTier = normalizeTier(data.influence_tier);

      const currentPlatform = safeStr(getCell(fullRow, headerIdx, "primary_platform"));
      const currentTier = safeStr(getCell(fullRow, headerIdx, "influence_tier")).toUpperCase();

      const finalPlatform = nextPlatform || normalizePrimaryPlatform(currentPlatform) || "";
      const finalTier = nextTier || (["C", "B", "A", "S"].includes(currentTier) ? currentTier : "");

      if (!finalPlatform) return reply(400, { ok: false, error: "primary_platform_required" }, origin);
      if (!finalTier) return reply(400, { ok: false, error: "influence_tier_required" }, origin);

      fullRow[headerIdx["social_status"]] = "approved";
      fullRow[headerIdx["primary_platform"]] = sanitizeForSheet(finalPlatform);
      fullRow[headerIdx["influence_tier"]] = sanitizeForSheet(finalTier);

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

    return reply(400, { ok: false, error: "unknown_action" }, origin);
  } catch (err) {
    console.error("admin.cjs error:", err);
    return reply(500, { ok: false, error: "server_error" }, origin);
  }
};
