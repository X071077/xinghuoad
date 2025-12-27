// netlify/functions/admin.cjs
// ✅ Admin API：JWT 驗證 + CORS 白名單 + Sheet 公式注入防護 + 讀取範圍 A:ZZ
// action:
// - snapshot:              後台總覽（回傳 users 總數 + social submitted 待審數 + 隨機 5 筆 users 預覽）
// - users_preview:         隨機 5 筆用戶（給前台預設顯示）
// - users_list:            用戶清單（q/role 篩選）
// - users_get:             讀取單一用戶（排除 password_hash）
// - users_update_role:     更新用戶 role（admin/dealer/partner）
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

function getRequestOrigin(headers) {
  const h = headers || {};
  return (
    h.origin ||
    h.Origin ||
    h.referer ||
    h.Referer ||
    ""
  );
}

function getAllowedOrigins() {
  const raw = process.env.CORS_ALLOWED_ORIGINS || "";
  if (!raw.trim()) return DEFAULT_ALLOWED_ORIGINS;
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function isOriginAllowed(origin) {
  if (!origin) return true; // allow server-to-server
  const allowed = getAllowedOrigins();
  return allowed.includes(origin);
}

function corsHeaders(origin) {
  const allowed = getAllowedOrigins();
  const o = origin && allowed.includes(origin) ? origin : allowed[0];
  return {
    "Access-Control-Allow-Origin": o,
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Credentials": "true",
  };
}

function reply(statusCode, body, origin) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders(origin),
    },
    body: JSON.stringify(body || {}),
  };
}

function safeStr(v) {
  if (v === null || v === undefined) return "";
  return String(v).trim();
}

// Google Sheets formula injection防護（寫入用）
function sanitizeForSheet(value) {
  const s = safeStr(value);
  if (!s) return "";
  if (/^[=\-+@]/.test(s)) return "'" + s;
  return s;
}

function getBearerToken(event) {
  const h = event.headers || {};
  const auth = h.authorization || h.Authorization || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : "";
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

function parseServiceAccountJson() {
  const raw = process.env.GOOGLE_SERVICE_ACCOUNT_JSON || "";
  if (!raw) throw new Error("GOOGLE_SERVICE_ACCOUNT_JSON missing");
  try {
    return JSON.parse(raw);
  } catch (e) {
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
  await auth.authorize();
  return google.sheets({ version: "v4", auth });
}

function getSpreadsheetId() {
  const id = process.env.SPREADSHEET_ID || "";
  if (!id) throw new Error("SPREADSHEET_ID missing");
  return id;
}

function getUsersSheetName() {
  return process.env.USERS_SHEET || "users";
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

function pickRandomSample(arr, n) {
  const a = Array.isArray(arr) ? arr : [];
  const count = Math.max(0, Math.floor(n || 0));
  if (count === 0) return [];
  if (a.length <= count) return a.slice();

  // Partial Fisher–Yates on index array (avoid mutating original rows)
  const idxs = Array.from({ length: a.length }, (_, i) => i);
  for (let i = 0; i < count; i++) {
    const j = i + Math.floor(Math.random() * (idxs.length - i));
    const tmp = idxs[i];
    idxs[i] = idxs[j];
    idxs[j] = tmp;
  }
  return idxs.slice(0, count).map((k) => a[k]);
}

function toUserSummary(row, headerIdx) {
  return {
    user_id: safeStr(row[headerIdx["user_id"]]),
    username: safeStr(row[headerIdx["username"]]),
    name: safeStr(row[headerIdx["name"]]), // ✅ 第2版：補回 name，前台可用
    email: safeStr(row[headerIdx["email"]]),
    role: safeStr(row[headerIdx["role"]]),
  };
}

function rowToObject(headers, row, { omit = [] } = {}) {
  const omitSet = new Set((omit || []).map((x) => String(x || "").trim()));
  const obj = {};
  for (let i = 0; i < headers.length; i++) {
    const k = String(headers[i] || "").trim();
    if (!k || omitSet.has(k)) continue;
    obj[k] = safeStr(row[i] || "");
  }
  return obj;
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

function findRowIndexByUserId(rows, uidIdx, userId) {
  const target = String(userId || "").trim();
  if (!target) return -1;
  for (let i = 0; i < rows.length; i++) {
    const cell = String(rows[i][uidIdx] || "").trim();
    if (cell === target) return i;
  }
  return -1;
}

function normalizePrimaryPlatform(v) {
  const s = safeStr(v).toLowerCase();
  if (!s) return "";
  if (s === "ig" || s === "instagram") return "ig";
  if (s === "fb" || s === "facebook") return "fb";
  return s;
}

function normalizeTier(v) {
  const s = safeStr(v).toLowerCase();
  if (!s) return "";
  if (["s", "a", "b", "c"].includes(s)) return s;
  return s;
}

function nowISO() {
  return new Date().toISOString();
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
      "name",
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

      "influence_tier",
      "primary_platform",
      "social_submitted_at",
      "verified_at",
      "verified_by",

      "level",
      "can_take_tasks",
      "can_withdraw",
    ]);

    const headerIdx = buildHeaderIndex(headers);
    const uidIdx = headerIdx["user_id"];
    const headersLen = headers.length;

    // ===== users preview (random 5) =====
    if (action === "users_preview") {
      const total = rows.length;
      const items = pickRandomSample(rows, 5).map((r) => toUserSummary(r, headerIdx));
      return reply(200, { ok: true, total, items }, origin);
    }

    // ===== users list (search/filter) =====
    if (action === "users_list") {
      const qRaw = safeStr(body.q || body.query || "");
      const q = qRaw.trim().toLowerCase();

      const roleRaw = safeStr(body.role || "");
      const role = roleRaw.trim().toLowerCase();

      const limitIn = Number(body.limit ?? 50);
      const offsetIn = Number(body.offset ?? 0);
      const limit = Math.max(1, Math.min(200, Number.isFinite(limitIn) ? limitIn : 50));
      const offset = Math.max(0, Number.isFinite(offsetIn) ? offsetIn : 0);

      const matched = [];
      for (let i = 0; i < rows.length; i++) {
        const row = rows[i] || [];
        const rRole = safeStr(row[headerIdx["role"]]).toLowerCase();
        if (role && rRole !== role) continue;

        if (q) {
          const hay = [
            safeStr(row[headerIdx["user_id"]]),
            safeStr(row[headerIdx["username"]]),
            safeStr(row[headerIdx["email"]]),
            safeStr(row[headerIdx["name"]]),
          ]
            .join(" ")
            .toLowerCase();
          if (!hay.includes(q)) continue;
        }

        matched.push(row);
      }

      const total = matched.length;
      const slice = matched.slice(offset, offset + limit);
      const items = slice.map((r) => toUserSummary(r, headerIdx));

      return reply(200, { ok: true, total, items }, origin);
    }

    // ===== users get =====
    if (action === "users_get") {
      const tUid = safeStr(target_user_id);
      if (!tUid) return reply(400, { ok: false, error: "target_user_id_required" }, origin);

      const foundRowIndex = findRowIndexByUserId(rows, uidIdx, tUid);
      if (foundRowIndex === -1) return reply(404, { ok: false, error: "user_not_found" }, origin);

      const row = rows[foundRowIndex] || [];
      const fullRow = Array.from({ length: headersLen }, (_, j) => safeStr(row[j] || ""));
      const user = rowToObject(headers, fullRow, { omit: ["password_hash"] });

      return reply(200, { ok: true, user }, origin);
    }

    // ===== users update role =====
    if (action === "users_update_role") {
      const tUid = safeStr(target_user_id);
      if (!tUid) return reply(400, { ok: false, error: "target_user_id_required" }, origin);

      const roleNext = safeStr(body.role || data.role || "").trim().toLowerCase();
      if (!["admin", "dealer", "partner"].includes(roleNext)) {
        return reply(400, { ok: false, error: "role_invalid" }, origin);
      }

      const foundRowIndex = findRowIndexByUserId(rows, uidIdx, tUid);
      if (foundRowIndex === -1) return reply(404, { ok: false, error: "user_not_found" }, origin);

      const rowNumber1Based = foundRowIndex + 2;
      const row = rows[foundRowIndex] || [];
      const fullRow = Array.from({ length: headersLen }, (_, j) => safeStr(row[j] || ""));

      fullRow[headerIdx["role"]] = roleNext;
      await updateRowRange(sheets, spreadsheetId, usersSheet, rowNumber1Based, headersLen, fullRow);

      return reply(200, { ok: true }, origin);
    }

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
          users: pickRandomSample(rows, 5).map((r) => toUserSummary(r, headerIdx)), // ✅ 隨機 5 筆預覽
          dealers: [],
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
        const social_screenshot_url = safeStr(row[headerIdx["social_screenshot_url"]]);
        const user_type = safeStr(row[headerIdx["user_type"]]);
        const region = safeStr(row[headerIdx["region"]]);
        const brand_desc = safeStr(row[headerIdx["brand_desc"]]);
        const audience_desc = safeStr(row[headerIdx["audience_desc"]]);
        const influence_tier = safeStr(row[headerIdx["influence_tier"]]);
        const primary_platform = safeStr(row[headerIdx["primary_platform"]]);
        const social_submitted_at = safeStr(row[headerIdx["social_submitted_at"]]);

        const suggest_platform = inferSuggestPlatform(ig_url, fb_url);

        items.push({
          user_id,
          username,
          email,
          ig_url,
          fb_url,
          followers_count,
          avg_views_7d,
          social_screenshot_url,
          user_type,
          region,
          brand_desc,
          audience_desc,
          influence_tier,
          primary_platform,
          social_submitted_at,
          suggest_platform,
        });
      }

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

      const currentStatus = safeStr(fullRow[headerIdx["social_status"]]).toLowerCase();

      if (action === "social_get") {
        const user_id = safeStr(fullRow[headerIdx["user_id"]]);
        const username = safeStr(fullRow[headerIdx["username"]]);
        const email = safeStr(fullRow[headerIdx["email"]]);

        const social = {
          social_status: safeStr(fullRow[headerIdx["social_status"]]),
          influence_tier: safeStr(fullRow[headerIdx["influence_tier"]]),
          primary_platform: safeStr(fullRow[headerIdx["primary_platform"]]),
          ig_url: safeStr(fullRow[headerIdx["ig_url"]]),
          fb_url: safeStr(fullRow[headerIdx["fb_url"]]),
          followers_count: safeStr(fullRow[headerIdx["followers_count"]]),
          avg_views_7d: safeStr(fullRow[headerIdx["avg_views_7d"]]),
          social_screenshot_url: safeStr(fullRow[headerIdx["social_screenshot_url"]]),
          user_type: safeStr(fullRow[headerIdx["user_type"]]),
          region: safeStr(fullRow[headerIdx["region"]]),
          brand_desc: safeStr(fullRow[headerIdx["brand_desc"]]),
          audience_desc: safeStr(fullRow[headerIdx["audience_desc"]]),
          social_submitted_at: safeStr(fullRow[headerIdx["social_submitted_at"]]),
          verified_at: safeStr(fullRow[headerIdx["verified_at"]]),
          verified_by: safeStr(fullRow[headerIdx["verified_by"]]),
        };

        social.suggest_platform = inferSuggestPlatform(social.ig_url, social.fb_url);

        return reply(200, { ok: true, user_id, username, email, social }, origin);
      }

      if (currentStatus !== "submitted") return reply(400, { ok: false, error: "not_submitted" }, origin);

      const adminId = safeStr(authPayload.user_id);
      const ts = nowISO();

      if (action === "social_reject") {
        fullRow[headerIdx["social_status"]] = "rejected";
        fullRow[headerIdx["verified_at"]] = ts;
        fullRow[headerIdx["verified_by"]] = adminId;

        fullRow[headerIdx["level"]] = "0";
        fullRow[headerIdx["can_take_tasks"]] = "false";
        fullRow[headerIdx["can_withdraw"]] = "false";

        await updateRowRange(sheets, spreadsheetId, usersSheet, rowNumber1Based, headersLen, fullRow);

        return reply(
          200,
          {
            ok: true,
            social_status: "rejected",
            verified_at: ts,
            verified_by: adminId,
            level: 0,
            can_take_tasks: false,
            can_withdraw: false,
          },
          origin
        );
      }

      const primary_platform = normalizePrimaryPlatform(body.primary_platform || data.primary_platform || "");
      const influence_tier = normalizeTier(body.influence_tier || data.influence_tier || "");

      if (primary_platform) fullRow[headerIdx["primary_platform"]] = primary_platform;
      if (influence_tier) fullRow[headerIdx["influence_tier"]] = influence_tier;

      fullRow[headerIdx["social_status"]] = "approved";
      fullRow[headerIdx["verified_at"]] = ts;
      fullRow[headerIdx["verified_by"]] = adminId;

      fullRow[headerIdx["level"]] = "1";
      fullRow[headerIdx["can_take_tasks"]] = "true";
      fullRow[headerIdx["can_withdraw"]] = "true";

      await updateRowRange(sheets, spreadsheetId, usersSheet, rowNumber1Based, headersLen, fullRow);

      return reply(
        200,
        {
          ok: true,
          social_status: "approved",
          verified_at: ts,
          verified_by: adminId,
          primary_platform: fullRow[headerIdx["primary_platform"]],
          influence_tier: fullRow[headerIdx["influence_tier"]],
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
