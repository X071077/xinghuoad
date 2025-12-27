// netlify/functions/admin.cjs
// ✅ Admin API：JWT 驗證 + CORS 白名單 + Sheet 公式注入防護 + 讀取範圍 A:ZZ
// ✅ 第2版：補齊 Quests / Submissions actions + snapshot 統計 + 修正 dealer summary bug
//
// action:
// - snapshot:               後台總覽（回傳 users 總數 + social submitted 待審數 + dealers總數 + dealers pending + 任務統計 + payout 統計）
// - users_preview:          隨機 5 筆用戶（給前台預設顯示）
// - users_list:             用戶清單（q/role 篩選）
// - users_get:              讀取單一用戶（排除 password_hash）
// - users_update_role:      更新用戶 role（admin/dealer/partner）
//
// - social_list_submitted:  列出 users 中 social_status=submitted 的待審清單
// - social_get:             讀取指定 target_user_id 的社群驗證資料
// - social_approve:         submitted → approved + verified_at/by + level=1 + 開權限 + 設定 tier/platform
// - social_need_fix:        submitted → need_fix + verified_at/by + level=0 + 關權限 (+ 可選寫入補件原因)
// - social_reject:          submitted → rejected + verified_at/by + level=0 + 關權限
//
// ✅ Dealer 管理（dealers sheet）
// - dealers_list:           dealers 清單（q/status/limit/offset）
// - dealers_get:            讀取單一 dealer（by dealer_id）
// - dealers_approve:        submitted → approved（寫入 verified_at/by）+ 可選同步 users.role=dealer
// - dealers_need_fix:       submitted → need_fix（寫入 need_fix_reason/need_fix_at + verified_at/by）
// - dealers_reject:         submitted → rejected（寫入 verified_at/by）
//
// ✅ Quests（quests sheet）
// - quests_list:            任務清單（q/status/limit/offset）
// - quests_get:             讀取單一任務（by quest_id）
// - quests_create:          新增任務（自動寫 created_at/by、quest_id 可自動生成）
// - quests_update:          更新任務（by quest_id，寫 updated_at/by）
// - quests_set_status:      更新任務 status（draft/active/paused/closed）
////
// ✅ Submissions（quest_submissions sheet）
// - submissions_list:       交付清單（q/status/payout_status/limit/offset）
// - submissions_get:        讀取單一交付（by submission_id）
// - submissions_review:     審核交付（submitted → approved/rejected/need_fix，寫 reviewed_at/by + 可選 reason）
// - submissions_payout:     發放款項（approved 且未 paid → paid，寫 payout_at/by + payout_amount）

const { google } = require("googleapis");
const jwt = require("jsonwebtoken");

const DEFAULT_ALLOWED_ORIGINS = [
  "https://xinghuoad.xyz",
  "https://www.xinghuoad.xyz",
];

function getRequestOrigin(headers) {
  const h = headers || {};
  return h.origin || h.Origin || h.referer || h.Referer || "";
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

function getDealersSheetName() {
  return process.env.DEALERS_SHEET || "dealers";
}

function getQuestsSheetName() {
  return process.env.QUESTS_SHEET || "quests";
}

function getQuestSubmissionsSheetName() {
  return process.env.QUEST_SUBMISSIONS_SHEET || "quest_submissions";
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
    name: safeStr(row[headerIdx["name"]]),
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

function ensureDealerHeader(headers, want) {
  const missing = want.filter((h) => !headers.includes(h));
  if (missing.length) throw new Error(`Dealers sheet missing columns: ${missing.join(", ")}`);
}

function ensureQuestHeader(headers, want) {
  const missing = want.filter((h) => !headers.includes(h));
  if (missing.length) throw new Error(`Quests sheet missing columns: ${missing.join(", ")}`);
}

function ensureSubmissionHeader(headers, want) {
  const missing = want.filter((h) => !headers.includes(h));
  if (missing.length) throw new Error(`Quest submissions sheet missing columns: ${missing.join(", ")}`);
}

// ✅ 可選欄位（存在才寫/才讀）
function hasHeader(headers, name) {
  return Array.isArray(headers) && headers.includes(name);
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

async function appendRow(sheets, spreadsheetId, sheetName, valuesRow) {
  await sheets.spreadsheets.values.append({
    spreadsheetId,
    range: `${sheetName}!A:ZZ`,
    valueInputOption: "RAW",
    insertDataOption: "INSERT_ROWS",
    requestBody: { values: [valuesRow] },
  });
}

function findRowIndexByColValue(rows, colIdx, value) {
  const target = String(value || "").trim();
  if (!target) return -1;
  for (let i = 0; i < rows.length; i++) {
    const cell = String(rows[i][colIdx] || "").trim();
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

function normalizeDealerStatus(v) {
  const s = safeStr(v).toLowerCase();
  if (!s) return "";
  if (["submitted", "approved", "need_fix", "rejected"].includes(s)) return s;
  return s;
}

function normalizeQuestStatus(v) {
  const s = safeStr(v).toLowerCase();
  if (!s) return "";
  if (["draft", "active", "paused", "closed"].includes(s)) return s;
  return s;
}

function normalizeSubmissionStatus(v) {
  const s = safeStr(v).toLowerCase();
  if (!s) return "";
  if (["submitted", "approved", "need_fix", "rejected", "paid"].includes(s)) return s; // paid 可用於部分前台顯示（可選）
  return s;
}

function normalizePayoutStatus(v) {
  const s = safeStr(v).toLowerCase();
  if (!s) return "";
  if (["unpaid", "paid"].includes(s)) return s;
  return s;
}

function nowISO() {
  return new Date().toISOString();
}

function isTodayISO(iso) {
  const t = Date.parse(iso || "");
  if (!t) return false;
  const d = new Date(t);
  const n = new Date();
  return (
    d.getUTCFullYear() === n.getUTCFullYear() &&
    d.getUTCMonth() === n.getUTCMonth() &&
    d.getUTCDate() === n.getUTCDate()
  );
}

function inferSuggestPlatform(ig_url, fb_url) {
  const ig = safeStr(ig_url);
  const fb = safeStr(fb_url);
  if (ig) return "ig";
  if (fb) return "fb";
  return "";
}

function safeId(prefix) {
  // 不依賴外部 lib，簡單可用：q_20251227_xxxxxx
  const r = Math.random().toString(36).slice(2, 8);
  const ts = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
  return `${prefix}_${ts}_${r}`;
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

    // users target
    const target_user_id =
      safeStr(body.target_user_id) ||
      safeStr(body.targetUserId) ||
      safeStr(body.user_id) ||
      "";

    // dealers target
    const target_dealer_id =
      safeStr(body.target_dealer_id) ||
      safeStr(body.targetDealerId) ||
      safeStr(body.dealer_id) ||
      "";

    // quests target
    const target_quest_id =
      safeStr(body.target_quest_id) ||
      safeStr(body.targetQuestId) ||
      safeStr(body.quest_id) ||
      "";

    // submissions target
    const target_submission_id =
      safeStr(body.target_submission_id) ||
      safeStr(body.targetSubmissionId) ||
      safeStr(body.submission_id) ||
      "";

    const data = (body && typeof body === "object" ? body.data : {}) || {};

    const sheets = await getSheetsClient();
    const spreadsheetId = getSpreadsheetId();

    // =========================
    // ✅ Users sheet (always read)
    // =========================
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

      const foundRowIndex = findRowIndexByColValue(rows, uidIdx, tUid);
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

      const foundRowIndex = findRowIndexByColValue(rows, uidIdx, tUid);
      if (foundRowIndex === -1) return reply(404, { ok: false, error: "user_not_found" }, origin);

      const rowNumber1Based = foundRowIndex + 2;
      const row = rows[foundRowIndex] || [];
      const fullRow = Array.from({ length: headersLen }, (_, j) => safeStr(row[j] || ""));

      fullRow[headerIdx["role"]] = roleNext;
      await updateRowRange(sheets, spreadsheetId, usersSheet, rowNumber1Based, headersLen, fullRow);

      return reply(200, { ok: true }, origin);
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

    // ===== social get / approve / need_fix / reject need target_user_id =====
    if (
      action === "social_get" ||
      action === "social_approve" ||
      action === "social_need_fix" ||
      action === "social_reject"
    ) {
      const tUid = safeStr(target_user_id);
      if (!tUid) return reply(400, { ok: false, error: "target_user_id_required" }, origin);

      const foundRowIndex = findRowIndexByColValue(rows, uidIdx, tUid);
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

        if (hasHeader(headers, "need_fix_reason")) social.need_fix_reason = safeStr(fullRow[headerIdx["need_fix_reason"]]);
        if (hasHeader(headers, "need_fix_at")) social.need_fix_at = safeStr(fullRow[headerIdx["need_fix_at"]]);

        social.suggest_platform = inferSuggestPlatform(social.ig_url, social.fb_url);

        return reply(200, { ok: true, user_id, username, email, social }, origin);
      }

      if (currentStatus !== "submitted") return reply(400, { ok: false, error: "not_submitted" }, origin);

      const adminId = safeStr(authPayload.user_id);
      const ts = nowISO();

      if (action === "social_need_fix") {
        fullRow[headerIdx["social_status"]] = "need_fix";
        fullRow[headerIdx["verified_at"]] = ts;
        fullRow[headerIdx["verified_by"]] = adminId;

        fullRow[headerIdx["level"]] = "0";
        fullRow[headerIdx["can_take_tasks"]] = "false";
        fullRow[headerIdx["can_withdraw"]] = "false";

        const reason = sanitizeForSheet(body.reason || data.reason || "");
        if (hasHeader(headers, "need_fix_reason")) fullRow[headerIdx["need_fix_reason"]] = reason;
        if (hasHeader(headers, "need_fix_at")) fullRow[headerIdx["need_fix_at"]] = ts;

        await updateRowRange(sheets, spreadsheetId, usersSheet, rowNumber1Based, headersLen, fullRow);

        return reply(200, { ok: true, social_status: "need_fix" }, origin);
      }

      if (action === "social_reject") {
        fullRow[headerIdx["social_status"]] = "rejected";
        fullRow[headerIdx["verified_at"]] = ts;
        fullRow[headerIdx["verified_by"]] = adminId;

        fullRow[headerIdx["level"]] = "0";
        fullRow[headerIdx["can_take_tasks"]] = "false";
        fullRow[headerIdx["can_withdraw"]] = "false";

        await updateRowRange(sheets, spreadsheetId, usersSheet, rowNumber1Based, headersLen, fullRow);

        return reply(200, { ok: true, social_status: "rejected" }, origin);
      }

      // approve
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

      return reply(200, { ok: true, social_status: "approved" }, origin);
    }

    // =========================
    // ✅ Dealers sheet actions
    // =========================
    if (
      action === "dealers_list" ||
      action === "dealers_get" ||
      action === "dealers_approve" ||
      action === "dealers_need_fix" ||
      action === "dealers_reject" ||
      action === "snapshot"
    ) {
      const dealersSheet = getDealersSheetName();
      const { headers: dHeaders, rows: dRows } = await readAllRows(sheets, spreadsheetId, dealersSheet);

      ensureDealerHeader(dHeaders, [
        "dealer_id",
        "user_id",
        "dealer_name",
        "email",
        "dealer_status",
        "submitted_at",
        "verified_at",
        "verified_by",
        "need_fix_reason",
        "need_fix_at",
      ]);

      const dIdx = buildHeaderIndex(dHeaders);
      const dDealerIdIdx = dIdx["dealer_id"];
      const dUserIdIdx = dIdx["user_id"];
      const dHeadersLen = dHeaders.length;

      // =========================
      // ✅ Quests + Submissions (for snapshot + quest actions)
      // =========================
      const questsSheet = getQuestsSheetName();
      const subsSheet = getQuestSubmissionsSheetName();

      // 這兩張表只有在需要時才讀，但 snapshot 會用到
      const needQuestRead =
        action === "snapshot" ||
        action.startsWith("quests_") ||
        action.startsWith("submissions_");

      let qHeaders = [];
      let qRows = [];
      let qIdx = {};
      let sHeaders = [];
      let sRows = [];
      let sIdx = {};

      if (needQuestRead) {
        const qr = await readAllRows(sheets, spreadsheetId, questsSheet);
        qHeaders = qr.headers;
        qRows = qr.rows;

        // 任務表：最小必需欄位（其他欄位存在就一併回傳/可更新）
        ensureQuestHeader(qHeaders, ["quest_id", "title", "status", "created_at", "created_by"]);
        qIdx = buildHeaderIndex(qHeaders);

        const sr = await readAllRows(sheets, spreadsheetId, subsSheet);
        sHeaders = sr.headers;
        sRows = sr.rows;

        // 交付表：最小必需欄位
        ensureSubmissionHeader(sHeaders, ["submission_id", "quest_id", "user_id", "status", "submitted_at"]);
        sIdx = buildHeaderIndex(sHeaders);
      }

      // ===== snapshot =====
      if (action === "snapshot") {
        const totalUsers = rows.length;
        const pendingSocial = rows.filter((r) => safeStr(r[headerIdx["social_status"]]).toLowerCase() === "submitted").length;

        const totalDealers = dRows.length;
        const pendingDealers = dRows.filter((r) => safeStr(r[dIdx["dealer_status"]]).toLowerCase() === "submitted").length;

        const activeQuests = qRows.filter((r) => safeStr(r[qIdx["status"]]).toLowerCase() === "active").length;

        const paidCount = sRows.filter((r) => {
          const ps = hasHeader(sHeaders, "payout_status") ? safeStr(r[sIdx["payout_status"]]).toLowerCase() : "";
          return ps === "paid";
        }).length;

        const todayPaidCount = sRows.filter((r) => {
          const ps = hasHeader(sHeaders, "payout_status") ? safeStr(r[sIdx["payout_status"]]).toLowerCase() : "";
          const pat = hasHeader(sHeaders, "payout_at") ? safeStr(r[sIdx["payout_at"]]) : "";
          return ps === "paid" && isTodayISO(pat);
        }).length;

        const dealerPreview = pickRandomSample(dRows, 5).map((r) => ({
          dealer_id: safeStr(r[dIdx["dealer_id"]]),
          dealer_name: safeStr(r[dIdx["dealer_name"]]),
          email: safeStr(r[dIdx["email"]]),
          dealer_status: safeStr(r[dIdx["dealer_status"]]),
          user_id: safeStr(r[dIdx["user_id"]]),
          submitted_at: safeStr(r[dIdx["submitted_at"]]),
        }));

        return reply(
          200,
          {
            ok: true,
            stats: {
              users: totalUsers,
              dealers: totalDealers,
              pending: pendingSocial,
              payouts: paidCount,
              todayUsers: 0, // 若你未來要算「今天註冊數」，再加 users.created_at 判斷即可
              pendingDealers,
              activeQuests,
              todayPayouts: todayPaidCount,
            },
            users: pickRandomSample(rows, 5).map((r) => toUserSummary(r, headerIdx)),
            dealers: dealerPreview,
          },
          origin
        );
      }

      // ===== dealers list =====
      if (action === "dealers_list") {
        const qRaw = safeStr(body.q || body.query || "");
        const q = qRaw.trim().toLowerCase();

        const statusRaw = safeStr(body.status || body.dealer_status || "");
        const status = normalizeDealerStatus(statusRaw);

        const limitIn = Number(body.limit ?? 50);
        const offsetIn = Number(body.offset ?? 0);
        const limit = Math.max(1, Math.min(200, Number.isFinite(limitIn) ? limitIn : 50));
        const offset = Math.max(0, Number.isFinite(offsetIn) ? offsetIn : 0);

        const matched = [];
        for (let i = 0; i < dRows.length; i++) {
          const row = dRows[i] || [];
          const st = safeStr(row[dIdx["dealer_status"]]).toLowerCase();
          if (status && st !== status) continue;

          if (q) {
            const hay = [
              safeStr(row[dIdx["dealer_id"]]),
              safeStr(row[dIdx["dealer_name"]]),
              safeStr(row[dIdx["email"]]),
              safeStr(row[dIdx["user_id"]]),
            ]
              .join(" ")
              .toLowerCase();
            if (!hay.includes(q)) continue;
          }

          matched.push(row);
        }

        matched.sort((a, b) => {
          const ta = Date.parse(safeStr(a[dIdx["submitted_at"]])) || 0;
          const tb = Date.parse(safeStr(b[dIdx["submitted_at"]])) || 0;
          return tb - ta;
        });

        const total = matched.length;
        const slice = matched.slice(offset, offset + limit);
        const items = slice.map((r) => ({
          dealer_id: safeStr(r[dIdx["dealer_id"]]),
          user_id: safeStr(r[dIdx["user_id"]]),
          dealer_name: safeStr(r[dIdx["dealer_name"]]),
          email: safeStr(r[dIdx["email"]]),
          dealer_status: safeStr(r[dIdx["dealer_status"]]),
          submitted_at: safeStr(r[dIdx["submitted_at"]]),
          verified_at: safeStr(r[dIdx["verified_at"]]),
          verified_by: safeStr(r[dIdx["verified_by"]]),
          need_fix_reason: safeStr(r[dIdx["need_fix_reason"]]),
          need_fix_at: safeStr(r[dIdx["need_fix_at"]]),
        }));

        return reply(200, { ok: true, total, items }, origin);
      }

      // ===== dealers get =====
      if (action === "dealers_get") {
        const tDid = safeStr(target_dealer_id);
        if (!tDid) return reply(400, { ok: false, error: "target_dealer_id_required" }, origin);

        const foundRowIndex = findRowIndexByColValue(dRows, dDealerIdIdx, tDid);
        if (foundRowIndex === -1) return reply(404, { ok: false, error: "dealer_not_found" }, origin);

        const row = dRows[foundRowIndex] || [];
        const fullRow = Array.from({ length: dHeadersLen }, (_, j) => safeStr(row[j] || ""));
        const dealer = rowToObject(dHeaders, fullRow, { omit: [] });

        return reply(200, { ok: true, dealer }, origin);
      }

      // ===== dealers approve / need_fix / reject =====
      if (action === "dealers_approve" || action === "dealers_need_fix" || action === "dealers_reject") {
        const tDid = safeStr(target_dealer_id);
        if (!tDid) return reply(400, { ok: false, error: "target_dealer_id_required" }, origin);

        const foundRowIndex = findRowIndexByColValue(dRows, dDealerIdIdx, tDid);
        if (foundRowIndex === -1) return reply(404, { ok: false, error: "dealer_not_found" }, origin);

        const rowNumber1Based = foundRowIndex + 2;
        const row = dRows[foundRowIndex] || [];
        const fullRow = Array.from({ length: dHeadersLen }, (_, j) => safeStr(row[j] || ""));

        const currentStatus = safeStr(fullRow[dIdx["dealer_status"]]).toLowerCase();
        if (currentStatus !== "submitted") return reply(400, { ok: false, error: "not_submitted" }, origin);

        const adminId = safeStr(authPayload.user_id);
        const ts = nowISO();

        if (action === "dealers_need_fix") {
          const reason = sanitizeForSheet(body.reason || data.reason || "");
          fullRow[dIdx["dealer_status"]] = "need_fix";
          fullRow[dIdx["verified_at"]] = ts;
          fullRow[dIdx["verified_by"]] = adminId;
          fullRow[dIdx["need_fix_reason"]] = reason;
          fullRow[dIdx["need_fix_at"]] = ts;

          await updateRowRange(sheets, spreadsheetId, dealersSheet, rowNumber1Based, dHeadersLen, fullRow);

          return reply(200, { ok: true, dealer_status: "need_fix", verified_at: ts, verified_by: adminId }, origin);
        }

        if (action === "dealers_reject") {
          fullRow[dIdx["dealer_status"]] = "rejected";
          fullRow[dIdx["verified_at"]] = ts;
          fullRow[dIdx["verified_by"]] = adminId;

          await updateRowRange(sheets, spreadsheetId, dealersSheet, rowNumber1Based, dHeadersLen, fullRow);

          return reply(200, { ok: true, dealer_status: "rejected", verified_at: ts, verified_by: adminId }, origin);
        }

        // approve
        fullRow[dIdx["dealer_status"]] = "approved";
        fullRow[dIdx["verified_at"]] = ts;
        fullRow[dIdx["verified_by"]] = adminId;

        await updateRowRange(sheets, spreadsheetId, dealersSheet, rowNumber1Based, dHeadersLen, fullRow);

        // ✅ 可選：同步 users.role = dealer（如果有 user_id 且 users 中存在）
        const dealerUserId = safeStr(fullRow[dUserIdIdx]);
        if (dealerUserId) {
          const uRowIndex = findRowIndexByColValue(rows, uidIdx, dealerUserId);
          if (uRowIndex !== -1) {
            const uRowNumber1Based = uRowIndex + 2;
            const uRow = rows[uRowIndex] || [];
            const uFullRow = Array.from({ length: headersLen }, (_, j) => safeStr(uRow[j] || ""));
            uFullRow[headerIdx["role"]] = "dealer";
            await updateRowRange(sheets, spreadsheetId, usersSheet, uRowNumber1Based, headersLen, uFullRow);
          }
        }

        return reply(200, { ok: true, dealer_status: "approved", verified_at: ts, verified_by: adminId }, origin);
      }

      // =========================
      // ✅ Quests actions
      // =========================
      if (action === "quests_list") {
        const qRaw = safeStr(body.q || body.query || "");
        const q = qRaw.trim().toLowerCase();

        const statusRaw = safeStr(body.status || "");
        const status = normalizeQuestStatus(statusRaw);

        const limitIn = Number(body.limit ?? 50);
        const offsetIn = Number(body.offset ?? 0);
        const limit = Math.max(1, Math.min(200, Number.isFinite(limitIn) ? limitIn : 50));
        const offset = Math.max(0, Number.isFinite(offsetIn) ? offsetIn : 0);

        const matched = [];
        for (let i = 0; i < qRows.length; i++) {
          const row = qRows[i] || [];
          const st = safeStr(row[qIdx["status"]]).toLowerCase();
          if (status && st !== status) continue;

          if (q) {
            const hay = [
              safeStr(row[qIdx["quest_id"]]),
              safeStr(row[qIdx["title"]]),
              hasHeader(qHeaders, "description") ? safeStr(row[qIdx["description"]]) : "",
            ]
              .join(" ")
              .toLowerCase();
            if (!hay.includes(q)) continue;
          }

          matched.push(row);
        }

        // 預設依 created_at 新到舊
        if (hasHeader(qHeaders, "created_at")) {
          matched.sort((a, b) => {
            const ta = Date.parse(safeStr(a[qIdx["created_at"]])) || 0;
            const tb = Date.parse(safeStr(b[qIdx["created_at"]])) || 0;
            return tb - ta;
          });
        }

        const total = matched.length;
        const slice = matched.slice(offset, offset + limit);
        const items = slice.map((r) => ({
          quest_id: safeStr(r[qIdx["quest_id"]]),
          title: safeStr(r[qIdx["title"]]),
          status: safeStr(r[qIdx["status"]]),
          created_at: hasHeader(qHeaders, "created_at") ? safeStr(r[qIdx["created_at"]]) : "",
          created_by: hasHeader(qHeaders, "created_by") ? safeStr(r[qIdx["created_by"]]) : "",
        }));

        return reply(200, { ok: true, total, items }, origin);
      }

      if (action === "quests_get") {
        const tQid = safeStr(target_quest_id);
        if (!tQid) return reply(400, { ok: false, error: "target_quest_id_required" }, origin);

        const qidIdx = qIdx["quest_id"];
        const found = findRowIndexByColValue(qRows, qidIdx, tQid);
        if (found === -1) return reply(404, { ok: false, error: "quest_not_found" }, origin);

        const row = qRows[found] || [];
        const fullRow = Array.from({ length: qHeaders.length }, (_, j) => safeStr(row[j] || ""));
        const quest = rowToObject(qHeaders, fullRow, { omit: [] });

        return reply(200, { ok: true, quest }, origin);
      }

      if (action === "quests_create") {
        const adminId = safeStr(authPayload.user_id);
        const ts = nowISO();

        const qLen = qHeaders.length;
        const fullRow = Array.from({ length: qLen }, () => "");

        const quest_id = sanitizeForSheet(data.quest_id || body.quest_id || safeId("q"));
        const title = sanitizeForSheet(data.title || body.title || "");
        if (!title) return reply(400, { ok: false, error: "title_required" }, origin);

        const status = normalizeQuestStatus(data.status || body.status || "draft") || "draft";

        fullRow[qIdx["quest_id"]] = quest_id;
        fullRow[qIdx["title"]] = title;
        fullRow[qIdx["status"]] = status;

        if (hasHeader(qHeaders, "description")) fullRow[qIdx["description"]] = sanitizeForSheet(data.description || body.description || "");
        if (hasHeader(qHeaders, "reward_min")) fullRow[qIdx["reward_min"]] = sanitizeForSheet(data.reward_min || body.reward_min || "");
        if (hasHeader(qHeaders, "reward_max")) fullRow[qIdx["reward_max"]] = sanitizeForSheet(data.reward_max || body.reward_max || "");
        if (hasHeader(qHeaders, "reward_note")) fullRow[qIdx["reward_note"]] = sanitizeForSheet(data.reward_note || body.reward_note || "");

        if (hasHeader(qHeaders, "created_at")) fullRow[qIdx["created_at"]] = ts;
        if (hasHeader(qHeaders, "created_by")) fullRow[qIdx["created_by"]] = adminId;

        // 一些常見可選欄位（存在就寫）
        const optionalFields = [
          "start_at",
          "end_at",
          "region",
          "platform",
          "tier_min",
          "tier_max",
          "budget",
          "notes",
        ];
        for (const f of optionalFields) {
          if (hasHeader(qHeaders, f)) fullRow[qIdx[f]] = sanitizeForSheet(data[f] ?? body[f] ?? "");
        }

        await appendRow(sheets, spreadsheetId, questsSheet, fullRow);

        return reply(200, { ok: true, quest_id }, origin);
      }

      if (action === "quests_update") {
        const tQid = safeStr(target_quest_id);
        if (!tQid) return reply(400, { ok: false, error: "target_quest_id_required" }, origin);

        const qidIdx = qIdx["quest_id"];
        const found = findRowIndexByColValue(qRows, qidIdx, tQid);
        if (found === -1) return reply(404, { ok: false, error: "quest_not_found" }, origin);

        const rowNumber1Based = found + 2;
        const row = qRows[found] || [];
        const qLen = qHeaders.length;
        const fullRow = Array.from({ length: qLen }, (_, j) => safeStr(row[j] || ""));

        // 允許更新的欄位：除了 quest_id / created_* 以外，其他存在就可改
        const deny = new Set(["quest_id", "created_at", "created_by"]);
        for (const k of Object.keys(data || {})) {
          const key = String(k || "").trim();
          if (!key || deny.has(key)) continue;
          if (!hasHeader(qHeaders, key)) continue;
          fullRow[qIdx[key]] = sanitizeForSheet(data[key]);
        }

        // body 也可直傳欄位
        const bodyFields = Object.keys(body || {});
        for (const k of bodyFields) {
          if (["action", "target_quest_id", "targetQuestId", "quest_id", "data"].includes(k)) continue;
          const key = String(k || "").trim();
          if (!key || deny.has(key)) continue;
          if (!hasHeader(qHeaders, key)) continue;
          fullRow[qIdx[key]] = sanitizeForSheet(body[key]);
        }

        const adminId = safeStr(authPayload.user_id);
        const ts = nowISO();
        if (hasHeader(qHeaders, "updated_at")) fullRow[qIdx["updated_at"]] = ts;
        if (hasHeader(qHeaders, "updated_by")) fullRow[qIdx["updated_by"]] = adminId;

        await updateRowRange(sheets, spreadsheetId, questsSheet, rowNumber1Based, qLen, fullRow);

        return reply(200, { ok: true }, origin);
      }

      if (action === "quests_set_status") {
        const tQid = safeStr(target_quest_id);
        if (!tQid) return reply(400, { ok: false, error: "target_quest_id_required" }, origin);

        const statusNext = normalizeQuestStatus(data.status || body.status || "");
        if (!statusNext) return reply(400, { ok: false, error: "status_invalid" }, origin);

        const qidIdx = qIdx["quest_id"];
        const found = findRowIndexByColValue(qRows, qidIdx, tQid);
        if (found === -1) return reply(404, { ok: false, error: "quest_not_found" }, origin);

        const rowNumber1Based = found + 2;
        const row = qRows[found] || [];
        const qLen = qHeaders.length;
        const fullRow = Array.from({ length: qLen }, (_, j) => safeStr(row[j] || ""));

        fullRow[qIdx["status"]] = statusNext;

        const adminId = safeStr(authPayload.user_id);
        const ts = nowISO();
        if (hasHeader(qHeaders, "updated_at")) fullRow[qIdx["updated_at"]] = ts;
        if (hasHeader(qHeaders, "updated_by")) fullRow[qIdx["updated_by"]] = adminId;

        await updateRowRange(sheets, spreadsheetId, questsSheet, rowNumber1Based, qLen, fullRow);

        return reply(200, { ok: true, status: statusNext }, origin);
      }

      // =========================
      // ✅ Submissions actions
      // =========================
      if (action === "submissions_list") {
        const qRaw = safeStr(body.q || body.query || "");
        const q = qRaw.trim().toLowerCase();

        const statusRaw = safeStr(body.status || "");
        const status = normalizeSubmissionStatus(statusRaw);

        const payoutRaw = safeStr(body.payout_status || body.payoutStatus || "");
        const payout_status = normalizePayoutStatus(payoutRaw);

        const limitIn = Number(body.limit ?? 50);
        const offsetIn = Number(body.offset ?? 0);
        const limit = Math.max(1, Math.min(200, Number.isFinite(limitIn) ? limitIn : 50));
        const offset = Math.max(0, Number.isFinite(offsetIn) ? offsetIn : 0);

        const matched = [];
        for (let i = 0; i < sRows.length; i++) {
          const row = sRows[i] || [];

          const st = safeStr(row[sIdx["status"]]).toLowerCase();
          if (status && st !== status) continue;

          if (payout_status && hasHeader(sHeaders, "payout_status")) {
            const ps = safeStr(row[sIdx["payout_status"]]).toLowerCase();
            if (ps !== payout_status) continue;
          }

          if (q) {
            const hay = [
              safeStr(row[sIdx["submission_id"]]),
              safeStr(row[sIdx["quest_id"]]),
              safeStr(row[sIdx["user_id"]]),
              hasHeader(sHeaders, "username") ? safeStr(row[sIdx["username"]]) : "",
              hasHeader(sHeaders, "note") ? safeStr(row[sIdx["note"]]) : "",
            ]
              .join(" ")
              .toLowerCase();
            if (!hay.includes(q)) continue;
          }

          matched.push(row);
        }

        // 預設依 submitted_at 新到舊
        matched.sort((a, b) => {
          const ta = Date.parse(safeStr(a[sIdx["submitted_at"]])) || 0;
          const tb = Date.parse(safeStr(b[sIdx["submitted_at"]])) || 0;
          return tb - ta;
        });

        const total = matched.length;
        const slice = matched.slice(offset, offset + limit);
        const items = slice.map((r) => ({
          submission_id: safeStr(r[sIdx["submission_id"]]),
          quest_id: safeStr(r[sIdx["quest_id"]]),
          user_id: safeStr(r[sIdx["user_id"]]),
          status: safeStr(r[sIdx["status"]]),
          submitted_at: safeStr(r[sIdx["submitted_at"]]),
          payout_status: hasHeader(sHeaders, "payout_status") ? safeStr(r[sIdx["payout_status"]]) : "",
          payout_amount: hasHeader(sHeaders, "payout_amount") ? safeStr(r[sIdx["payout_amount"]]) : "",
        }));

        return reply(200, { ok: true, total, items }, origin);
      }

      if (action === "submissions_get") {
        const tSid = safeStr(target_submission_id);
        if (!tSid) return reply(400, { ok: false, error: "target_submission_id_required" }, origin);

        const sidIdx = sIdx["submission_id"];
        const found = findRowIndexByColValue(sRows, sidIdx, tSid);
        if (found === -1) return reply(404, { ok: false, error: "submission_not_found" }, origin);

        const row = sRows[found] || [];
        const sLen = sHeaders.length;
        const fullRow = Array.from({ length: sLen }, (_, j) => safeStr(row[j] || ""));
        const submission = rowToObject(sHeaders, fullRow, { omit: [] });

        return reply(200, { ok: true, submission }, origin);
      }

      if (action === "submissions_review") {
        const tSid = safeStr(target_submission_id);
        if (!tSid) return reply(400, { ok: false, error: "target_submission_id_required" }, origin);

        const decisionRaw = safeStr(data.decision || body.decision || data.status || body.status || "");
        const decision = normalizeSubmissionStatus(decisionRaw);
        if (!["approved", "rejected", "need_fix"].includes(decision)) {
          return reply(400, { ok: false, error: "decision_invalid" }, origin);
        }

        const sidIdx = sIdx["submission_id"];
        const found = findRowIndexByColValue(sRows, sidIdx, tSid);
        if (found === -1) return reply(404, { ok: false, error: "submission_not_found" }, origin);

        const rowNumber1Based = found + 2;
        const row = sRows[found] || [];
        const sLen = sHeaders.length;
        const fullRow = Array.from({ length: sLen }, (_, j) => safeStr(row[j] || ""));

        const currentStatus = safeStr(fullRow[sIdx["status"]]).toLowerCase();
        if (currentStatus !== "submitted") return reply(400, { ok: false, error: "not_submitted" }, origin);

        const adminId = safeStr(authPayload.user_id);
        const ts = nowISO();

        fullRow[sIdx["status"]] = decision;

        if (hasHeader(sHeaders, "reviewed_at")) fullRow[sIdx["reviewed_at"]] = ts;
        if (hasHeader(sHeaders, "reviewed_by")) fullRow[sIdx["reviewed_by"]] = adminId;

        const reason = sanitizeForSheet(data.reason || body.reason || "");
        if (reason) {
          if (hasHeader(sHeaders, "review_reason")) fullRow[sIdx["review_reason"]] = reason;
          if (hasHeader(sHeaders, "need_fix_reason") && decision === "need_fix") fullRow[sIdx["need_fix_reason"]] = reason;
        }
        if (hasHeader(sHeaders, "need_fix_at") && decision === "need_fix") fullRow[sIdx["need_fix_at"]] = ts;

        await updateRowRange(sheets, spreadsheetId, subsSheet, rowNumber1Based, sLen, fullRow);

        return reply(200, { ok: true, status: decision }, origin);
      }

      if (action === "submissions_payout") {
        const tSid = safeStr(target_submission_id);
        if (!tSid) return reply(400, { ok: false, error: "target_submission_id_required" }, origin);

        const sidIdx = sIdx["submission_id"];
        const found = findRowIndexByColValue(sRows, sidIdx, tSid);
        if (found === -1) return reply(404, { ok: false, error: "submission_not_found" }, origin);

        const rowNumber1Based = found + 2;
        const row = sRows[found] || [];
        const sLen = sHeaders.length;
        const fullRow = Array.from({ length: sLen }, (_, j) => safeStr(row[j] || ""));

        const st = safeStr(fullRow[sIdx["status"]]).toLowerCase();
        if (st !== "approved") return reply(400, { ok: false, error: "not_approved" }, origin);

        const payoutAlready = hasHeader(sHeaders, "payout_status") ? safeStr(fullRow[sIdx["payout_status"]]).toLowerCase() : "";
        if (payoutAlready === "paid") return reply(400, { ok: false, error: "already_paid" }, origin);

        const adminId = safeStr(authPayload.user_id);
        const ts = nowISO();

        const payoutAmount = sanitizeForSheet(data.payout_amount || body.payout_amount || data.amount || body.amount || "");
        if (hasHeader(sHeaders, "payout_amount") && payoutAmount) fullRow[sIdx["payout_amount"]] = payoutAmount;

        if (hasHeader(sHeaders, "payout_status")) fullRow[sIdx["payout_status"]] = "paid";
        if (hasHeader(sHeaders, "payout_at")) fullRow[sIdx["payout_at"]] = ts;
        if (hasHeader(sHeaders, "payout_by")) fullRow[sIdx["payout_by"]] = adminId;

        // 有些 UI 會想看到狀態變 paid（可選）
        // 不強制改 status，避免你未來狀態機想分開
        // 若你希望 payout 後 status=paid，可在表有該規則時自行調整
        if (hasHeader(sHeaders, "status_after_paid") && safeStr(fullRow[sIdx["status_after_paid"]])) {
          // nothing
        }

        await updateRowRange(sheets, spreadsheetId, subsSheet, rowNumber1Based, sLen, fullRow);

        return reply(200, { ok: true, payout_status: "paid", payout_at: ts, payout_by: adminId }, origin);
      }

      // 若進到這裡，表示是 dealers/snapshot/quests/submissions 但沒命中
      return reply(400, { ok: false, error: "unknown_action" }, origin);
    }

    // ===== fallback unknown action =====
    return reply(400, { ok: false, error: "unknown_action" }, origin);
  } catch (err) {
    console.error("admin.cjs error:", err);
    return reply(500, { ok: false, error: "server_error" }, origin);
  }
};
