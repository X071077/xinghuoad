// netlify/functions/quests.cjs
// ✅ 任務 API（最小閉環 v1）：列出可接任務（active）+ quota 計算（依 quest_submissions）
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

function isOriginAllowed(origin) {
  if (!origin) return false;
  const allowed = getAllowedOrigins();
  return allowed.includes(origin);
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
  return {
    statusCode,
    headers: corsHeaders(origin),
    body: JSON.stringify(data),
  };
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
  } catch (e) {
    return null;
  }
}

function toInt(v, fallback = 0) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.trunc(n);
}

function parseDateSafe(v) {
  // 支援 ISO / yyyy-mm-dd / 空字串
  const s = String(v || "").trim();
  if (!s) return null;
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return null;
  return d;
}

async function getSheetsClient() {
  const saJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
  const sheetId = process.env.GOOGLE_SHEET_ID || process.env.SPREADSHEET_ID;

  if (!saJson) throw new Error("Missing GOOGLE_SERVICE_ACCOUNT_JSON");
  if (!sheetId) throw new Error("Missing GOOGLE_SHEET_ID (or SPREADSHEET_ID)");

  const creds = JSON.parse(saJson);
  const auth = new google.auth.JWT(
    creds.client_email,
    null,
    creds.private_key,
    ["https://www.googleapis.com/auth/spreadsheets"]
  );

  const sheets = google.sheets({ version: "v4", auth });
  return { sheets, sheetId };
}

function rowToObj(headers, row) {
  const obj = {};
  headers.forEach((h, i) => (obj[h] = row[i] ?? ""));
  return obj;
}

function normStatus(s) {
  return String(s || "").trim().toLowerCase();
}

exports.handler = async (event) => {
  const origin = (event.headers && (event.headers.origin || event.headers.Origin)) || "";

  if (event.httpMethod === "OPTIONS") {
    return reply(200, { ok: true }, origin);
  }
  if (event.httpMethod !== "POST") {
    return reply(405, { ok: false, error: "Method Not Allowed" }, origin);
  }

  let body = {};
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return reply(400, { ok: false, error: "Invalid JSON" }, origin);
  }

  const action = String(body.action || "list_active").trim();

  // 目前所有任務讀取都要求登入（避免未登入被爬取）
  const user = requireAuth(event);
  if (!user) return reply(401, { ok: false, error: "Unauthorized" }, origin);

  try {
    const { sheets, sheetId } = await getSheetsClient();
    const questsTab = process.env.QUESTS_TAB || "quests";
    const subsTab = process.env.QUEST_SUBMISSIONS_TAB || "quest_submissions";

    if (action === "list_active") {
      // 讀 quests
      const qRes = await sheets.spreadsheets.values.get({
        spreadsheetId: sheetId,
        range: `${questsTab}!A1:Z`,
      });
      const qValues = qRes.data.values || [];
      if (qValues.length < 1) {
        return reply(200, { ok: true, quests: [] }, origin);
      }
      const qHeaders = qValues[0].map((h) => String(h || "").trim());
      const qRows = qValues.slice(1).filter((r) => r && r.some((c) => String(c || "").trim() !== ""));
      const quests = qRows.map((r) => rowToObj(qHeaders, r));

      // 讀 submissions（用來算 quota）
      const sRes = await sheets.spreadsheets.values.get({
        spreadsheetId: sheetId,
        range: `${subsTab}!A1:Z`,
      });
      const sValues = sRes.data.values || [];
      const sHeaders = (sValues[0] || []).map((h) => String(h || "").trim());
      const sRows = sValues.slice(1).filter((r) => r && r.some((c) => String(c || "").trim() !== ""));
      const subs = sRows.map((r) => rowToObj(sHeaders, r));

      const now = new Date();

      const active = quests
        .filter((q) => normStatus(q.status) === "active")
        .filter((q) => {
          const start = parseDateSafe(q.start_at);
          const end = parseDateSafe(q.end_at);
          if (start && now < start) return false;
          if (end && now > end) return false;
          // require_role：空字串=不限
          const reqRole = String(q.require_role || "").trim();
          if (reqRole && String(user.role || "") !== reqRole) return false;
          return true;
        })
        .map((q) => {
          const questId = String(q.quest_id || "").trim();
          const quotaTotal = toInt(q.quota_total, 0);
          const quotaPerUser = toInt(q.quota_per_user, 0);

          const relevant = subs.filter((s) => String(s.quest_id || "").trim() === questId);
          // 計入占用的狀態：submitted/approved/paid（避免 rejected 佔額）
          const occupied = relevant.filter((s) => {
            const st = normStatus(s.status);
            return st === "submitted" || st === "approved" || st === "paid" || st === "payout" || st === "completed";
          });

          const usedTotal = occupied.length;

          const myUsed = occupied.filter((s) => String(s.user_id || "").trim() === String(user.user_id || "")).length;

          const remaining = quotaTotal > 0 ? Math.max(0, quotaTotal - usedTotal) : null;
          const canTakeByTotal = quotaTotal > 0 ? remaining > 0 : true;
          const canTakeByUser = quotaPerUser > 0 ? myUsed < quotaPerUser : true;

          return {
            ...q,
            quota_used: usedTotal,
            quota_remaining: remaining,
            my_submissions: myUsed,
            can_take: Boolean(canTakeByTotal && canTakeByUser),
          };
        });

      return reply(200, { ok: true, quests: active }, origin);
    }

    return reply(400, { ok: false, error: "Unknown action" }, origin);
  } catch (e) {
    return reply(500, { ok: false, error: "Server error" }, origin);
  }
};
