// netlify/functions/quest-submissions.cjs
// ✅ Quest Submissions: member submit + list my submissions
// v2: robust quest_id matching (trim + remove zero-width/whitespace)

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
    "Access-Control-Allow-Headers": "content-type, authorization",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Max-Age": "86400",
  };
}

function json(statusCode, body, origin) {
  return {
    statusCode,
    headers: corsHeaders(origin),
    body: JSON.stringify(body),
  };
}

function getBearerToken(event) {
  const h = event.headers || {};
  const v = h.authorization || h.Authorization || "";
  const m = String(v).match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : "";
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

function sanitizeForSheet(value) {
  // Prevent Google Sheets formula injection
  const s = String(value ?? "");
  if (/^[=\+\-@]/.test(s)) return "'" + s;
  return s;
}

function normalizeId(s) {
  // Remove common invisible chars + all whitespace
  return String(s || "")
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .replace(/\s+/g, "")
    .trim();
}

async function getSheetsClient() {
  const saJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
  const sheetId = process.env.GOOGLE_SHEET_ID || process.env.SPREADSHEET_ID;

  if (!saJson) throw new Error("Missing GOOGLE_SERVICE_ACCOUNT_JSON");
  if (!sheetId) throw new Error("Missing GOOGLE_SHEET_ID (or SPREADSHEET_ID)");

  const credentials = JSON.parse(saJson);
  const auth = new google.auth.JWT(
    credentials.client_email,
    null,
    credentials.private_key,
    ["https://www.googleapis.com/auth/spreadsheets"]
  );

  const sheets = google.sheets({ version: "v4", auth });
  return { sheets, sheetId };
}

async function readTab(sheets, sheetId, tab) {
  const res = await sheets.spreadsheets.values.get({
    spreadsheetId: sheetId,
    range: `${tab}!A1:ZZ`,
  });
  const values = res.data.values || [];
  if (values.length === 0) return { headers: [], rows: [] };
  const headers = (values[0] || []).map(normalizeHeader);
  const rows = values.slice(1);
  return { headers, rows };
}

function rowToObject(headers, row) {
  const obj = {};
  headers.forEach((h, i) => {
    obj[h] = row[i] ?? "";
  });
  return obj;
}

async function appendRow(sheets, sheetId, tab, headers, obj) {
  const row = headers.map((h) => obj[h] ?? "");
  await sheets.spreadsheets.values.append({
    spreadsheetId: sheetId,
    range: `${tab}!A1`,
    valueInputOption: "RAW",
    insertDataOption: "INSERT_ROWS",
    requestBody: { values: [row] },
  });
}

function nowIso() {
  return new Date().toISOString();
}

function makeId(prefix) {
  const rnd = Math.random().toString(16).slice(2, 10);
  const ts = Date.now().toString(36);
  return `${prefix}_${ts}_${rnd}`;
}

function parseJsonBody(event) {
  try {
    return event.body ? JSON.parse(event.body) : {};
  } catch {
    return null;
  }
}

function asInt(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : fallback;
}

exports.handler = async (event) => {
  const origin = getRequestOrigin(event.headers);

  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: corsHeaders(origin), body: "" };
  }
  if (event.httpMethod !== "POST") {
    return json(405, { ok: false, error: "Method Not Allowed" }, origin);
  }
  if (!isOriginAllowed(origin)) {
    return json(403, { ok: false, error: "Forbidden" }, origin);
  }

  const user = requireAuth(event);
  if (!user) return json(401, { ok: false, error: "Unauthorized" }, origin);

  const body = parseJsonBody(event);
  if (!body) return json(400, { ok: false, error: "Invalid JSON" }, origin);

  const action = String(body.action || "").trim();

  try {
    const { sheets, sheetId } = await getSheetsClient();
    const submissionsTab = process.env.QUEST_SUBMISSIONS_TAB || "quest_submissions";
    const questsTab = process.env.QUESTS_TAB || "quests";

    if (action === "submit") {
      const quest_id = String(body.quest_id || "");
      const proof_url = String(body.proof_url || "").trim();
      const note = String(body.note || "").trim();

      const wantId = normalizeId(quest_id);
      if (!wantId) return json(400, { ok: false, error: "quest_id required" }, origin);

      const { headers: qh, rows: qrows } = await readTab(sheets, sheetId, questsTab);
      const qIdx = qh.indexOf("quest_id");
      if (qIdx < 0) return json(500, { ok: false, error: "quests header missing quest_id" }, origin);

      const questRow = qrows.find((r) => normalizeId(r[qIdx]) === wantId);
      if (!questRow) {
        // Provide minimal diagnostic without leaking too much
        const sample = qrows
          .map((r) => String(r[qIdx] || ""))
          .filter((x) => String(x).trim() !== "")
          .slice(0, 10);
        return json(404, { ok: false, error: "quest not found", want: String(quest_id || "").trim(), sample_ids: sample }, origin);
      }

      const quest = rowToObject(qh, questRow);

      const status = String(quest.status || "").toLowerCase().trim();
      if (status && status !== "active") return json(400, { ok: false, error: "quest not active" }, origin);

      const start_at = String(quest.start_at || "").trim();
      const end_at = String(quest.end_at || "").trim();
      const now = Date.now();
      if (start_at) {
        const t = Date.parse(start_at);
        if (!Number.isNaN(t) && now < t) return json(400, { ok: false, error: "quest not started" }, origin);
      }
      if (end_at) {
        const t = Date.parse(end_at);
        if (!Number.isNaN(t) && now > t) return json(400, { ok: false, error: "quest ended" }, origin);
      }

      const require_role = String(quest.require_role || "").trim();
      if (require_role && String(user.role || "") !== require_role) {
        return json(403, { ok: false, error: "role not allowed" }, origin);
      }

      const { headers: sh, rows: srows } = await readTab(sheets, sheetId, submissionsTab);
      const sQuestIdx = sh.indexOf("quest_id");
      const sUserIdx = sh.indexOf("user_id");
      const sStatusIdx = sh.indexOf("status");

      if (sQuestIdx < 0 || sUserIdx < 0) {
        return json(500, { ok: false, error: "quest_submissions headers missing quest_id/user_id" }, origin);
      }

      const existing = srows.filter((r) =>
        normalizeId(r[sQuestIdx]) === wantId &&
        String(r[sUserIdx] || "").trim() === String(user.user_id || "").trim()
      );

      const quota_per_user = asInt(quest.quota_per_user || 1, 1);
      const activeCount = existing.filter((r) => {
        const st = String(r[sStatusIdx] || "").toLowerCase().trim();
        return st !== "rejected" && st !== "need_fix";
      }).length;

      if (quota_per_user > 0 && activeCount >= quota_per_user) {
        return json(400, { ok: false, error: "quota_per_user reached" }, origin);
      }

      const quota_total = asInt(quest.quota_total || 0, 0);
      if (quota_total > 0) {
        const questCount = srows.filter((r) => {
          if (normalizeId(r[sQuestIdx]) !== wantId) return false;
          const st = String(r[sStatusIdx] || "").toLowerCase().trim();
          return st !== "rejected";
        }).length;
        if (questCount >= quota_total) {
          return json(400, { ok: false, error: "quota_total reached" }, origin);
        }
      }

      const submission_id = makeId("sub");
      const submitted_at = nowIso();

      const obj = {};
      sh.forEach((h) => (obj[h] = ""));
      obj["submission_id"] = submission_id;
      obj["quest_id"] = String(quest_id || "").trim();
      obj["user_id"] = String(user.user_id || "");
      obj["submitted_at"] = submitted_at;
      if (sh.includes("proof_url")) obj["proof_url"] = sanitizeForSheet(proof_url);
      if (sh.includes("note")) obj["note"] = sanitizeForSheet(note);
      obj["status"] = "submitted";

      await appendRow(sheets, sheetId, submissionsTab, sh, obj);

      return json(200, {
        ok: true,
        submission: {
          submission_id,
          quest_id: String(quest_id || "").trim(),
          user_id: String(user.user_id || ""),
          submitted_at,
          status: "submitted",
        },
      }, origin);
    }

    if (action === "list_my") {
      const { headers: sh, rows: srows } = await readTab(sheets, sheetId, submissionsTab);
      const sUserIdx = sh.indexOf("user_id");
      if (sUserIdx < 0) return json(500, { ok: false, error: "quest_submissions header missing user_id" }, origin);

      const my = srows
        .filter((r) => String(r[sUserIdx] || "").trim() === String(user.user_id || "").trim())
        .slice(-50)
        .reverse()
        .map((r) => rowToObject(sh, r));

      return json(200, { ok: true, submissions: my }, origin);
    }

    return json(400, { ok: false, error: "Unknown action" }, origin);
  } catch (e) {
    return json(500, { ok: false, error: "Server error" }, origin);
  }
};
