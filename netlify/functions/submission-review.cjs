// netlify/functions/submission-review.cjs
// ✅ Admin 審核任務提交（quest_submissions）→ 寫入 economy_ledger（award_once 防重複）→ 同步 dashboard.coins_calc
// - action=list_pending: 列出待審（status=submitted）
// - action=approve: 審核通過 + 發幣（ref_type=quest_submission, ref_id=submission_id）
// - action=reject: 退件（不發幣）
//
// 依賴環境變數：
// - GOOGLE_SERVICE_ACCOUNT_JSON
// - GOOGLE_SHEET_ID（或 SPREADSHEET_ID）
// - JWT_SECRET
// 可選：
// - QUESTS_TAB（預設 quests）
// - QUEST_SUBMISSIONS_TAB（預設 quest_submissions）
// - LEDGER_TAB（預設 economy_ledger）
// - DASHBOARD_TAB（預設 dashboard）
// - ALLOWED_ORIGINS（逗號分隔）

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

function isOriginAllowed(origin) {
  if (!origin) return false;
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
    "Vary": "Origin",
  };
}

function reply(statusCode, data, origin) {
  return { statusCode, headers: corsHeaders(origin), body: JSON.stringify(data) };
}

function safeStr(v) {
  return String(v ?? "").trim();
}

function nowISO() {
  return new Date().toISOString();
}

function getBearerToken(event) {
  const h = event.headers || {};
  const auth = h.authorization || h.Authorization || "";
  const m = String(auth).match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : "";
}

function requireAuth(event) {
  const token = getBearerToken(event);
  if (!token) return null;
  const secret = process.env.JWT_SECRET || "";
  if (!secret) return null;
  try {
    return jwt.verify(token, secret);
  } catch {
    return null;
  }
}

function isAdmin(payload) {
  return safeStr(payload?.role).toLowerCase() === "admin";
}

function normalizeHeader(name) {
  return safeStr(name).toLowerCase().replace(/\s+/g, "_");
}

function toNumber(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return null;
  return n;
}

// 將任意字串中的 quest_id / submission_id 萃取為乾淨的 id（避免隱形字元）
function extractId(raw, prefix) {
  const s = String(raw ?? "");
  const m = s.match(new RegExp(`${prefix}_[A-Za-z0-9_]+`));
  return m ? m[0] : safeStr(raw);
}

function getSheets() {
  const saJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
  const sheetId = process.env.GOOGLE_SHEET_ID || process.env.SPREADSHEET_ID;

  if (!saJson) throw new Error("Missing GOOGLE_SERVICE_ACCOUNT_JSON");
  if (!sheetId) throw new Error("Missing GOOGLE_SHEET_ID (or SPREADSHEET_ID)");

  const credentials = JSON.parse(saJson);
  const auth = new google.auth.JWT({
    email: credentials.client_email,
    key: credentials.private_key,
    scopes: ["https://www.googleapis.com/auth/spreadsheets"],
  });

  const sheets = google.sheets({ version: "v4", auth });
  return { sheets, sheetId };
}

function cell(row, i) {
  return i >= 0 ? (row[i] ?? "") : "";
}

/** economy_ledger helpers **/
function genLedgerId() {
  return "l_" + crypto.randomBytes(10).toString("hex");
}

function findApprovedByRef(rows, headers, { user_id, ref_type, ref_id }) {
  const hUser = headers.indexOf("user_id");
  const hRefType = headers.indexOf("ref_type");
  const hRefId = headers.indexOf("ref_id");
  const hStatus = headers.indexOf("status");

  for (let r = 0; r < rows.length; r++) {
    const row = rows[r];
    const ru = safeStr(cell(row, hUser));
    const rt = safeStr(cell(row, hRefType));
    const rid = safeStr(cell(row, hRefId));
    const st = safeStr(cell(row, hStatus)).toLowerCase();
    if (ru === user_id && rt === ref_type && rid === ref_id && st === "approved") {
      return { rowIndex0: r + 1, row }; // +1 because rows exclude header; still 0-based within data rows
    }
  }
  return null;
}

async function appendRow(sheets, sheetId, tab, rowValues) {
  await sheets.spreadsheets.values.append({
    spreadsheetId: sheetId,
    range: `${tab}!A:Z`,
    valueInputOption: "RAW",
    insertDataOption: "INSERT_ROWS",
    requestBody: { values: [rowValues] },
  });
}

async function updateRow(sheets, sheetId, tab, rowNumber1, values, startColLetter = "A") {
  await sheets.spreadsheets.values.update({
    spreadsheetId: sheetId,
    range: `${tab}!${startColLetter}${rowNumber1}:Z${rowNumber1}`,
    valueInputOption: "RAW",
    requestBody: { values: [values] },
  });
}

// 計算某 user 的 approved coins（單一真實來源）
async function sumApprovedCoinsFromLedger(sheets, sheetId, ledgerTab, userId) {
  const res = await sheets.spreadsheets.values.get({
    spreadsheetId: sheetId,
    range: `${ledgerTab}!A:Z`,
  });
  const values = res.data.values || [];
  if (values.length === 0) return 0;

  const headers = values[0].map(normalizeHeader);
  const rows = values.slice(1);

  const idxUser = headers.indexOf("user_id");
  const idxDelta = headers.indexOf("delta");
  const idxStatus = headers.indexOf("status");

  let sum = 0;
  for (const r of rows) {
    if (safeStr(cell(r, idxUser)) !== userId) continue;
    const st = safeStr(cell(r, idxStatus)).toLowerCase();
    if (st !== "approved") continue;
    const d = Number(cell(r, idxDelta));
    if (Number.isFinite(d)) sum += d;
  }
  return Math.trunc(sum);
}

// 同步 dashboard.coins_calc（D 欄），若沒有該 user_id 就 append 一列
async function syncDashboardCoins(sheets, sheetId, dashboardTab, userId, coins) {
  const res = await sheets.spreadsheets.values.get({
    spreadsheetId: sheetId,
    range: `${dashboardTab}!A:Z`,
  });
  const values = res.data.values || [];
  const headers = (values[0] || []).map(normalizeHeader);
  const rows = values.slice(1);

  // 期待 header：user_id, data_json, updated_at, coins_calc
  const idxUser = headers.indexOf("user_id");
  const idxData = headers.indexOf("data_json");
  const idxUpdated = headers.indexOf("updated_at");
  const idxCoins = headers.indexOf("coins_calc");

  // 如果缺 header，就直接跳過同步（不擋主流程）
  if (idxUser < 0 || idxCoins < 0) return { synced: false, reason: "dashboard_header_missing" };

  // 找 row
  let foundRowNumber1 = null;
  let foundRow = null;
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    if (safeStr(cell(r, idxUser)) === userId) {
      foundRowNumber1 = i + 2; // header is row 1
      foundRow = r;
      break;
    }
  }

  const now = nowISO();

  if (!foundRowNumber1) {
    // 新增：user_id, data_json, updated_at, coins_calc
    // 其他欄位若存在也一律留空
    const maxCols = Math.max(headers.length, 4);
    const newRow = new Array(maxCols).fill("");
    newRow[idxUser] = userId;
    if (idxData >= 0) newRow[idxData] = "{}";
    if (idxUpdated >= 0) newRow[idxUpdated] = now;
    newRow[idxCoins] = String(coins);
    await appendRow(sheets, sheetId, dashboardTab, newRow);
    return { synced: true, mode: "append" };
  }

  // 更新既有 row：只動 updated_at / coins_calc
  const updatedRow = [...foundRow];
  const maxCols = Math.max(updatedRow.length, headers.length);
  while (updatedRow.length < maxCols) updatedRow.push("");
  if (idxUpdated >= 0) updatedRow[idxUpdated] = now;
  updatedRow[idxCoins] = String(coins);

  await updateRow(sheets, sheetId, dashboardTab, foundRowNumber1, updatedRow, "A");
  return { synced: true, mode: "update", row: foundRowNumber1 };
}

/** Read table (A:Z) and map */
async function readTable(sheets, sheetId, tab) {
  const res = await sheets.spreadsheets.values.get({
    spreadsheetId: sheetId,
    range: `${tab}!A:Z`,
  });
  const values = res.data.values || [];
  const headers = (values[0] || []).map(normalizeHeader);
  const rows = values.slice(1);
  return { headers, rows };
}

function headerIndex(headers, name) {
  const idx = headers.indexOf(name);
  return idx;
}

async function handlerListPending(sheets, sheetId, questSubTab) {
  const { headers, rows } = await readTable(sheets, sheetId, questSubTab);
  const idxStatus = headerIndex(headers, "status");
  const idxSubmissionId = headerIndex(headers, "submission_id");
  const idxQuestId = headerIndex(headers, "quest_id");
  const idxUserId = headerIndex(headers, "user_id");
  const idxSubmittedAt = headerIndex(headers, "submitted_at");

  if (idxStatus < 0 || idxSubmissionId < 0) {
    return { ok: false, error: "quest_submissions_header_missing" };
  }

  const pending = [];
  for (const r of rows) {
    const st = safeStr(cell(r, idxStatus)).toLowerCase();
    if (st !== "submitted") continue;
    pending.push({
      submission_id: extractId(cell(r, idxSubmissionId), "sub"),
      quest_id: extractId(cell(r, idxQuestId), "q"),
      user_id: safeStr(cell(r, idxUserId)),
      submitted_at: safeStr(cell(r, idxSubmittedAt)),
      status: st,
    });
  }
  return { ok: true, pending, count: pending.length };
}

async function handlerApprove({ sheets, sheetId, tabs, authPayload, body }) {
  const questSubTab = tabs.questSubTab;
  const questsTab = tabs.questsTab;
  const ledgerTab = tabs.ledgerTab;
  const dashboardTab = tabs.dashboardTab;

  const submission_id = extractId(body.submission_id, "sub");
  if (!submission_id) return { ok: false, error: "missing_submission_id" };

  const { headers: subH, rows: subRows } = await readTable(sheets, sheetId, questSubTab);
  const idxSubId = headerIndex(subH, "submission_id");
  const idxQuestId = headerIndex(subH, "quest_id");
  const idxUserId = headerIndex(subH, "user_id");
  const idxStatus = headerIndex(subH, "status");
  const idxReviewReason = headerIndex(subH, "review_reason");
  const idxReviewedAt = headerIndex(subH, "reviewed_at");
  const idxReviewedBy = headerIndex(subH, "reviewed_by");
  const idxPayoutAmount = headerIndex(subH, "payout_amount");
  const idxPayoutAt = headerIndex(subH, "payout_at");
  const idxPayoutBy = headerIndex(subH, "payout_by");

  if (idxSubId < 0 || idxQuestId < 0 || idxUserId < 0 || idxStatus < 0) {
    return { ok: false, error: "quest_submissions_header_missing" };
  }

  let subRowIdx = -1;
  let subRow = null;

  for (let i = 0; i < subRows.length; i++) {
    const rawCell = String(cell(subRows[i], idxSubId) ?? "");
    const rid = extractId(rawCell, "sub");

    // 先做嚴格比對
    if (rid === submission_id) {
      subRowIdx = i;
      subRow = subRows[i];
      break;
    }

    // 再做寬鬆比對（避免 Sheets 儲存了不可見字元/額外內容）
    const rawTrim = rawCell.trim();
    if (rawTrim === submission_id) {
      subRowIdx = i;
      subRow = subRows[i];
      break;
    }
    if (rawTrim.includes(submission_id) || submission_id.includes(rid)) {
      subRowIdx = i;
      subRow = subRows[i];
      break;
    }
  }

  if (!subRow) return { ok: false, error: "submission_not_found", submission_id };

  const curStatus = safeStr(cell(subRow, idxStatus)).toLowerCase();
  if (curStatus !== "submitted") {
    return { ok: false, error: "invalid_status", status: curStatus };
  }

  const quest_id = extractId(cell(subRow, idxQuestId), "q");
  const user_id = safeStr(cell(subRow, idxUserId));
  if (!quest_id) return { ok: false, error: "missing_quest_id_in_submission" };
  if (!user_id) return { ok: false, error: "missing_user_id_in_submission" };

  // 讀 quests，取得 reward_min 作為預設 payout
  const { headers: qH, rows: qRows } = await readTable(sheets, sheetId, questsTab);
  const idxQId = headerIndex(qH, "quest_id");
  const idxRewardMin = headerIndex(qH, "reward_min");
  const idxRewardMax = headerIndex(qH, "reward_max");
  const idxTitle = headerIndex(qH, "title");

  let questRow = null;
  for (const r of qRows) {
    const qid = extractId(cell(r, idxQId), "q");
    if (qid === quest_id) {
      questRow = r;
      break;
    }
  }
  if (!questRow) return { ok: false, error: "quest_not_found", quest_id };

  const title = safeStr(cell(questRow, idxTitle));
  const rewardMin = toNumber(cell(questRow, idxRewardMin));
  const rewardMax = toNumber(cell(questRow, idxRewardMax));

  let payout = toNumber(body.payout_amount);
  if (payout === null) {
    // default: rewardMin else rewardMax else 0
    payout = rewardMin ?? rewardMax ?? 0;
  }
  payout = Math.trunc(payout);

  // award_once 寫入 economy_ledger（防重複）
  const { headers: lH, rows: lRows } = await readTable(sheets, sheetId, ledgerTab);
  const requiredLedgerHeaders = [
    "ledger_id","user_id","delta","reason","ref_type","ref_id","status",
    "created_at","created_by","approved_at","approved_by","notes"
  ];
  for (const h of requiredLedgerHeaders) {
    if (lH.indexOf(h) < 0) return { ok: false, error: "ledger_header_missing", missing: h };
  }

  const ref_type = "quest_submission";
  const ref_id = submission_id;

  const existing = findApprovedByRef(lRows, lH, { user_id, ref_type, ref_id });
  let ledger_id = existing ? safeStr(cell(existing.row, lH.indexOf("ledger_id"))) : null;
  let deduped = false;

  if (!existing) {
    ledger_id = genLedgerId();
    const now = nowISO();
    const row = new Array(lH.length).fill("");
    row[lH.indexOf("ledger_id")] = ledger_id;
    row[lH.indexOf("user_id")] = user_id;
    row[lH.indexOf("delta")] = String(payout);
    row[lH.indexOf("reason")] = safeStr(body.reason) || `quest_reward:${quest_id}`;
    row[lH.indexOf("ref_type")] = ref_type;
    row[lH.indexOf("ref_id")] = ref_id;
    row[lH.indexOf("status")] = "approved";
    row[lH.indexOf("created_at")] = now;
    row[lH.indexOf("created_by")] = safeStr(authPayload.user_id);
    row[lH.indexOf("approved_at")] = now;
    row[lH.indexOf("approved_by")] = safeStr(authPayload.user_id);
    row[lH.indexOf("notes")] = safeStr(body.notes) || `quest=${quest_id} title=${title}`;
    await appendRow(sheets, sheetId, ledgerTab, row);
  } else {
    deduped = true;
  }

  // 更新 quest_submissions：approved + reviewed/payout 欄位
  const now = nowISO();
  const updatedRow = [...subRow];
  const maxCols = Math.max(updatedRow.length, subH.length);
  while (updatedRow.length < maxCols) updatedRow.push("");

  updatedRow[idxStatus] = "approved";
  if (idxReviewReason >= 0) updatedRow[idxReviewReason] = safeStr(body.review_reason) || "";
  if (idxReviewedAt >= 0) updatedRow[idxReviewedAt] = now;
  if (idxReviewedBy >= 0) updatedRow[idxReviewedBy] = safeStr(authPayload.user_id);
  if (idxPayoutAmount >= 0) updatedRow[idxPayoutAmount] = String(payout);
  if (idxPayoutAt >= 0) updatedRow[idxPayoutAt] = now;
  if (idxPayoutBy >= 0) updatedRow[idxPayoutBy] = safeStr(authPayload.user_id);

  const rowNumber1 = subRowIdx + 2; // header row = 1
  await updateRow(sheets, sheetId, questSubTab, rowNumber1, updatedRow, "A");

  // 同步 dashboard.coins_calc
  const coins = await sumApprovedCoinsFromLedger(sheets, sheetId, ledgerTab, user_id);
  const syncRes = await syncDashboardCoins(sheets, sheetId, dashboardTab, user_id, coins);

  return {
    ok: true,
    submission_id,
    quest_id,
    user_id,
    payout_amount: payout,
    ledger: { ledger_id, deduped, ref_type, ref_id },
    dashboard_sync: syncRes,
    coins,
  };
}

async function handlerReject({ sheets, sheetId, tabs, authPayload, body }) {
  const questSubTab = tabs.questSubTab;

  const submission_id = extractId(body.submission_id, "sub");
  if (!submission_id) return { ok: false, error: "missing_submission_id" };

  const { headers: subH, rows: subRows } = await readTable(sheets, sheetId, questSubTab);
  const idxSubId = headerIndex(subH, "submission_id");
  const idxStatus = headerIndex(subH, "status");
  const idxReviewReason = headerIndex(subH, "review_reason");
  const idxReviewedAt = headerIndex(subH, "reviewed_at");
  const idxReviewedBy = headerIndex(subH, "reviewed_by");

  if (idxSubId < 0 || idxStatus < 0) return { ok: false, error: "quest_submissions_header_missing" };

  let subRowIdx = -1;
  let subRow = null;

  for (let i = 0; i < subRows.length; i++) {
    const rawCell = String(cell(subRows[i], idxSubId) ?? "");
    const rid = extractId(rawCell, "sub");

    // 先做嚴格比對
    if (rid === submission_id) {
      subRowIdx = i;
      subRow = subRows[i];
      break;
    }

    // 再做寬鬆比對（避免 Sheets 儲存了不可見字元/額外內容）
    const rawTrim = rawCell.trim();
    if (rawTrim === submission_id) {
      subRowIdx = i;
      subRow = subRows[i];
      break;
    }
    if (rawTrim.includes(submission_id) || submission_id.includes(rid)) {
      subRowIdx = i;
      subRow = subRows[i];
      break;
    }
  }
  if (!subRow) return { ok: false, error: "submission_not_found", submission_id };

  const now = nowISO();
  const updatedRow = [...subRow];
  const maxCols = Math.max(updatedRow.length, subH.length);
  while (updatedRow.length < maxCols) updatedRow.push("");

  updatedRow[idxStatus] = "rejected";
  if (idxReviewReason >= 0) updatedRow[idxReviewReason] = safeStr(body.review_reason) || "rejected";
  if (idxReviewedAt >= 0) updatedRow[idxReviewedAt] = now;
  if (idxReviewedBy >= 0) updatedRow[idxReviewedBy] = safeStr(authPayload.user_id);

  const rowNumber1 = subRowIdx + 2;
  await updateRow(sheets, sheetId, questSubTab, rowNumber1, updatedRow, "A");

  return { ok: true, submission_id, status: "rejected" };
}

exports.handler = async (event) => {
  const origin = event.headers?.origin || event.headers?.Origin || "";

  try {
    if (event.httpMethod === "OPTIONS") return reply(200, { ok: true }, origin);
    if (event.httpMethod !== "POST") return reply(405, { ok: false, error: "method_not_allowed" }, origin);
    if (origin && !isOriginAllowed(origin)) return reply(403, { ok: false, error: "origin_not_allowed" }, origin);

    const authPayload = requireAuth(event);
    if (!authPayload?.user_id) return reply(401, { ok: false, error: "unauthorized" }, origin);
    if (!isAdmin(authPayload)) return reply(403, { ok: false, error: "forbidden" }, origin);

    const body = JSON.parse(event.body || "{}");
    const action = safeStr(body.action).toLowerCase();

    const { sheets, sheetId } = getSheets();

    const tabs = {
      questsTab: process.env.QUESTS_TAB || "quests",
      questSubTab: process.env.QUEST_SUBMISSIONS_TAB || "quest_submissions",
      ledgerTab: process.env.LEDGER_TAB || "economy_ledger",
      dashboardTab: process.env.DASHBOARD_TAB || "dashboard",
    };

    if (action === "list_pending") {
      const data = await handlerListPending(sheets, sheetId, tabs.questSubTab);
      return reply(200, data, origin);
    }

    if (action === "approve") {
      const data = await handlerApprove({ sheets, sheetId, tabs, authPayload, body });
      return reply(200, data, origin);
    }

    if (action === "reject") {
      const data = await handlerReject({ sheets, sheetId, tabs, authPayload, body });
      return reply(200, data, origin);
    }

    return reply(400, { ok: false, error: "unknown_action" }, origin);
  } catch (e) {
    // 不回傳內部細節
    return reply(500, { ok: false, error: "server_error" }, origin);
  }
};
