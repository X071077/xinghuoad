// netlify/functions/dashboard.cjs
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

function getRequestOrigin(headers = {}) {
  return headers.origin || headers.Origin || "";
}

function isOriginAllowed(origin) {
  if (!origin) return true;
  return getAllowedOrigins().includes(origin);
}

function corsHeaders(origin) {
  const allowOrigin = origin && isOriginAllowed(origin) ? origin : getAllowedOrigins()[0];
  return {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Vary": "Origin",
  };
}

function reply(statusCode, data, origin) {
  return { statusCode, headers: corsHeaders(origin), body: JSON.stringify(data) };
}

function nowISO() {
  return new Date().toISOString();
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

function normalizeHeader(s) {
  return String(s || "").trim().toLowerCase();
}

function toNumber(v) {
  const n = Number(String(v || "").replace(/,/g, "").trim());
  return Number.isFinite(n) ? n : 0;
}


function colToA1(colIndex0Based) {
  let n = colIndex0Based + 1;
  let s = "";
  while (n > 0) {
    const mod = (n - 1) % 26;
    s = String.fromCharCode(65 + mod) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
}

const DEFAULT_DATA = {
  stats: { coins: 0, xp: 0, level: 1 },
  my_quests: [],
};

async function getSheets() {
  const saJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
  const sheetId = process.env.GOOGLE_SHEET_ID || process.env.SPREADSHEET_ID;
  const tab = process.env.DASHBOARD_TAB || "dashboard";

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

// ✅ 以 economy_ledger 為單一真實來源：計算某 user 的 approved coins
async function sumApprovedCoinsFromLedger(sheets, sheetId, ledgerTab, userId) {
  const res = await sheets.spreadsheets.values.get({
    spreadsheetId: sheetId,
    range: `${ledgerTab}!A:Z`,
  });
  const values = res.data.values || [];
  if (values.length === 0) return 0;

  const headers = values[0].map(normalizeHeader);
  const rows = values.slice(1);

  const idx = {};
  headers.forEach((h, i) => (idx[h] = i));

  // 必要欄位：user_id / delta / status
  const userIdx = idx["user_id"];
  const deltaIdx = idx["delta"];
  const statusIdx = idx["status"];
  if (userIdx === undefined || deltaIdx === undefined || statusIdx === undefined) return 0;

  let sum = 0;
  for (const r of rows) {
    const uid = String(r[userIdx] || "").trim();
    if (!uid || uid !== userId) continue;
    const status = String(r[statusIdx] || "").trim().toLowerCase();
    if (status !== "approved") continue;
    sum += toNumber(r[deltaIdx]);
  }
  return sum;
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
    const action = String(body.action || "").trim();

    const { sheets, sheetId, tab } = await getSheets();
    const { headers, rows } = await loadAllRows(sheets, sheetId, tab);

    const headerIdx = {};
    headers.forEach((h, i) => (headerIdx[h] = i));

    for (const k of ["user_id", "data_json", "updated_at"]) {
      if (headerIdx[k] === undefined) {
        return reply(500, { ok: false, error: `sheet_missing_header_${k}` }, origin);
      }
    }

    const coinsCalcIdx = headerIdx["coins_calc"]; // optional
    const ledgerTab = process.env.ECONOMY_LEDGER_TAB || "economy_ledger";

    const uid = String(authPayload.user_id);
    const uidCol = headerIdx["user_id"];

    let foundRowIndex = -1;
    for (let i = 0; i < rows.length; i++) {
      const cell = String(rows[i][uidCol] || "").trim();
      if (cell === uid) {
        foundRowIndex = i;
        break;
      }
    }

    if (action === "get") {
      if (foundRowIndex === -1) {
        const initData = DEFAULT_DATA;
        const updatedAt = nowISO();

        // ✅ 新用戶初始 coins 也以 ledger approved 加總為準（避免先入帳後建立 dashboard row 顯示錯誤）
        const initCoins = await sumApprovedCoinsFromLedger(sheets, sheetId, ledgerTab, uid);
        const newRow = new Array(headers.length).fill("");
        newRow[headerIdx["user_id"]] = uid;
        newRow[headerIdx["data_json"]] = JSON.stringify(initData);
        newRow[headerIdx["updated_at"]] = updatedAt;

        // 初始化 coins_calc（若欄位存在）
        if (coinsCalcIdx !== undefined) newRow[coinsCalcIdx] = String(initCoins);

        await sheets.spreadsheets.values.append({
          spreadsheetId: sheetId,
          range: `${tab}!A:Z`,
          valueInputOption: "RAW",
          insertDataOption: "INSERT_ROWS",
          requestBody: { values: [newRow] },
        });

        return reply(200, { ok: true, data: initData, updated_at: updatedAt, created: true, coins_calc: initCoins }, origin);
      }

      const row = rows[foundRowIndex];
      const dataJson = String(row[headerIdx["data_json"]] || "").trim();
      const updatedAt = String(row[headerIdx["updated_at"]] || "").trim();
      // 先讀 sheet 的 coins_calc（快取/顯示用）
      const coinsCalcInSheet = coinsCalcIdx === undefined ? 0 : toNumber(row[coinsCalcIdx]);

      // ✅ 真實 coins 以 economy_ledger approved 加總為準
      const coinsCalc = await sumApprovedCoinsFromLedger(sheets, sheetId, ledgerTab, uid);

      // 若 dashboard.coins_calc 與真實值不同，順手回寫（保持快取一致）
      if (coinsCalcIdx !== undefined && coinsCalc !== coinsCalcInSheet) {
        const sheetRowNumber = foundRowIndex + 2;
        const colCoins = colToA1(coinsCalcIdx);
        await sheets.spreadsheets.values.update({
          spreadsheetId: sheetId,
          range: `${tab}!${colCoins}${sheetRowNumber}:${colCoins}${sheetRowNumber}`,
          valueInputOption: "RAW",
          requestBody: { values: [[String(coinsCalc)]] },
        });
      }


      let parsed = null;
      try {
        parsed = dataJson ? JSON.parse(dataJson) : null;
      } catch {
        parsed = null;
      }

      const statsIn = parsed && parsed.stats ? parsed.stats : null;
      const myQuestsIn = parsed && Array.isArray(parsed.my_quests) ? parsed.my_quests : null;

      const stats = {
        ...DEFAULT_DATA.stats,
        ...(statsIn && typeof statsIn === "object" ? statsIn : {}),
      };

      // ✅ coins 以 economy_ledger 為單一真實來源
      stats.coins = coinsCalc;
      stats.totalEarned = coinsCalc;

      const data = {
        stats,
        my_quests: Array.isArray(myQuestsIn) ? myQuestsIn : DEFAULT_DATA.my_quests,
      };

      return reply(200, { ok: true, data, updated_at: updatedAt, coins_calc: coinsCalc }, origin);
    }

    if (action === "save") {
      if (foundRowIndex === -1) return reply(404, { ok: false, error: "user_not_found" }, origin);

      const payload = body.data || {};
      const row = rows[foundRowIndex];
      // ✅ 真實 coins 以 economy_ledger approved 加總為準
      const coinsCalc = await sumApprovedCoinsFromLedger(sheets, sheetId, ledgerTab, uid);
      const statsIn = payload && payload.stats ? payload.stats : null;
      const myQuestsIn = payload && Array.isArray(payload.my_quests) ? payload.my_quests : null;

      const safeStats = {
        ...DEFAULT_DATA.stats,
        ...(statsIn && typeof statsIn === "object" ? statsIn : {}),
      };

      // ✅ 不允許前台自行改動 coins：以 ledger 加總為準
      safeStats.coins = coinsCalc;
      safeStats.totalEarned = coinsCalc;

      const safeData = {
        stats: safeStats,
        my_quests: Array.isArray(myQuestsIn) ? myQuestsIn : [],
      };

      const dataJson = JSON.stringify(safeData);
      const updatedAt = nowISO();

      const sheetRowNumber = foundRowIndex + 2;
      const colData = colToA1(headerIdx["data_json"]);
      const colUpdated = colToA1(headerIdx["updated_at"]);

      await sheets.spreadsheets.values.update({
        spreadsheetId: sheetId,
        range: `${tab}!${colData}${sheetRowNumber}:${colUpdated}${sheetRowNumber}`,
        valueInputOption: "RAW",
        requestBody: { values: [[dataJson, updatedAt]] },
      });

      // 同步回寫 coins_calc（若欄位存在）
      if (coinsCalcIdx !== undefined) {
        const colCoins = colToA1(coinsCalcIdx);
        await sheets.spreadsheets.values.update({
          spreadsheetId: sheetId,
          range: `${tab}!${colCoins}${sheetRowNumber}:${colCoins}${sheetRowNumber}`,
          valueInputOption: "RAW",
          requestBody: { values: [[String(coinsCalc)]] },
        });
      }

      return reply(200, { ok: true, updated_at: updatedAt }, origin);
    }

    return reply(400, { ok: false, error: "bad_request" }, origin);
  } catch (err) {
    console.error("dashboard.cjs error:", err);
    return reply(500, { ok: false, error: "server_error" }, origin);
  }
};
