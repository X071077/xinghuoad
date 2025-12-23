// netlify/functions/dashboard.cjs
const { google } = require("googleapis");
const jwt = require("jsonwebtoken");

function reply(statusCode, data) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Methods": "POST,OPTIONS",
    },
    body: JSON.stringify(data),
  };
}

function nowISO() {
  return new Date().toISOString();
}

function safeParse(json, fallback) {
  try { return JSON.parse(json); } catch { return fallback; }
}

function normalizeHeader(h) {
  return String(h || "").trim();
}

function buildHeaderIndex(headers) {
  const idx = {};
  headers.forEach((h, i) => { if (h) idx[h] = i; });
  return idx;
}

function colToA1(n) {
  let s = "";
  n = n + 1;
  while (n > 0) {
    const m = (n - 1) % 26;
    s = String.fromCharCode(65 + m) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
}

function getBearerToken(event) {
  const auth = event.headers?.authorization || event.headers?.Authorization || "";
  const m = String(auth).match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : "";
}

function requireAuth(event) {
  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) throw new Error("Missing JWT_SECRET");
  const token = getBearerToken(event);
  if (!token) return null;
  try {
    return jwt.verify(token, jwtSecret); // { user_id, username, iat, exp }
  } catch {
    return null;
  }
}

// ===== Default "all zero" data for NEW users =====
const DEFAULT_DATA = {
  my_quests: [],
  stats: {
    level: 0,
    xp: 0,
    nextLevelXP: 100,
    totalEarned: 0,        // 金幣
    todayEarnings: 0,      // 今日收益
    monthEarnings: 0,      // 本月累積
    completedQuests: 0,    // 已完成任務
    activeDays: 0,         // 活躍天數
  },
};

function normalizeIncomingData(incoming) {
  const statsIn = (incoming && typeof incoming === "object") ? incoming.stats : null;
  const myQuestsIn = (incoming && typeof incoming === "object") ? incoming.my_quests : null;

  const stats = {
    ...DEFAULT_DATA.stats,
    ...(statsIn && typeof statsIn === "object" ? statsIn : {}),
  };

  // 強制數字化（避免傳字串）
  for (const k of Object.keys(stats)) {
    const v = Number(stats[k]);
    stats[k] = Number.isFinite(v) ? v : DEFAULT_DATA.stats[k];
  }

  const my_quests = Array.isArray(myQuestsIn) ? myQuestsIn : DEFAULT_DATA.my_quests;

  return { my_quests, stats };
}

// ===== Google Sheets =====
async function getSheets() {
  const sheetId = process.env.GOOGLE_SHEET_ID;
  const tab = process.env.GOOGLE_DASHBOARD_TAB; // 你建立好的 dashboard 分頁名
  const saJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;

  if (!sheetId || !tab || !saJson) {
    throw new Error("Missing env vars: GOOGLE_SHEET_ID / GOOGLE_DASHBOARD_TAB / GOOGLE_SERVICE_ACCOUNT_JSON");
  }

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

exports.handler = async (event) => {
  try {
    if (event.httpMethod === "OPTIONS") return reply(200, { ok: true });
    if (event.httpMethod !== "POST") return reply(405, { error: "Method not allowed" });

    const authPayload = requireAuth(event);
    if (!authPayload?.user_id) return reply(401, { error: "unauthorized" });

    const body = safeParse(event.body || "{}", {});
    const action = String(body?.action || "").trim();
    if (!["get", "save"].includes(action)) {
      return reply(400, { error: "Invalid action. Use get or save." });
    }

    const { sheets, sheetId, tab } = await getSheets();
    const { headers, rows } = await loadAllRows(sheets, sheetId, tab);
    const headerIdx = buildHeaderIndex(headers);

    const mustHave = ["user_id", "data_json", "updated_at"];
    for (const k of mustHave) {
      if (headerIdx[k] === undefined) {
        return reply(500, { error: `Sheet missing header: ${k}` });
      }
    }

    const uid = String(authPayload.user_id);
    const uidCol = headerIdx["user_id"];

    let foundRowIndex = -1;
    for (let i = 0; i < rows.length; i++) {
      const cell = String(rows[i][uidCol] || "").trim();
      if (cell === uid) { foundRowIndex = i; break; }
    }

    // ---------- GET: 如果找不到該 user_id，就自動建立全 0 初始資料 ----------
    if (action === "get") {
      if (foundRowIndex === -1) {
        const initData = DEFAULT_DATA;
        const updatedAt = nowISO();
        const newRow = new Array(headers.length).fill("");
        newRow[headerIdx["user_id"]] = uid;
        newRow[headerIdx["data_json"]] = JSON.stringify(initData);
        newRow[headerIdx["updated_at"]] = updatedAt;

        await sheets.spreadsheets.values.append({
          spreadsheetId: sheetId,
          range: `${tab}!A:Z`,
          valueInputOption: "RAW",
          insertDataOption: "INSERT_ROWS",
          requestBody: { values: [newRow] },
        });

        return reply(200, { ok: true, data: initData, updated_at: updatedAt });
      }

      const row = rows[foundRowIndex];
      const dataJson = row[headerIdx["data_json"]] || "{}";
      const updatedAt = row[headerIdx["updated_at"]] || "";

      const dataRaw = safeParse(dataJson, DEFAULT_DATA);
      const data = normalizeIncomingData(dataRaw);

      return reply(200, { ok: true, data, updated_at: updatedAt || null });
    }

    // ---------- SAVE: 存回雲端（登出時呼叫） ----------
    if (action === "save") {
      const incoming = body?.data ?? {};
      const data = normalizeIncomingData(incoming);
      const dataJson = JSON.stringify(data);
      const updatedAt = nowISO();

      if (foundRowIndex === -1) {
        const newRow = new Array(headers.length).fill("");
        newRow[headerIdx["user_id"]] = uid;
        newRow[headerIdx["data_json"]] = dataJson;
        newRow[headerIdx["updated_at"]] = updatedAt;

        await sheets.spreadsheets.values.append({
          spreadsheetId: sheetId,
          range: `${tab}!A:Z`,
          valueInputOption: "RAW",
          insertDataOption: "INSERT_ROWS",
          requestBody: { values: [newRow] },
        });

        return reply(200, { ok: true, updated_at: updatedAt });
      }

      const sheetRowNumber = foundRowIndex + 2; // + header row
      const colData = colToA1(headerIdx["data_json"]);
      const colUpdated = colToA1(headerIdx["updated_at"]);

      await sheets.spreadsheets.values.update({
        spreadsheetId: sheetId,
        range: `${tab}!${colData}${sheetRowNumber}:${colUpdated}${sheetRowNumber}`,
        valueInputOption: "RAW",
        requestBody: { values: [[dataJson, updatedAt]] },
      });

      return reply(200, { ok: true, updated_at: updatedAt });
    }

    return reply(400, { error: "bad_request" });
  } catch (err) {
    return reply(500, { error: "server_error", detail: String(err?.message || err) });
  }
};
	