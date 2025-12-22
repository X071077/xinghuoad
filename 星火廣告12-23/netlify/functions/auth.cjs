// netlify/functions/auth.cjs
const { google } = require("googleapis");
const crypto = require("crypto");
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

function colToA1(n) {
  // 0 -> A, 25 -> Z, 26 -> AA
  let s = "";
  n = n + 1;
  while (n > 0) {
    const m = (n - 1) % 26;
    s = String.fromCharCode(65 + m) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
}

function nowISO() {
  return new Date().toISOString();
}

function makeUserId() {
  return "u_" + crypto.randomBytes(12).toString("hex");
}

function normalizeHeader(h) {
  return String(h || "").trim();
}

function makePasswordHash(password, pepper) {
  const salt = crypto.randomBytes(16).toString("hex");
  const key = crypto.scryptSync(password + pepper, salt, 64).toString("hex");
  // 格式：scrypt$<salt>$<hash>
  return `scrypt$${salt}$${key}`;
}

function verifyPassword(password, pepper, stored) {
  const parts = String(stored || "").split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") return false;
  const salt = parts[1];
  const hash = parts[2];
  const key = crypto.scryptSync(password + pepper, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(key, "hex"), Buffer.from(hash, "hex"));
}

async function getSheets() {
  const sheetId = process.env.GOOGLE_SHEET_ID;
  const tab = process.env.GOOGLE_SHEET_TAB;
  const saJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;

  if (!sheetId || !tab || !saJson) {
    throw new Error("Missing env vars: GOOGLE_SHEET_ID / GOOGLE_SHEET_TAB / GOOGLE_SERVICE_ACCOUNT_JSON");
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
  // 讀取整張表（欄位順序可變，所以靠表頭對應）
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

function buildHeaderIndex(headers) {
  const idx = {};
  headers.forEach((h, i) => {
    if (h) idx[h] = i;
  });
  return idx;
}

exports.handler = async (event) => {
  try {
    if (event.httpMethod === "OPTIONS") {
      return reply(200, { ok: true });
    }
    if (event.httpMethod !== "POST") {
      return reply(405, { error: "Method not allowed" });
    }

    const { action, username, password, name } = JSON.parse(event.body || "{}");

    if (!action || !["register", "login"].includes(action)) {
      return reply(400, { error: "Invalid action. Use register or login." });
    }
    if (!username || typeof username !== "string" || username.trim().length < 3) {
      return reply(400, { error: "username too short (>=3)" });
    }
    if (!password || typeof password !== "string" || password.length < 6) {
      return reply(400, { error: "password too short (>=6)" });
    }

    const pepper = process.env.AUTH_PEPPER || "";
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) return reply(500, { error: "Missing JWT_SECRET" });

    const { sheets, sheetId, tab } = await getSheets();
    const { headers, rows } = await loadAllRows(sheets, sheetId, tab);

    const required = ["username", "password_hash", "create_at", "last_login_at", "user_id", "name"];
    const headerIdx = buildHeaderIndex(headers);

    // 允許你表頭沒有全部，但至少要有這三個
    const mustHave = ["username", "password_hash", "user_id"];
    for (const k of mustHave) {
      if (headerIdx[k] === undefined) {
        return reply(500, { error: `Sheet missing header: ${k}` });
      }
    }

    const uCol = headerIdx["username"];
    const pCol = headerIdx["password_hash"];

    const u = username.trim();

    // 找使用者所在的「資料列」（0-based for rows array; 真實 sheet row = +2）
    let foundRowIndex = -1;
    for (let i = 0; i < rows.length; i++) {
      const cell = (rows[i][uCol] || "").trim();
      if (cell === u) {
        foundRowIndex = i;
        break;
      }
    }

    if (action === "register") {
      if (foundRowIndex !== -1) {
        return reply(409, { error: "username already exists" });
      }

      const user_id = makeUserId();
      const password_hash = makePasswordHash(password, pepper);

      // 依照「你表頭的順序」組出一列資料
      const newRow = new Array(headers.length).fill("");
      if (headerIdx["name"] !== undefined) newRow[headerIdx["name"]] = (name || "").trim();
      newRow[headerIdx["username"]] = u;
      newRow[headerIdx["password_hash"]] = password_hash;
      if (headerIdx["create_at"] !== undefined) newRow[headerIdx["create_at"]] = nowISO();
      if (headerIdx["last_login_at"] !== undefined) newRow[headerIdx["last_login_at"]] = "";
      newRow[headerIdx["user_id"]] = user_id;

      await sheets.spreadsheets.values.append({
        spreadsheetId: sheetId,
        range: `${tab}!A:Z`,
        valueInputOption: "RAW",
        insertDataOption: "INSERT_ROWS",
        requestBody: { values: [newRow] },
      });

      const token = jwt.sign({ user_id, username: u }, jwtSecret, { expiresIn: "30d" });
      return reply(200, { ok: true, user: { user_id, username: u }, token });
    }

    // action === "login"
    if (foundRowIndex === -1) {
      return reply(401, { error: "invalid username or password" });
    }

    const row = rows[foundRowIndex];
    const storedHash = row[pCol] || "";
    const ok = verifyPassword(password, pepper, storedHash);
    if (!ok) return reply(401, { error: "invalid username or password" });

    // 更新 last_login_at
    if (headerIdx["last_login_at"] !== undefined) {
      const sheetRowNumber = foundRowIndex + 2; // +1 header, +1 to 1-based
      const colLetter = colToA1(headerIdx["last_login_at"]);
      const a1 = `${tab}!${colLetter}${sheetRowNumber}`;
      await sheets.spreadsheets.values.update({
        spreadsheetId: sheetId,
        range: a1,
        valueInputOption: "RAW",
        requestBody: { values: [[nowISO()]] },
      });
    }

    // 取 user_id
    const uid = row[headerIdx["user_id"]] || "";
    const token = jwt.sign({ user_id: uid, username: u }, jwtSecret, { expiresIn: "30d" });
    return reply(200, { ok: true, user: { user_id: uid, username: u }, token });
  } catch (err) {
    return reply(500, { error: "server_error", detail: String(err && err.message ? err.message : err) });
  }
};
