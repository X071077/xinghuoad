// netlify/functions/dealer-listings.cjs
// ✅ Dealer 車源刊登草稿（dealer_listings）寫入/查詢 API
// - Dealer: 建立/查詢自己的 listing
// - Admin: 可查詢全部（後續審核流程會用到）
// ✅ CORS 白名單 + JWT 驗證 + Sheet 公式注入防護

const { google } = require('googleapis');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const DEFAULT_ALLOWED_ORIGINS = [
  'https://xinghuoad.xyz',
  'https://www.xinghuoad.xyz',
];

function getAllowedOrigins() {
  const env = String(process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
  return env.length ? env : DEFAULT_ALLOWED_ORIGINS;
}

function getRequestOrigin(headers = {}) {
  return headers.origin || headers.Origin || '';
}

function isOriginAllowed(origin) {
  if (!origin) return true; // allow server-to-server
  return getAllowedOrigins().includes(origin);
}

function corsHeaders(origin) {
  const allowOrigin = origin && isOriginAllowed(origin) ? origin : getAllowedOrigins()[0];
  return {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Credentials': 'true',
    Vary: 'Origin',
  };
}

function reply(statusCode, body, origin) {
  return { statusCode, headers: corsHeaders(origin), body: JSON.stringify(body) };
}

function nowISO() {
  return new Date().toISOString();
}

function safeStr(v) {
  return String(v == null ? '' : v).trim();
}

// ✅ 防公式注入：若以 = + - @ 開頭，前面加 '
function sanitizeForSheet(v) {
  const s = safeStr(v);
  if (!s) return '';
  return /^[=+\-@]/.test(s) ? `'${s}` : s;
}

function toNumber(v) {
  const n = Number(String(v || '').replace(/,/g, '').trim());
  return Number.isFinite(n) ? n : NaN;
}

function getBearerToken(event) {
  const h = event.headers || {};
  const auth = h.authorization || h.Authorization || '';
  const m = String(auth).match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : '';
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

async function getSheetsClient() {
  const saJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
  const sheetId = process.env.GOOGLE_SHEET_ID || process.env.SPREADSHEET_ID;
  const tab = process.env.DEALER_LISTINGS_TAB || 'dealer_listings';
  if (!saJson) throw new Error('Missing GOOGLE_SERVICE_ACCOUNT_JSON');
  if (!sheetId) throw new Error('Missing GOOGLE_SHEET_ID (or SPREADSHEET_ID)');

  const credentials = JSON.parse(saJson);
  const auth = new google.auth.JWT({
    email: credentials.client_email,
    key: credentials.private_key,
    scopes: ['https://www.googleapis.com/auth/spreadsheets'],
  });
  const sheets = google.sheets({ version: 'v4', auth });
  return { sheets, sheetId, tab };
}

async function readAllRows(sheets, sheetId, tab) {
  const res = await sheets.spreadsheets.values.get({
    spreadsheetId: sheetId,
    range: `${tab}!A:Z`,
  });
  const values = res.data.values || [];
  if (!values.length) return { headers: [], rows: [] };
  const headers = values[0].map(h => String(h || '').trim());
  const rows = values.slice(1);
  return { headers, rows };
}

function headerIndex(headers) {
  const m = {};
  headers.forEach((h, i) => (m[h] = i));
  return m;
}

function ensureHeaders(headers, want) {
  const missing = want.filter(h => !headers.includes(h));
  if (missing.length) throw new Error(`dealer_listings missing columns: ${missing.join(', ')}`);
}

function makeListingId() {
  return `dl_${crypto.randomBytes(10).toString('hex')}`;
}

function pickRow(row, idx, keys) {
  const out = {};
  for (const k of keys) out[k] = row[idx[k]] ?? '';
  return out;
}

exports.handler = async (event) => {
  const origin = getRequestOrigin(event.headers || {});
  try {
    if (event.httpMethod === 'OPTIONS') return reply(200, { ok: true }, origin);
    if (event.httpMethod !== 'POST') return reply(405, { ok: false, error: 'Method not allowed' }, origin);
    if (origin && !isOriginAllowed(origin)) return reply(403, { ok: false, error: 'origin_not_allowed' }, origin);

    const authPayload = requireAuth(event);
    if (!authPayload?.user_id) return reply(401, { ok: false, error: 'unauthorized' }, origin);

    const role = String(authPayload.role || '').toLowerCase();
    const body = JSON.parse(event.body || '{}');
    const action = safeStr(body.action);

    const { sheets, sheetId, tab } = await getSheetsClient();
    const { headers, rows } = await readAllRows(sheets, sheetId, tab);

    // expected schema
    const required = [
      'listing_id','dealer_id','user_id','title','car_info_json','budget_total','reward_min','reward_max',
      'status','submitted_at','reviewed_at','reviewed_by','review_note','quest_id','updated_at',
    ];
    if (!headers.length) return reply(500, { ok: false, error: 'dealer_listings_sheet_empty' }, origin);
    ensureHeaders(headers, required);

    const idx = headerIndex(headers);

    // --- Dealer create listing ---
    if (action === 'create') {
      if (!(role === 'dealer' || role === 'admin')) {
        return reply(403, { ok: false, error: 'forbidden' }, origin);
      }

      const listing_id = makeListingId();
      const dealer_id = safeStr(body.dealer_id || authPayload.dealer_id || '');
      const user_id = safeStr(body.user_id || authPayload.user_id || '');
      if (!user_id) return reply(400, { ok: false, error: 'missing_user_id' }, origin);

      // Dealer 身分只能替自己建立
      if (role === 'dealer' && user_id !== authPayload.user_id) {
        return reply(403, { ok: false, error: 'forbidden_user_mismatch' }, origin);
      }

      const title = safeStr(body.title);
      const car_info_json = safeStr(body.car_info_json || body.car_info || '');

      const budget_total = toNumber(body.budget_total);
      const reward_min = toNumber(body.reward_min);
      const reward_max = toNumber(body.reward_max);

      if (!title) return reply(400, { ok: false, error: 'missing_title' }, origin);
      if (!Number.isFinite(budget_total) || budget_total <= 0) {
        return reply(400, { ok: false, error: 'invalid_budget_total' }, origin);
      }
      if (!Number.isFinite(reward_min) || reward_min <= 0) {
        return reply(400, { ok: false, error: 'invalid_reward_min' }, origin);
      }
      if (!Number.isFinite(reward_max) || reward_max < reward_min) {
        return reply(400, { ok: false, error: 'invalid_reward_max' }, origin);
      }

      const now = nowISO();
      const status = 'submitted';

      const newRow = Array(headers.length).fill('');
      newRow[idx['listing_id']] = listing_id;
      newRow[idx['dealer_id']] = sanitizeForSheet(dealer_id);
      newRow[idx['user_id']] = user_id;
      newRow[idx['title']] = sanitizeForSheet(title);
      newRow[idx['car_info_json']] = sanitizeForSheet(car_info_json);
      newRow[idx['budget_total']] = String(budget_total);
      newRow[idx['reward_min']] = String(reward_min);
      newRow[idx['reward_max']] = String(reward_max);
      newRow[idx['status']] = status;
      newRow[idx['submitted_at']] = now;
      newRow[idx['updated_at']] = now;

      await sheets.spreadsheets.values.append({
        spreadsheetId: sheetId,
        range: `${tab}!A:Z`,
        valueInputOption: 'RAW',
        insertDataOption: 'INSERT_ROWS',
        requestBody: { values: [newRow] },
      });

      return reply(200, {
        ok: true,
        listing: {
          listing_id,
          dealer_id,
          user_id,
          title,
          budget_total,
          reward_min,
          reward_max,
          status,
          submitted_at: now,
        },
      }, origin);
    }

    // --- Dealer list own listings ---
    if (action === 'list_my') {
      if (!(role === 'dealer' || role === 'admin')) {
        return reply(403, { ok: false, error: 'forbidden' }, origin);
      }
      const targetUserId = safeStr(body.user_id || authPayload.user_id || '');
      if (role === 'dealer' && targetUserId !== authPayload.user_id) {
        return reply(403, { ok: false, error: 'forbidden_user_mismatch' }, origin);
      }

      const out = [];
      for (const r of rows) {
        const ru = safeStr(r[idx['user_id']]);
        if (ru && ru === targetUserId) {
          out.push(pickRow(r, idx, [
            'listing_id','dealer_id','user_id','title','budget_total','reward_min','reward_max',
            'status','submitted_at','reviewed_at','reviewed_by','review_note','quest_id','updated_at',
          ]));
        }
      }
      // newest first by submitted_at (string ISO)
      out.sort((a, b) => String(b.submitted_at || '').localeCompare(String(a.submitted_at || '')));
      return reply(200, { ok: true, listings: out.slice(0, 50) }, origin);
    }

    // --- Admin list all (for later review UI) ---
    if (action === 'list_all') {
      if (role !== 'admin') return reply(403, { ok: false, error: 'forbidden' }, origin);
      const out = rows.map(r => pickRow(r, idx, [
        'listing_id','dealer_id','user_id','title','car_info_json','budget_total','reward_min','reward_max',
        'status','submitted_at','reviewed_at','reviewed_by','review_note','quest_id','updated_at',
      ]));
      out.sort((a, b) => String(b.submitted_at || '').localeCompare(String(a.submitted_at || '')));
      return reply(200, { ok: true, listings: out.slice(0, 200) }, origin);
    }

    return reply(400, { ok: false, error: 'unknown_action' }, origin);
  } catch (e) {
    return reply(500, { ok: false, error: 'internal_error' }, origin);
  }
};
