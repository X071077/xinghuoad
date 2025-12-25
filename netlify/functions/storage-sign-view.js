const { createClient } = require("@supabase/supabase-js");
const jwt = require("jsonwebtoken");

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function resJson(statusCode, obj) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json; charset=utf-8", ...corsHeaders },
    body: JSON.stringify(obj),
  };
}

function getBearerToken(authHeader) {
  if (!authHeader) return null;
  const m = String(authHeader).match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

function requireAdmin(event) {
  const JWT_SECRET = process.env.JWT_SECRET;
  if (!JWT_SECRET) {
    return { ok: false, status: 500, error: "Missing JWT_SECRET env var" };
  }

  const token = getBearerToken(event.headers?.authorization || event.headers?.Authorization);
  if (!token) {
    return { ok: false, status: 401, error: "Missing Authorization Bearer token" };
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);

    // 這裡假設你的 auth token payload 內有 role 或 roles
    // 常見兩種：
    // 1) payload.role === "admin"
    // 2) payload.roles 包含 "admin"
    const role = payload?.role;
    const roles = payload?.roles;

    const isAdmin =
      role === "admin" ||
      (Array.isArray(roles) && roles.includes("admin"));

    if (!isAdmin) {
      return { ok: false, status: 403, error: "Admin only" };
    }

    return { ok: true, payload };
  } catch (e) {
    return { ok: false, status: 401, error: "Invalid token" };
  }
}

function isSafePath(p) {
  if (typeof p !== "string") return false;
  const s = p.trim();
  if (!s) return false;
  if (s.includes("..")) return false;
  if (s.includes("\\")) return false;
  return /^[a-zA-Z0-9._\-\/]+$/.test(s);
}

exports.handler = async (event) => {
  try {
    if (event.httpMethod === "OPTIONS") {
      return { statusCode: 200, headers: corsHeaders, body: "" };
    }
    if (event.httpMethod !== "POST") {
      return resJson(405, { ok: false, error: "Method Not Allowed" });
    }

    const auth = requireAdmin(event);
    if (!auth.ok) {
      return resJson(auth.status, { ok: false, error: auth.error });
    }

    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE_KEY;

    if (!SUPABASE_URL || !SERVICE_ROLE) {
      return resJson(500, { ok: false, error: "Missing SUPABASE env vars" });
    }

    let body = {};
    try {
      body = JSON.parse(event.body || "{}");
    } catch {
      return resJson(400, { ok: false, error: "Invalid JSON" });
    }

    const path = body.path;

    if (!isSafePath(path)) {
      return resJson(400, { ok: false, error: "Invalid path" });
    }

    const supabase = createClient(SUPABASE_URL, SERVICE_ROLE, {
      auth: { persistSession: false, autoRefreshToken: false },
    });

    // 10 分鐘有效
    const expiresIn = 600;

    const { data, error } = await supabase.storage
      .from("admin-only")
      .createSignedUrl(path, expiresIn);

    if (error) {
      return resJson(500, { ok: false, error: error.message || "Supabase error" });
    }

    return resJson(200, {
      ok: true,
      bucket: "admin-only",
      path,
      signedViewUrl: data.signedUrl,
      expiresIn,
    });
  } catch (e) {
    return resJson(500, { ok: false, error: e?.message || "Server error" });
  }
};
