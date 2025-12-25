const { createClient } = require("@supabase/supabase-js");

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

function isSafePath(p) {
  if (typeof p !== "string") return false;
  const s = p.trim();
  if (!s) return false;
  if (s.includes("..")) return false;
  if (s.includes("\\")) return false;
  // 允許：英數、底線、連字號、斜線、點
  return /^[a-zA-Z0-9._\-\/]+$/.test(s);
}

exports.handler = async (event) => {
  try {
    // CORS preflight
    if (event.httpMethod === "OPTIONS") {
      return { statusCode: 200, headers: corsHeaders, body: "" };
    }
    if (event.httpMethod !== "POST") {
      return resJson(405, { ok: false, error: "Method Not Allowed" });
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

    const { bucket, path, contentType } = body;

    const allowedBuckets = new Set(["public-assets", "admin-only"]);
    if (!allowedBuckets.has(bucket)) {
      return resJson(400, { ok: false, error: "Invalid bucket" });
    }

    if (!isSafePath(path)) {
      return resJson(400, { ok: false, error: "Invalid path" });
    }

    // 先只允許圖片（你未來要上傳 pdf 再擴充）
    if (typeof contentType !== "string" || !contentType.startsWith("image/")) {
      return resJson(400, { ok: false, error: "Only image/* is allowed" });
    }

    const supabase = createClient(SUPABASE_URL, SERVICE_ROLE, {
      auth: { persistSession: false, autoRefreshToken: false },
    });

    // Supabase 會回傳：signedUrl / token / path
    const { data, error } = await supabase.storage
      .from(bucket)
      .createSignedUploadUrl(path);

    if (error) {
      return resJson(500, { ok: false, error: error.message || "Supabase error" });
    }

    return resJson(200, {
      ok: true,
      bucket,
      path: data.path,
      token: data.token,
      signedUrl: data.signedUrl,
    });
  } catch (e) {
    return resJson(500, { ok: false, error: e?.message || "Server error" });
  }
};
