// netlify/functions/public-config.js
// 作用：提供前端需要的公開設定（Supabase URL + Anon Key）
// 注意：SUPABASE_SERVICE_ROLE_KEY 絕對不能回傳

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
};

function resJson(statusCode, obj) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...corsHeaders,
    },
    body: JSON.stringify(obj),
  };
}

exports.handler = async (event) => {
  try {
    if (event.httpMethod === "OPTIONS") {
      return { statusCode: 200, headers: corsHeaders, body: "" };
    }
    if (event.httpMethod !== "GET") {
      return resJson(405, { ok: false, error: "Method Not Allowed" });
    }

    const url = process.env.SUPABASE_URL;
    const anon = process.env.SUPABASE_ANON_KEY;

    if (!url || !anon) {
      return resJson(500, { ok: false, error: "Missing SUPABASE_URL / SUPABASE_ANON_KEY" });
    }

    return resJson(200, {
      ok: true,
      supabaseUrl: url,
      supabaseAnonKey: anon,
    });
  } catch (e) {
    return resJson(500, { ok: false, error: e?.message || "Server error" });
  }
};
