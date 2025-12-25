// netlify/functions/tasks-abandon.js
const {
  corsHeaders, resJson, requireUser,
  updateRowById, nowIso
} = require("./_lib");

exports.handler = async (event) => {
  try {
    if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers: corsHeaders, body: "" };
    if (event.httpMethod !== "POST") return resJson(405, { ok: false, error: "Method Not Allowed" });

    const auth = requireUser(event);
    if (!auth.ok) return resJson(auth.status, { ok: false, error: auth.error });
    const user_id = auth.user_id;

    const body = JSON.parse(event.body || "{}");
    const claim_id = String(body.claim_id || "").trim();
    if (!claim_id) return resJson(400, { ok: false, error: "Missing claim_id" });

    // 先讀出那列，確保是自己的 claim 且狀態 ACTIVE
    const { header, rows } = await require("./_lib").getSheetValues("task_claims");
    const idIdx = header.indexOf("claim_id");
    const userIdx = header.indexOf("user_id");
    const stIdx = header.indexOf("status");
    const row = rows.find(r => String(r[idIdx] || "") === claim_id);
    if (!row) return resJson(404, { ok: false, error: "Claim not found" });
    if (String(row[userIdx] || "") !== String(user_id)) return resJson(403, { ok: false, error: "Not your claim" });
    if (String(row[stIdx] || "") !== "ACTIVE") return resJson(400, { ok: false, error: "Only ACTIVE can abandon" });

    await updateRowById("task_claims", "claim_id", claim_id, {
      status: "ABANDONED",
      abandoned_at: nowIso(),
    });

    return resJson(200, { ok: true, claim_id });
  } catch (e) {
    return resJson(500, { ok: false, error: e?.message || "Server error" });
  }
};
