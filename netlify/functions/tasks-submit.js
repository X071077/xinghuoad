// netlify/functions/tasks-submit.js
const {
  corsHeaders, resJson, requireUser,
  getSheetValues, appendRow, updateRowById, nowIso, genId
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
    const share_link = String(body.share_link || "").trim();
    const share_screenshot_path = String(body.share_screenshot_path || "").trim();
    const insights_screenshot_path = String(body.insights_screenshot_path || "").trim();
    const note = String(body.note || "").trim();

    if (!claim_id) return resJson(400, { ok: false, error: "Missing claim_id" });
    if (!share_link) return resJson(400, { ok: false, error: "Missing share_link" });
    if (!share_screenshot_path) return resJson(400, { ok: false, error: "Missing share_screenshot_path" });

    // 查 claim，確認是自己的且 ACTIVE
    const { header: ch, rows: cr } = await getSheetValues("task_claims");
    const idIdx = ch.indexOf("claim_id");
    const tIdx = ch.indexOf("task_id");
    const uIdx = ch.indexOf("user_id");
    const stIdx = ch.indexOf("status");

    const crow = cr.find(r => String(r[idIdx] || "") === claim_id);
    if (!crow) return resJson(404, { ok: false, error: "Claim not found" });
    if (String(crow[uIdx] || "") !== String(user_id)) return resJson(403, { ok: false, error: "Not your claim" });
    if (String(crow[stIdx] || "") !== "ACTIVE") return resJson(400, { ok: false, error: "Only ACTIVE can submit" });

    const task_id = String(crow[tIdx] || "");

    const submission_id = genId("sub");
    const row = [
      submission_id,
      claim_id,
      task_id,
      user_id,
      share_link,
      share_screenshot_path,
      insights_screenshot_path, // admin-only（可空）
      note,
    ];

    await appendRow("submissions", row);

    await updateRowById("task_claims", "claim_id", claim_id, {
      status: "SUBMITTED",
      submitted_at: nowIso(),
    });

    return resJson(200, { ok: true, submission_id, claim_id });
  } catch (e) {
    return resJson(500, { ok: false, error: e?.message || "Server error" });
  }
};
