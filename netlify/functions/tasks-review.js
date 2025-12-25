// netlify/functions/tasks-review.js
const {
  corsHeaders, resJson, requireUser,
  requireRole, getSheetValues, updateRowById, appendRow, nowIso, genId
} = require("./_lib");

async function ledgerExists(claim_id, type) {
  const { header, rows } = await getSheetValues("reward_ledger");
  const cIdx = header.indexOf("claim_id");
  const tIdx = header.indexOf("type");
  return rows.some(r => String(r[cIdx] || "") === String(claim_id) && String(r[tIdx] || "") === String(type));
}

exports.handler = async (event) => {
  try {
    if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers: corsHeaders, body: "" };
    if (event.httpMethod !== "POST") return resJson(405, { ok: false, error: "Method Not Allowed" });

    const auth = requireUser(event);
    if (!auth.ok) return resJson(auth.status, { ok: false, error: auth.error });
    const admin_id = auth.user_id;

    const isAdmin = await requireRole(admin_id, "admin");
    if (!isAdmin) return resJson(403, { ok: false, error: "Admin only" });

    const body = JSON.parse(event.body || "{}");
    const claim_id = String(body.claim_id || "").trim();
    const decision = String(body.decision || "").toUpperCase(); // APPROVE / REJECT
    const review_note = String(body.review_note || "").trim();

    const coin = Number(body.coin || 0);
    const xp = Number(body.xp || 0);
    const point = Number(body.point || 0);

    if (!claim_id) return resJson(400, { ok: false, error: "Missing claim_id" });
    if (!["APPROVE", "REJECT"].includes(decision)) return resJson(400, { ok: false, error: "decision must be APPROVE or REJECT" });

    // 先抓 claim，確認目前是 SUBMITTED
    const { header: ch, rows: cr } = await getSheetValues("task_claims");
    const idIdx = ch.indexOf("claim_id");
    const stIdx = ch.indexOf("status");
    const uIdx = ch.indexOf("user_id");

    const crow = cr.find(r => String(r[idIdx] || "") === claim_id);
    if (!crow) return resJson(404, { ok: false, error: "Claim not found" });
    if (String(crow[stIdx] || "") !== "SUBMITTED") return resJson(400, { ok: false, error: "Only SUBMITTED can be reviewed" });

    const user_id = String(crow[uIdx] || "");
    const reviewed_at = nowIso();

    if (decision === "REJECT") {
      await updateRowById("task_claims", "claim_id", claim_id, {
        status: "REJECTED",
        reviewed_at,
        review_note,
      });
      return resJson(200, { ok: true, claim_id, status: "REJECTED" });
    }

    // APPROVE：更新狀態
    await updateRowById("task_claims", "claim_id", claim_id, {
      status: "APPROVED",
      reviewed_at,
      review_note,
    });

    // 發獎（防重複：以 claim_id + type）
    const created_at = reviewed_at;

    const toGrant = [
      { type: "coin", amount: coin },
      { type: "xp", amount: xp },
      { type: "point", amount: point },
    ].filter(x => Number(x.amount) > 0);

    for (const g of toGrant) {
      const exists = await ledgerExists(claim_id, g.type);
      if (exists) continue;

      await appendRow("reward_ledger", [
        genId("led"),
        user_id,
        claim_id,
        g.type,
        Number(g.amount),
        "task_approved",
        created_at,
      ]);
    }

    return resJson(200, { ok: true, claim_id, status: "APPROVED", granted: toGrant });
  } catch (e) {
    return resJson(500, { ok: false, error: e?.message || "Server error" });
  }
};
