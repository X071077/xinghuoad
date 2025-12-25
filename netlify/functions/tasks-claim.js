// netlify/functions/tasks-claim.js
const {
  corsHeaders, resJson, requireUser,
  getSheetValues, appendRow, nowIso, genId, requireRole
} = require("./_lib");

exports.handler = async (event) => {
  try {
    if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers: corsHeaders, body: "" };
    if (event.httpMethod !== "POST") return resJson(405, { ok: false, error: "Method Not Allowed" });

    const auth = requireUser(event);
    if (!auth.ok) return resJson(auth.status, { ok: false, error: auth.error });

    const user_id = auth.user_id;
    const isPartner = await requireRole(user_id, "partner");
    if (!isPartner) return resJson(403, { ok: false, error: "Partner only" });

    const body = JSON.parse(event.body || "{}");
    const task_id = String(body.task_id || "").trim();
    if (!task_id) return resJson(400, { ok: false, error: "Missing task_id" });

    const { header: th, rows: tr } = await getSheetValues("tasks");
    const tidIdx = th.indexOf("task_id");
    const statusIdx = th.indexOf("status");
    const endIdx = th.indexOf("end_at");
    const quotaIdx = th.indexOf("quota");
    if (tidIdx === -1) return resJson(500, { ok: false, error: "tasks missing task_id column" });

    const trow = tr.find(r => String(r[tidIdx] || "") === task_id);
    if (!trow) return resJson(404, { ok: false, error: "Task not found" });

    const status = String(trow[statusIdx] || "");
    if (status !== "PUBLISHED") return resJson(400, { ok: false, error: "Task not available" });

    const endAt = String(trow[endIdx] || "");
    if (endAt) {
      const endMs = Date.parse(endAt);
      if (endMs && endMs <= Date.now()) return resJson(400, { ok: false, error: "Task expired" });
    }

    const quota = Number(trow[quotaIdx] ?? 0);

    const { header: ch, rows: cr } = await getSheetValues("task_claims");
    const cTaskIdx = ch.indexOf("task_id");
    const cUserIdx = ch.indexOf("user_id");
    const cStatusIdx = ch.indexOf("status");

    // 不允許同一人重複 ACTIVE/SUBMITTED/APPROVED
    const hasActive = cr.some(r => {
      if (String(r[cTaskIdx] || "") !== task_id) return false;
      if (String(r[cUserIdx] || "") !== String(user_id)) return false;
      const st = String(r[cStatusIdx] || "");
      return ["ACTIVE", "SUBMITTED", "APPROVED"].includes(st);
    });
    if (hasActive) return resJson(400, { ok: false, error: "You already claimed this task" });

    // 名額檢查（quota=-1 無上限）
    if (quota !== -1) {
      const used = cr.filter(r => {
        if (String(r[cTaskIdx] || "") !== task_id) return false;
        const st = String(r[cStatusIdx] || "");
        return ["ACTIVE", "SUBMITTED", "APPROVED"].includes(st);
      }).length;

      if (used >= quota) return resJson(400, { ok: false, error: "No slots remaining" });
    }

    const claim_id = genId("claim");
    const claimed_at = nowIso();

    const row = [
      claim_id,
      task_id,
      user_id,
      "ACTIVE",
      claimed_at,
      "", // abandoned_at
      "", // submitted_at
      "", // reviewed_at
      "", // review_note
    ];

    await appendRow("task_claims", row);

    return resJson(200, { ok: true, claim_id });
  } catch (e) {
    return resJson(500, { ok: false, error: e?.message || "Server error" });
  }
};
