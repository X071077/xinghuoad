// netlify/functions/tasks-my.js
// 作用：回傳「我接取的任務」清單（含 claim 狀態、任務內容、以及是否已提交 submission）

const {
  corsHeaders, resJson, requireUser,
  getSheetValues
} = require("./_lib");

function rowToObj(header, row){
  const o = {};
  header.forEach((h,i)=> o[h] = row[i] ?? "");
  return o;
}

function splitPhotoPaths(s){
  return String(s||"").split(",").map(x=>x.trim()).filter(Boolean);
}

exports.handler = async (event) => {
  try{
    if (event.httpMethod === "OPTIONS") return { statusCode:200, headers:corsHeaders, body:"" };
    if (event.httpMethod !== "GET") return resJson(405, { ok:false, error:"Method Not Allowed" });

    const auth = requireUser(event);
    if(!auth.ok) return resJson(auth.status, { ok:false, error:auth.error });

    const user_id = String(auth.user_id);

    const { header: th, rows: tr } = await getSheetValues("tasks");
    const { header: ch, rows: cr } = await getSheetValues("task_claims");
    const { header: sh, rows: sr } = await getSheetValues("submissions");

    const tasksById = new Map(
      tr.map(r=>{
        const t = rowToObj(th, r);
        t.photo_paths = splitPhotoPaths(t.photo_paths);
        t.budget_plan = Number(t.budget_plan || 0);
        t.duration_days = Number(t.duration_days || 0);
        t.quota = Number(t.quota ?? 0);
        return [String(t.task_id), t];
      })
    );

    const subsByClaim = new Map(
      sr.map(r=>{
        const s = rowToObj(sh, r);
        return [String(s.claim_id), s];
      })
    );

    const claims = cr
      .map(r => rowToObj(ch, r))
      .filter(c => String(c.user_id) === user_id)
      .filter(c => ["ACTIVE","SUBMITTED","APPROVED","REJECTED"].includes(String(c.status)));

    const items = claims.map(c=>{
      const task = tasksById.get(String(c.task_id)) || null;
      const sub = subsByClaim.get(String(c.claim_id)) || null;
      return { claim: c, task, submission: sub };
    });

    // 最新在前
    items.sort((a,b)=>{
      const ta = Date.parse(a.claim.claimed_at || a.claim.submitted_at || "") || 0;
      const tb = Date.parse(b.claim.claimed_at || b.claim.submitted_at || "") || 0;
      return tb - ta;
    });

    return resJson(200, { ok:true, items });
  }catch(e){
    return resJson(500, { ok:false, error: e?.message || "Server error" });
  }
};
