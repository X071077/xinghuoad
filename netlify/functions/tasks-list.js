// netlify/functions/tasks-list.js
const {
  corsHeaders, resJson, requireUser,
  getSheetValues, getRolesByUserId
} = require("./_lib");

function parseTask(header, row) {
  const obj = {};
  header.forEach((h, i) => obj[h] = row[i] ?? "");
  // photo_paths 字串 -> array
  obj.photo_paths = String(obj.photo_paths || "").split(",").map(s => s.trim()).filter(Boolean);
  obj.budget_plan = Number(obj.budget_plan || 0);
  obj.duration_days = Number(obj.duration_days || 0);
  obj.quota = Number(obj.quota ?? 0);
  return obj;
}

function parseClaim(header, row) {
  const obj = {};
  header.forEach((h, i) => obj[h] = row[i] ?? "");
  return obj;
}

exports.handler = async (event) => {
  try {
    if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers: corsHeaders, body: "" };
    if (event.httpMethod !== "GET") return resJson(405, { ok: false, error: "Method Not Allowed" });

    const auth = requireUser(event);
    if (!auth.ok) return resJson(auth.status, { ok: false, error: auth.error });

    const user_id = auth.user_id;
    const roles = await getRolesByUserId(user_id);
    const isAdmin = roles.includes("admin");
    const isDealer = roles.includes("dealer");

    const { header: th, rows: tr } = await getSheetValues("tasks");
    const { header: ch, rows: cr } = await getSheetValues("task_claims");

    const now = Date.now();

    const tasks = tr.map(r => parseTask(th, r));

    // 計算每個 task 的已佔用名額（ACTIVE + SUBMITTED + APPROVED）
    const claims = cr.map(r => parseClaim(ch, r));
    const usedByTask = new Map();
    for (const c of claims) {
      const st = String(c.status || "");
      if (!["ACTIVE", "SUBMITTED", "APPROVED"].includes(st)) continue;
      const tid = String(c.task_id || "");
      usedByTask.set(tid, (usedByTask.get(tid) || 0) + 1);
    }

    // 依角色過濾
    let visible = tasks;

    if (isAdmin) {
      // admin 看全部
      visible = tasks;
    } else if (isDealer) {
      // dealer 看自己的
      visible = tasks.filter(t => String(t.dealer_id) === String(user_id));
    } else {
      // partner 看可接取：PUBLISHED 且未過期
      visible = tasks.filter(t => {
        if (String(t.status) !== "PUBLISHED") return false;
        const end = Date.parse(String(t.end_at || ""));
        if (!end) return true;
        return end > now;
      });
    }

    // 補充 remaining
    visible = visible.map(t => {
      const used = usedByTask.get(String(t.task_id)) || 0;
      const quota = Number(t.quota);
      const remaining = quota === -1 ? -1 : Math.max(0, quota - used);
      return { ...t, used, remaining };
    });

    return resJson(200, { ok: true, roles, tasks: visible });
  } catch (e) {
    return resJson(500, { ok: false, error: e?.message || "Server error" });
  }
};
