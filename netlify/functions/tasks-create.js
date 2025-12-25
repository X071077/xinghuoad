// netlify/functions/tasks-create.js
const {
  corsHeaders, resJson, requireUser,
  appendRow, requireRole, nowIso, addDaysIso
} = require("./_lib");

exports.handler = async (event) => {
  try {
    if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers: corsHeaders, body: "" };
    if (event.httpMethod !== "POST") return resJson(405, { ok: false, error: "Method Not Allowed" });

    const auth = requireUser(event);
    if (!auth.ok) return resJson(auth.status, { ok: false, error: auth.error });

    const user_id = auth.user_id;
    const isDealer = await requireRole(user_id, "dealer");
    if (!isDealer) return resJson(403, { ok: false, error: "Dealer only" });

    const body = JSON.parse(event.body || "{}");
    const {
      task_id,
      title = "",
      vehicle_text,
      budget_plan,
      duration_days,
      quota,
      photo_paths
    } = body;

    if (!task_id) return resJson(400, { ok: false, error: "Missing task_id" });
    if (!vehicle_text || !String(vehicle_text).trim()) return resJson(400, { ok: false, error: "Missing vehicle_text" });

    const bp = Number(budget_plan);
    if (![3000, 5000, 15000].includes(bp)) return resJson(400, { ok: false, error: "Invalid budget_plan" });

    const dd = Number(duration_days);
    if (![3, 7, 30].includes(dd)) return resJson(400, { ok: false, error: "Invalid duration_days" });

    const q = Number(quota);
    if (!(q === -1 || q >= 1)) return resJson(400, { ok: false, error: "Invalid quota" });

    if (!Array.isArray(photo_paths) || photo_paths.length < 1 || photo_paths.length > 3) {
      return resJson(400, { ok: false, error: "photo_paths must be 1-3 items" });
    }

    const created_at = nowIso();
    const start_at = created_at;
    const end_at = addDaysIso(dd);

    const photo_paths_str = photo_paths.map(String).join(",");

    // tasks 欄位順序（你 sheets 已確認）
    const row = [
      task_id,
      user_id,
      String(vehicle_text),
      bp,
      dd,
      q,
      "PUBLISHED",
      created_at,
      start_at,
      end_at,
      photo_paths_str,
    ];

    await appendRow("tasks", row);

    return resJson(200, { ok: true, task_id });
  } catch (e) {
    return resJson(500, { ok: false, error: e?.message || "Server error" });
  }
};
