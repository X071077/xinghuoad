const { corsHeaders, resJson, requireUser, requireRole, getSheetValues } = require("./_lib");

exports.handler = async (event) => {
  try{
    if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers: corsHeaders, body: "" };
    if (event.httpMethod !== "GET") return resJson(405, { ok:false, error:"Method Not Allowed" });

    const auth=requireUser(event);
    if(!auth.ok) return resJson(auth.status,{ok:false,error:auth.error});
    const isAdmin=await requireRole(auth.user_id,"admin");
    if(!isAdmin) return resJson(403,{ok:false,error:"Admin only"});

    const { header, rows } = await getSheetValues("task_claims");
    const claims = rows.map(r=>{
      const o={}; header.forEach((h,i)=>o[h]=r[i]??"");
      return o;
    });

    return resJson(200,{ok:true,claims});
  }catch(e){
    return resJson(500,{ok:false,error:e?.message||"Server error"});
  }
};
