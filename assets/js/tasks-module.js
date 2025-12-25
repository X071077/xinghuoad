// assets/js/tasks-module.js
import { uploadImage } from "./uploader.js";

function getToken(){ return localStorage.getItem("xinghuo_token") || ""; }

async function loadConfig(){
  const r = await fetch("/.netlify/functions/public-config");
  const j = await r.json();
  if(!j.ok) throw new Error(j.error || "public-config failed");
  window.SUPABASE_URL = j.supabaseUrl;
  window.SUPABASE_ANON_KEY = j.supabaseAnonKey;
}

function publicUrl(bucketPath){
  const s=String(bucketPath||"").trim();
  if(!s) return "";
  const parts=s.split("/");
  const bucket=parts.shift();
  const path=parts.join("/");
  return `${window.SUPABASE_URL}/storage/v1/object/public/${bucket}/${path}`;
}

export async function mountTasksModule(rootId="tasksModule"){
  await loadConfig();
  const root = document.getElementById(rootId);
  if(!root) throw new Error(`Missing #${rootId}`);

  root.innerHTML = `
    <div style="margin-top:12px;border:1px solid rgba(255,255,255,.1);border-radius:14px;padding:12px;background:rgba(255,255,255,.04)">
      <div style="font-weight:900">任務列表</div>
      <div id="tasksList" style="margin-top:10px;color:rgba(255,255,255,.8)">載入中…</div>
    </div>
  `;

  async function fetchTasks(){
    const r=await fetch("/.netlify/functions/tasks-list",{ headers:{Authorization:"Bearer "+getToken()} });
    const j=await r.json();
    if(!r.ok||!j.ok) throw new Error(j.error||"tasks-list failed");
    return j.tasks || [];
  }

  async function claim(task_id){
    const r=await fetch("/.netlify/functions/tasks-claim",{
      method:"POST",
      headers:{ "Content-Type":"application/json", Authorization:"Bearer "+getToken() },
      body: JSON.stringify({ task_id })
    });
    const j=await r.json();
    if(!r.ok||!j.ok) throw new Error(j.error||"claim failed");
    return j.claim_id;
  }

  async function submit({ claim_id, share_link, shareFile, insightsFile }){
    // 上傳截圖
    const share_screenshot_path = await uploadImage({
      bucket:"public-assets",
      prefix:"proof",
      id:claim_id,
      file:shareFile
    });

    let insights_screenshot_path = "";
    if(insightsFile){
      insights_screenshot_path = await uploadImage({
        bucket:"admin-only",
        prefix:"proof",
        id:claim_id,
        file:insightsFile
      });
    }

    const r=await fetch("/.netlify/functions/tasks-submit",{
      method:"POST",
      headers:{ "Content-Type":"application/json", Authorization:"Bearer "+getToken() },
      body: JSON.stringify({ claim_id, share_link, share_screenshot_path, insights_screenshot_path })
    });
    const j=await r.json();
    if(!r.ok||!j.ok) throw new Error(j.error||"submit failed");
    return j;
  }

  async function render(){
    const box=document.getElementById("tasksList");
    box.textContent="載入中…";
    try{
      const tasks=await fetchTasks();
      if(tasks.length===0){ box.textContent="目前沒有可接取任務"; return; }

      box.innerHTML="";
      for(const t of tasks){
        const photos = (t.photo_paths||[]).map(p=>`<img src="${publicUrl(p)}" style="width:120px;height:90px;object-fit:cover;border-radius:10px;border:1px solid rgba(255,255,255,.1);margin-right:8px;">`).join("");
        const remainText = t.remaining === -1 ? "無上限" : String(t.remaining);

        const div=document.createElement("div");
        div.style.cssText="border:1px solid rgba(255,255,255,.1);border-radius:14px;padding:12px;margin-bottom:10px;background:rgba(0,0,0,.18)";
        div.innerHTML=`
          <div style="font-weight:800">task_id：${t.task_id}</div>
          <div style="color:rgba(255,255,255,.7);font-size:13px;margin-top:4px;">名額剩餘：${remainText}｜天數：${t.duration_days}</div>
          <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;">${photos}</div>
          <div style="margin-top:10px;color:rgba(255,255,255,.82);white-space:pre-wrap;">${(t.vehicle_text||"")}</div>
          <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;">
            <button data-claim="${t.task_id}" style="padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.1);background:rgba(255,255,255,.06);color:#fff;cursor:pointer;">接取</button>
          </div>
          <div id="panel_${t.task_id}" style="margin-top:10px;"></div>
        `;

        div.querySelector(`[data-claim="${t.task_id}"]`).onclick = async ()=>{
          try{
            const claim_id = await claim(t.task_id);
            const panel = div.querySelector(`#panel_${t.task_id}`);
            panel.innerHTML = `
              <div style="color:rgba(255,255,255,.7);font-size:13px;">✅ 已接取：claim_id = ${claim_id}</div>
              <div style="margin-top:10px;display:grid;gap:8px;max-width:520px">
                <input id="link_${claim_id}" placeholder="轉發連結" style="padding:10px;border-radius:10px;border:1px solid rgba(255,255,255,.1);background:rgba(0,0,0,.25);color:#fff">
                <input id="share_${claim_id}" type="file" accept="image/*" />
                <input id="ins_${claim_id}" type="file" accept="image/*" />
                <button id="send_${claim_id}" style="padding:10px 12px;border-radius:12px;border:1px solid rgba(255,255,255,.1);background:rgba(124,92,255,.75);color:#fff;cursor:pointer;">提交回傳</button>
              </div>
            `;
            panel.querySelector(`#send_${claim_id}`).onclick = async ()=>{
              const share_link = panel.querySelector(`#link_${claim_id}`).value.trim();
              const shareFile = panel.querySelector(`#share_${claim_id}`).files?.[0];
              const insightsFile = panel.querySelector(`#ins_${claim_id}`).files?.[0] || null;
              if(!share_link) return alert("請填轉發連結");
              if(!shareFile) return alert("請選轉發截圖");
              await submit({ claim_id, share_link, shareFile, insightsFile });
              alert("✅ 已提交，等待審核");
              render();
            };
          }catch(e){
            alert(e.message||"接取失敗");
          }
        };

        box.appendChild(div);
      }
    }catch(e){
      box.textContent="載入失敗："+(e.message||"未知錯誤");
    }
  }

  render();
}
