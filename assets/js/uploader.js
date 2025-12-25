// assets/js/uploader.js
// 作用：前端統一上傳流程：
// 1) 向 Netlify function 要 signed upload (storage-sign-upload)
// 2) 直傳到 Supabase Storage（uploadToSignedUrl）
// 3) 回傳 bucket/path 供你寫進 Google Sheet

import { createClient } from "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm";

function mustEnv(name) {
  const v = window[name];
  if (!v) throw new Error(`Missing window.${name}`);
  return v;
}

// 你要在頁面上先設定：
// window.SUPABASE_URL = "..."
// window.SUPABASE_ANON_KEY = "..."
export function getSupabaseClient() {
  const url = mustEnv("SUPABASE_URL");
  const anon = mustEnv("SUPABASE_ANON_KEY");
  return createClient(url, anon);
}

export async function signUpload({ bucket, path, contentType }) {
  const r = await fetch("/.netlify/functions/storage-sign-upload", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ bucket, path, contentType }),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.ok) {
    throw new Error(j.error || "signUpload failed");
  }
  return j; // {bucket, path, token, signedUrl}
}

export async function uploadFileToSupabaseSignedUrl({ bucket, path, token, file }) {
  const supabase = getSupabaseClient();
  const { data, error } = await supabase.storage
    .from(bucket)
    .uploadToSignedUrl(path, token, file);

  if (error) throw new Error(error.message || "uploadToSignedUrl failed");
  return data; // { path, fullPath? }
}

export function guessImageExt(file) {
  const t = (file?.type || "").toLowerCase();
  if (t.includes("png")) return "png";
  if (t.includes("webp")) return "webp";
  return "jpg";
}

export function makePath({ prefix, id, filename, ext }) {
  const safeName = String(filename || "img")
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, "-")
    .slice(0, 40);

  const ts = Date.now();
  const e = ext || "jpg";
  return `${prefix}/${id}/${ts}_${safeName}.${e}`;
}

// 一鍵上傳：給你最常用的用法
export async function uploadImage({ bucket, prefix, id, file }) {
  if (!file) throw new Error("No file");

  const ext = guessImageExt(file);
  const path = makePath({ prefix, id, filename: file.name, ext });

  const signed = await signUpload({
    bucket,
    path,
    contentType: file.type || "image/jpeg",
  });

  await uploadFileToSupabaseSignedUrl({
    bucket: signed.bucket,
    path: signed.path,
    token: signed.token,
    file,
  });

  // 回傳你要存進 Sheet 的值（bucket/path）
  return `${signed.bucket}/${signed.path}`;
}
