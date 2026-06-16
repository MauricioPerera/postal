// Postal — GitHub transport (Contents + Trees API). Isomorphic (browser + Node).
// GitHub sends CORS headers, so this also works from a file:// page.
// This layer knows nothing about crypto; it only reads/writes .postal/ files.

import { bytesToBase64, base64ToBytes, utf8Bytes, utf8Text, randomBytes } from "./crypto.js";

const API = "https://api.github.com";
const b64encodeUtf8 = (s) => bytesToBase64(utf8Bytes(s));
const b64decodeUtf8 = (b) => utf8Text(base64ToBytes(String(b)));

export function ghClient({ owner, repo, token, branch = "main" }) {
  const headers = { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" };
  if (token) headers.Authorization = "Bearer " + token;

  const req = (method, path, body) => fetch(API + path, {
    method,
    headers: body ? Object.assign({ "Content-Type": "application/json" }, headers) : headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  async function getFile(path) {
    const res = await req("GET", `/repos/${owner}/${repo}/contents/${enc(path)}?ref=${encodeURIComponent(branch)}`);
    if (res.status === 404) return null;
    if (!res.ok) throw await ghErr(res, "getFile " + path);
    const d = await res.json();
    return { content: b64decodeUtf8(d.content || ""), sha: d.sha };
  }

  async function putFile(path, contentString, message) {
    const existing = await getFile(path).catch(() => null);
    const body = { message: message || ("postal: " + path), content: b64encodeUtf8(contentString), branch };
    if (existing && existing.sha) body.sha = existing.sha;
    const res = await req("PUT", `/repos/${owner}/${repo}/contents/${enc(path)}`, body);
    if (!res.ok) throw await ghErr(res, "putFile " + path);
    return res.json();
  }

  async function listTree(prefix) {
    const res = await req("GET", `/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`);
    if (res.status === 404 || res.status === 409) return [];
    if (!res.ok) throw await ghErr(res, "listTree");
    const d = await res.json();
    return (d.tree || []).filter((e) => e.type === "blob" && e.path.indexOf(prefix) === 0).map((e) => e.path);
  }

  return { owner, repo, branch, getFile, putFile, listTree };
}

const enc = (p) => String(p).split("/").map(encodeURIComponent).join("/");
async function ghErr(res, where) {
  let m = ""; try { m = (await res.json()).message || ""; } catch {}
  const e = new Error(`GitHub ${res.status} (${where})${m ? ": " + m : ""}`); e.status = res.status; return e;
}

export const newRnd = () => Array.from(randomBytes(4)).map((b) => b.toString(16).padStart(2, "0")).join("");
