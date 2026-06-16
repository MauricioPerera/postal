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

  // --- Git Data API: many files in ONE commit (for batching) -----------------

  async function getHeadSha() {
    const res = await req("GET", `/repos/${owner}/${repo}/git/ref/heads/${encodeURIComponent(branch)}`);
    if (!res.ok) throw await ghErr(res, "getRef");
    return (await res.json()).object.sha;
  }
  async function getCommitTree(commitSha) {
    const res = await req("GET", `/repos/${owner}/${repo}/git/commits/${commitSha}`);
    if (!res.ok) throw await ghErr(res, "getCommit");
    return (await res.json()).tree.sha;
  }
  async function createBlob(contentString) {
    const res = await req("POST", `/repos/${owner}/${repo}/git/blobs`, { content: contentString, encoding: "utf-8" });
    if (!res.ok) throw await ghErr(res, "createBlob");
    return (await res.json()).sha;
  }
  async function createTree(baseTree, entries) {
    const res = await req("POST", `/repos/${owner}/${repo}/git/trees`, { base_tree: baseTree, tree: entries });
    if (!res.ok) throw await ghErr(res, "createTree");
    return (await res.json()).sha;
  }
  async function createCommit(message, tree, parents) {
    const res = await req("POST", `/repos/${owner}/${repo}/git/commits`, { message, tree, parents });
    if (!res.ok) throw await ghErr(res, "createCommit");
    return (await res.json()).sha;
  }
  async function updateRef(sha) {
    const res = await req("PATCH", `/repos/${owner}/${repo}/git/refs/heads/${encodeURIComponent(branch)}`, { sha });
    if (!res.ok) throw await ghErr(res, "updateRef");
    return (await res.json()).object.sha;
  }

  // Commit several files atomically in ONE commit. files: [{ path, content }].
  // Returns the new commit sha.
  async function commitFiles(files, message) {
    const head = await getHeadSha();
    const baseTree = await getCommitTree(head);
    const entries = [];
    for (const f of files) {
      entries.push({ path: f.path, mode: "100644", type: "blob", sha: await createBlob(f.content) });
    }
    const tree = await createTree(baseTree, entries);
    const commit = await createCommit(message || `postal: batch ${files.length}`, tree, [head]);
    await updateRef(commit);
    return commit;
  }

  return { owner, repo, branch, getFile, putFile, listTree, commitFiles };
}

const enc = (p) => String(p).split("/").map(encodeURIComponent).join("/");
async function ghErr(res, where) {
  let m = ""; try { m = (await res.json()).message || ""; } catch {}
  const e = new Error(`GitHub ${res.status} (${where})${m ? ": " + m : ""}`); e.status = res.status; return e;
}

export const newRnd = () => Array.from(randomBytes(4)).map((b) => b.toString(16).padStart(2, "0")).join("");
