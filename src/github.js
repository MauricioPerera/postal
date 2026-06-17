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
  //
  // CONCURRENCY: postal is multi-writer (several members post at once). Two commits racing on the
  // same HEAD make the loser's updateRef a non-fast-forward -> GitHub 422/409. We RETRY: re-read
  // HEAD and rebuild the tree/commit on the new base, so concurrent appends serialize instead of
  // failing. Blobs are content-addressed, so re-running createBlob on retry is cheap/idempotent.
  // Honest limit: bounded retries (no infinite livelock); at very high write contention an append
  // can still exhaust them and throw — fine at the "tens of members" scale this targets.
  async function commitFiles(files, message) {
    return withRetry(async () => {
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
    }, { retryable: isRefConflict });
  }

  // --- commit history (for git-anchored ordering, src/commit-order.js) -------

  // List commit shas on the branch, OLDEST-FIRST (so the array index is the commit order).
  // Paginates the REST commits API. The list endpoint does NOT include per-commit files; use
  // getCommitFiles(sha) for that.
  async function listCommits({ perPage = 100, maxPages = 50 } = {}) {
    const shas = [];
    for (let page = 1; page <= maxPages; page++) {
      const res = await req("GET", `/repos/${owner}/${repo}/commits?sha=${encodeURIComponent(branch)}&per_page=${perPage}&page=${page}`);
      if (res.status === 404 || res.status === 409) break;            // empty repo / no commits
      if (!res.ok) throw await ghErr(res, "listCommits");
      const batch = await res.json();
      for (const c of batch) shas.push(c.sha);
      if (batch.length < perPage) break;
    }
    return shas.reverse();                                            // oldest-first
  }

  // Paths ADDED by a single commit (status "added"). One API call per commit.
  async function getCommitFiles(sha) {
    const res = await req("GET", `/repos/${owner}/${repo}/commits/${encodeURIComponent(sha)}`);
    if (!res.ok) throw await ghErr(res, "getCommitFiles " + sha);
    const d = await res.json();
    return (d.files || []).filter((f) => f.status === "added").map((f) => f.filename);
  }

  return { owner, repo, branch, getFile, putFile, listTree, commitFiles, getHeadSha, listCommits, getCommitFiles };
}

// A non-fast-forward ref update (lost an optimistic-lock race) is what GitHub returns when two
// commits raced the same HEAD: 422 (Git Data API) or 409 (Contents API). Only these are retried.
export const isRefConflict = (e) => e && (e.status === 422 || e.status === 409);

// Run `fn` with bounded retry + linear backoff PLUS jitter. Jitter is essential here: without it,
// N racers that collide all re-read the same HEAD and retry in lockstep, colliding again forever;
// a random spread desynchronizes them so they serialize. Retries only when `retryable(err)` is
// true; any other error (auth, 404, ...) throws immediately. `sleep`/`rand` are injectable so
// tests are deterministic.
export async function withRetry(fn, { tries = 6, base = 150, retryable = () => true, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), rand = Math.random } = {}) {
  let last;
  for (let i = 0; i < tries; i++) {
    try { return await fn(i); }
    catch (e) {
      last = e;
      if (i === tries - 1 || !retryable(e)) throw e;
      await sleep(base * (i + 1) + Math.floor(rand() * base));   // linear backoff + jitter [0,base)
    }
  }
  throw last;
}

const enc = (p) => String(p).split("/").map(encodeURIComponent).join("/");
async function ghErr(res, where) {
  let m = ""; try { m = (await res.json()).message || ""; } catch {}
  const e = new Error(`GitHub ${res.status} (${where})${m ? ": " + m : ""}`); e.status = res.status; return e;
}

export const newRnd = () => Array.from(randomBytes(4)).map((b) => b.toString(16).padStart(2, "0")).join("");
