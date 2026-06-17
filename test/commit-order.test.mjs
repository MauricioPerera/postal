// Tests for the git-backed commitIndex source (src/commit-order.js).
import { parseCommitAdds, attachCommitIndex, readLocalCommitIndex, ghCommitIndex } from "../src/commit-order.js";
import { canonicalOrder } from "../src/order.js";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let p = 0, f = 0;
const ok = (n, c) => { if (c) { p++; console.log("  ok  - " + n); } else { f++; console.log("  FAIL - " + n); } };

console.log("# parseCommitAdds");
// Two commits, oldest-first: commit 0 adds a.json, commit 1 adds b.json (+ re-touches a.json).
const sample = "\x00sha0\nchats/c/a.json\n\x00sha1\nchats/c/b.json\n";
const m = parseCommitAdds(sample);
ok("primer commit -> index 0", m.get("chats/c/a.json") === 0);
ok("segundo commit -> index 1", m.get("chats/c/b.json") === 1);
ok("primer add gana (no se re-mapea)", parseCommitAdds(sample + "\x00sha2\nchats/c/a.json\n").get("chats/c/a.json") === 0);
ok("paths desconocidos no aparecen", m.has("nope") === false);

console.log("# attachCommitIndex (no muta, default { path } shape)");
const items = [{ path: "chats/c/b.json", event: { id: "B" } }, { path: "chats/c/a.json", event: { id: "A" } }];
const tagged = attachCommitIndex(items, m);
ok("adjunta commitIndex por path", tagged[0].commitIndex === 1 && tagged[1].commitIndex === 0);
ok("no muta el input", items[0].commitIndex === undefined);
ok("path desconocido queda sin index", attachCommitIndex([{ path: "x", event: { id: "X" } }], m)[0].commitIndex === undefined);

console.log("# integración: el antedatado NO se cuela tras anclar a commit");
// B se firma con created_at ANTEDATADO para colarse al frente; pero su commit es posterior.
const live = [
  { path: "chats/c/a.json", event: { id: "A", created_at: "2026-01-02T00:00:00Z" } },
  { path: "chats/c/b.json", event: { id: "B", created_at: "2026-01-01T00:00:00Z" } }, // antedatado
];
const byTime = canonicalOrder(live).map((i) => i.event.id).join();
const byCommit = canonicalOrder(attachCommitIndex(live, m)).map((i) => i.event.id).join();
ok("sin anclar: el antedatado gana (B,A)", byTime === "B,A");
ok("anclado a commit: orden real (A,B)", byCommit === "A,B");

console.log("# readLocalCommitIndex contra un repo git real");
const dir = mkdtempSync(join(tmpdir(), "postal-co-"));
try {
  const git = (...a) => execFileSync("git", ["-C", dir, ...a], { encoding: "utf8" });
  git("init", "-q");
  git("config", "user.email", "t@t"); git("config", "user.name", "t"); git("config", "commit.gpgsign", "false");
  writeFileSync(join(dir, "first.json"), "{}");
  git("add", "first.json"); git("commit", "-q", "-m", "add first");
  writeFileSync(join(dir, "second.json"), "{}");
  git("add", "second.json"); git("commit", "-q", "-m", "add second");
  const idx = await readLocalCommitIndex(dir);
  ok("first.json -> 0 (commit más viejo)", idx.get("first.json") === 0);
  ok("second.json -> 1", idx.get("second.json") === 1);
  ok("dir sin git -> mapa vacío", (await readLocalCommitIndex(join(dir, "nope"))).size === 0);
} finally {
  rmSync(dir, { recursive: true, force: true });
}

console.log("# ghCommitIndex (hosted GitHub-API source) with a fake client");
// Fake client: two commits, oldest-first sha0 adds a.json, sha1 adds b.json. listCommits returns
// oldest-first (as the real one does after its internal reverse). Count calls to prove caching.
let calls;
const makeClient = (head) => ({
  owner: "o", repo: "r",
  getHeadSha: async () => { calls.headSha++; return head; },
  listCommits: async () => { calls.listCommits++; return ["sha0", "sha1"]; },
  getCommitFiles: async (sha) => { calls.getCommitFiles++; return sha === "sha0" ? ["a.json"] : ["b.json"]; },
});
calls = { headSha: 0, listCommits: 0, getCommitFiles: 0 };
const gi = await ghCommitIndex(makeClient("HEAD1"));
ok("maps added paths to commit ordinal (oldest=0)", gi.get("a.json") === 0 && gi.get("b.json") === 1);
ok("walked every commit once", calls.getCommitFiles === 2 && calls.listCommits === 1);
await ghCommitIndex(makeClient("HEAD1"));                          // same head -> cache hit
ok("cache hit on unchanged HEAD: no re-walk", calls.listCommits === 1 && calls.getCommitFiles === 2);
await ghCommitIndex(makeClient("HEAD2"));                          // new head -> re-walk
ok("new HEAD invalidates cache: re-walks", calls.listCommits === 2 && calls.getCommitFiles === 4);
const forced = await ghCommitIndex(makeClient("HEAD2"), { cache: false });
ok("cache:false forces a walk", calls.listCommits === 3 && forced.get("b.json") === 1);

console.log(`\n${p} passed, ${f} failed`);
if (f) process.exit(1);
