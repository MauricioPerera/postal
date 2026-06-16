// Batching tests: offline quantization + a real ONE-commit-for-N-files batch.
// Offline part always runs. Set GH_OWNER/GH_REPO/GH_TOKEN to run the live part.
import { boundary, quantizeTime, nextBoundary, makeOutbox, DEFAULT_PERIOD_MS } from "../src/batch.js";
import { createIdentity } from "../src/postal.js";
import { buildPrivateEvent, privateEventPath } from "../src/private.js";
import { ghClient } from "../src/github.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

console.log("# time quantization (offline)");
const P = 10 * 60 * 1000;
ok("DEFAULT_PERIOD_MS is 10 min", DEFAULT_PERIOD_MS === P);
ok("quantize floors to the boundary",
  quantizeTime("2026-06-16T20:07:33.512Z", P) === "2026-06-16T20:00:00.000Z");
ok("quantize is stable within a window",
  quantizeTime("2026-06-16T20:00:00.000Z", P) === quantizeTime("2026-06-16T20:09:59.999Z", P));
ok("different windows quantize differently",
  quantizeTime("2026-06-16T20:05:00Z", P) !== quantizeTime("2026-06-16T20:15:00Z", P));
ok("nextBoundary advances to the next slot",
  nextBoundary(Date.parse("2026-06-16T20:03:00Z"), P) === Date.parse("2026-06-16T20:10:00Z"));

console.log("# outbox accumulates then flushes (offline shape)");
const fakeClient = { commitFiles: async (files) => { fakeClient._last = files; return "deadbeef"; } };
const ob = makeOutbox(fakeClient);
ob.add("a.json", "1"); ob.add("b.json", "2");
ok("queue holds 2", ob.size() === 2);
const r = await ob.flush("x");
ok("flush returns one sha for 2 files", r.sha === "deadbeef" && r.count === 2);
ok("queue cleared after flush", ob.size() === 0);
ok("empty flush is a no-op", (await ob.flush()) === null);

// --- live: prove N events land in ONE real commit ---------------------------
const owner = process.env.GH_OWNER, repo = process.env.GH_REPO, token = process.env.GH_TOKEN;
if (owner && repo && token) {
  console.log("# live: 3 events -> 1 commit on a real repo");
  const client = ghClient({ owner, repo, token });
  const alice = await createIdentity("Alice");
  const bob = await createIdentity("Bob");
  const recipients = [
    { id: alice.id, encPublicKey: alice.enc.publicKey },
    { id: bob.id, encPublicKey: bob.enc.publicKey },
  ];
  const chat = "c_" + alice.id + "_batch";
  const tag = Date.now().toString(36);
  const period = 10 * 60 * 1000;
  const outbox = makeOutbox(client);
  for (let i = 0; i < 3; i++) {
    const created_at = quantizeTime(new Date().toISOString(), period); // same boundary for all
    const ev = await buildPrivateEvent(alice, { chat_id: chat, to: [bob.id], text: `msg ${tag}-${i}`, created_at }, recipients);
    outbox.add(await privateEventPath(chat), JSON.stringify(ev, null, 2));
  }
  const result = await outbox.flush(`postal: batch ${tag}`);
  ok("flush committed 3 files", result && result.count === 3);

  // Fetch the commit and confirm it touched exactly 3 files in ONE commit.
  const res = await fetch(`https://api.github.com/repos/${owner}/${repo}/commits/${result.sha}`, {
    headers: { Authorization: "Bearer " + token, Accept: "application/vnd.github+json" },
  });
  const commit = await res.json();
  ok("the single commit contains all 3 files", (commit.files || []).length === 3);
  ok("commit has exactly one parent (linear, one batch)", (commit.parents || []).length === 1);
} else {
  console.log("# live batch test skipped (set GH_OWNER/GH_REPO/GH_TOKEN)");
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
