// Integration test: cli.js wires COMMIT-ANCHORED order into verifyRepo (ALTA-1).
//
// Builds a real git repo with two message events from DISTINCT authors whose
// created_at is in REVERSE order to their commit order (the event committed
// first has the NEWER created_at). Then:
//   (1) verifyRepo(tempdir) -> ok:true  (wiring does not break the happy path).
//   (2) attachCommitIndex(items, readLocalCommitIndex(tempdir)) feeds canonicalOrder
//       the commit order, which is DISTINCT from the created_at order -> proves the
//       verifier now anchors to commit, not the self-asserted created_at.
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import {
  createIdentity, publicIdentityDoc, buildChatMeta, buildEvent, buildMemberEvent,
  eventPath, userPath, chatMetaPath, newChatId,
} from "../src/postal.js";
import { verifyRepo } from "../src/cli.js";
import { readLocalCommitIndex, attachCommitIndex } from "../src/commit-order.js";
import { canonicalOrder } from "../src/order.js";

let pass = 0, fail = 0, n = 0;
const ok = (c, label) => {
  n++;
  if (c) { pass++; console.log("ok -", n, label); }
  else { fail++; console.log("FAIL -", n, label); }
};

const dir = mkdtempSync(join(tmpdir(), "postal-cli-co-"));
const git = (...a) => execFileSync("git", ["-C", dir, ...a], {
  encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
});
const writeRel = (rel, obj) => {
  const full = join(dir, ...rel.split("/"));
  mkdirSync(join(full, ".."), { recursive: true });
  writeFileSync(full, typeof obj === "string" ? obj : JSON.stringify(obj, null, 2));
};
const commit = (msg) => { git("add", "-A"); git("commit", "-q", "-m", msg); };

try {
  git("init", "-q");
  git("config", "user.email", "t@t");
  git("config", "user.name", "t");
  git("config", "commit.gpgsign", "false");

  // Two identities: Alice (owner) and Bob (member-to-be).
  const alice = await createIdentity("Alice");
  const bob = await createIdentity("Bob");
  const recipients = [
    { id: alice.id, encPublicKey: alice.enc.publicKey },
    { id: bob.id, encPublicKey: bob.enc.publicKey },
  ];

  const chat = newChatId(alice.id, "demo");
  const meta = await buildChatMeta(alice, { chat_id: chat, created_at: "2026-06-16T19:00:00.000Z" });

  // Initial commit: identities + meta.
  writeRel(userPath(alice.id), await publicIdentityDoc(alice));
  writeRel(userPath(bob.id), await publicIdentityDoc(bob));
  writeRel(chatMetaPath(chat), meta);
  commit("init: identities + meta");

  // Member event: Alice adds Bob (quorum add=1, Alice is owner -> passes).
  // Must precede Bob's message in replay order so Bob is a member when his
  // message is verified. created_at between meta and the messages.
  const memberEv = await buildMemberEvent(alice, {
    chat_id: chat, created_at: "2026-06-16T19:30:00.000Z", rnd: "mem1",
    op: "add", target: bob.id, role: "member",
  });
  writeRel(eventPath(chat, memberEv), memberEv);
  commit("add Bob as member");

  // Two message events from DISTINCT authors. created_at INVERSE to commit order:
  //   Alice's message: created_at 20:00 (NEWER)  -> committed FIRST
  //   Bob's message:   created_at 19:45 (OLDER)  -> committed SECOND
  const aliceMsg = await buildEvent(alice, {
    kind: "message", chat_id: chat, to: [bob.id],
    created_at: "2026-06-16T20:00:00.000Z", rnd: "a1",
    body: { text: "hi from alice" }, recipients,
  });
  writeRel(eventPath(chat, aliceMsg), aliceMsg);
  commit("alice message (newer created_at, committed first)");

  const bobMsg = await buildEvent(bob, {
    kind: "message", chat_id: chat, to: [alice.id],
    created_at: "2026-06-16T19:45:00.000Z", rnd: "b1",
    body: { text: "hi from bob" }, recipients,
  });
  writeRel(eventPath(chat, bobMsg), bobMsg);
  commit("bob message (older created_at, committed second)");

  // (1) Happy path: the wiring must not break verifyRepo.
  console.log("# verifyRepo on a commit-anchored tree");
  const r = await verifyRepo(dir);
  ok(r.ok === true, "verifyRepo ok:true (both messages valid)");
  ok(r.checked === 3, "verifyRepo checked 3 events (member + 2 messages)");
  ok(r.failures.length === 0, "no failures");

  // (2) Proof: commit order is used, NOT created_at.
  console.log("# canonicalOrder anchored to commit != created_at order");
  const idx = await readLocalCommitIndex(dir);
  const alicePath = eventPath(chat, aliceMsg);
  const bobPath = eventPath(chat, bobMsg);
  ok(idx.has(alicePath) && idx.has(bobPath), "both message paths present in commit index");
  ok(idx.get(alicePath) < idx.get(bobPath), "alice committed before bob (lower commitIndex)");

  const items = [
    { path: alicePath, event: aliceMsg },
    { path: bobPath, event: bobMsg },
  ];
  const byTime = canonicalOrder(items).map((i) => i.event.from).join(",");
  const byCommit = canonicalOrder(attachCommitIndex(items, idx)).map((i) => i.event.from).join(",");

  ok(byTime === `${bob.id},${alice.id}`, "by created_at: bob(older) first, alice(second)");
  ok(byCommit === `${alice.id},${bob.id}`, "by commit: alice(first commit) first, bob(second)");
  ok(byTime !== byCommit, "commit order DISTINCT from created_at order -> commit anchor is in effect");
} finally {
  rmSync(dir, { recursive: true, force: true });
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);