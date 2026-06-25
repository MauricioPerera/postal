// pollChat anchors canonical order to COMMIT history (hosted GitHub-API path), not self-asserted
// created_at. Run: node test/transport-commit-order.test.mjs
import { createIdentity, publicIdentityDoc, buildEvent, buildMemberEvent, eventPath, newChatId, buildChatMeta, chatMetaPath } from "../src/postal.js";
import { pollChat } from "../src/transport.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

const alice = await createIdentity("Alice"), bob = await createIdentity("Bob");
const directory = { [alice.id]: await publicIdentityDoc(alice), [bob.id]: await publicIdentityDoc(bob) };
const members = [{ id: alice.id, role: "owner" }, { id: bob.id, role: "member" }];
const enc = [{ id: alice.id, encPublicKey: alice.enc.publicKey }, { id: bob.id, encPublicKey: bob.enc.publicKey }];

const chat = newChatId(alice.id, "cc1");

// Membership: alice (genesis owner) adds bob. Required so bob's later message passes the gate.
const evMember = await buildMemberEvent(alice, { chat_id: chat, created_at: "2026-06-17T00:00:00.000Z", rnd: "rm", op: "add", target: bob.id, role: "member" });

// Two messages by DIFFERENT authors. Their created_at is the REVERSE of their commit order:
//   commit order:  evA (idx1) then evB (idx2)
//   created_at:    evB (18th)  then evA (19th)
// So a created_at-ordered return would diverge from the commit-anchored return.
const evA = await buildEvent(alice, { kind: "message", chat_id: chat, to: [bob.id], created_at: "2026-06-19T08:00:00.000Z", rnd: "rA", body: { text: "A" }, recipients: enc });
const evB = await buildEvent(bob,   { kind: "message", chat_id: chat, to: [alice.id], created_at: "2026-06-18T12:00:00.000Z", rnd: "rB", body: { text: "B" }, recipients: enc });

const pMember = eventPath(chat, evMember);
const pA = eventPath(chat, evA);
const pB = eventPath(chat, evB);
const metaPath = chatMetaPath(chat);

ok("fixture: created_at order is the reverse of commit order (evB before evA)", evB.created_at < evA.created_at);

const store = new Map([
  [pMember, JSON.stringify(evMember)],
  [pA, JSON.stringify(evA)],
  [pB, JSON.stringify(evB)],
  [metaPath, JSON.stringify(await buildChatMeta(alice, { chat_id: chat }))],
]);

// Fake HOSTED client that DOES expose the GitHub commits API (oldest-first history).
// getCommitFiles maps each commit sha to the path(s) it ADDED -> ghCommitIndex assigns ordinal.
const commitFiles = new Map([
  ["shaC0", [pMember]],
  ["shaC1", [pA]],
  ["shaC2", [pB]],
]);
const fakeClient = {
  owner: "o", repo: "r",
  listTree: async (p) => [...store.keys()].filter((k) => k.indexOf(p) === 0).sort(),
  getFile: async (p) => (store.has(p) ? { content: store.get(p) } : null),
  getHeadSha: async () => "head-sha-fixed",
  commitsSince: async (_since) => ({ full: true, shas: ["shaC0", "shaC1", "shaC2"] }), // oldest-first
  getCommitFiles: async (sha) => commitFiles.get(sha) || [],
};

console.log("# pollChat (hosted, commit API): order follows COMMIT history, not created_at");
const rCommit = await pollChat(fakeClient, bob, chat, { directory, members });
const msgsCommit = rCommit.filter((r) => r.verdict.ok && r.event && r.event.kind === "message");
ok("both messages verify (gate passes for both authors)", msgsCommit.length === 2 && msgsCommit.every((r) => r.verdict.ok));
ok("returned order is COMMIT order (evA before evB), the opposite of created_at",
  msgsCommit.length === 2 && msgsCommit[0].event.id === evA.id && msgsCommit[1].event.id === evB.id);

// --- fallback: a client WITHOUT the commit API must keep the historical created_at order ---
console.log("# pollChat (no commit API): falls back to created_at order, no throw");
const memClient = {
  listTree: async (p) => [...store.keys()].filter((k) => k.indexOf(p) === 0).sort(),
  getFile: async (p) => (store.has(p) ? { content: store.get(p) } : null),
};
let rFallback, threw = false;
try { rFallback = await pollChat(memClient, bob, chat, { directory, members }); } catch { threw = true; }
ok("pollChat does not throw without a commit API", !threw);
const msgsFallback = rFallback.filter((r) => r.verdict.ok && r.event && r.event.kind === "message");
ok("both messages verify under fallback", msgsFallback.length === 2);
ok("fallback order is created_at order (evB before evA)",
  msgsFallback.length === 2 && msgsFallback[0].event.id === evB.id && msgsFallback[1].event.id === evA.id);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);