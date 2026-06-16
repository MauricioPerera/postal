// Membership replay tests. Run: node test/replay.test.mjs
// The gate rebuilds membership from the genesis owner; no members.json snapshot.
import {
  createIdentity, publicIdentityDoc,
  buildEvent, buildMemberEvent, eventPath, verifyChat,
} from "../src/postal.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

const a = await createIdentity("Owner");
const b = await createIdentity("Bob");
const c = await createIdentity("Cand");

const directory = {};
for (const i of [a, b, c]) directory[i.id] = await publicIdentityDoc(i);

const chat = "c1";
const enc = (ids) => ids.map((id) => ({ id, encPublicKey: ({ [a.id]: a, [b.id]: b, [c.id]: c })[id].enc.publicKey }));
const item = (ev) => ({ path: eventPath(chat, ev), event: ev });

// Timeline:
//  t1  A adds B as admin            (op:add role:admin, quorum 1 — bootstrap)
//  t2  A + B promote C to admin     (op:set_role, quorum 2)
//  t3  C sends a message            (C is a member by now -> allowed)
const t1 = await buildMemberEvent(a, { chat_id: chat, created_at: "2026-06-16T22:00:00.000Z", rnd: "r1", op: "add", target: b.id, role: "admin" });
const t2 = await buildMemberEvent(a, { chat_id: chat, created_at: "2026-06-16T22:01:00.000Z", rnd: "r2", op: "set_role", target: c.id, role: "admin" }, [b]);
const t3 = await buildEvent(c, { kind: "message", chat_id: chat, to: [a.id], created_at: "2026-06-16T22:02:00.000Z", rnd: "r3", body: { text: "hola" }, recipients: enc([a.id, c.id]) });

// Note: t2 promotes C but C was never added. set_role on a non-member is a no-op for
// membership, so C still isn't a member -> t3 should FAIL author-not-member.
console.log("# replay catches an out-of-order membership gap");
let res = await verifyChat([item(t3), item(t2), item(t1)], { directory, genesisOwner: a.id });
const t3res = res.results.find((r) => r.path === item(t3).path);
ok("C's message rejected: C was promoted but never added (author-not-member)",
  t3res && !t3res.verdict.ok && t3res.verdict.reasons.includes("author-not-member"));

// Fix the timeline: add C before promoting.
console.log("# correct timeline replays cleanly");
const addC = await buildMemberEvent(a, { chat_id: chat, created_at: "2026-06-16T22:00:30.000Z", rnd: "r0", op: "add", target: c.id, role: "member" });
res = await verifyChat([item(t3), item(t2), item(t1), item(addC)], { directory, genesisOwner: a.id });
ok("all events valid when C is added then promoted", res.ok);
ok("final membership: A owner, B admin, C admin",
  res.members.find((m) => m.id === a.id).role === "owner" &&
  res.members.find((m) => m.id === b.id).role === "admin" &&
  res.members.find((m) => m.id === c.id).role === "admin");

console.log("# a single genesis owner can bootstrap (add admin at quorum 1)");
ok("B was added as admin by the owner alone",
  (await verifyChat([item(t1)], { directory, genesisOwner: a.id })).ok);

console.log("# promotion before a second admin exists is blocked");
// Only A is owner; A alone tries set_role on B (who isn't a member) -> needs quorum 2.
const promoEarly = await buildMemberEvent(a, { chat_id: chat, created_at: "2026-06-16T22:05:00.000Z", rnd: "r9", op: "set_role", target: b.id, role: "admin" });
const r2 = await verifyChat([item(promoEarly)], { directory, genesisOwner: a.id });
ok("lone owner cannot set_role (quorum 2 unmet)",
  !r2.ok && r2.failures[0].reasons.some((x) => x.startsWith("insufficient-quorum")));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
