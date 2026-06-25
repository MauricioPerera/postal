// Runtime schema enforcement (issue #23). The on-disk schema/event.schema.json is
// NOT loaded at runtime — verifyEvent enforces the declared shape INLINE, with no
// JSON-Schema library (dep-free, isomorphic browser+node). This test breaks ONE field
// at a time on a valid signed event and asserts the new reason fires; and that fully
// valid events (incl. a member with attestations and a message with a sealed body)
// still PASS. The allowed top-level set is a SUPERSET of the schema properties: it
// includes `attestations`, which member events carry and signedView strips to sign.
// Run: node test/schema-runtime.test.mjs
import {
  createIdentity, publicIdentityDoc, buildEvent, buildMemberEvent, verifyEvent,
} from "../src/postal.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

const alice = await createIdentity("Alice");
const bob = await createIdentity("Bob");
const directory = { [alice.id]: await publicIdentityDoc(alice), [bob.id]: await publicIdentityDoc(bob) };
const members = [{ id: alice.id, role: "owner" }, { id: bob.id, role: "member" }];
const recipients = [
  { id: alice.id, encPublicKey: alice.enc.publicKey },
  { id: bob.id, encPublicKey: bob.enc.publicKey },
];

// A valid non-message signed event: the base to break one field at a time.
const base = await buildEvent(alice, {
  kind: "receipt", chat_id: "c1", to: [bob.id],
  created_at: "2026-06-16T20:00:00.000Z", rnd: "rt1",
  body: { note: "seen" },
});
// A valid message event (sealed body).
const msg = await buildEvent(alice, {
  kind: "message", chat_id: "c1", to: [bob.id],
  created_at: "2026-06-16T20:05:00.000Z", rnd: "msg1",
  body: { text: "hi" }, recipients,
});
// A valid member event (carries attestations; owner alone adds at quorum 1).
const mem = await buildMemberEvent(alice, {
  chat_id: "c1", created_at: "2026-06-16T20:10:00.000Z", rnd: "mem1",
  op: "add", target: bob.id, role: "member",
});

const rejects = async (name, broken, reason) => {
  const r = await verifyEvent(broken, { directory, members });
  ok(`${name} -> ${reason}`, !r.ok && r.reasons.includes(reason));
};

console.log("# valid events pass (incl. attestations + sealed)");
ok("base receipt passes", (await verifyEvent(base, { directory, members })).ok);
ok("message with sealed passes", (await verifyEvent(msg, { directory, members })).ok);
ok("member with attestations passes", (await verifyEvent(mem, { directory, members })).ok);

console.log("# unknown top-level field -> unknown-field");
await rejects("extra field", { ...base, extra: "x" }, "unknown-field");

console.log("# body required + plain object -> bad-body");
await rejects("body null", { ...base, body: null }, "bad-body");
await rejects("body array", { ...base, body: [] }, "bad-body");
const noBody = { ...base }; delete noBody.body;
await rejects("body missing", noBody, "bad-body");

console.log("# to items must all be strings -> bad-to-item");
await rejects("to with number", { ...base, to: [123] }, "bad-to-item");
await rejects("to with object", { ...base, to: [{ x: 1 }] }, "bad-to-item");

console.log("# optional chain field types");
await rejects("seq negative", { ...base, seq: -1 }, "bad-seq");
await rejects("seq non-integer", { ...base, seq: 1.5 }, "bad-seq");
await rejects("prev non-string", { ...base, prev: 5 }, "bad-prev");
await rejects("supersedes non-string", { ...base, supersedes: 7 }, "bad-supersedes");

console.log("# message body must seal -> bad-message-body");
await rejects("message without sealed", { ...msg, body: {} }, "bad-message-body");
await rejects("message sealed no marker", { ...msg, body: { sealed: "X" } }, "bad-message-body");

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);