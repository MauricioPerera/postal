// Postal protocol tests. Run: node test/postal.test.mjs
import {
  createIdentity, publicIdentityDoc, verifyIdentityDoc, fingerprintOf,
  buildEvent, openMessage, verifyEvent, eventPath,
} from "../src/postal.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };
async function rejects(n, fn) { try { await fn(); fail++; console.error("  FAIL- (expected throw)", n); } catch { pass++; console.log("  ok  - (threw)", n); } }

const alice = await createIdentity("Alice");
const bob = await createIdentity("Bob");
const eve = await createIdentity("Eve");

console.log("# identity (HARD: self-signed, id = key fingerprint)");
const aliceDoc = await publicIdentityDoc(alice);
ok("identity doc self-verifies", await verifyIdentityDoc(aliceDoc));
ok("id is derived from sign key (16 hex)", /^[0-9A-F]{16}$/.test(alice.id) && aliceDoc.id === alice.id);
ok("human fingerprint is shown for OOB trust", (await fingerprintOf(aliceDoc)).includes(":"));

// Tamper: swap display name without re-signing -> must fail.
const forgedDoc = { ...aliceDoc, display_name: "Mallory" };
ok("tampered identity doc rejected", !(await verifyIdentityDoc(forgedDoc)));
// Tamper: claim Alice's id with Eve's keys -> id won't match the key.
const impersonation = { ...(await publicIdentityDoc(eve)), id: alice.id };
ok("id/key mismatch rejected (no impersonation)", !(await verifyIdentityDoc(impersonation)));

console.log("# messages (HARD signature + sealed body)");
const directory = {
  [alice.id]: aliceDoc,
  [bob.id]: await publicIdentityDoc(bob),
  [eve.id]: await publicIdentityDoc(eve),
};
const members = [{ id: alice.id, role: "owner" }, { id: bob.id, role: "member" }];
const recipients = [
  { id: alice.id, encPublicKey: alice.enc.publicKey },
  { id: bob.id, encPublicKey: bob.enc.publicKey },
];

const ev = await buildEvent(alice, {
  kind: "message", chat_id: "c1", to: [bob.id],
  created_at: "2026-06-16T20:00:00.000Z", rnd: "a1b2c3",
  body: { text: "Bob: firmado por mí, legible solo por ti" }, recipients,
});

ok("message body is sealed (not plaintext)",
  ev.body.sealed.startsWith("POSTAL1:") && !JSON.stringify(ev).includes("legible solo"));
ok("recipient Bob opens it", (await openMessage(ev, bob)) === "Bob: firmado por mí, legible solo por ti");
ok("sender Alice re-opens it", (await openMessage(ev, alice)) === "Bob: firmado por mí, legible solo por ti");
await rejects("non-recipient Eve cannot open", () => openMessage(ev, eve));

console.log("# the deterministic gate (verifyEvent)");
const seen = new Set();
ok("valid event passes the gate", (await verifyEvent(ev, { directory, members })).ok);

// Forge: flip the signature -> invalid-signature.
const forgedSig = { ...ev, sig: ev.sig.slice(0, -4) + (ev.sig.endsWith("AAAA") ? "BBBB" : "AAAA") };
const r1 = await verifyEvent(forgedSig, { directory, members });
ok("forged signature rejected", !r1.ok && r1.reasons.includes("invalid-signature"));

// Tamper a signed field (chat_id) without re-signing.
const tampered = { ...ev, chat_id: "c2" };
const r2 = await verifyEvent(tampered, { directory, members });
ok("tampered field rejected", !r2.ok && r2.reasons.includes("invalid-signature"));

// Author not in members -> author-not-member.
const r3 = await verifyEvent(ev, { directory, members: [{ id: bob.id, role: "member" }] });
ok("non-member author rejected", !r3.ok && r3.reasons.includes("author-not-member"));

// Unknown author (not in directory).
const r4 = await verifyEvent(ev, { directory: {}, members });
ok("unknown author rejected", !r4.ok && r4.reasons.includes("unknown-author"));

// Append-only: path already seen -> overwrites-existing.
seen.add(eventPath(ev.chat_id, ev));
const r5 = await verifyEvent(ev, { directory, members, seenPaths: seen });
ok("overwrite of existing path rejected", !r5.ok && r5.reasons.includes("overwrites-existing"));

// Non-deterministic id (id not derived from created_at+from).
const badId = { ...ev, id: "whatever_random" };
badId.sig = ev.sig; // sig won't match anyway, but check the id rule fires
const r6 = await verifyEvent(badId, { directory, members });
ok("non-deterministic id rejected", !r6.ok && r6.reasons.includes("non-deterministic-id"));

console.log("# open kinds (apps define their own)");
const custom = await buildEvent(alice, { kind: "task", chat_id: "c1", to: [bob.id], created_at: "2026-06-16T20:30:00.000Z", rnd: "tsk1", body: { title: "do X" }, recipients });
ok("an app-defined kind ('task') passes the gate", (await verifyEvent(custom, { directory, members })).ok);
const emptyKind = { ...ev, kind: "" };
ok("an empty kind is rejected", !(await verifyEvent(emptyKind, { directory, members })).ok);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
