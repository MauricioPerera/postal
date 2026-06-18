// Key-rotation tests. Run: node test/rotation.test.mjs
import {
  createIdentity, rotateIdentity, publicIdentityDoc, verifyIdentityDoc,
  fingerprintOf, identitySignKeys, buildEvent, openMessage, verifyEvent,
} from "../src/postal.js";
import { canonical, importSignPrivate, sign } from "../src/crypto.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

const alice0 = await createIdentity("Alice");
const bob = await createIdentity("Bob");

console.log("# rotation preserves id and verifies");
const alice1 = await rotateIdentity(alice0, "2026-06-16T23:00:00.000Z");
const alice2 = await rotateIdentity(alice1, "2026-06-16T23:30:00.000Z");
ok("id is stable across rotations", alice0.id === alice1.id && alice1.id === alice2.id);
ok("current sign key changed", alice0.sign.publicKey !== alice2.sign.publicKey);

const doc2 = await publicIdentityDoc(alice2);
ok("rotated identity doc verifies (chain intact)", await verifyIdentityDoc(doc2));
ok("doc carries 2 rotations", doc2.rotations.length === 2);
ok("fingerprint shown is the GENESIS fingerprint (stable for OOB trust)",
  (await fingerprintOf(doc2)) === (await fingerprintOf(await publicIdentityDoc(alice0))));
ok("identitySignKeys lists genesis + 2 targets", identitySignKeys(doc2).length === 3);

console.log("# tampering the chain is rejected");
// Break a rotation signature.
const broken = JSON.parse(JSON.stringify(doc2));
broken.rotations[1].sig = broken.rotations[1].sig.slice(0, -4) + (broken.rotations[1].sig.endsWith("AAAA") ? "BBBB" : "AAAA");
ok("forged rotation signature rejected", !(await verifyIdentityDoc(broken)));

// Inject a rotation not signed by the previous key (attacker appends their own key).
const mallory = await createIdentity("Mallory");
const hijack = JSON.parse(JSON.stringify(await publicIdentityDoc(alice0)));
hijack.rotations = [{
  seq: 1, from_sign_pub: alice0.sign.publicKey,
  to_sign_pub: mallory.sign.publicKey, to_enc_pub: mallory.enc.publicKey,
  created_at: "2026-06-16T23:00:00.000Z",
  sig: await sign(await importSignPrivate(mallory.sign.privateJwk), "x"), // signed by Mallory, not Alice0
}];
hijack.sign_key.pub = mallory.sign.publicKey;
hijack.enc_key.pub = mallory.enc.publicKey;
ok("hijack rotation (not signed by prev key) rejected", !(await verifyIdentityDoc(hijack)));

console.log("# events across a rotation");
const directory = { [alice2.id]: doc2, [bob.id]: await publicIdentityDoc(bob) };
const members = [{ id: alice2.id, role: "owner" }, { id: bob.id, role: "member" }];
const enc = [
  { id: alice2.id, encPublicKey: alice2.enc.publicKey },
  { id: bob.id, encPublicKey: bob.enc.publicKey },
];

// Event signed with an OLD key (alice0) must still verify against the chain.
const oldEvent = await buildEvent(alice0, { kind: "message", chat_id: "c1", to: [bob.id], created_at: "2026-06-16T22:00:00.000Z", rnd: "old1", body: { text: "antiguo" }, recipients: enc });
ok("event signed by an old key still verifies after rotation",
  (await verifyEvent(oldEvent, { directory, members })).ok);

// Event signed with the current key.
const newEvent = await buildEvent(alice2, { kind: "message", chat_id: "c1", to: [bob.id], created_at: "2026-06-17T00:00:00.000Z", rnd: "new1", body: { text: "nuevo" }, recipients: enc });
ok("event signed by current key verifies", (await verifyEvent(newEvent, { directory, members })).ok);

// Decrypt an old message sealed to a previous enc key, using encHistory.
const sealedToOld = await buildEvent(bob, { kind: "message", chat_id: "c1", to: [alice0.id], created_at: "2026-06-16T22:10:00.000Z", rnd: "seal1", body: { text: "para alice vieja" }, recipients: [{ id: alice0.id, encPublicKey: alice0.enc.publicKey }, { id: bob.id, encPublicKey: bob.enc.publicKey }] });
ok("rotated identity opens a message sealed to an OLD enc key",
  (await openMessage(sealedToOld, alice2)) === "para alice vieja");

console.log("# a rotation is not a time machine: the new key cannot backdate before its activation");
// alice2 activated at its rotation time (23:30). An event it signs dated BEFORE that (when key1
// was the active key) must be rejected — otherwise rotating would grant retroactive forging power.
const newBackdated = await buildEvent(alice2, { kind: "message", chat_id: "c1", to: [bob.id], created_at: "2026-06-16T23:15:00.000Z", rnd: "nbd", body: { text: "backdated" }, recipients: enc });
const rnb = await verifyEvent(newBackdated, { directory, members });
ok("current key signing an event dated before its activation is rejected", !rnb.ok && rnb.reasons.includes("invalid-signature"));

console.log("# the rotation chain must have strictly increasing timestamps");
const backRot = await rotateIdentity(alice2, "2026-06-16T22:00:00.000Z");   // earlier than the prev rotation (23:30)
ok("non-monotonic rotation chain is rejected", !(await verifyIdentityDoc(await publicIdentityDoc(backRot))));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
