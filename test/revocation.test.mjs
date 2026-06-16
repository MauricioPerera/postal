// Per-key time window + revocation. Run: node test/revocation.test.mjs
import {
  createIdentity, rotateIdentity, publicIdentityDoc, keyTimeline,
  buildEvent, verifyEvent,
} from "../src/postal.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

const bob = await createIdentity("Bob");
const enc = (id, idnt) => ({ id, encPublicKey: idnt.enc.publicKey });
const msg = (signer, created_at, rnd, idnt) => buildEvent(signer, {
  kind: "message", chat_id: "c1", to: [bob.id], created_at, rnd,
  body: { text: "x" }, recipients: [enc(signer.id, signer), enc(bob.id, bob)],
});

const T = "2026-06-16T12:00:00.000Z";          // rotation time
const before = "2026-06-16T11:00:00.000Z";
const after = "2026-06-16T13:00:00.000Z";

console.log("# graceful rotation: old key valid only BEFORE the rotation");
const a0 = await createIdentity("Alice");
const a1 = await rotateIdentity(a0, T);          // graceful
const dirG = { [a1.id]: await publicIdentityDoc(a1), [bob.id]: await publicIdentityDoc(bob) };
const members = [{ id: a1.id, role: "owner" }, { id: bob.id, role: "member" }];

ok("timeline: genesis key until=T, current key until=null",
  keyTimeline(dirG[a1.id]).map((k) => k.until).join("|") === `${T}|`);

const oldBefore = await msg(a0, before, "ob", a0);
ok("old key signing an event dated BEFORE rotation -> valid",
  (await verifyEvent(oldBefore, { directory: dirG, members })).ok);

const oldAfter = await msg(a0, after, "oa", a0);
const rAfter = await verifyEvent(oldAfter, { directory: dirG, members });
ok("old key signing an event dated AFTER rotation -> rejected", !rAfter.ok && rAfter.reasons.includes("invalid-signature"));

const curAfter = await msg(a1, after, "ca", a1);
ok("current key signing an event after rotation -> valid",
  (await verifyEvent(curAfter, { directory: dirG, members })).ok);

console.log("# compromise revocation: old key invalid for ALL events (even backdated)");
const b0 = await createIdentity("Carol");
const b1 = await rotateIdentity(b0, T, "compromise");   // revoke the old key
const dirC = { [b1.id]: await publicIdentityDoc(b1), [bob.id]: await publicIdentityDoc(bob) };
const membersC = [{ id: b1.id, role: "owner" }, { id: bob.id, role: "member" }];

ok("timeline marks the genesis key revoked", keyTimeline(dirC[b1.id])[0].revoked === true);

const backdated = await msg(b0, before, "bd", b0); // attacker backdates with compromised key
const rBack = await verifyEvent(backdated, { directory: dirC, members: membersC });
ok("compromised key cannot sign even a BACKDATED event", !rBack.ok && rBack.reasons.includes("invalid-signature"));

const curOk = await msg(b1, after, "cok", b1);
ok("the new (current) key still works after a compromise rotation",
  (await verifyEvent(curOk, { directory: dirC, members: membersC })).ok);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
