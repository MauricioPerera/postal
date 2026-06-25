// Issue #22 — metadata privacy: anonymous sealing by default + omitable `to`.
// Reduces social-graph leakage: messages seal anonymously (no recipient ids in the
// envelope) and `to` may be omitted (carried as []) so the event names no recipient.
// openMessage opens BOTH the anonymous and the legacy labeled formats (backward compat).
// Run: node test/metadata-privacy.test.mjs
import {
  createIdentity, publicIdentityDoc, buildEvent, openMessage, verifyEvent, newChatId,
} from "../src/postal.js";
import { base64ToBytes, utf8Text } from "../src/crypto.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };
// openMessage returns null for non-messages and THROWS when a real message won't open
// for the caller. "Does not open" = either outcome, so we normalize both to a boolean.
const opens = async (ev, who) => {
  try { const t = await openMessage(ev, who); return t != null; }
  catch { return false; }
};
const sealedJson = (ev) => JSON.parse(utf8Text(base64ToBytes(String(ev.body.sealed).slice("POSTAL1:".length))));

const alice = await createIdentity("Alice");
const bob = await createIdentity("Bob");
const carol = await createIdentity("Carol");
const directory = {
  [alice.id]: await publicIdentityDoc(alice),
  [bob.id]: await publicIdentityDoc(bob),
  [carol.id]: await publicIdentityDoc(carol),
};
const chat = newChatId(alice.id, "meta");

// NOTE: sealAnonymous pads the plaintext to a size bucket and openAnonymous trims
// TRAILING spaces (`/ +$/`). Test texts below have NO trailing spaces, so the opened
// text equals the input verbatim. A text ending in spaces would be silently trimmed.
console.log("# anonymous sealing is the DEFAULT; `to` may be omitted (no recipient named)");
const ev1 = await buildEvent(alice, {
  kind: "message", chat_id: chat, created_at: "2026-06-25T10:00:00.000Z", rnd: "m1",
  body: { text: "hola-mundo" },
  recipients: [{ id: bob.id, encPublicKey: bob.enc.publicKey }],
  // `to` intentionally OMITTED -> the event must not name Bob
});
ok("ev.to is [] (no recipient named in clear)", Array.isArray(ev1.to) && ev1.to.length === 0);
ok("sealed.alg is the anonymous form (ends in /anon)", /\/anon$/.test(String(sealedJson(ev1).alg)));
ok("Bob (recipient) opens the anonymous message", await opens(ev1, bob));
ok("Carol (non-recipient) cannot open it", !(await opens(ev1, carol)));
ok("opened plaintext matches input (no trailing-space trim here)",
  (await openMessage(ev1, bob)) === "hola-mundo");
// Document the openAnonymous trailing-space trim: a text padded with spaces at the end
// would be trimmed. We assert the trim happens so callers know the contract.
const evPad = await buildEvent(alice, {
  kind: "message", chat_id: chat, created_at: "2026-06-25T10:01:00.000Z", rnd: "m1p",
  body: { text: "padded   " }, // trailing spaces
  recipients: [{ id: bob.id, encPublicKey: bob.enc.publicKey }],
});
ok("openAnonymous trims trailing size-padding spaces (documented contract)",
  (await openMessage(evPad, bob)) === "padded");

console.log("# multi-recipient anonymous: both open, envelope names no one");
const ev2 = await buildEvent(alice, {
  kind: "message", chat_id: chat, created_at: "2026-06-25T10:05:00.000Z", rnd: "m2",
  body: { text: "hola-ambos" },
  recipients: [
    { id: bob.id, encPublicKey: bob.enc.publicKey },
    { id: carol.id, encPublicKey: carol.enc.publicKey },
  ],
});
const s2 = sealedJson(ev2);
ok("both recipients open the same anonymous message",
  (await opens(ev2, bob)) && (await opens(ev2, carol)));
ok("envelope has no `keys` map (no recipient ids)", !("keys" in s2));
ok("envelope carries an unlabeled wrap array `w`", Array.isArray(s2.w));
ok("no recipient id appears in the sealed envelope blob",
  !JSON.stringify(s2).includes(bob.id) && !JSON.stringify(s2).includes(carol.id));

console.log("# backward compatibility: legacy labeled (seal:'labeled') still opens");
const ev3 = await buildEvent(alice, {
  kind: "message", chat_id: chat, to: [bob.id], seal: "labeled",
  created_at: "2026-06-25T10:10:00.000Z", rnd: "m3",
  body: { text: "directo" },
  recipients: [{ id: bob.id, encPublicKey: bob.enc.publicKey }],
});
const s3 = sealedJson(ev3);
ok("labeled envelope alg is the legacy form (not /anon)", !String(s3.alg).includes("/anon"));
ok("labeled envelope carries a keyed `keys` map naming the recipient", "keys" in s3 && bob.id in s3.keys);
ok("Bob opens the legacy labeled message (openMessage legacy branch)", await opens(ev3, bob));
ok("Carol (not in labeled keys) cannot open the legacy message", !(await opens(ev3, carol)));

console.log("# gate: an event with to:[] passes verifyEvent (no to-not-array / bad-to-item)");
const r4 = await verifyEvent(ev1, { directory });
ok("verifyEvent ok for an omitted-to (to:[]) message", r4.ok);
ok("no 'to-not-array' reason", !r4.reasons.includes("to-not-array"));
ok("no 'bad-to-item' reason", !r4.reasons.includes("bad-to-item"));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);