// Private mode (metadata reduction) tests. Run: node test/private.test.mjs
import { createIdentity, publicIdentityDoc } from "../src/postal.js";
import { buildPrivateEvent, openPrivateEvent, chatTag, privateEventPath } from "../src/private.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

const alice = await createIdentity("Alice");
const bob = await createIdentity("Bob");
const eve = await createIdentity("Eve");
const directory = { [alice.id]: await publicIdentityDoc(alice), [bob.id]: await publicIdentityDoc(bob), [eve.id]: await publicIdentityDoc(eve) };

const chat = "c_" + alice.id + "_secret";
const recipients = [
  { id: alice.id, encPublicKey: alice.enc.publicKey },
  { id: bob.id, encPublicKey: bob.enc.publicKey },
];
const members = [
  { id: alice.id, role: "owner" },
  { id: bob.id, role: "member" },
];
const secret = "el grafo social no debe verse";
const outer = await buildPrivateEvent(alice, { chat_id: chat, to: [bob.id], text: secret, created_at: "2026-06-16T20:00:00.000Z" }, recipients);

console.log("# the outer file leaks no routing metadata");
const blob = JSON.stringify(outer);
ok("no 'from'/author id in clear", !blob.includes(alice.id));
ok("no recipient id in clear", !blob.includes(bob.id));
ok("no chat_id in clear", !blob.includes(chat));
ok("no plaintext in clear", !blob.includes("grafo social"));
ok("no created_at field in clear", !blob.includes("2026-06-16T20:00:00"));
ok("only opaque fields present", Object.keys(outer).sort().join(",") === "alg,ct,epk,iv,t,v,w");

console.log("# path is opaque (hashed chat dir, random file)");
const p = await privateEventPath(chat);
ok("path uses hashed chat tag, no chat_id", p.includes(await chatTag(chat)) && !p.includes(chat));
ok("path has no date components", !/\/20\d\d\//.test(p));

console.log("# recipient count is hidden (padded to a bucket)");
ok("wrap slots padded to >=4 despite 2 recipients", outer.w.length >= 4);

console.log("# only recipients can open; signature verified after decrypt");
const bobView = await openPrivateEvent(outer, bob, chat, directory, members);
ok("Bob opens + verifies", bobView.ok && bobView.event.text === secret && bobView.event.from === alice.id);
const aliceView = await openPrivateEvent(outer, alice, chat, directory, members);
ok("Alice (sender) re-reads", aliceView.ok && aliceView.event.text === secret);
const eveView = await openPrivateEvent(outer, eve, chat, directory, members);
ok("Eve (not a recipient) cannot open", !eveView.ok && eveView.reason === "not-a-recipient");

console.log("# tampering / forgery");
// Flip a byte in the body ciphertext -> AEAD fails -> not-a-recipient (can't unwrap/decrypt).
const tampered = { ...outer, ct: outer.ct.slice(0, -2) + (outer.ct.endsWith("AA") ? "BB" : "AA") };
const tView = await openPrivateEvent(tampered, bob, chat, directory, members);
ok("tampered ciphertext rejected", !tView.ok);

// Forge inner signature: re-seal with Eve signing but claiming from=alice is impossible
// without Alice's key; here we check a wrong-chat aad fails to open.
const otherChatView = await openPrivateEvent(outer, bob, "c_" + alice.id + "_OTHER", directory, members);
ok("opening under a different chat tag fails (aad binding)", !otherChatView.ok);

console.log("# non-member author is rejected even if signature + decryption succeed");
// Eve (NOT in members) seals a private event from=eve to bob. Bob can decrypt (he is a
// recipient) and Eve's signature is valid (her key is in the directory), but she is not a
// member of the chat -> openPrivateEvent must reject as author-not-member. Without the
// members roster, this would be accepted (ok:true) — the H2 hole.
const eveRecipients = [
  { id: bob.id, encPublicKey: bob.enc.publicKey },
  { id: eve.id, encPublicKey: eve.enc.publicKey },
];
const eveOuter = await buildPrivateEvent(eve, { chat_id: chat, to: [bob.id], text: "inyectado", created_at: "2026-06-16T21:00:00.000Z" }, eveRecipients);
const r = await openPrivateEvent(eveOuter, bob, chat, directory, members);
ok("non-member author rejected (author-not-member)", !r.ok && r.reason === "author-not-member");
// Sanity: without the roster the same event is accepted (signature-only) — proves the
// members arg is what closes the hole, not some other change.
const rNoMembers = await openPrivateEvent(eveOuter, bob, chat, directory);
ok("without members roster, non-member author is accepted (signature-only)", rNoMembers.ok && rNoMembers.event.from === eve.id);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
