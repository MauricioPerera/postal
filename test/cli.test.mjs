// Offline test for the filesystem gate (src/cli.js). Builds a temp .postal tree
// with one valid and one forged event, then asserts verifyRepo blocks the forgery.
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createIdentity, publicIdentityDoc, buildEvent, eventPath, userPath } from "../src/postal.js";
import { canonical, importSignPrivate, sign } from "../src/crypto.js";
import { verifyRepo } from "../src/cli.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

const root = mkdtempSync(join(tmpdir(), "postal-"));
const write = (rel, obj) => {
  const full = join(root, rel.split("/").join("/"));
  mkdirSync(join(full, ".."), { recursive: true });
  writeFileSync(full, JSON.stringify(obj, null, 2));
};

const alice = await createIdentity("Alice");
const bob = await createIdentity("Bob");
const eve = await createIdentity("Eve");

write(userPath(alice.id), await publicIdentityDoc(alice));
write(userPath(bob.id), await publicIdentityDoc(bob));
write(userPath(eve.id), await publicIdentityDoc(eve));

const chat = "c1";
// meta.json declares the genesis owner; membership is replayed from here.
write(`.postal/chats/${chat}/meta.json`, { v: 1, id: chat, created_by: alice.id, created_at: "2026-06-16T19:59:00.000Z" });
const recipients = [
  { id: alice.id, encPublicKey: alice.enc.publicKey },
  { id: bob.id, encPublicKey: bob.enc.publicKey },
];
const good = await buildEvent(alice, {
  kind: "message", chat_id: chat, to: [bob.id],
  created_at: "2026-06-16T20:00:00.000Z", rnd: "aaa111",
  body: { text: "legit" }, recipients,
});
write(eventPath(chat, good), good);

console.log("# gate on a clean tree");
let r = await verifyRepo(root);
ok("clean tree passes", r.ok && r.checked === 1 && r.identities === 3);

console.log("# gate catches a forged from=Alice event");
const created_at = "2026-06-16T20:05:00.000Z";
const forged = {
  v: 1, kind: "message", chat_id: chat, from: alice.id, to: [bob.id],
  created_at, id: created_at.replace(/[:.]/g, "-") + "_" + alice.id + "_dead99",
  body: { sealed: "POSTAL1:ZmFrZQ==" },
};
forged.sig = await sign(await importSignPrivate(eve.sign.privateJwk), canonical(forged)); // Eve's key!
write(eventPath(chat, forged), forged);

r = await verifyRepo(root);
ok("forged tree is blocked", !r.ok);
ok("failure points at the forged file with invalid-signature",
  r.failures.some((f) => f.path.includes("dead99") && f.reasons.includes("invalid-signature")));

rmSync(root, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
