// Forward secrecy by epoch (issue #21): retired enc keys can be pruned so a future
// key compromise cannot open messages from already-pruned epochs.
// Run: node test/forward-secrecy.test.mjs
import {
  createIdentity, rotateIdentity, buildEvent, openMessage, pruneEncKeys,
} from "../src/postal.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };
const throws = async (fn) => { try { await fn(); return false; } catch { return true; } };

const t1 = "2026-06-20T10:00:00.000Z";
const t2 = "2026-06-20T12:00:00.000Z";
const t3 = "2026-06-20T14:00:00.000Z";
const before = "2026-06-20T13:00:00.000Z"; // after t2 (the rotation), before t3

const alice = await createIdentity("Alice");
let bob = await createIdentity("Bob");

console.log("# before pruning: rotated identity still opens old messages via encHistory");

// msg1: Alice seals to Bob's CURRENT (pre-rotation) enc key at t1.
const msg1 = await buildEvent(alice, {
  kind: "message", chat_id: "c1", to: [bob.id], created_at: t1, rnd: "m1",
  body: { text: "secreto de la epoca 1" },
  recipients: [{ id: bob.id, encPublicKey: bob.enc.publicKey }],
});

// Bob rotates at t2 -> his pre-rotation enc key moves into encHistory.
const bobRotated = await rotateIdentity(bob, t2);
ok("rotation pushed the old enc key into encHistory", bobRotated.encHistory.length === 1);
ok("the current enc key changed after rotation", bob.enc.publicKey !== bobRotated.enc.publicKey);

// Bob can still open msg1 (sealed to the retired key) via encHistory.
ok("rotated Bob still opens msg1 (sealed to retired key)", (await openMessage(msg1, bobRotated)) === "secreto de la epoca 1");

console.log("# after pruning: pruned identity cannot open old-epoch messages");
// msg2: Alice seals to Bob's NEW (post-rotation) enc key at t3.
const msg2 = await buildEvent(alice, {
  kind: "message", chat_id: "c1", to: [bobRotated.id], created_at: t3, rnd: "m2",
  body: { text: "secreto de la epoca 2" },
  recipients: [{ id: bobRotated.id, encPublicKey: bobRotated.enc.publicKey }],
});
ok("Bob opens msg2 (sealed to current key)", (await openMessage(msg2, bobRotated)) === "secreto de la epoca 2");

// Bob prunes enc keys retired before `before` (t2 < before -> the epoch-1 key is dropped).
const bobPruned = pruneEncKeys(bobRotated, { before });
ok("prune dropped the retired enc key (encHistory now empty)", bobPruned.encHistory.length === 0);
ok("prune kept the current enc key", bobPruned.enc.publicKey === bobRotated.enc.publicKey);

// Forward secrecy: msg1 (old epoch) can NO LONGER be opened.
ok("pruned Bob CANNOT open msg1 (forward secrecy)", await throws(() => openMessage(msg1, bobPruned)));
// msg2 (current epoch) still opens.
ok("pruned Bob still opens msg2 (current key intact)", (await openMessage(msg2, bobPruned)) === "secreto de la epoca 2");

console.log("# pruneEncKeys does not mutate the original identity");
ok("original identity still has the retired enc key", bobRotated.encHistory.length === 1);
ok("original identity still opens msg1", (await openMessage(msg1, bobRotated)) === "secreto de la epoca 1");

console.log("# error case: missing/invalid `before` throws");
ok("pruneEncKeys without `before` throws", await throws(() => pruneEncKeys(bobRotated, {})));
ok("pruneEncKeys with invalid `before` throws", await throws(() => pruneEncKeys(bobRotated, { before: "not-a-date" })));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);