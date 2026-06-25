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

// Bob prunes enc keys retired before `before` (t2 < before -> the epoch-1 key is tombstoned).
const bobPruned = pruneEncKeys(bobRotated, { before });
// Tombstone semantics: encHistory stays length-aligned with rotations via null slots,
// so the index invariant survives repeated prunes. The retired key is now null, NOT
// removed (length is still 1, but the slot is null).
ok("prune tombstoned the retired enc key (slot null, length kept)", bobPruned.encHistory.length === 1 && bobPruned.encHistory[0] === null);
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

// --- repeated prune (the real bug): index misalignment used to over-prune ----------
// 3 rotations: E0 retired feb, E1 retired mar, E2 retired abr. encHistory grows
// [E0,E1,E2] aligned with rotations [r@feb, r@mar, r@abr]. prune#1 before=feb15 drops
// E0 (tombstone). prune#2 before=mar20 must drop E1 (mar<mar20) AND KEEP E2 (abr>mar20).
// Before the fix, the compacted encHistory=[E1,E2] was compared against rotations
// [r@feb,r@mar], so E2 was compared against mar (not abr) and wrongly dropped — leaving
// the epoch-E2 message unreadable. Tombstones keep the index aligned, so prune#2
// compares E2 against rotations[2]=abr and keeps it.
console.log("# repeated prune: index alignment via tombstones (the real bug)");

const feb = "2026-02-01T00:00:00.000Z";
const mar = "2026-03-01T00:00:00.000Z";
const abr = "2026-04-01T00:00:00.000Z";
const feb15 = "2026-02-15T00:00:00.000Z";
const mar20 = "2026-03-20T00:00:00.000Z";
const farFuture = "2027-01-01T00:00:00.000Z";

let carol = await createIdentity("Carol");

// Rotate 3 times -> encHistory = [E0, E1, E2] aligned with rotations [r@feb, r@mar, r@abr].
// Seal a message to the enc key CURRENT at each epoch, BEFORE rotating, so each message
// is openable only via the corresponding encHistory entry.
const epochs = [];
for (const [rotAt, label] of [[feb, "E0"], [mar, "E1"], [abr, "E2"]]) {
  // Seal to Carol's enc key as it stands RIGHT NOW (this epoch), then rotate.
  const encPub = carol.enc.publicKey;
  const m = await buildEvent(alice, {
    kind: "message", chat_id: "c2", to: [carol.id], created_at: "2026-01-01T00:00:00.000Z", rnd: "m-" + label,
    body: { text: "secreto de la epoca " + label },
    recipients: [{ id: carol.id, encPublicKey: encPub }],
  });
  epochs.push({ label, msg: m });
  carol = await rotateIdentity(carol, rotAt);
}
// After 3 rotations: carol.enc is the CURRENT (actual) key; encHistory = [E0,E1,E2].
// Seal a message to the CURRENT key — it must survive every prune (never in encHistory).
const msgCurrent = await buildEvent(alice, {
  kind: "message", chat_id: "c2", to: [carol.id], created_at: "2026-05-01T00:00:00.000Z", rnd: "mc",
  body: { text: "mensaje de la clave actual" },
  recipients: [{ id: carol.id, encPublicKey: carol.enc.publicKey }],
});
ok("3 rotations produced 3 encHistory entries aligned with rotations", carol.encHistory.length === 3 && carol.rotations.length === 3);

// Sanity: each epoch message opens via its encHistory entry; current via identity.enc.
ok("pre-prune: E0 message opens", (await openMessage(epochs[0].msg, carol)) === "secreto de la epoca E0");
ok("pre-prune: E1 message opens", (await openMessage(epochs[1].msg, carol)) === "secreto de la epoca E1");
ok("pre-prune: E2 message opens", (await openMessage(epochs[2].msg, carol)) === "secreto de la epoca E2");
ok("pre-prune: current-key message opens", (await openMessage(msgCurrent, carol)) === "mensaje de la clave actual");

// prune#1: before=feb15 -> E0 retired at feb < feb15 -> tombstone index 0. E1 (mar) and E2 (abr) kept.
const carolP1 = pruneEncKeys(carol, { before: feb15 });
ok("prune#1: encHistory length kept at 3 (tombstone, no compaction)", carolP1.encHistory.length === 3);
ok("prune#1: slot 0 is null (E0 tombstoned)", carolP1.encHistory[0] === null);
ok("prune#1: slot 1 still E1 (kept)", carolP1.encHistory[1] !== null);
ok("prune#1: slot 2 still E2 (kept)", carolP1.encHistory[2] !== null);
// E0 no longer opens (forward secrecy); E1, E2, current still open.
ok("prune#1: E0 message NO LONGER opens (forward secrecy)", await throws(() => openMessage(epochs[0].msg, carolP1)));
ok("prune#1: E1 message still opens", (await openMessage(epochs[1].msg, carolP1)) === "secreto de la epoca E1");
ok("prune#1: E2 message still opens", (await openMessage(epochs[2].msg, carolP1)) === "secreto de la epoca E2");
ok("prune#1: current-key message still opens", (await openMessage(msgCurrent, carolP1)) === "mensaje de la clave actual");

// prune#2: before=mar20 -> E1 retired at mar < mar20 -> tombstone index 1. E2 (abr > mar20) KEPT.
// This is the bug: with compaction, E2 would be compared against rotations[1]=mar and dropped.
const carolP2 = pruneEncKeys(carolP1, { before: mar20 });
ok("prune#2: encHistory length still 3 (idempotent tombstones)", carolP2.encHistory.length === 3);
ok("prune#2: slot 0 still null", carolP2.encHistory[0] === null);
ok("prune#2: slot 1 now null (E1 tombstoned)", carolP2.encHistory[1] === null);
ok("prune#2: slot 2 STILL E2 (the bug fix — kept, not over-pruned)", carolP2.encHistory[2] !== null);
// THE BUG ASSERT: E2 message must still open after prune#2 (was over-pruned before the fix).
ok("prune#2: E2 message STILL opens (was the bug — now conserved)", (await openMessage(epochs[2].msg, carolP2)) === "secreto de la epoca E2");
ok("prune#2: E1 message NO LONGER opens (forward secrecy)", await throws(() => openMessage(epochs[1].msg, carolP2)));
ok("prune#2: current-key message still opens", (await openMessage(msgCurrent, carolP2)) === "mensaje de la clave actual");

// Idempotency: re-running prune#2 with the same cutoff changes nothing.
const carolP2bis = pruneEncKeys(carolP2, { before: mar20 });
ok("prune#2 repeated: E2 still kept (idempotent)", carolP2bis.encHistory[2] !== null);
ok("prune#2 repeated: E2 message still opens (idempotent)", (await openMessage(epochs[2].msg, carolP2bis)) === "secreto de la epoca E2");

// Far-future cutoff: every retired epoch is before it -> only the current key survives.
// All historical messages (E0/E1/E2) become unreadable; the current-key message still opens.
const carolFar = pruneEncKeys(carol, { before: farFuture });
ok("far-future prune: all 3 encHistory slots tombstoned", carolFar.encHistory.every((e) => e === null));
ok("far-future prune: no historical message opens (E2)", await throws(() => openMessage(epochs[2].msg, carolFar)));
ok("far-future prune: current-key message STILL opens", (await openMessage(msgCurrent, carolFar)) === "mensaje de la clave actual");
ok("far-future prune: current enc key kept", carolFar.enc.publicKey === carol.enc.publicKey);

// pruneEncKeys does not mutate the original across repeated prunes.
ok("original carol still has all 3 enc keys (unmutated)", carol.encHistory.length === 3 && carol.encHistory.every((e) => e !== null));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);