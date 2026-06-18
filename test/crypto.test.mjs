// Crypto core invariants (the properties an external audit wants pinned). No network.
// Run: node test/crypto.test.mjs
import {
  generateSignKeypair, generateEncKeypair, fingerprintId,
  sealForRecipients, openSealed, sealAnonymous, openAnonymous,
} from "../src/crypto.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };
const throws = async (fn) => { try { await fn(); return false; } catch { return true; } };

const A = await generateEncKeypair(), B = await generateEncKeypair();
const rA = { id: "A", encPublicKey: A.publicKey }, rB = { id: "B", encPublicKey: B.publicKey };
const aad = "chat|from|to|id|t";

console.log("# freshness: same plaintext -> different ciphertext (no deterministic leak, no IV reuse)");
const e1 = await sealForRecipients("hola", [rA], aad);
const e2 = await sealForRecipients("hola", [rA], aad);
ok("body ciphertext differs across two seals (fresh CEK/IV)", e1.ct !== e2.ct);
ok("ephemeral pubkey differs across two seals", e1.epk !== e2.epk);

console.log("# directed sealing: recipient binding + AAD integrity");
const sealed = await sealForRecipients("secreto", [rA, rB], aad);
ok("A opens with A's key", (await openSealed(sealed, "A", A.privateJwk, aad)) === "secreto");
ok("B opens with B's key", (await openSealed(sealed, "B", B.privateJwk, aad)) === "secreto");
const relabeled = { ...sealed, keys: { ...sealed.keys, B: sealed.keys.A } };
ok("A's wrap relabeled as B does NOT open (per-recipient AAD binding)",
  await throws(() => openSealed(relabeled, "B", B.privateJwk, aad)));
ok("opening with a tampered AAD (altered context) fails",
  await throws(() => openSealed(sealed, "A", A.privateJwk, aad + "X")));

console.log("# anonymous sealing: non-recipient cannot open, envelope names no one");
const anon = await sealAnonymous("anon-secreto", [A.publicKey], aad, { keySlots: 4 });
ok("recipient A opens the anonymous envelope", (await openAnonymous(anon, A.privateJwk, aad)) === "anon-secreto");
ok("non-recipient B cannot open it", await throws(() => openAnonymous(anon, B.privateJwk, aad)));
ok("envelope is an unlabeled wrap array (no recipient ids)", Array.isArray(anon.w) && !("keys" in anon));

console.log("# fingerprint: deterministic, 16-hex, distinct per key");
const k1 = await generateSignKeypair(), k2 = await generateSignKeypair();
const f1 = await fingerprintId(k1.publicKey), f1b = await fingerprintId(k1.publicKey), f2 = await fingerprintId(k2.publicKey);
ok("id is 16 uppercase hex chars (64-bit)", /^[0-9A-F]{16}$/.test(f1));
ok("same key -> same id (deterministic)", f1 === f1b);
ok("distinct keys -> distinct ids", f1 !== f2);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
