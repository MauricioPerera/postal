// HKDF wrap-key derivation (alg v2): round-trip + domain-separation properties.
// Run: node test/hkdf.test.mjs
import {
  generateEncKeypair, sealForRecipients, openSealed, sealAnonymous, openAnonymous,
} from "../src/crypto.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };
const throws = async (fn) => { try { await fn(); return false; } catch { return true; } };

const A = await generateEncKeypair(), B = await generateEncKeypair(), C = await generateEncKeypair();
const rA = { id: "A", encPublicKey: A.publicKey }, rB = { id: "B", encPublicKey: B.publicKey }, rC = { id: "C", encPublicKey: C.publicKey };
const aad = "chat|from|to|id|t";
const ALG = "ECDH-P256+HKDF-SHA256+AES-256-GCM";
const ALG_ANON = "ECDH-P256+HKDF-SHA256+AES-256-GCM/anon";

console.log("# alg versioning: new envelopes carry the HKDF alg tag");
const sealed = await sealForRecipients("secreto-hkdf", [rA, rB, rC], aad);
ok("normal envelope alg is HKDF v2", sealed.alg === ALG);
const anon = await sealAnonymous("anon-hkdf", [A.publicKey, B.publicKey], aad, { keySlots: 4 });
ok("anon envelope alg is HKDF v2 anon", anon.alg === ALG_ANON);

console.log("# round-trip (HKDF): every recipient opens, non-recipient does not");
ok("A opens (multi-recipient)", (await openSealed(sealed, "A", A.privateJwk, aad)) === "secreto-hkdf");
ok("B opens (multi-recipient)", (await openSealed(sealed, "B", B.privateJwk, aad)) === "secreto-hkdf");
ok("C opens (multi-recipient)", (await openSealed(sealed, "C", C.privateJwk, aad)) === "secreto-hkdf");
ok("A opens anonymous", (await openAnonymous(anon, A.privateJwk, aad)) === "anon-hkdf");
ok("B opens anonymous", (await openAnonymous(anon, B.privateJwk, aad)) === "anon-hkdf");
ok("C (non-recipient) cannot open anonymous", await throws(() => openAnonymous(anon, C.privateJwk, aad)));

console.log("# domain separation: HKDF-derived wrap key != legacy ECDH-direct key");
// An HKDF envelope whose alg is forced back to the legacy tag MUST fail to open: the
// legacy ECDH-direct derivation cannot unwrap a key wrapped under HKDF. This proves the
// two derivations are distinct AND that openSealed dispatches on alg (not silently one path).
const relabeled = { ...sealed, alg: "ECDH-P256+AES-256-GCM" };
ok("HKDF envelope relabeled legacy does NOT open (derivations differ)",
  await throws(() => openSealed(relabeled, "A", A.privateJwk, aad)));
const anonRelabeled = { ...anon, alg: "ECDH-P256+AES-256-GCM/anon" };
ok("HKDF anon envelope relabeled legacy does NOT open",
  await throws(() => openAnonymous(anonRelabeled, A.privateJwk, aad)));

console.log("# AAD integrity preserved under HKDF");
ok("tampered AAD still fails (normal)", await throws(() => openSealed(sealed, "A", A.privateJwk, aad + "X")));
ok("tampered AAD still fails (anon)", await throws(() => openAnonymous(anon, A.privateJwk, aad + "X")));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);