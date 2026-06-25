// Backward compatibility: envelopes sealed under the LEGACY alg (ECDH-direct -> AES-GCM,
// no HKDF) MUST still open after the HKDF migration. The legacy derivation is replicated
// here with raw WebCrypto so the test is an independent oracle — it does not import the
// legacy path from src/crypto.js (which is kept private for opening old envelopes).
// Run: node test/legacy-envelope.test.mjs
import {
  generateEncKeypair, openSealed, openAnonymous,
  utf8Bytes, bytesToBase64, base64ToBytes, randomBytes, importEncPublic,
} from "../src/crypto.js";

const subtle = globalThis.crypto.subtle;
const ECDH = { name: "ECDH", namedCurve: "P-256" };
const IV_BYTES = 12;

// Exact replica of the pre-HKDF derivation: AES-256-GCM key straight from the ECDH secret.
async function legacyDeriveWrapKey(priv, pub) {
  return subtle.deriveKey({ name: "ECDH", public: pub }, priv, { name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"]);
}

// Build a legacy normal envelope identical in shape to the old sealForRecipients output.
async function sealLegacy(plaintext, recipients, aad) {
  const cek = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const eph = await subtle.generateKey(ECDH, true, ["deriveKey", "deriveBits"]);
  const epk = bytesToBase64(new Uint8Array(await subtle.exportKey("raw", eph.publicKey)));
  const iv = randomBytes(IV_BYTES);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: utf8Bytes(aad) }, cek, utf8Bytes(plaintext));
  const keys = {};
  for (const r of recipients) {
    const pub = await importEncPublic(r.encPublicKey);
    const wk = await legacyDeriveWrapKey(eph.privateKey, pub);
    const wiv = randomBytes(IV_BYTES);
    const wrapped = await subtle.wrapKey("raw", cek, wk, { name: "AES-GCM", iv: wiv, additionalData: utf8Bytes(aad + "|rcpt:" + r.id) });
    keys[r.id] = { iv: bytesToBase64(wiv), ct: bytesToBase64(new Uint8Array(wrapped)) };
  }
  return { alg: "ECDH-P256+AES-256-GCM", epk, iv: bytesToBase64(iv), ct: bytesToBase64(new Uint8Array(ct)), keys };
}

// Build a legacy anonymous envelope (unlabeled wrap array, AAD only, no per-recipient id).
async function sealLegacyAnon(plaintext, recipientPubs, aad) {
  const cek = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const eph = await subtle.generateKey(ECDH, true, ["deriveKey", "deriveBits"]);
  const epk = bytesToBase64(new Uint8Array(await subtle.exportKey("raw", eph.publicKey)));
  const iv = randomBytes(IV_BYTES);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: utf8Bytes(aad) }, cek, utf8Bytes(plaintext));
  const wraps = [];
  for (const pubB64 of recipientPubs) {
    const wk = await legacyDeriveWrapKey(eph.privateKey, await importEncPublic(pubB64));
    const wiv = randomBytes(IV_BYTES);
    const wrapped = await subtle.wrapKey("raw", cek, wk, { name: "AES-GCM", iv: wiv, additionalData: utf8Bytes(aad) });
    wraps.push({ iv: bytesToBase64(wiv), ct: bytesToBase64(new Uint8Array(wrapped)) });
  }
  return { alg: "ECDH-P256+AES-256-GCM/anon", epk, iv: bytesToBase64(iv), ct: bytesToBase64(new Uint8Array(ct)), w: wraps };
}

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

const A = await generateEncKeypair(), B = await generateEncKeypair();
const rA = { id: "A", encPublicKey: A.publicKey }, rB = { id: "B", encPublicKey: B.publicKey };
const aad = "chat|from|to|id|t";

console.log("# legacy normal envelope (no HKDF) still opens");
const legacy = await sealLegacy("legacy-secreto", [rA, rB], aad);
ok("legacy alg tag is the pre-HKDF string", legacy.alg === "ECDH-P256+AES-256-GCM");
ok("A opens the legacy envelope", (await openSealed(legacy, "A", A.privateJwk, aad)) === "legacy-secreto");
ok("B opens the legacy envelope", (await openSealed(legacy, "B", B.privateJwk, aad)) === "legacy-secreto");

console.log("# legacy anonymous envelope (no HKDF) still opens");
const legacyAnon = await sealLegacyAnon("legacy-anon", [A.publicKey], aad);
ok("legacy anon alg tag is the pre-HKDF string", legacyAnon.alg === "ECDH-P256+AES-256-GCM/anon");
ok("A opens the legacy anonymous envelope", (await openAnonymous(legacyAnon, A.privateJwk, aad)) === "legacy-anon");

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);