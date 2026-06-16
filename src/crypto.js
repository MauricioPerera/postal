// Postal — cryptographic primitives.
//
// Isomorphic (browser + Node >=18). Two curves, both P-256 (universal WebCrypto):
//   - ECDSA P-256  -> signatures (authenticity)   [the HARD slot v1 left null]
//   - ECDH  P-256  -> hybrid encryption (privacy)  [per-recipient sealing]
//
// Plus: canonical JSON (deterministic bytes for signing) and SHA-256 fingerprints
// (so an identity id is derived from its key, not a lucky 4-char guess).

const subtle = globalThis.crypto.subtle;
const getRandomValues = globalThis.crypto.getRandomValues.bind(globalThis.crypto);
const IV_BYTES = 12;
const enc = new TextEncoder(), dec = new TextDecoder();

export const utf8Bytes = (v) => enc.encode(String(v == null ? "" : v));
export const utf8Text = (b) => dec.decode(b);

export function bytesToBase64(bytes) {
  let s = ""; const c = 0x8000;
  for (let i = 0; i < bytes.length; i += c) s += String.fromCharCode.apply(null, bytes.subarray(i, i + c));
  return btoa(s);
}
export function base64ToBytes(v) {
  const bin = atob(String(v || "").replace(/\n/g, "")); const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export const randomBytes = (n) => getRandomValues(new Uint8Array(n));

// --- canonical JSON: stable, sorted-key serialization for signing --------------
// Two semantically equal objects MUST produce identical bytes, or signatures break.
export function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  const keys = Object.keys(value).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(value[k])).join(",") + "}";
}

export async function sha256(bytes) {
  return new Uint8Array(await subtle.digest("SHA-256", bytes));
}

// Identity id from a signing public key: 16 hex chars (64-bit) of its SHA-256.
// Cryptographically derived -> no 4-char collision lottery.
export async function fingerprintId(signPubB64) {
  const h = await sha256(base64ToBytes(signPubB64));
  return Array.from(h.slice(0, 8)).map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

// Human-checkable fingerprint (for out-of-band trust): grouped hex.
export async function humanFingerprint(signPubB64) {
  const h = await sha256(base64ToBytes(signPubB64));
  return Array.from(h.slice(0, 8)).map((b) => b.toString(16).padStart(2, "0")).join(":").toUpperCase();
}

// --- ECDSA P-256: signatures --------------------------------------------------
const ECDSA = { name: "ECDSA", namedCurve: "P-256" };
const SIGN = { name: "ECDSA", hash: "SHA-256" };

export async function generateSignKeypair() {
  const kp = await subtle.generateKey(ECDSA, true, ["sign", "verify"]);
  const pub = new Uint8Array(await subtle.exportKey("raw", kp.publicKey));
  const priv = await subtle.exportKey("jwk", kp.privateKey);
  return { publicKey: bytesToBase64(pub), privateJwk: priv };
}
export const importSignPublic = (b64) => subtle.importKey("raw", base64ToBytes(b64), ECDSA, false, ["verify"]);
export const importSignPrivate = (jwk) => subtle.importKey("jwk", jwk, ECDSA, false, ["sign"]);

export async function sign(privateKey, message) {
  const sig = await subtle.sign(SIGN, privateKey, utf8Bytes(message));
  return bytesToBase64(new Uint8Array(sig));
}
export async function verify(publicKey, sigB64, message) {
  return subtle.verify(SIGN, publicKey, base64ToBytes(sigB64), utf8Bytes(message));
}

// --- ECDH P-256: hybrid per-recipient encryption ------------------------------
const ECDH = { name: "ECDH", namedCurve: "P-256" };

export async function generateEncKeypair() {
  const kp = await subtle.generateKey(ECDH, true, ["deriveKey", "deriveBits"]);
  const pub = new Uint8Array(await subtle.exportKey("raw", kp.publicKey));
  const priv = await subtle.exportKey("jwk", kp.privateKey);
  return { publicKey: bytesToBase64(pub), privateJwk: priv };
}
export const importEncPublic = (b64) => subtle.importKey("raw", base64ToBytes(b64), ECDH, false, []);
export const importEncPrivate = (jwk) => subtle.importKey("jwk", jwk, ECDH, false, ["deriveKey", "deriveBits"]);

async function encryptString(key, plaintext, aad = "") {
  const iv = randomBytes(IV_BYTES);
  const p = { name: "AES-GCM", iv }; if (aad) p.additionalData = utf8Bytes(aad);
  const ct = await subtle.encrypt(p, key, utf8Bytes(plaintext));
  return { iv: bytesToBase64(iv), ct: bytesToBase64(new Uint8Array(ct)) };
}
async function decryptString(key, e, aad = "") {
  const p = { name: "AES-GCM", iv: base64ToBytes(e.iv) }; if (aad) p.additionalData = utf8Bytes(aad);
  return utf8Text(new Uint8Array(await subtle.decrypt(p, key, base64ToBytes(e.ct))));
}
async function deriveWrapKey(priv, pub) {
  return subtle.deriveKey({ name: "ECDH", public: pub }, priv, { name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"]);
}
const newContentKey = () => subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
async function newEphemeral() {
  const kp = await subtle.generateKey(ECDH, true, ["deriveKey", "deriveBits"]);
  const pub = new Uint8Array(await subtle.exportKey("raw", kp.publicKey));
  return { publicKey: bytesToBase64(pub), privateKey: kp.privateKey };
}

// Encrypt plaintext for a set of recipients. `aad` binds the body to its context.
// recipients: [{ id, encPublicKey(b64) }]. Returns the sealed envelope object.
export async function sealForRecipients(plaintext, recipients, aad = "") {
  const cek = await newContentKey();
  const eph = await newEphemeral();
  const body = await encryptString(cek, plaintext, aad);
  const keys = {};
  for (const r of recipients) {
    const pub = await importEncPublic(r.encPublicKey);
    const wk = await deriveWrapKey(eph.privateKey, pub);
    const iv = randomBytes(IV_BYTES);
    const wrapped = await subtle.wrapKey("raw", cek, wk, { name: "AES-GCM", iv, additionalData: utf8Bytes(aad + "|rcpt:" + r.id) });
    keys[r.id] = { iv: bytesToBase64(iv), ct: bytesToBase64(new Uint8Array(wrapped)) };
  }
  return { alg: "ECDH-P256+AES-256-GCM", epk: eph.publicKey, iv: body.iv, ct: body.ct, keys };
}

// Open a sealed envelope as recipient `id` with their ECDH private key.
export async function openSealed(sealed, id, encPrivateJwk, aad = "") {
  const mine = sealed.keys && sealed.keys[id];
  if (!mine) throw new Error("not a recipient");
  const priv = await importEncPrivate(encPrivateJwk);
  const eph = await importEncPublic(sealed.epk);
  const wk = await deriveWrapKey(priv, eph);
  const cek = await subtle.unwrapKey(
    "raw", base64ToBytes(mine.ct), wk,
    { name: "AES-GCM", iv: base64ToBytes(mine.iv), additionalData: utf8Bytes(aad + "|rcpt:" + id) },
    { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
  return decryptString(cek, { iv: sealed.iv, ct: sealed.ct }, aad);
}

// --- anonymous sealing: recipients carry NO id (metadata reduction) -----------
//
// Like sealForRecipients, but the wrapped content keys are an unlabeled ARRAY:
// a recipient finds theirs by trial-unwrapping, so the envelope never names who
// can read it. The wrap list is shuffled and padded with indistinguishable decoys
// to a bucket, so even the recipient COUNT only leaks coarsely. Body is padded to a
// length bucket to hide message size.

function padToBucket(n, bucket) { return Math.ceil((n + 1) / bucket) * bucket; }

// Deterministic-ish shuffle driven by a seed byte stream (no Math.random).
function shuffle(arr, seedBytes) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = seedBytes[(a.length - 1 - i) % seedBytes.length] % (i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

export async function sealAnonymous(plaintext, recipientPubs, aad = "", { keySlots = 4, sizeBucket = 256 } = {}) {
  const cek = await newContentKey();
  const eph = await newEphemeral();

  // pad the plaintext to a size bucket before encrypting (hide length)
  const padded = String(plaintext) + " ".repeat(Math.max(0, padToBucket(String(plaintext).length, sizeBucket) - String(plaintext).length));
  const body = await encryptString(cek, padded, aad);

  const wraps = [];
  for (const pubB64 of recipientPubs) {
    const wk = await deriveWrapKey(eph.privateKey, await importEncPublic(pubB64));
    const iv = randomBytes(IV_BYTES);
    const wrapped = await subtle.wrapKey("raw", cek, wk, { name: "AES-GCM", iv, additionalData: utf8Bytes(aad) });
    wraps.push({ iv: bytesToBase64(iv), ct: bytesToBase64(new Uint8Array(wrapped)) });
  }
  // decoys: random blobs the size of a real wrap; nobody can unwrap them
  const slots = Math.max(keySlots, padToBucket(wraps.length, keySlots));
  while (wraps.length < slots) {
    wraps.push({ iv: bytesToBase64(randomBytes(IV_BYTES)), ct: bytesToBase64(randomBytes(48)) });
  }

  return { alg: "ECDH-P256+AES-256-GCM/anon", epk: eph.publicKey, iv: body.iv, ct: body.ct, w: shuffle(wraps, eph.publicKey ? base64ToBytes(eph.publicKey) : new Uint8Array([1])) };
}

// Try every wrap until one yields the content key, then decrypt. Returns the
// plaintext with size-padding trimmed, or throws if none is for us.
export async function openAnonymous(env, encPrivateJwk, aad = "") {
  const priv = await importEncPrivate(encPrivateJwk);
  const eph = await importEncPublic(env.epk);
  const wk = await deriveWrapKey(priv, eph);
  for (const wrap of env.w || []) {
    try {
      const cek = await subtle.unwrapKey(
        "raw", base64ToBytes(wrap.ct), wk,
        { name: "AES-GCM", iv: base64ToBytes(wrap.iv), additionalData: utf8Bytes(aad) },
        { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
      );
      const out = await decryptString(cek, { iv: env.iv, ct: env.ct }, aad);
      return out.replace(/ +$/, ""); // trim size padding
    } catch { /* not our slot, keep trying */ }
  }
  throw new Error("not a recipient");
}
