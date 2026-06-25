// Postal — protocol layer: identities, signed events, and the deterministic gate.
//
// An identity owns TWO keypairs: a sign key (ECDSA, authenticity) and an enc key
// (ECDH, privacy). Its id is the fingerprint of the sign key — cryptographic, not
// a random guess. Every event is a SIGNED envelope; messages are additionally
// SEALED (encrypted per-recipient). The verifier is the "hard" CCDD gate: schema
// + signature + append-only, checked at read-time AND in CI.

import {
  canonical, fingerprintId, humanFingerprint, sha256, utf8Bytes, utf8Text,
  bytesToBase64, base64ToBytes,
  generateSignKeypair, generateEncKeypair,
  importSignPublic, importSignPrivate, sign, verify,
  sealForRecipients, openSealed,
} from "./crypto.js";
import { canonicalOrder } from "./order.js";
import { validateAttestation } from "./trust.js";

export const VERSION = 1;
export const MARKER = "POSTAL1:";

// --- identity ----------------------------------------------------------------

export async function createIdentity(displayName = "") {
  const signKp = await generateSignKeypair();
  const encKp = await generateEncKeypair();
  const id = await fingerprintId(signKp.publicKey);
  return {
    id,                          // = fingerprint of the GENESIS sign key (immutable)
    display_name: displayName,
    sign: signKp,                // current signing keypair { publicKey, privateJwk }
    enc: encKp,                  // current encryption keypair
    genesisSignPub: signKp.publicKey,
    rotations: [],               // signed chain genesis -> current
    encHistory: [],              // previous enc keypairs (to open old sealed messages)
  };
}

// Rotate to fresh sign + enc keys. The id does NOT change: it stays anchored to the
// genesis key. The new keys are authorized by a rotation entry SIGNED BY THE OLD
// sign key, so anyone who trusted the genesis fingerprint can follow the chain.
// `reason: "compromise"` marks the OLD key as fully revoked: events signed by it are
// rejected regardless of timestamp (a compromised key could have backdated forgeries).
// Any other/absent reason is a graceful rotation: the old key stays valid only for
// events dated before this rotation.
export async function rotateIdentity(identity, created_at, reason) {
  const newSign = await generateSignKeypair();
  const newEnc = await generateEncKeypair();
  const entry = {
    seq: (identity.rotations?.length || 0) + 1,
    from_sign_pub: identity.sign.publicKey,
    to_sign_pub: newSign.publicKey,
    to_enc_pub: newEnc.publicKey,
    created_at: created_at || new Date().toISOString(),
    ...(reason ? { reason } : {}),
  };
  const oldPriv = await importSignPrivate(identity.sign.privateJwk);
  entry.sig = await sign(oldPriv, canonical(stripField(entry, "sig")));
  return {
    ...identity,
    sign: newSign,
    enc: newEnc,
    rotations: [...(identity.rotations || []), entry],
    encHistory: [...(identity.encHistory || []), identity.enc],
  };
}

// The public identity document published to .postal/users/<id>.json.
// Carries the rotation chain; signed by the CURRENT sign key.
export async function publicIdentityDoc(identity) {
  const doc = {
    v: VERSION,
    id: identity.id,
    display_name: identity.display_name || "",
    sign_key: { alg: "ECDSA-P256", pub: identity.sign.publicKey },
    enc_key: { alg: "ECDH-P256", pub: identity.enc.publicKey },
    rotations: identity.rotations || [],
  };
  const priv = await importSignPrivate(identity.sign.privateJwk);
  doc.sig = await sign(priv, canonical(stripField(doc, "sig")));
  return doc;
}

export const userPath = (id) => `.postal/users/${id}.json`;

const stripField = (o, k) => { const { [k]: _, ...rest } = o; return rest; };

// The genesis sign key a doc's id must anchor to.
function genesisSignPub(doc) {
  const rot = doc.rotations || [];
  return rot.length ? rot[0].from_sign_pub : doc.sign_key.pub;
}

// All sign public keys this identity has ever used (genesis + each rotation target).
// Used to verify event signatures made before a rotation.
export function identitySignKeys(doc) {
  const keys = [genesisSignPub(doc)];
  for (const r of doc.rotations || []) keys.push(r.to_sign_pub);
  return [...new Set(keys)];
}

// Verify a doc is internally consistent: id anchors to the genesis key, the
// rotation chain is intact (each rotation signed by the previous key), the current
// keys equal the end of the chain, and the self-signature is valid.
export async function verifyIdentityDoc(doc) {
  if (!doc || doc.v !== VERSION || !doc.sign_key || !doc.enc_key || !doc.sig) return false;
  const rot = doc.rotations || [];

  // id anchors to genesis
  if ((await fingerprintId(genesisSignPub(doc))) !== doc.id) return false;

  // walk the rotation chain
  let prevSign = genesisSignPub(doc);
  let lastEnc = null;
  let prevTime = null;
  for (let i = 0; i < rot.length; i++) {
    const r = rot[i];
    if (!r || r.seq !== i + 1 || r.from_sign_pub !== prevSign || !r.to_sign_pub || !r.to_enc_pub || !r.sig) return false;
    // Timestamps must be valid and strictly increasing: a rotation can never move BACK in time.
    // Non-monotonic created_at would produce inverted/overlapping key validity windows
    // (keyTimeline), widening the backdating window an attacker gets from a compromised key.
    const t = Date.parse(r.created_at || "");
    if (Number.isNaN(t) || (prevTime !== null && t <= prevTime)) return false;
    prevTime = t;
    const fromPub = await importSignPublic(r.from_sign_pub);
    if (!(await verify(fromPub, r.sig, canonical(stripField(r, "sig"))))) return false;
    prevSign = r.to_sign_pub;
    lastEnc = r.to_enc_pub;
  }

  // current keys must equal the end of the chain
  if (doc.sign_key.pub !== prevSign) return false;
  if (rot.length && doc.enc_key.pub !== lastEnc) return false;

  // self-signature by the current sign key
  const cur = await importSignPublic(doc.sign_key.pub);
  return verify(cur, doc.sig, canonical(stripField(doc, "sig")));
}

export const fingerprintOf = (doc) => humanFingerprint(genesisSignPub(doc));

// --- chat meta (signed: genesis owner + governance) --------------------------

// A chat id embeds its creator, so a meta.json cannot be forged for someone else's
// chat by swapping created_by. The gate enforces this binding.
export const newChatId = (ownerId, rnd) => `c_${ownerId}_${rnd}`;
export const chatMetaPath = (chatId) => `.postal/chats/${chatId}/meta.json`;

// Build a signed meta.json. `created_by` is the genesis owner; `governance` (optional)
// is the quorum policy. Signed by the owner's current key.
export async function buildChatMeta(owner, { chat_id, title = "", created_at, governance }) {
  const meta = {
    v: VERSION,
    id: chat_id,
    title,
    created_by: owner.id,
    created_at: created_at || new Date().toISOString(),
    ...(governance ? { governance } : {}),
  };
  const priv = await importSignPrivate(owner.sign.privateJwk);
  meta.sig = await sign(priv, canonical(stripField(meta, "sig")));
  return meta;
}

// Verify meta.json (HARD). Returns { ok, reasons }. The genesis owner and governance
// policy used by the gate come ONLY from a meta that passes this check.
export async function verifyChatMeta(meta, { directory, chatId } = {}) {
  const reasons = [];
  const R = (c, m) => { if (c) reasons.push(m); };
  R(!meta || meta.v !== VERSION || !meta.id || !meta.created_by || !meta.created_at || !meta.sig, "bad-meta-shape");
  if (reasons.length) return { ok: false, reasons };

  R(chatId && meta.id !== chatId, "meta-id-mismatch");
  // The chat id must be canonically bound to its creator: a substring match would
  // let `c_X_<rnd>` pass for an id that merely mentions X (e.g. `c_Y_XZ_1`), opening
  // a forgery where a meta is swapped onto someone else's chat. Require the exact
  // `c_<created_by>_` prefix that newChatId produces.
  R(!String(meta.id).startsWith("c_" + meta.created_by + "_"), "chat-id-not-bound-to-creator");

  const creator = directory && directory[meta.created_by];
  if (!creator) {
    reasons.push("unknown-chat-creator");
  } else {
    const good = await verifyEventSig(creator, meta.sig, canonical(stripField(meta, "sig")), meta.created_at);
    R(!good, "invalid-meta-signature");
  }
  return { ok: reasons.length === 0, reasons };
}

// --- events ------------------------------------------------------------------

export function eventPath(chatId, ev) {
  const d = new Date(ev.created_at);
  const p = (n) => String(n).padStart(2, "0");
  return `.postal/chats/${chatId}/events/${d.getUTCFullYear()}/${p(d.getUTCMonth() + 1)}/${p(d.getUTCDate())}/${ev.id}.json`;
}

function makeEventId(createdAt, from, rnd) {
  return `${createdAt.replace(/[:.]/g, "-")}_${from}_${rnd}`;
}

// Build a signed (and, for messages, sealed) event.
// kind: "message" | "receipt" | "member"
//   message  -> body.text encrypted for `recipients` ([{id, encPublicKey}])
//   others   -> body is signed but stored in clear (no secret content)
// `seq`/`prev` chain an author's events: seq is a per-author-per-chat counter (from 0)
// and prev is the hash of that author's previous event. Both are signed, so order and
// continuity no longer depend on the spoofable created_at, and deleting a middle event
// breaks the successor's prev link.
export async function buildEvent(identity, { kind, chat_id, to = [], created_at, rnd, body, recipients, seq, prev, supersedes }) {
  const ev = {
    v: VERSION,
    kind,
    chat_id,
    from: identity.id,
    to: [...to].sort(),
    created_at,
    id: makeEventId(created_at, identity.id, rnd),
    ...(seq != null ? { seq, prev: prev || null } : {}),
    ...(supersedes !== undefined ? { supersedes: supersedes || null } : {}),
    body: body || {},
  };

  if (kind === "message") {
    const aad = canonical({ chat_id, from: ev.from, to: ev.to, id: ev.id, created_at });
    ev.body = { sealed: MARKER + (await sealEnvelope(body.text, recipients, aad)) };
  }

  const priv = await importSignPrivate(identity.sign.privateJwk);
  ev.sig = await sign(priv, canonical(signedView(ev)));
  return ev;
}

async function sealEnvelope(text, recipients, aad) {
  const sealed = await sealForRecipients(String(text || ""), recipients, aad);
  return bytesToBase64(utf8Bytes(JSON.stringify(sealed)));
}

// The canonical signed payload: everything EXCEPT the signature and the
// attestations. Both the author's `sig` and each attestor's signature cover this,
// so adding attestations never invalidates the author's signature.
const signedView = (ev) => { const { sig, attestations, ...rest } = ev; return rest; };

// Hash of a full stored event (canonical bytes, including its signature). This is the
// value the NEXT event in the same author's chain references as `prev`.
export async function eventHash(ev) {
  const h = await sha256(utf8Bytes(canonical(ev)));
  return Array.from(h).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Tracks per-author-per-chat seq + last hash, so a sender can build a continuous chain.
export function chainState() {
  const seqOf = new Map(), lastHash = new Map();
  const key = (from, chat) => from + "|" + chat;
  return {
    next(from, chat) {
      const k = key(from, chat);
      return { seq: seqOf.has(k) ? seqOf.get(k) + 1 : 0, prev: lastHash.get(k) || null };
    },
    async record(ev) {
      const k = key(ev.from, ev.chat_id);
      seqOf.set(k, ev.seq);
      lastHash.set(k, await eventHash(ev));
    },
  };
}

// Verify per-author hash chains: seq contiguous from 0 and each prev = hash of the
// author's previous event. Detects deletion/omission (gap or broken link) and any
// tampering (a changed event changes its hash, breaking the successor's prev).
// Only events carrying a numeric `seq` are chained. Returns [{ path, reasons }].
async function verifyChains(items) {
  const groups = new Map();
  for (const it of items) {
    if (!it.event || typeof it.event.seq !== "number") continue;
    const k = it.event.from + "|" + it.event.chat_id;
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(it);
  }
  const failures = [];
  for (const list of groups.values()) {
    list.sort((a, b) => a.event.seq - b.event.seq);
    let expected = 0, prevHash = null;
    for (const it of list) {
      const ev = it.event;
      const reasons = [];
      if (ev.seq !== expected) reasons.push(`chain-gap(expected ${expected}, got ${ev.seq})`);
      if ((ev.prev || null) !== prevHash) reasons.push("chain-prev-mismatch");
      if (reasons.length) failures.push({ path: it.path, reasons });
      prevHash = await eventHash(ev);
      expected = ev.seq + 1;
    }
  }
  return failures;
}

// Open a message event as `identity` (decrypt the sealed body).
export async function openMessage(ev, identity) {
  if (ev.kind !== "message" || !ev.body || !ev.body.sealed) return null;
  const raw = String(ev.body.sealed);
  if (raw.indexOf(MARKER) !== 0) return null;
  const sealed = JSON.parse(utf8Text(base64ToBytes(raw.slice(MARKER.length))));
  const aad = canonical({ chat_id: ev.chat_id, from: ev.from, to: ev.to, id: ev.id, created_at: ev.created_at });
  // Try the current enc key, then any rotated-out enc keys (old sealed messages
  // were wrapped to a previous enc key).
  const candidates = [identity.enc, ...(identity.encHistory || [])];
  let lastErr;
  for (const e of candidates) {
    try { return await openSealed(sealed, identity.id, e.privateJwk, aad); }
    catch (err) { lastErr = err; }
  }
  throw lastErr || new Error("cannot open");
}

// Forward secrecy by epoch: prune RETIRED enc keys whose epoch ended BEFORE `before`.
//
// encHistory[i] is the enc keypair that was RETIRED at rotations[i].created_at (same
// index). Given a cutoff `before`, this drops every encHistory[i] whose rotation is
// strictly older than the cutoff, and returns a NEW identity (the original is never
// mutated). The current enc key (identity.enc) is ALWAYS kept, as are encHistory
// entries retired at or after `before`. The rotations chain itself is untouched — it
// is the signed root of trust; only the private enc material is dropped.
//
// TRADE-OFF (forward secrecy): after pruning, messages sealed to those retired keys
// CAN NO LONGER BE OPENED by this identity. That is the point — you trade historical
// readability for the guarantee that a future theft of the current key material does
// NOT expose messages from already-pruned epochs. If `before` is missing or not a
// parseable date, this throws (never silently drop everything).
export function pruneEncKeys(identity, { before } = {}) {
  const cutoff = Date.parse(before);
  if (before == null || Number.isNaN(cutoff)) {
    throw new Error("pruneEncKeys: `before` must be a valid ISO date string");
  }
  const rotations = identity.rotations || [];
  const history = identity.encHistory || [];
  const kept = [];
  for (let i = 0; i < history.length; i++) {
    const r = rotations[i];
    // Discard only when a matching rotation exists AND it retired this key strictly
    // before the cutoff. An unmatched entry (impossible in normal use — encHistory and
    // rotations grow in lockstep) or an unparseable rotation date is KEPT, so we never
    // drop a key we cannot confidently date.
    const retiredAt = r ? Date.parse(r.created_at) : NaN;
    const discard = r != null && retiredAt < cutoff;
    if (!discard) kept.push(history[i]);
  }
  return { ...identity, encHistory: kept };
}

// The validity window of every sign key the identity has used:
//   from   : key became active (null for genesis = no lower bound)
//   until  : key was rotated out (null for the current key = no upper bound)
//   revoked: the rotation that retired it marked it compromised
export function keyTimeline(doc) {
  const rot = doc.rotations || [];
  const keys = identitySignKeys(doc); // [genesis, ...rotation targets], length rot.length+1
  return keys.map((pub, i) => ({
    pub,
    from: i === 0 ? null : rot[i - 1].created_at,
    until: i < rot.length ? rot[i].created_at : null,
    revoked: i < rot.length && rot[i].reason === "compromise",
  }));
}

// Verify a signature made at `createdAt` against the identity, honoring each key's
// validity window and revocation. A revoked (compromised) key never validates; a
// gracefully-rotated key only validates for events dated before it was rotated out.
async function verifyEventSig(doc, sig, payload, createdAt) {
  const t = Date.parse(createdAt);
  // Fail-closed: an unparseable createdAt must NOT validate a signature. Otherwise the
  // key validity windows below are skipped (t === NaN bypasses the from/until guards)
  // and the signature is checked against any non-revoked key. verifyEvent rejects bad
  // dates upstream, but verifyChatMeta reaches here without that check.
  if (Number.isNaN(t)) return false;
  for (const k of keyTimeline(doc)) {
    if (k.revoked) continue;
    if (!Number.isNaN(t)) {
      if (k.from && t < Date.parse(k.from)) continue;
      if (k.until && t >= Date.parse(k.until)) continue;
    }
    const pub = await importSignPublic(k.pub);
    if (await verify(pub, sig, payload)) return true;
  }
  return false;
}

// --- governance (HARD: quorum of attestations) -------------------------------

// Default quorum per membership op: how many distinct authorized approvers are
// required. A chat can override this in meta.json `governance`.
export const DEFAULT_GOVERNANCE = { add: 1, remove: 2, set_role: 2 };
const AUTHORIZED_ROLES = new Set(["owner", "admin"]);

// Build a membership-change event attested by a quorum.
//   proposer  : identity proposing the change (counts as one approver if authorized)
//   change    : { op:"add"|"remove"|"set_role", target, role? }
//   attestors : [identity] of other authorized members who co-sign
export async function buildMemberEvent(proposer, { chat_id, created_at, rnd, op, target, role }, attestors = []) {
  const ev = {
    v: VERSION, kind: "member", chat_id, from: proposer.id, to: [],
    created_at, id: makeEventId(created_at, proposer.id, rnd),
    body: { op, target, ...(role ? { role } : {}) },
  };
  const payload = canonical(signedView(ev));
  ev.attestations = [];
  for (const a of attestors) {
    ev.attestations.push({ by: a.id, sig: await sign(await importSignPrivate(a.sign.privateJwk), payload) });
  }
  ev.sig = await sign(await importSignPrivate(proposer.sign.privateJwk), payload);
  return ev;
}

// Evolve a membership array by applying a (already-verified) member event.
export function applyMemberEvent(members, ev) {
  const list = (members || []).map((m) => ({ ...m }));
  const b = ev.body || {};
  if (b.op === "add" && !list.some((m) => m.id === b.target)) {
    list.push({ id: b.target, role: b.role || "member" });
  } else if (b.op === "remove") {
    return list.filter((m) => m.id !== b.target);
  } else if (b.op === "set_role") {
    const m = list.find((x) => x.id === b.target);
    if (m) m.role = b.role || m.role;
  }
  return list;
}

// Count distinct authorized approvers of a member event (proposer + attestations).
async function countApprovers(ev, directory, members) {
  const authorized = new Set((members || []).filter((m) => AUTHORIZED_ROLES.has(m.role)).map((m) => m.id));
  const payload = canonical(signedView(ev));
  const approvers = new Set();

  // proposer counts if authorized (their main sig already verified upstream)
  if (authorized.has(ev.from)) approvers.add(ev.from);

  for (const att of ev.attestations || []) {
    if (!att || !att.by || !att.sig || approvers.has(att.by) || !authorized.has(att.by)) continue;
    const doc = directory && directory[att.by];
    if (!doc) continue;
    if (await verifyEventSig(doc, att.sig, payload, ev.created_at)) approvers.add(att.by);
  }
  return approvers.size;
}

// --- the deterministic gate (HARD) -------------------------------------------
// Returns { ok, reasons:[...] }. A reason present = the event is rejected.
// `directory` maps id -> verified public identity doc. `seenPaths` enforces
// append-only. `members` is the chat membership for authorization. `governance`
// overrides the default quorum policy for member events.

// 1. schema-lite: required envelope shape. Returns reasons (empty = ok).
// Open kinds: any non-empty string is a valid signed record. Reserved kinds keep
// special semantics (member -> governance, message -> sealing); apps define their own.
// Per-field predicates. Each lives in its own scope so its `||`/`&&` count
// toward its own (small) complexity, not toward _checkEnvelopeShape's. The
// conditions are identical to the historical R(...) calls.
function _isBadVersion(e) { return !e || e.v !== VERSION; }
function _isBadKind(e) { return !e || typeof e.kind !== "string" || !e.kind.trim(); }
function _isMissingFields(e) { return !e || !e.from || !e.chat_id || !e.id || !e.created_at; }
function _isToNotArray(e) { return e && !Array.isArray(e.to); }
function _isBadDate(e) { return e && Number.isNaN(Date.parse(e.created_at || "")); }
function _isMissingSig(e) { return e && !e.sig; }

function _checkEnvelopeShape(ev) {
  const reasons = [];
  // Data-driven: iterate [predicate, reason] and push reason when the predicate
  // holds. Same 6 reasons and conditions as the old R(...) chain.
  const checks = [
    [_isBadVersion, "bad-version"],
    [_isBadKind, "bad-kind"],
    [_isMissingFields, "missing-fields"],
    [_isToNotArray, "to-not-array"],
    [_isBadDate, "bad-date"],
    [_isMissingSig, "missing-signature"],
  ];
  for (const [pred, reason] of checks) if (pred(ev)) reasons.push(reason);
  return reasons;
}

// 1c. field formats: the schema is NOT enforced at runtime, so the gate must reject
//     `from`/`chat_id` shapes that would poison eventPath (path traversal via '/' or
//     '..'). `from` is a 16-hex-char identity fingerprint; `chat_id` is the newChatId
//     form `c_<from>_<rnd>` or an app id, restricted to path-safe chars.
function _isBadFromFormat(e) { return e && !/^[0-9A-F]{16}$/.test(e.from); }
function _isBadChatIdFormat(e) { return e && !/^[A-Za-z0-9_-]+$/.test(e.chat_id); }
function _checkFieldFormats(ev) {
  const reasons = [];
  if (_isBadFromFormat(ev)) reasons.push("bad-from-format");
  if (_isBadChatIdFormat(ev)) reasons.push("bad-chat-id-format");
  return reasons;
}

// 2. id determinism + safe suffix. The id is `${created_at}:${from}:${rnd}` with
//    [:.]->-; the prefix must encode created_at+from (non-deterministic-id otherwise),
//    AND the free suffix must be non-empty path-safe [A-Za-z0-9-] so an adversary
//    cannot smuggle '/' or '..' into the id (which eventPath would splice into a path).
function _idPrefix(ev) {
  return ev.created_at.replace(/[:.]/g, "-") + "_" + ev.from + "_";
}
function _checkIdFormat(ev) {
  const prefix = _idPrefix(ev);
  if (ev.id.indexOf(prefix) !== 0) return ["non-deterministic-id"];
  const suffix = ev.id.slice(prefix.length);
  return suffix && /^[A-Za-z0-9-]+$/.test(suffix) ? [] : ["bad-id-format"];
}


// 1d. additionalProperties at runtime. The schema declares additionalProperties:
//     false but does NOT enforce it at runtime (it is only a drift-guard for tests).
//     Reject any top-level field outside the allowed envelope. NOTE: the allowed set
//     is a SUPERSET of schema properties — it includes `attestations` (carried by
//     member events, stripped out of signedView before signing) which the schema
//     historically omitted. Enforcing the schema literally would reject valid
//     member events; the list below is the real envelope.
const _ALLOWED_EVENT_FIELDS = new Set([
  "v", "kind", "seq", "prev", "supersedes", "chat_id", "from", "to",
  "created_at", "id", "body", "sig", "attestations",
]);
function _checkUnknownFields(ev) {
  for (const k of Object.keys(ev)) if (!_ALLOWED_EVENT_FIELDS.has(k)) return ["unknown-field"];
  return [];
}

// 1e. body: required, plain object (not array, not null). The schema-lite envelope
//     check does not cover body, so a missing/non-object body is rejected here.
function _checkBodyShape(ev) {
  const b = ev.body;
  if (typeof b !== "object" || b === null || Array.isArray(b)) return ["bad-body"];
  return [];
}

// 1f. `to` items must all be strings. The envelope check only ensures `to` is an
//     array; a non-string item would poison downstream consumers.
function _checkToItems(ev) {
  if (!Array.isArray(ev.to)) return [];
  for (const r of ev.to) if (typeof r !== "string") return ["bad-to-item"];
  return [];
}

// 1g. optional chain fields: when present, must match their declared types.
function _checkOptionalTypes(ev) {
  const reasons = [];
  if ("seq" in ev && (typeof ev.seq !== "number" || !Number.isInteger(ev.seq) || ev.seq < 0)) reasons.push("bad-seq");
  if ("prev" in ev && ev.prev !== null && typeof ev.prev !== "string") reasons.push("bad-prev");
  if ("supersedes" in ev && ev.supersedes !== null && typeof ev.supersedes !== "string") reasons.push("bad-supersedes");
  return reasons;
}

// 1h. message body must carry a `sealed` string starting with POSTAL1:. Today this
//     is only checked at open-time; the gate must reject an unsealed message early.
function _checkMessageBody(ev) {
  if (ev.kind !== "message") return [];
  const sealed = ev.body && ev.body.sealed;
  if (typeof sealed !== "string" || sealed.indexOf(MARKER) !== 0) return ["bad-message-body"];
  return [];
}

// Orchestrator for the runtime schema extras (1d-1h). Thin: each rule lives in its
// own helper so the per-rule complexity stays low; this just concatenates results.
function _checkStructuralExtras(ev) {
  let reasons = [];
  reasons.push(..._checkUnknownFields(ev));
  reasons.push(..._checkBodyShape(ev));
  reasons.push(..._checkToItems(ev));
  reasons.push(..._checkOptionalTypes(ev));
  reasons.push(..._checkMessageBody(ev));
  return reasons;
}

// 1b. body shape per kind (fail-closed). Reserved kinds carry required fields;
//     open kinds stay free-form. The attest validator is the canonical one from
//     trust.js (single source of truth) — a malformed attest is rejected HERE,
//     not silently surfaced later as 'invalid' by activeEdges.
// Returns { reasons, halt }: halt=true means fail-closed immediately (attest case).
// 1b-member: body shape for the "member" kind. Extracted from _checkKindBody so
// the parent stays thin; reasons are bad-member-target / bad-member-role.
function _checkMemberBody(ev) {
  const reasons = [];
  const b = ev.body || {};
  if ((b.op === "add" || b.op === "remove" || b.op === "set_role") &&
      (typeof b.target !== "string" || !b.target)) reasons.push("bad-member-target");
  if (b.role != null && !["member", "admin", "owner"].includes(b.role)) reasons.push("bad-member-role");
  return reasons;
}

// Returns { reasons, halt }: halt=true means fail-closed immediately (attest case).
function _checkKindBody(ev) {
  if (ev.kind === "attest" || ev.kind === "attest-revoke") {
    const av = validateAttestation(ev);
    return av.ok ? { reasons: [], halt: false } : { reasons: av.reasons, halt: true };
  }
  if (ev.kind === "member") return { reasons: _checkMemberBody(ev), halt: false };
  return { reasons: [], halt: false };
}

// 5. governance: membership changes need a quorum of authorized approvers, PLUS two
//    root-of-trust invariants that a quorum alone cannot override:
//      (a) the genesis owner cannot be removed or have its role changed by anyone, and
//      (b) only the owner may promote to admin/owner — so a lone admin cannot mint a
//          complice admin and then form a quorum to depose the owner.

const _ownerId = (members) => (members.find((m) => m.role === "owner") || {}).id;

// Invariant (a): the genesis owner is untouchable by remove/set_role.
function _deposingOwnerReason(ev, members, op) {
  const ownerId = _ownerId(members);
  if (ownerId && ev.body.target === ownerId && (op === "remove" || op === "set_role")) {
    return "cannot-depose-owner";
  }
  return null;
}

// Invariant (b)-promote: only the owner may promote to admin/owner.
function _promotingReason(ev, members, op) {
  const promoting = (op === "add" || op === "set_role") && (ev.body.role === "admin" || ev.body.role === "owner");
  if (promoting && ev.from !== _ownerId(members)) return "only-owner-promotes";
  return null;
}

// Invariant (b)-demote: only the owner may demote an admin.
function _demotingAdminReason(ev, members, op) {
  if (op !== "set_role") return null;
  const targetRole = (members.find((m) => m.id === ev.body.target) || {}).role;
  const demoting = targetRole === "admin" && ev.body.role !== "admin" && ev.body.role !== "owner";
  if (demoting && ev.from !== _ownerId(members)) return "only-owner-demotes-admin";
  return null;
}

// Returns the first applicable invariant-violation reason, or null. Priority order
// matches the historical if/else-if chain: depose > promote > demote.
function _governanceInvariantReason(ev, members, op) {
  return _deposingOwnerReason(ev, members, op)
    || _promotingReason(ev, members, op)
    || _demotingAdminReason(ev, members, op);
}

// Returns reasons to push (may be empty).
async function _checkMemberGovernance(ev, { directory, members, governance }) {
  const op = ev.body && ev.body.op;
  const policy = Object.assign({}, DEFAULT_GOVERNANCE, governance || {});
  if (!op || !(op in policy)) return ["unknown-member-op"];
  if (!members) return [];

  const invariant = _governanceInvariantReason(ev, members, op);
  if (invariant) return [invariant];

  const need = policy[op];
  const have = await countApprovers(ev, directory, members);
  return have < need ? [`insufficient-quorum(${have}/${need})`] : [];
}

// Governance note: quorum / root-of-trust invariants are ONLY enforced when
// `members` is provided. Verifying a loose event without members cannot impose a
// quorum (it has no membership state to count against); that replay-time quorum
// is enforced by verifyChat, which rebuilds membership and feeds it in here.
// `chatId` (optional): when a caller knows which chat it is replaying, an event
// signed for another chat must be rejected (anti cross-chat replay). Omitting it
// keeps backward-compatible behavior for callers/tests that predate this guard.
function _chatIdMismatch(ev, chatId) {
  return chatId && ev.chat_id !== chatId;
}

export async function verifyEvent(ev, { directory, seenPaths, members, governance, chatId } = {}) {
  const reasons = [];
  const R = (c, m) => { if (c) reasons.push(m); };

  // 1. schema-lite: required shape
  const shapeReasons = _checkEnvelopeShape(ev);
  if (shapeReasons.length) return { ok: false, reasons: shapeReasons };

  // 1a. chat binding: a signed event is valid ONLY for the chat it claims.
  //     Without this, an event valid for chat B could be dropped into chat A's
  //     directory and pass (cross-chat replay).
  R(_chatIdMismatch(ev, chatId), "chat-id-mismatch");

  // 1b. body shape per kind (fail-closed)
  const body = _checkKindBody(ev);
  if (body.halt) return { ok: false, reasons: body.reasons };
  reasons.push(...body.reasons);

  // 1d-1h. runtime schema enforcement (additionalProperties, body shape, to items,
  // optional chain types, message sealed body) — the schema is NOT loaded at runtime.
  reasons.push(..._checkStructuralExtras(ev));

  // 1c. field formats (from / chat_id) — runtime shape the schema does not enforce.
  reasons.push(..._checkFieldFormats(ev));

  // 2. path determinism: id must encode created_at + from, with a path-safe suffix.
  reasons.push(..._checkIdFormat(ev));

  // 3. signature valid against ANY of the author's keys (current or rotated-out),
  //    so events signed before a key rotation remain verifiable.
  const author = directory && directory[ev.from];
  if (!author) {
    reasons.push("unknown-author");
  } else {
    const good = await verifyEventSig(author, ev.sig, canonical(signedView(ev)), ev.created_at);
    R(!good, "invalid-signature");
  }

  // 4. authorization: author must be a chat member (if membership is provided)
  if (members) {
    R(!members.some((m) => m.id === ev.from), "author-not-member");
  }

  // 5. governance (member events only)
  if (ev.kind === "member") {
    reasons.push(...await _checkMemberGovernance(ev, { directory, members, governance }));
  }

  // 6. append-only: this path must not already exist
  if (seenPaths) {
    R(seenPaths.has(eventPath(ev.chat_id, ev)), "overwrites-existing");
  }

  return { ok: reasons.length === 0, reasons };
}

// --- chat replay: rebuild membership from genesis (no snapshot needed) --------
//
// Authorization and quorum depend on the membership AS OF each event. Rather than
// trust a possibly-stale (or forged) members.json, replay the chat: start from the
// genesis owner (meta.created_by) and apply each VALID member event in order. Every
// event is verified against the membership state at its position in time.
//
// Bootstrap rule: `add` has quorum 1, so the genesis owner can bring in the first
// admins directly (op:"add", role:"admin"); promoting an EXISTING member (set_role)
// needs the full quorum. This avoids a single-owner deadlock.
//
// items: [{ path, event }]. Returns { ok, members, results:[{path,verdict}], failures }.
export async function verifyChat(items, { directory, genesisOwner, governance, chatId } = {}) {
  // Canonical cross-author order: commit-anchored when a git reader attached `commitIndex`,
  // else created_at+id (identical to the historical behavior). See order.js.
  const sorted = canonicalOrder(items.filter((it) => it && it.event));

  let members = genesisOwner ? [{ id: genesisOwner, role: "owner" }] : null;
  const seenPaths = new Set();
  const results = [];
  const failures = [];

  for (const it of sorted) {
    const ev = it.event;
    const verdict = await verifyEvent(ev, { directory, members, seenPaths, governance, chatId });
    results.push({ path: it.path, verdict });
    if (!verdict.ok) { failures.push({ path: it.path, reasons: verdict.reasons }); continue; }
    seenPaths.add(eventPath(ev.chat_id, ev));   // only a VALID event reserves its path: an invalid
    // event must NOT poison the path, or a forgery with a real event's id would suppress the real one.
    if (ev.kind === "member" && members) members = applyMemberEvent(members, ev);
  }

  // Per-author hash-chain integrity (order/continuity independent of created_at).
  for (const f of await verifyChains(sorted)) failures.push(f);

  return { ok: failures.length === 0, members, results, failures };
}
