// Postal — protocol layer: identities, signed events, and the deterministic gate.
//
// An identity owns TWO keypairs: a sign key (ECDSA, authenticity) and an enc key
// (ECDH, privacy). Its id is the fingerprint of the sign key — cryptographic, not
// a random guess. Every event is a SIGNED envelope; messages are additionally
// SEALED (encrypted per-recipient). The verifier is the "hard" CCDD gate: schema
// + signature + append-only, checked at read-time AND in CI.

import {
  canonical, fingerprintId, humanFingerprint, sha256, utf8Bytes,
  generateSignKeypair, generateEncKeypair,
  importSignPublic, importSignPrivate, sign, verify,
  sealForRecipients, openSealed,
} from "./crypto.js";

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
  for (let i = 0; i < rot.length; i++) {
    const r = rot[i];
    if (!r || r.seq !== i + 1 || r.from_sign_pub !== prevSign || !r.to_sign_pub || !r.to_enc_pub || !r.sig) return false;
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
  R(!String(meta.id).includes(meta.created_by), "chat-id-not-bound-to-creator");

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
  return btoa(unescape(encodeURIComponent(JSON.stringify(sealed))));
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
  const sealed = JSON.parse(decodeURIComponent(escape(atob(raw.slice(MARKER.length)))));
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
export async function verifyEvent(ev, { directory, seenPaths, members, governance } = {}) {
  const reasons = [];
  const R = (c, m) => { if (c) reasons.push(m); };

  // 1. schema-lite: required shape
  R(!ev || ev.v !== VERSION, "bad-version");
  R(!ev || !ev.kind || !["message", "receipt", "member", "knowledge", "skill", "tombstone"].includes(ev.kind), "bad-kind");
  R(!ev || !ev.from || !ev.chat_id || !ev.id || !ev.created_at, "missing-fields");
  R(ev && !Array.isArray(ev.to), "to-not-array");
  R(ev && Number.isNaN(Date.parse(ev.created_at || "")), "bad-date");
  R(ev && !ev.sig, "missing-signature");
  if (reasons.length) return { ok: false, reasons };

  // 2. path determinism: id must encode created_at + from
  const expectIdPrefix = ev.created_at.replace(/[:.]/g, "-") + "_" + ev.from + "_";
  R(ev.id.indexOf(expectIdPrefix) !== 0, "non-deterministic-id");

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

  // 5. governance: membership changes need a quorum of authorized approvers
  if (ev.kind === "member") {
    const op = ev.body && ev.body.op;
    const policy = Object.assign({}, DEFAULT_GOVERNANCE, governance || {});
    if (!op || !(op in policy)) {
      reasons.push("unknown-member-op");
    } else if (members) {
      const need = policy[op];
      const have = await countApprovers(ev, directory, members);
      R(have < need, `insufficient-quorum(${have}/${need})`);
    }
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
export async function verifyChat(items, { directory, genesisOwner, governance } = {}) {
  const sorted = [...items].filter((it) => it && it.event).sort((a, b) => {
    const ta = String(a.event.created_at || ""), tb = String(b.event.created_at || "");
    if (ta !== tb) return ta < tb ? -1 : 1;
    return String(a.event.id || "") < String(b.event.id || "") ? -1 : 1;
  });

  let members = genesisOwner ? [{ id: genesisOwner, role: "owner" }] : null;
  const seenPaths = new Set();
  const results = [];
  const failures = [];

  for (const it of sorted) {
    const ev = it.event;
    const verdict = await verifyEvent(ev, { directory, members, seenPaths, governance });
    seenPaths.add(eventPath(ev.chat_id, ev));
    results.push({ path: it.path, verdict });
    if (!verdict.ok) { failures.push({ path: it.path, reasons: verdict.reasons }); continue; }
    if (ev.kind === "member" && members) members = applyMemberEvent(members, ev);
  }

  // Per-author hash-chain integrity (order/continuity independent of created_at).
  for (const f of await verifyChains(sorted)) failures.push(f);

  return { ok: failures.length === 0, members, results, failures };
}
