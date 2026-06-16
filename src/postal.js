// Postal — protocol layer: identities, signed events, and the deterministic gate.
//
// An identity owns TWO keypairs: a sign key (ECDSA, authenticity) and an enc key
// (ECDH, privacy). Its id is the fingerprint of the sign key — cryptographic, not
// a random guess. Every event is a SIGNED envelope; messages are additionally
// SEALED (encrypted per-recipient). The verifier is the "hard" CCDD gate: schema
// + signature + append-only, checked at read-time AND in CI.

import {
  canonical, fingerprintId, humanFingerprint,
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
    id,
    display_name: displayName,
    sign: signKp,   // { publicKey, privateJwk }
    enc: encKp,     // { publicKey, privateJwk }
  };
}

// The public identity document published to .postal/users/<id>.json.
// Self-signed: the sign key signs the whole doc (binds id<->keys<->name).
export async function publicIdentityDoc(identity) {
  const doc = {
    v: VERSION,
    id: identity.id,
    display_name: identity.display_name || "",
    sign_key: { alg: "ECDSA-P256", pub: identity.sign.publicKey },
    enc_key: { alg: "ECDH-P256", pub: identity.enc.publicKey },
  };
  const priv = await importSignPrivate(identity.sign.privateJwk);
  doc.sig = await sign(priv, canonical(doc));
  return doc;
}

export const userPath = (id) => `.postal/users/${id}.json`;

// Verify an identity doc is internally consistent: id matches the sign key, and
// the self-signature is valid. (Trusting the id is a SOFT, out-of-band decision.)
export async function verifyIdentityDoc(doc) {
  if (!doc || doc.v !== VERSION || !doc.sign_key || !doc.enc_key || !doc.sig) return false;
  const expectId = await fingerprintId(doc.sign_key.pub);
  if (expectId !== doc.id) return false;
  const { sig, ...unsigned } = doc;
  const pub = await importSignPublic(doc.sign_key.pub);
  return verify(pub, sig, canonical(unsigned));
}

export const fingerprintOf = (doc) => humanFingerprint(doc.sign_key.pub);

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
export async function buildEvent(identity, { kind, chat_id, to = [], created_at, rnd, body, recipients }) {
  const ev = {
    v: VERSION,
    kind,
    chat_id,
    from: identity.id,
    to: [...to].sort(),
    created_at,
    id: makeEventId(created_at, identity.id, rnd),
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

// Open a message event as `identity` (decrypt the sealed body).
export async function openMessage(ev, identity) {
  if (ev.kind !== "message" || !ev.body || !ev.body.sealed) return null;
  const raw = String(ev.body.sealed);
  if (raw.indexOf(MARKER) !== 0) return null;
  const sealed = JSON.parse(decodeURIComponent(escape(atob(raw.slice(MARKER.length)))));
  const aad = canonical({ chat_id: ev.chat_id, from: ev.from, to: ev.to, id: ev.id, created_at: ev.created_at });
  return openSealed(sealed, identity.id, identity.enc.privateJwk, aad);
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
    const pub = await importSignPublic(doc.sign_key.pub);
    if (await verify(pub, att.sig, payload)) approvers.add(att.by);
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
  R(!ev || !ev.kind || !["message", "receipt", "member"].includes(ev.kind), "bad-kind");
  R(!ev || !ev.from || !ev.chat_id || !ev.id || !ev.created_at, "missing-fields");
  R(ev && !Array.isArray(ev.to), "to-not-array");
  R(ev && Number.isNaN(Date.parse(ev.created_at || "")), "bad-date");
  R(ev && !ev.sig, "missing-signature");
  if (reasons.length) return { ok: false, reasons };

  // 2. path determinism: id must encode created_at + from
  const expectIdPrefix = ev.created_at.replace(/[:.]/g, "-") + "_" + ev.from + "_";
  R(ev.id.indexOf(expectIdPrefix) !== 0, "non-deterministic-id");

  // 3. signature valid against the author's published sign key
  const author = directory && directory[ev.from];
  if (!author) {
    reasons.push("unknown-author");
  } else {
    const pub = await importSignPublic(author.sign_key.pub);
    const good = await verify(pub, ev.sig, canonical(signedView(ev)));
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

  return { ok: failures.length === 0, members, results, failures };
}
