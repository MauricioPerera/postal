// Postal — private mode: metadata-reduced events.
//
// In the default protocol the file leaks from/to/kind/chat_id/created_at in clear,
// so the git host sees the social graph. Private mode moves ALL routing metadata —
// and the author's signature — INSIDE the sealed body. The outer file carries only:
//   - an opaque chat tag (hash of chat_id) as the directory
//   - a random file name
//   - the anonymous sealed envelope (no recipient ids, padded count, padded size)
//
// Trade-off (honest): because from/to are encrypted, the PUBLIC CI gate can no longer
// verify authorship/authorization — only members (who hold keys) can, at read time.
// And because hiding metadata means NO deterministic id/path and no seq/prev chain,
// private mode provides NO anti-replay: a host could duplicate an outer file and a naive
// reader would process it twice. Consumers MUST dedup at read time — e.g. by the inner
// signature, which is identical across a replayed copy. See docs/metadata.md.

import {
  canonical, sha256, utf8Bytes, bytesToBase64, randomBytes,
  importSignPrivate, importSignPublic, sign, verify,
  sealAnonymous, openAnonymous,
} from "./crypto.js";
import { keyTimeline } from "./postal.js";

export const PRIVATE_VERSION = 1;
const stripSig = (o) => { const { sig, ...rest } = o; return rest; };

// Opaque per-chat directory: a hash, so the chat_id (which embeds the owner) never
// appears in a path the host can read. Members know chat_id, so they can recompute it.
export async function chatTag(chatId) {
  const h = await sha256(utf8Bytes("postal-chat|" + String(chatId)));
  return Array.from(h.slice(0, 16)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function privateEventPath(chatId) {
  const tag = await chatTag(chatId);
  const rnd = bytesToBase64(randomBytes(12)).replace(/[^a-z0-9]/gi, "").slice(0, 16);
  return `.postal/x/${tag}/${rnd}.json`;
}

// Build a private event. `recipients`: [{ id, encPublicKey }] — include the sender so
// they can re-read. Returns the OUTER file object (the only thing committed).
export async function buildPrivateEvent(sender, { chat_id, kind = "message", to = [], text, created_at }, recipients, opts = {}) {
  const inner = {
    from: sender.id,
    to: [...to].sort(),
    kind,
    chat_id,
    created_at: created_at || new Date().toISOString(),
    text,
  };
  const priv = await importSignPrivate(sender.sign.privateJwk);
  inner.sig = await sign(priv, canonical(stripSig(inner)));

  const aad = await chatTag(chat_id);
  const pubs = recipients.map((r) => r.encPublicKey);
  const env = await sealAnonymous(canonical(inner), pubs, aad, opts);
  return { v: PRIVATE_VERSION, t: "psealed", ...env };
}

// Verify an inner event's signature against the author's key chain (time-windowed).
async function verifyInner(inner, directory) {
  const doc = directory && directory[inner.from];
  if (!doc) return false;
  const payload = canonical(stripSig(inner));
  const t = Date.parse(inner.created_at);
  for (const k of keyTimeline(doc)) {
    if (k.revoked) continue;
    if (!Number.isNaN(t)) {
      if (k.from && t < Date.parse(k.from)) continue;
      if (k.until && t >= Date.parse(k.until)) continue;
    }
    if (await verify(await importSignPublic(k.pub), inner.sig, payload)) return true;
  }
  return false;
}

// Open + verify a private event as a member. Returns { ok, event } where event is the
// decrypted inner routing+content, or { ok:false } if not a recipient / bad signature.
export async function openPrivateEvent(outer, identity, chat_id, directory) {
  if (!outer || outer.t !== "psealed") return { ok: false, reason: "not-private" };
  const aad = await chatTag(chat_id);
  let inner;
  try {
    inner = JSON.parse(await openAnonymous(outer, identity.enc.privateJwk, aad));
  } catch {
    // try rotated-out enc keys too
    for (const e of identity.encHistory || []) {
      try { inner = JSON.parse(await openAnonymous(outer, e.privateJwk, aad)); break; } catch {}
    }
    if (!inner) return { ok: false, reason: "not-a-recipient" };
  }
  if (inner.chat_id !== chat_id) return { ok: false, reason: "chat-mismatch" };
  if (!(await verifyInner(inner, directory))) return { ok: false, reason: "invalid-signature" };
  return { ok: true, event: inner };
}
