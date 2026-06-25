// Postal — shared web-of-trust resolver (single source of truth).
//
// Attestations and trust-gating are used by multiple consumers (attest, a2a, dashboards).
// To avoid divergent copies (one safe, one buggy), the canonical, fail-safe resolver lives
// here in the protocol core; consumers import it instead of inlining their own.
//
// Safety properties baked in:
//   - expiry ON by default (`now` defaults to current time),
//   - weight clamped to [0,1] (a weight > 1 can't invert decay / exceed the root),
//   - malformed bodies surfaced in `invalid`, never silently dropped.

const clamp01 = (x) => Math.min(1, Math.max(0, x));
// Edge identity is scoped per chat: an attest / attest-revoke emitted in chat B
// can no longer collide with (or revoke) one of the same (from, subject, claim)
// emitted in chat A. chat_id ?? null keeps backward compat for legacy events.
const edgeKey = (from, subject, claim, chat_id) => JSON.stringify([from, subject, claim ?? null, chat_id ?? null]);

// Validate an attest / attest-revoke body. Returns { ok, reasons }.
export function validateAttestation(ev) {
  const reasons = [];
  const b = (ev && ev.body) || {};
  if (!ev || (ev.kind !== "attest" && ev.kind !== "attest-revoke")) reasons.push("not-an-attestation");
  if (typeof b.subject !== "string" || !b.subject) reasons.push("bad-subject");
  if (b.claim != null && typeof b.claim !== "string") reasons.push("bad-claim");
  if (ev && ev.kind === "attest") {
    if (b.weight != null && (typeof b.weight !== "number" || Number.isNaN(b.weight))) reasons.push("bad-weight");
    else if (typeof b.weight === "number" && (b.weight < 0 || b.weight > 1)) reasons.push("weight-out-of-range");
    if (b.expires != null && Number.isNaN(Date.parse(b.expires))) reasons.push("bad-expires");
  }
  return { ok: reasons.length === 0, reasons };
}

// Latest event per (attester, subject, claim, chat) wins; expired/malformed handled safely.
// If `chatId` is passed (truthy), only events whose e.chat_id === chatId are considered
// (filtered up front, before ordering). Without `chatId`, all events are considered but
// edges are still scoped per chat via edgeKey, so cross-chat attests/revokees never collide.
// Returns { edges, invalid }.
export function activeEdges(verifiedEvents, { now = new Date().toISOString(), chatId = null } = {}) {
  const latest = new Map();
  const invalid = [];
  const ordered = [...verifiedEvents]
    .filter((e) => e.kind === "attest" || e.kind === "attest-revoke")
    .filter((e) => !chatId || e.chat_id === chatId)
    .sort((a, b) => (a.created_at !== b.created_at ? (a.created_at < b.created_at ? -1 : 1) : (a.id < b.id ? -1 : 1)));

  for (const e of ordered) {
    const v = validateAttestation(e);
    const fatal = v.reasons.filter((r) => r !== "weight-out-of-range");
    if (fatal.length) { invalid.push({ event_id: e.id, from: e.from, reasons: fatal }); continue; }
    if (v.reasons.includes("weight-out-of-range")) invalid.push({ event_id: e.id, from: e.from, reasons: ["weight-out-of-range"], note: "clamped to [0,1]" });
    latest.set(edgeKey(e.from, e.body.subject, e.body.claim, e.chat_id), e);
  }

  const edges = [];
  for (const e of latest.values()) {
    if (e.kind !== "attest") continue;
    if (now && e.body.expires && Date.parse(e.body.expires) <= Date.parse(now)) continue;
    edges.push({ from: e.from, to: e.body.subject, claim: e.body.claim, weight: clamp01(Number(e.body.weight ?? 1)), event_id: e.id, chat_id: e.chat_id ?? null });
  }
  return { edges, invalid };
}

// Max-trust-path propagation from roots with multiplicative decay and bounded depth.
// `chatId` (optional, truthy) scopes the resolution to a single chat; propagated to activeEdges.
export function resolveTrust(verifiedEvents, { roots, decay = 0.5, maxDepth = 4, now = new Date().toISOString(), chatId = null } = {}) {
  const { edges, invalid } = activeEdges(verifiedEvents, { now, chatId });
  const trust = new Map();
  for (const r of Object.keys(roots || {})) trust.set(r, roots[r] ?? 1);

  for (let d = 0; d < maxDepth; d++) {
    let changed = false;
    for (const e of edges) {
      const ta = trust.get(e.from) ?? 0;
      if (ta <= 0) continue;
      const cand = ta * e.weight * decay;
      if (cand > (trust.get(e.to) ?? 0)) { trust.set(e.to, cand); changed = true; }
    }
    if (!changed) break;
  }

  return {
    trust, edges, invalid,
    trustOf: (id) => trust.get(id) ?? 0,
    isTrusted: (id, threshold = 0.1) => (trust.get(id) ?? 0) >= threshold,
    attestationsOf: (subject) => edges.filter((e) => e.to === subject),
    attestedBy: (id) => edges.filter((e) => e.from === id),
  };
}
