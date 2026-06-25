// Postal — protocol-over-git layer: ties the GitHub transport to identities,
// signed/sealed events, and the deterministic gate (verify-on-read).

import { ghClient, newRnd } from "./github.js";
import {
  publicIdentityDoc, verifyIdentityDoc, userPath,
  buildEvent, eventPath, openMessage, verifyEvent,
  chatMetaPath, verifyChatMeta, verifyChat,
} from "./postal.js";
import { canonicalOrder } from "./order.js";

export { ghClient };

// Publish your self-signed public identity to .postal/users/<id>.json.
export async function publishIdentity(client, identity) {
  const doc = await publicIdentityDoc(identity);
  await client.putFile(userPath(identity.id), JSON.stringify(doc, null, 2), `postal: publish identity ${identity.id}`);
  return doc;
}

// Load + cryptographically verify identity docs for a set of ids. Only docs that
// pass verifyIdentityDoc (id matches key, self-sig valid) are returned.
export async function loadDirectory(client, ids) {
  const directory = {};
  for (const id of ids) {
    const file = await client.getFile(userPath(id));
    if (!file) continue;
    let doc;
    try { doc = JSON.parse(file.content); } catch { continue; }
    if (await verifyIdentityDoc(doc)) directory[id] = doc;
  }
  return directory;
}

// Send a signed + sealed message. Recipients' enc keys come from the directory.
export async function postMessage(client, identity, { chat_id, to, text, directory, created_at }) {
  const recipients = [identity.id, ...to]
    .filter((id, i, a) => a.indexOf(id) === i)
    .map((id) => {
      const doc = directory[id];
      if (!doc) throw new Error("no verified identity for recipient: " + id);
      return { id, encPublicKey: doc.enc_key.pub };
    });

  const ev = await buildEvent(identity, {
    kind: "message", chat_id, to,
    created_at: created_at || new Date().toISOString(),
    rnd: newRnd(),
    body: { text },
    recipients,
  });
  await client.putFile(eventPath(chat_id, ev), JSON.stringify(ev, null, 2), `postal: message in ${chat_id}`);
  return ev;
}

// Send a signed, PUBLIC (unsealed) event — a journal / decision record readable by ANYONE with
// repo access (provenance + tamper-evidence, no secrecy). For sealed private messages use
// postMessage. `kind` is an open kind (e.g. "decision", "note") and must NOT be "message".
export async function postEvent(client, identity, { chat_id, kind, body, to = [], created_at }) {
  if (kind === "message") throw new Error("postEvent es para eventos públicos; usá postMessage para mensajes sellados");
  if (!kind || !String(kind).trim()) throw new Error("postEvent requiere un kind no vacío");
  const ev = await buildEvent(identity, {
    kind, chat_id, to,
    created_at: created_at || new Date().toISOString(),
    rnd: newRnd(),
    body: body || {},
  });
  await client.putFile(eventPath(chat_id, ev), JSON.stringify(ev, null, 2), `postal: ${kind} in ${chat_id}`);
  return ev;
}

// Read a chat through the FULL chat gate (verify-on-read). The chat's meta.json
// (signed by the genesis owner) is the ONLY source of the genesis owner and the
// governance policy the gate uses; a chat with no valid meta is NOT trusted. We
// therefore load + verify the meta first, then run verifyChat over all events at
// once (it derives membership from member events, so callers don't pass `members`).
// Returns [{ path, event, verdict, text }]. Events failing the gate are kept with
// verdict.ok=false so the caller can see WHY they were rejected — but a real client
// would simply not render them. The public signature is unchanged: `members` is
// ignored (the replay derives the membership).
export async function pollChat(client, identity, chat_id, { directory, members } = {}) {
  const prefix = `.postal/chats/${chat_id}/events/`;
  const paths = (await client.listTree(prefix)).sort();

  // Read + parse every file once. Non-parseable files are kept apart with a
  // 'unparseable' verdict — they must NOT vanish from the output.
  const items = [];      // { path, event }
  const unparseable = []; // { path, event:null, verdict }
  for (const path of paths) {
    const file = await client.getFile(path);
    if (!file) continue;
    let ev;
    try { ev = JSON.parse(file.content); } catch { unparseable.push({ path, event: null, verdict: { ok: false, reasons: ["unparseable"] } }); continue; }
    items.push({ path, event: ev });
  }

  // Load + verify the chat meta. The genesis owner and governance come ONLY from a
  // meta that passes verifyChatMeta; a chat without a valid meta is untrusted.
  let meta = null;
  const metaFile = await client.getFile(chatMetaPath(chat_id));
  if (metaFile) {
    try { meta = JSON.parse(metaFile.content); } catch { meta = null; }
  }
  const metaVerdict = await verifyChatMeta(meta, { directory, chatId: chat_id });

  if (!metaVerdict.ok) {
    // Untrusted chat: do NOT run the gate against its events. Mark every read item
    // with 'chat-meta-invalid' (plus the meta's own reasons); preserve the
    // non-parseable ones as 'unparseable'. No input mutation, canonical order kept.
    const reasons = ["chat-meta-invalid", ...metaVerdict.reasons];
    const parseable = items.map((it) => ({ path: it.path, event: it.event, verdict: { ok: false, reasons } }));
    return [...canonicalOrder(parseable), ...unparseable];
  }

  // Trusted chat: run the FULL gate over all events at once. verifyChat derives
  // membership from member events (genesis owner seeded from the meta) and
  // returns per-path verdicts plus cross-author hash-chain failures.
  const res = await verifyChat(items, { directory, genesisOwner: meta.created_by, governance: meta.governance, chatId: chat_id });

  // Build path -> verdict from res.results, then fold in res.failures: a failure
  // only OVERWRITES a verdict if that path isn't already ok=false (verifyChat's own
  // per-event verdict is the richer one; chain failures add reasons to valid-looking
  // events that nonetheless broke the per-author sequence).
  const verdicts = new Map();
  for (const r of res.results) verdicts.set(r.path, r.verdict);
  for (const f of res.failures) {
    const existing = verdicts.get(f.path);
    if (!existing || existing.ok) verdicts.set(f.path, { ok: false, reasons: f.reasons });
  }

  const out = [];
  for (const it of items) {
    const verdict = verdicts.get(it.path) || { ok: false, reasons: ["no-verdict"] };
    let text = null;
    if (verdict.ok && it.event.kind === "message") {
      try { text = await openMessage(it.event, identity); } catch { text = null; } // not a recipient
    }
    out.push({ path: it.path, event: it.event, verdict, text });
  }

  // Canonical order on the parseable items; non-parseable re-appended at the end in
  // their original (lexical) path order — invalid/unparseable items must NOT vanish.
  return [...canonicalOrder(out), ...unparseable];
}
