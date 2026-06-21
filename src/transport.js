// Postal — protocol-over-git layer: ties the GitHub transport to identities,
// signed/sealed events, and the deterministic gate (verify-on-read).

import { ghClient, newRnd } from "./github.js";
import {
  publicIdentityDoc, verifyIdentityDoc, userPath,
  buildEvent, eventPath, openMessage, verifyEvent,
} from "./postal.js";

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

// Read a chat: list events, run the HARD gate on each (verify-on-read), and for
// valid messages addressed to us, open (decrypt) the body.
// Returns [{ path, event, verdict, text }]. Events failing the gate are kept with
// verdict.ok=false so the caller can see WHY they were rejected — but a real client
// would simply not render them.
export async function pollChat(client, identity, chat_id, { directory, members } = {}) {
  const prefix = `.postal/chats/${chat_id}/events/`;
  const paths = (await client.listTree(prefix)).sort();
  const seenPaths = new Set();
  const out = [];

  for (const path of paths) {
    const file = await client.getFile(path);
    if (!file) continue;
    let ev;
    try { ev = JSON.parse(file.content); } catch { out.push({ path, event: null, verdict: { ok: false, reasons: ["unparseable"] } }); continue; }

    const verdict = await verifyEvent(ev, { directory, members, seenPaths });
    // The append-only key must be the event's CANONICAL path (the value verifyEvent checks),
    // not the file path — otherwise the SAME event committed at two different file paths passes
    // the gate twice. And only a VALID event reserves its path (an invalid copy must not poison it).
    if (verdict.ok) seenPaths.add(eventPath(ev.chat_id, ev));

    let text = null;
    if (verdict.ok && ev.kind === "message") {
      try { text = await openMessage(ev, identity); } catch { text = null; } // not a recipient
    }
    out.push({ path, event: ev, verdict, text });
  }
  return out;
}
