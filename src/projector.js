// Postal -> js-doc-store projector: the glue between TRUST and QUERY.
//
// Postal answers "can I trust this?" (signature, gate, chain, revocation).
// js-doc-store answers "find it fast" (indexes, queries). This projector feeds
// the index with ONLY gate-verified events, attaching provenance to every doc, so
// a query result is both fast AND trustworthy — and is rebuilt from git if lost.
//
// Trust boundary: js-doc-store does not verify signatures. We only ever project
// events that passed verifyChat; the index is a disposable derived cache.

import pkg from "../vendor/js-doc-store.cjs";
import { verifyChat } from "./postal.js";

const { DocStore, MemoryStorageAdapter } = pkg;

// Map a verified event to a derived, provenance-carrying index doc.
function toDoc(ev) {
  const b = ev.body || {};
  if (ev.kind === "knowledge") {
    return {
      _id: ev.id, kind: "knowledge",
      key: String(b.key || ""), value: String(b.value || ""), tags: b.tags || [],
      publisher: ev.from, seq: ev.seq ?? null, created_at: ev.created_at,
      event_id: ev.id, verified: true,
    };
  }
  if (ev.kind === "skill") {
    return {
      _id: ev.id, kind: "skill",
      key: String(b.name || ""), name: String(b.name || ""),
      description: String(b.description || ""), version: String(b.version || ""),
      tags: b.tags || [],
      publisher: ev.from, seq: ev.seq ?? null, created_at: ev.created_at,
      event_id: ev.id, verified: true,
    };
  }
  return null; // other kinds (message/member/...) are not indexed
}

export function makeProjector({ db } = {}) {
  const store = db || new DocStore(new MemoryStorageAdapter());
  const col = store.collection("knowledge");
  col.createIndex("key");
  col.createIndex("publisher");
  col.createIndex("kind");
  col.createIndex("value", { type: "text" });
  col.createIndex("description", { type: "text" });

  return {
    store, collection: col,

    // Project a chat's events. Runs the HARD gate, then indexes only the valid
    // knowledge/skill docs. Rebuilds the collection from scratch each call, so a
    // newly-revoked publisher's docs simply disappear. Returns a small report.
    async project(items, gateOpts) {
      const result = await verifyChat(items, gateOpts);
      const validIds = new Set(result.results.filter((r) => r.verdict.ok).map((r) => r.path));
      const failedPaths = new Set(result.failures.map((f) => f.path));

      // wipe + rebuild (the index is a derived cache)
      for (const d of col.find({}).toArray()) col.removeById(d._id);

      let indexed = 0, rejected = 0;
      // supersession: keep only the highest seq per (publisher,key) for the same kind
      const best = new Map();
      for (const it of items) {
        const ev = it.event;
        if (!ev) continue;
        if (failedPaths.has(it.path)) { rejected++; continue; }
        const doc = toDoc(ev);
        if (!doc) continue;
        const k = doc.kind + "|" + doc.publisher + "|" + doc.key;
        const prev = best.get(k);
        if (!prev || (doc.seq ?? -1) > (prev.seq ?? -1)) best.set(k, doc);
      }
      for (const doc of best.values()) { col.insert(doc); indexed++; }

      return { indexed, rejected, total: items.length };
    },

    // Fast queries — every result carries provenance (publisher, event_id, verified).
    findByKey(key) { return col.find({ key }).toArray(); },
    search(text) { return col.find({ value: { $text: text } }).toArray(); },
    byPublisher(id) { return col.find({ publisher: id }).toArray(); },
    skills() { return col.find({ kind: "skill" }).toArray(); },
    all() { return col.find({}).toArray(); },
  };
}
