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
import vec from "../vendor/js-vector-store.cjs";
import { verifyChat } from "./postal.js";

const { DocStore, MemoryStorageAdapter } = pkg;
const { VectorStore, MemoryStorageAdapter: VecMemoryAdapter } = vec;

// Default placeholder embedder: deterministic bag-of-tokens hashed into `dim` dims,
// normalized. It gives lexical-overlap similarity — enough to wire and test the vector
// path offline. Production swaps this for a real model via makeProjector({ embed }).
const EMBED_DIM = 64;
function localEmbed(text) {
  const v = new Float32Array(EMBED_DIM);
  const tokens = String(text || "").toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").split(/[^a-z0-9]+/).filter(Boolean);
  for (const tok of tokens) {
    let h = 2166136261 >>> 0;
    for (let i = 0; i < tok.length; i++) { h ^= tok.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }
    v[h % EMBED_DIM] += 1;
  }
  let norm = 0; for (let i = 0; i < EMBED_DIM; i++) norm += v[i] * v[i];
  norm = Math.sqrt(norm) || 1;
  return Array.from(v, (x) => x / norm);
}

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

export function makeProjector({ db, embed = localEmbed, dim = EMBED_DIM } = {}) {
  const store = db || new DocStore(new MemoryStorageAdapter());
  const col = store.collection("knowledge");
  col.createIndex("key");
  col.createIndex("publisher");
  col.createIndex("kind");
  col.createIndex("value", { type: "text" });
  col.createIndex("description", { type: "text" });

  // Vector index (semantic). Rebuilt fresh each projection (derived cache).
  let vstore = new VectorStore(new VecMemoryAdapter(), dim);
  const VCOL = "knowledge";
  const embedText = (doc) => embed(`${doc.value || ""} ${doc.name || ""} ${doc.description || ""} ${(doc.tags || []).join(" ")}`);

  return {
    store, collection: col, get vectorStore() { return vstore; },

    // Project a chat's events. Runs the HARD gate, then indexes only the valid
    // knowledge/skill docs into BOTH the doc index and the vector index. Rebuilt
    // from scratch each call, so a newly-revoked publisher's docs disappear.
    async project(items, gateOpts) {
      const result = await verifyChat(items, gateOpts);
      const failedPaths = new Set(result.failures.map((f) => f.path));

      for (const d of col.find({}).toArray()) col.removeById(d._id);
      vstore = new VectorStore(new VecMemoryAdapter(), dim); // fresh vector index

      let indexed = 0, rejected = 0;
      const best = new Map(); // supersession: highest seq per (kind,publisher,key)
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
      for (const doc of best.values()) {
        col.insert(doc);
        vstore.set(VCOL, doc._id, embedText(doc), {
          key: doc.key, kind: doc.kind, publisher: doc.publisher,
          event_id: doc.event_id, verified: true,
          value: doc.value, name: doc.name, description: doc.description,
        });
        indexed++;
      }
      return { indexed, rejected, total: items.length };
    },

    // Lexical queries — every result carries provenance (publisher, event_id, verified).
    findByKey(key) { return col.find({ key }).toArray(); },
    search(text) { return col.find({ value: { $text: text } }).toArray(); },
    byPublisher(id) { return col.find({ publisher: id }).toArray(); },
    skills() { return col.find({ kind: "skill" }).toArray(); },
    all() { return col.find({}).toArray(); },

    // Semantic search (RAG): embed the query, rank by cosine. Results carry provenance.
    semanticSearch(text, limit = 5) {
      return vstore.search(VCOL, embed(text), limit).map((r) => ({ score: r.score, ...r.metadata }));
    },
  };
}
