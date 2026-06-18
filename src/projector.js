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

// Resolve "records": a record is a (publisher, `key`) pair with a chain of versions linked by
// `supersedes` (event id of the version it replaces). The current value is the HEAD (a version no
// valid event supersedes). A tombstone head = deleted. Records are NAMESPACED BY AUTHOR: a key is
// owned per-publisher, so a foreign author cannot seize or shadow someone else's key by backdating
// a smaller-id root (created_at is self-asserted). Consequently only that author supersedes their
// own record. Queries by key may return one doc PER publisher; consumers disambiguate by `publisher`.
// Optimistic concurrency: an update must point at the current head; forks are flagged.
function resolveRecords(verifiedEvents, members) {
  const admins = new Set((members || []).filter((m) => ["owner", "admin"].includes(m.role)).map((m) => m.id));
  const byKey = new Map();
  for (const ev of verifiedEvents) {
    const key = String((ev.body && ev.body.key) || "");
    if (!key) continue;
    const nk = ev.from + "\x00" + key;   // namespace the record by its author
    if (!byKey.has(nk)) byKey.set(nk, []);
    byKey.get(nk).push(ev);
  }

  const records = new Map();
  for (const [key, versions] of byKey) {
    const roots = versions.filter((v) => !v.supersedes).sort((a, b) => (a.id < b.id ? -1 : 1));
    if (!roots.length) { records.set(key, { error: "no-root" }); continue; }
    const root = roots[0];
    const authorized = (v) => v.from === root.from || admins.has(v.from);

    let head = root;
    const used = new Set([root.id]);
    const conflicts = [...roots.slice(1)]; // extra roots = forked creation
    while (true) {
      const cands = versions.filter((v) => v.supersedes === head.id && !used.has(v.id) && authorized(v));
      if (!cands.length) break;
      cands.sort((a, b) => (a.id < b.id ? -1 : 1));
      head = cands[0]; used.add(head.id);
      for (const v of cands.slice(1)) conflicts.push(v); // forked update
    }
    records.set(key, { head, deleted: head.kind === "tombstone", conflicts, rootAuthor: root.from });
  }
  return records;
}

// Map an event to a provenance-carrying index doc. Does NOT assert `verified` — that flag
// is set by project() from the actual gate result (issue postal#1 / skills#1), so it can
// never be a false constant on a future path that indexes without verifying.
function toDoc(ev) {
  const b = ev.body || {};
  if (ev.kind === "knowledge") {
    return {
      _id: ev.id, kind: "knowledge",
      key: String(b.key || ""), value: String(b.value || ""), tags: b.tags || [],
      publisher: ev.from, seq: ev.seq ?? null, created_at: ev.created_at,
      event_id: ev.id,
    };
  }
  if (ev.kind === "skill") {
    return {
      _id: ev.id, kind: "skill",
      key: String(b.name || ""), name: String(b.name || ""),
      description: String(b.description || ""), version: String(b.version || ""),
      tags: b.tags || [],
      publisher: ev.from, seq: ev.seq ?? null, created_at: ev.created_at,
      event_id: ev.id,
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

      const rejected = failedPaths.size;
      // Resolve records (supersession + tombstones + authorization) over verified events.
      const verified = items.filter((it) => it.event && !failedPaths.has(it.path)).map((it) => it.event);
      const verifiedIds = new Set(verified.map((e) => e.id)); // gate-derived truth set
      const records = resolveRecords(verified, result.members);

      let indexed = 0, deleted = 0;
      for (const rec of records.values()) {
        if (rec.error || rec.deleted) { if (rec.deleted) deleted++; continue; } // tombstoned / broken
        const doc = toDoc(rec.head);
        if (!doc) continue;
        doc.verified = verifiedIds.has(doc.event_id); // consequence of the gate, not a constant
        col.insert(doc);
        vstore.set(VCOL, doc._id, embedText(doc), {
          key: doc.key, kind: doc.kind, publisher: doc.publisher,
          event_id: doc.event_id, verified: doc.verified,
          value: doc.value, name: doc.name, description: doc.description,
        });
        indexed++;
      }
      return { indexed, rejected, deleted, total: items.length };
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
