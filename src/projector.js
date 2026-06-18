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

// Resolve "records": a record is a shared `key` with a chain of versions linked by
// `supersedes` (event id of the version it replaces). The current value is the HEAD
// (a version no valid event supersedes). A tombstone head = deleted. Authorization:
// a version may supersede a record only if its author is the record's ORIGINAL author
// OR an owner/admin (governance override). Stale/unauthorized supersedes are dropped.
// Optimistic concurrency: an update must point at the current head; forks are flagged.
//
// Root (= owner) selection is by COMMIT ORDER — operator-anchored and NOT spoofable — when a git
// reader attaches `commitIndex`, falling back to `id` (created_at-derived) otherwise. This stops a
// foreign author from seizing a shared key by BACKDATING created_at on a git-anchored read. Honest
// residual: an OFFLINE read (no commitIndex) still falls back to created_at and remains squat-able.
// Takes ITEMS ({ event, commitIndex? }) so the anchor survives (project passes them through).
function resolveRecords(verifiedItems, members) {
  const admins = new Set((members || []).filter((m) => ["owner", "admin"].includes(m.role)).map((m) => m.id));
  const ci = (it) => (Number.isInteger(it.commitIndex) ? it.commitIndex
    : Number.isInteger(it.event.commitIndex) ? it.event.commitIndex : Number.MAX_SAFE_INTEGER);
  const before = (a, b) => { const ca = ci(a), cb = ci(b); if (ca !== cb) return ca - cb; return a.event.id < b.event.id ? -1 : 1; };

  const byKey = new Map();
  for (const it of verifiedItems) {
    const key = String((it.event.body && it.event.body.key) || "");
    if (!key) continue;
    if (!byKey.has(key)) byKey.set(key, []);
    byKey.get(key).push(it);
  }

  const records = new Map();
  for (const [key, vItems] of byKey) {
    const roots = vItems.filter((it) => !it.event.supersedes).sort(before);
    if (!roots.length) { records.set(key, { error: "no-root" }); continue; }
    const root = roots[0];
    const authorized = (it) => it.event.from === root.event.from || admins.has(it.event.from);

    let head = root;
    const used = new Set([root.event.id]);
    const conflicts = [...roots.slice(1)]; // extra roots = forked creation
    while (true) {
      const cands = vItems.filter((it) => it.event.supersedes === head.event.id && !used.has(it.event.id) && authorized(it));
      if (!cands.length) break;
      cands.sort(before);
      head = cands[0]; used.add(head.event.id);
      for (const it of cands.slice(1)) conflicts.push(it); // forked update
    }
    records.set(key, { head: head.event, deleted: head.event.kind === "tombstone", conflicts, rootAuthor: root.event.from });
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
      // Resolve records (supersession + tombstones + authorization) over verified items. We keep the
      // ITEMS (not just .event) so resolveRecords can anchor root selection on commitIndex.
      const verifiedItems = items.filter((it) => it.event && !failedPaths.has(it.path));
      const verifiedIds = new Set(verifiedItems.map((it) => it.event.id)); // gate-derived truth set
      const records = resolveRecords(verifiedItems, result.members);

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
