// GitHub transport unit tests (mocked fetch — no network). Run: node test/transport.test.mjs
import { ghClient } from "../src/github.js";
import { createIdentity, publicIdentityDoc, buildEvent, eventPath, newChatId, buildChatMeta, chatMetaPath } from "../src/postal.js";
import { pollChat } from "../src/transport.js";
import { canonicalOrder } from "../src/order.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

const origFetch = globalThis.fetch;
const mock = (body, status = 200) => {
  globalThis.fetch = async () => ({
    ok: status >= 200 && status < 300, status,
    json: async () => body, text: async () => "", headers: { get: () => null },
  });
};

const c = ghClient({ owner: "o", repo: "r", token: "t" });

console.log("# listTree must NOT silently return a truncated tree");
mock({ truncated: true, tree: [{ type: "blob", path: ".postal/chats/x/events/a.json" }] });
let threw = false;
try { await c.listTree(".postal/chats/"); } catch { threw = true; }
ok("a truncated tree throws (no silent partial read)", threw);

console.log("# a complete tree returns the blob paths under the prefix");
mock({ truncated: false, tree: [
  { type: "blob", path: ".postal/chats/x/events/a.json" },
  { type: "tree", path: ".postal/chats/x" },                 // non-blob: excluded
  { type: "blob", path: ".postal/users/other.json" },        // out of prefix: excluded
] });
const paths = await c.listTree(".postal/chats/");
ok("returns exactly the in-prefix blob paths", paths.length === 1 && paths[0] === ".postal/chats/x/events/a.json");

globalThis.fetch = origFetch;

// --- pollChat append-only: dedup by the event's canonical path, only valid events reserve it ---
const memClient = (store) => ({
  listTree: async (p) => [...store.keys()].filter((k) => k.indexOf(p) === 0).sort(),
  getFile: async (p) => (store.has(p) ? { content: store.get(p) } : null),
});
const alice = await createIdentity("Alice"), bob = await createIdentity("Bob");
const directory = { [alice.id]: await publicIdentityDoc(alice), [bob.id]: await publicIdentityDoc(bob) };
const members = [{ id: alice.id, role: "owner" }, { id: bob.id, role: "member" }];
const enc = [{ id: alice.id, encPublicKey: alice.enc.publicKey }, { id: bob.id, encPublicKey: bob.enc.publicKey }];

// Real chat ids: the owner (alice) is bound into the id, and each chat carries a valid
// meta.json signed by her. pollChat now rejects chats without a valid meta.
const chat1 = newChatId(alice.id, "c1");
const chat2 = newChatId(alice.id, "c2");
const chat3 = newChatId(alice.id, "c3");

const ev = await buildEvent(alice, { kind: "message", chat_id: chat1, to: [bob.id], created_at: "2026-06-18T12:00:00.000Z", rnd: "r1", body: { text: "hola" }, recipients: enc });
const canon = eventPath(chat1, ev);

console.log("# pollChat: the same event at two paths passes the gate only ONCE (append-only)");
const dup = new Map([
  [canon, JSON.stringify(ev)],
  [`.postal/chats/${chat1}/events/0000/00/00/dup.json`, JSON.stringify(ev)],
  [chatMetaPath(chat1), JSON.stringify(await buildChatMeta(alice, { chat_id: chat1 }))],
]);
const rDup = await pollChat(memClient(dup), bob, chat1, { directory, members });
ok("a duplicated event is accepted once, not twice", rDup.filter((r) => r.verdict.ok).length === 1);

console.log("# pollChat: a forged same-id copy processed first does not suppress the real event");
const forged = { ...ev, sig: ev.sig.slice(0, -2) + (ev.sig.endsWith("zz") ? "aa" : "zz") };
const poison = new Map([
  [`.postal/chats/${chat1}/events/0000/00/00/aaa.json`, JSON.stringify(forged)],
  [canon, JSON.stringify(ev)],
  [chatMetaPath(chat1), JSON.stringify(await buildChatMeta(alice, { chat_id: chat1 }))],
]);
const rPoison = await pollChat(memClient(poison), bob, chat1, { directory, members });
ok("the real event still verifies and decrypts", rPoison.some((r) => r.verdict.ok && r.text === "hola"));

// --- pollChat canonical order: returned order matches canonicalOrder, not lexical file-path order ---
console.log("# pollChat: returns events in canonicalOrder (created_at), not lexical path order");
// Both events are authored by alice (the chat owner). pollChat now derives membership from
// the meta (genesisOwner only), so bob is not a member; authoring evB by alice (still sealed
// to bob) keeps it authorized without needing synthetic member events. The order test only
// exercises created_at-vs-path ordering, so the author is irrelevant here.
const evA = await buildEvent(alice, { kind: "message", chat_id: chat2, to: [bob.id], created_at: "2026-06-18T12:00:00.000Z", rnd: "rA", body: { text: "A" }, recipients: enc });
const evB = await buildEvent(alice, { kind: "message", chat_id: chat2, to: [bob.id], created_at: "2026-06-19T08:00:00.000Z", rnd: "rB", body: { text: "B" }, recipients: enc });
// Place them at file paths whose LEXICAL order is the OPPOSITE of created_at order, so a
// path-order return would diverge from canonicalOrder. canonical paths (eventPath) stay
// derived from created_at, so the append-only dedup is unaffected by the file path we choose.
const pathA = `.postal/chats/${chat2}/events/9000/00/00/zzz.json`; // alice, 18th — sorts LATE lexically
const pathB = `.postal/chats/${chat2}/events/1000/00/00/aaa.json`; // alice, 19th — sorts EARLY lexically
const store2 = new Map([
  [pathA, JSON.stringify(evA)],
  [pathB, JSON.stringify(evB)],
  [chatMetaPath(chat2), JSON.stringify(await buildChatMeta(alice, { chat_id: chat2 }))],
]);
const lexOrder = [...store2.keys()].sort();
ok("fixture: lexical path order is the reverse of created_at order", lexOrder[0] === pathB && lexOrder[1] === pathA);
const rOrder = await pollChat(memClient(store2), bob, chat2, { directory, members });
const okOrder = rOrder.filter((r) => r.verdict.ok);
const expectedOrder = canonicalOrder(okOrder.map((r) => r.event));
ok("both events verified", okOrder.length === 2);
ok("returned order matches canonicalOrder, not lexical path order",
  okOrder.length === expectedOrder.length &&
  okOrder.every((r, i) => r.event.id === expectedOrder[i].id) &&
  okOrder[0].event.id === evA.id && okOrder[1].event.id === evB.id);

console.log("# pollChat: an unparseable item is kept in the output (does not vanish)");
const store3 = new Map([
  [pathA, JSON.stringify(evA)],
  [`.postal/chats/${chat2}/events/2000/00/00/bad.json`, "NOT-JSON{"],
  [chatMetaPath(chat2), JSON.stringify(await buildChatMeta(alice, { chat_id: chat2 }))],
]);
const rUnp = await pollChat(memClient(store3), bob, chat2, { directory, members });
ok("unparseable item is present with event:null and verdict.ok=false",
  rUnp.some((r) => r.event === null && r.verdict.ok === false && r.verdict.reasons.includes("unparseable")));

console.log("# pollChat: append-only dedup still works under canonical reordering");
const evC = await buildEvent(alice, { kind: "message", chat_id: chat3, to: [bob.id], created_at: "2026-06-18T12:00:00.000Z", rnd: "rC", body: { text: "C" }, recipients: enc });
const dupCanon = eventPath(chat3, evC);
const store4 = new Map([
  [dupCanon, JSON.stringify(evC)],
  [`.postal/chats/${chat3}/events/0000/00/00/dup.json`, JSON.stringify(evC)],
  [chatMetaPath(chat3), JSON.stringify(await buildChatMeta(alice, { chat_id: chat3 }))],
]);
const rDup2 = await pollChat(memClient(store4), bob, chat3, { directory, members });
ok("a duplicated event is accepted once, not twice (canonical reorder preserves dedup)",
  rDup2.filter((r) => r.verdict.ok).length === 1);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);