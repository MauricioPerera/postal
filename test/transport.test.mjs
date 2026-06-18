// GitHub transport unit tests (mocked fetch — no network). Run: node test/transport.test.mjs
import { ghClient } from "../src/github.js";
import { createIdentity, publicIdentityDoc, buildEvent, eventPath } from "../src/postal.js";
import { pollChat } from "../src/transport.js";

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
const ev = await buildEvent(alice, { kind: "message", chat_id: "c1", to: [bob.id], created_at: "2026-06-18T12:00:00.000Z", rnd: "r1", body: { text: "hola" }, recipients: enc });
const canon = eventPath("c1", ev);

console.log("# pollChat: the same event at two paths passes the gate only ONCE (append-only)");
const dup = new Map([[canon, JSON.stringify(ev)], [".postal/chats/c1/events/0000/00/00/dup.json", JSON.stringify(ev)]]);
const rDup = await pollChat(memClient(dup), bob, "c1", { directory, members });
ok("a duplicated event is accepted once, not twice", rDup.filter((r) => r.verdict.ok).length === 1);

console.log("# pollChat: a forged same-id copy processed first does not suppress the real event");
const forged = { ...ev, sig: ev.sig.slice(0, -2) + (ev.sig.endsWith("zz") ? "aa" : "zz") };
const poison = new Map([[".postal/chats/c1/events/0000/00/00/aaa.json", JSON.stringify(forged)], [canon, JSON.stringify(ev)]]);
const rPoison = await pollChat(memClient(poison), bob, "c1", { directory, members });
ok("the real event still verifies and decrypts", rPoison.some((r) => r.verdict.ok && r.text === "hola"));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
