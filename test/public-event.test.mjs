// postEvent: signed PUBLIC events (journal / decision records) — readable by anyone with repo
// access, no sealing. Run: node test/public-event.test.mjs
import { createIdentity, publicIdentityDoc, verifyEvent, newChatId, buildChatMeta, chatMetaPath } from "../src/postal.js";
import { postEvent, pollChat } from "../src/transport.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

const memClient = (store) => ({
  listTree: async (p) => [...store.keys()].filter((k) => k.indexOf(p) === 0).sort(),
  getFile: async (p) => (store.has(p) ? { content: store.get(p) } : null),
  putFile: async (p, content) => { store.set(p, content); },
});

const alice = await createIdentity("Alice");      // autora del journal
const bob = await createIdentity("Bob");          // OTRA identidad, NO destinataria
const directory = { [alice.id]: await publicIdentityDoc(alice), [bob.id]: await publicIdentityDoc(bob) };
const members = [{ id: alice.id, role: "owner" }, { id: bob.id, role: "member" }];

const store = new Map();
const chat = newChatId(alice.id, "journal");
const meta = await buildChatMeta(alice, { chat_id: chat });
await memClient(store).putFile(chatMetaPath(chat), JSON.stringify(meta));
const ev = await postEvent(memClient(store), alice, {
  chat_id: chat, kind: "decision",
  body: { title: "elegir qwen3-coder", rationale: "benchmark: cubre hard a ~4s; kimi no aporta" },
});

console.log("# el body queda EN CLARO (firmado, no sellado)");
ok("body legible en el evento (no 'sealed')", ev.body && ev.body.title === "elegir qwen3-coder" && !ev.body.sealed);

console.log("# pasa el gate verifyEvent");
const v = await verifyEvent(ev, { directory, members });
ok("evento público pasa verifyEvent", v.ok === true);

console.log("# rechaza kind 'message' (eso es sellado, va por postMessage)");
let threw = false;
try { await postEvent(memClient(new Map()), alice, { chat_id: "j", kind: "message", body: { text: "x" } }); } catch { threw = true; }
ok("postEvent rechaza kind 'message'", threw);

console.log("# CUALQUIERA con acceso lo lee: bob (no destinatario) ve el body en claro");
const items = await pollChat(memClient(store), bob, chat, { directory, members });
const got = items.find((i) => i.verdict.ok && i.event && i.event.kind === "decision");
ok("bob lee el body sin ser destinatario", got && got.event.body.title === "elegir qwen3-coder");

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
