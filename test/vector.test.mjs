// Semantic (vector) projection tests. Run: node test/vector.test.mjs
import {
  createIdentity, publicIdentityDoc, rotateIdentity,
  buildEvent, buildMemberEvent, eventPath, chainState,
} from "../src/postal.js";
import { canonical, importSignPrivate, sign } from "../src/crypto.js";
import { makeProjector } from "../src/projector.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

const alice = await createIdentity("Alice");
const bob = await createIdentity("Bob");
const mallory = await createIdentity("Mallory");
const chat = "c_" + alice.id + "_kb";
const directory = { [alice.id]: await publicIdentityDoc(alice), [bob.id]: await publicIdentityDoc(bob), [mallory.id]: await publicIdentityDoc(mallory) };

const chain = chainState();
const item = (ev) => ({ path: eventPath(chat, ev), event: ev });
async function know(who, key, value, when) {
  const { seq, prev } = chain.next(who.id, chat);
  const ev = await buildEvent(who, { kind: "knowledge", chat_id: chat, created_at: when, rnd: "k" + key + seq, body: { key, value }, seq, prev });
  await chain.record(ev);
  return item(ev);
}

const items = [
  item(await buildMemberEvent(alice, { chat_id: chat, created_at: "2026-06-16T19:00:00.000Z", rnd: "addb", op: "add", target: bob.id, role: "member" })),
  await know(alice, "k1", "Los gatos son mamiferos felinos domesticos", "2026-06-16T20:00:00.000Z"),
  await know(bob, "k2", "El motor diesel funciona por compresion de aire", "2026-06-16T20:30:00.000Z"),
  await know(alice, "k3", "Los perros son mamiferos caninos domesticos", "2026-06-16T21:00:00.000Z"),
];

console.log("# semantic search ranks the relevant verified doc first");
const proj = makeProjector();
let rep = await proj.project(items, { directory, genesisOwner: alice.id });
ok("3 knowledge docs vectorized", rep.indexed === 3);

const hits = proj.semanticSearch("animales mamiferos domesticos", 3);
ok("top hit is an animal/mammal doc (not the diesel one)", hits[0].key === "k1" || hits[0].key === "k3");
ok("the unrelated diesel doc is not the top match", hits[0].key !== "k2");
ok("results carry provenance", hits.every((h) => h.publisher && h.event_id && h.verified === true));

console.log("# forged poison never enters the vector index");
const created_at = "2026-06-16T23:00:00.000Z";
const forged = {
  v: 1, kind: "knowledge", chat_id: chat, from: alice.id, to: [],
  created_at, id: created_at.replace(/[:.]/g, "-") + "_" + alice.id + "_evil",
  body: { key: "k1", value: "VENENO gatos mamiferos domesticos felinos" },
};
forged.sig = await sign(await importSignPrivate(mallory.sign.privateJwk), canonical(forged));
rep = await proj.project([...items, item(forged)], { directory, genesisOwner: alice.id });
const all = proj.semanticSearch("gatos mamiferos", 5);
ok("poison is absent from semantic results", !all.some((h) => String(h.value || "").includes("VENENO")));

console.log("# revoking a publisher removes their vectors");
const bobC = await rotateIdentity(bob, "2026-06-16T19:30:00.000Z", "compromise");
rep = await proj.project(items, { directory: { ...directory, [bob.id]: await publicIdentityDoc(bobC) }, genesisOwner: alice.id });
const afterRevoke = proj.semanticSearch("motor diesel compresion", 5);
ok("revoked publisher's vector is gone", !afterRevoke.some((h) => h.publisher === bob.id));
ok("trusted vectors remain searchable", proj.semanticSearch("perros caninos", 3).some((h) => h.publisher === alice.id));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
