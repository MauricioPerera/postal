// Projector tests: only gate-verified events reach the index. Run: node test/projector.test.mjs
import {
  createIdentity, publicIdentityDoc, rotateIdentity,
  buildEvent, buildMemberEvent, eventPath, chainState,
} from "../src/postal.js";
import { canonical, importSignPrivate, sign } from "../src/crypto.js";
import { makeProjector } from "../src/projector.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

const alice = await createIdentity("Alice");     // genesis owner / trusted publisher
const bob = await createIdentity("Bob");         // member publisher
const mallory = await createIdentity("Mallory"); // attacker
const chat = "c_" + alice.id + "_kb";
const directory = {
  [alice.id]: await publicIdentityDoc(alice),
  [bob.id]: await publicIdentityDoc(bob),
  [mallory.id]: await publicIdentityDoc(mallory),
};

const chain = chainState();
const item = (ev) => ({ path: eventPath(chat, ev), event: ev });
async function knowledge(who, key, value, when, supersedes) {
  const { seq, prev } = chain.next(who.id, chat);
  const ev = await buildEvent(who, { kind: "knowledge", chat_id: chat, created_at: when, rnd: "k" + key + seq, body: { key, value }, seq, prev, supersedes });
  await chain.record(ev);
  return item(ev);
}

// Alice (owner) admits Bob as a member, then both publish knowledge.
const addBob = item(await buildMemberEvent(alice, { chat_id: chat, created_at: "2026-06-16T19:00:00.000Z", rnd: "addb", op: "add", target: bob.id, role: "member" }));
const capV0 = await knowledge(alice, "capital-fr", "La capital de Francia es Paris", "2026-06-16T20:00:00.000Z");
const items = [
  addBob,
  capV0,
  await knowledge(bob, "ph-water", "El pH del agua pura es 7", "2026-06-16T20:30:00.000Z"),
  await knowledge(alice, "capital-fr", "La capital de Francia es Paris (actualizado)", "2026-06-16T21:00:00.000Z", capV0.event.id), // supersedes v0
];

console.log("# only verified events are indexed");
const proj = makeProjector();
let rep = await proj.project(items, { directory, genesisOwner: alice.id });
ok("indexed the valid knowledge (deduped by supersession)", rep.indexed === 2);
ok("query by key returns the LATEST version", proj.findByKey("capital-fr")[0].value.includes("actualizado"));
ok("every result carries provenance", proj.all().every((d) => d.publisher && d.event_id && d.verified === true));
ok("text search works", proj.search("agua").length === 1 && proj.search("agua")[0].publisher === bob.id);

console.log("# a forged event never reaches the index (poisoning blocked)");
const created_at = "2026-06-16T23:00:00.000Z";
const forged = {
  v: 1, kind: "knowledge", chat_id: chat, from: alice.id, to: [],
  created_at, id: created_at.replace(/[:.]/g, "-") + "_" + alice.id + "_evil",
  body: { key: "capital-fr", value: "La capital de Francia es Berlin (VENENO)" },
};
forged.sig = await sign(await importSignPrivate(mallory.sign.privateJwk), canonical(forged)); // Mallory's key!
rep = await proj.project([...items, item(forged)], { directory, genesisOwner: alice.id });
ok("forged poison event is rejected by the gate", rep.rejected >= 1);
ok("poison never enters the index", !proj.findByKey("capital-fr").some((d) => d.value.includes("VENENO")));
ok("the real answer is still served", proj.findByKey("capital-fr")[0].value.includes("Paris"));

console.log("# revoking a publisher key drops their knowledge on reprojection");
const bobCompromised = await rotateIdentity(bob, "2026-06-16T19:30:00.000Z", "compromise"); // revoke before he published
const dir2 = { ...directory, [bob.id]: await publicIdentityDoc(bobCompromised) };
rep = await proj.project(items, { directory: dir2, genesisOwner: alice.id });
ok("revoked publisher's knowledge is gone after reprojection", proj.byPublisher(bob.id).length === 0);
ok("trusted publisher's knowledge remains", proj.byPublisher(alice.id).length === 1);

console.log("# key-squat blocked by commit order: a backdated root with a LATER commit loses");
const chat3 = "c_" + alice.id + "_kb3";
const chain3 = chainState();
const item3 = (ev, commitIndex) => ({ path: eventPath(chat3, ev), event: ev, commitIndex });
async function kn3(who, key, value, when) {
  const { seq, prev } = chain3.next(who.id, chat3);
  const ev = await buildEvent(who, { kind: "knowledge", chat_id: chat3, created_at: when, rnd: "s" + key + seq, body: { key, value }, seq, prev });
  await chain3.record(ev); return ev;
}
const addBob3 = item3(await buildMemberEvent(alice, { chat_id: chat3, created_at: "2026-06-16T19:00:00.000Z", rnd: "addb3", op: "add", target: bob.id, role: "member" }), 0);
// Alice committed her root FIRST (commitIndex 1) but with a LATER created_at; Bob backdates his
// created_at (smaller id) yet committed LATER (commitIndex 2). Commit order must make Alice the owner.
const aliceRoot = item3(await kn3(alice, "widget", "alice-legit", "2026-06-16T22:00:00.000Z"), 1);
const bobSquat = item3(await kn3(bob, "widget", "bob-backdated-squat", "2026-06-16T19:15:00.000Z"), 2);
const proj3 = makeProjector();
await proj3.project([addBob3, aliceRoot, bobSquat], { directory, genesisOwner: alice.id });
const widget = proj3.findByKey("widget");
ok("the earlier-COMMITTED root owns the key, not the earlier-DATED one", widget.length === 1 && widget[0].value === "alice-legit");

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
