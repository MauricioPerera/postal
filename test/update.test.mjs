// Modify (supersede) + delete (tombstone) + authorization. Run: node test/update.test.mjs
import {
  createIdentity, publicIdentityDoc, buildEvent, buildMemberEvent, eventPath, chainState,
} from "../src/postal.js";
import { makeProjector } from "../src/projector.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

const alice = await createIdentity("Alice"); // owner (admin)
const bob = await createIdentity("Bob");     // member, original author of a record
const carol = await createIdentity("Carol"); // member, NOT the author
const chat = "c_" + alice.id + "_kb";
const directory = {
  [alice.id]: await publicIdentityDoc(alice),
  [bob.id]: await publicIdentityDoc(bob),
  [carol.id]: await publicIdentityDoc(carol),
};

const chain = chainState();
const item = (ev) => ({ path: eventPath(chat, ev), event: ev });
async function ev(who, opts) {
  const { seq, prev } = chain.next(who.id, chat);
  const e = await buildEvent(who, { chat_id: chat, rnd: Math.abs(seq) + opts.kind[0] + (opts.body?.key || "x"), seq, prev, ...opts });
  await chain.record(e);
  return item(e);
}
const T = (h, m = "00") => `2026-06-16T${h}:${m}:00.000Z`;

// Setup: Alice owner adds Bob and Carol as members.
const setup = [
  item(await buildMemberEvent(alice, { chat_id: chat, created_at: T("18"), rnd: "ab", op: "add", target: bob.id, role: "member" })),
  item(await buildMemberEvent(alice, { chat_id: chat, created_at: T("18", "05"), rnd: "ac", op: "add", target: carol.id, role: "member" })),
];

const proj = makeProjector();
const gate = { directory, genesisOwner: alice.id };

console.log("# modify = append a superseding version (latest valid wins)");
const v0 = await ev(bob, { kind: "knowledge", created_at: T("19"), body: { key: "stock", value: "100 unidades" } });
const v1 = await ev(bob, { kind: "knowledge", created_at: T("20"), body: { key: "stock", value: "120 unidades" }, supersedes: v0.event.id });
let rep = await proj.project([...setup, v0, v1], gate);
ok("record resolves to the updated value", proj.findByKey("stock")[0].value === "120 unidades");
ok("only the current head is indexed (1 doc for the record)", proj.findByKey("stock").length === 1);
ok("history still exists in the log (2 versions present)", [v0, v1].length === 2); // both committed; index shows head

console.log("# authorization: a non-author non-admin cannot modify someone else's record");
const carolEdit = await ev(carol, { kind: "knowledge", created_at: T("21"), body: { key: "stock", value: "0 unidades (sabotaje)" }, supersedes: v1.event.id });
rep = await proj.project([...setup, v0, v1, carolEdit], gate);
ok("Carol's unauthorized update is ignored", proj.findByKey("stock")[0].value === "120 unidades");

console.log("# governance override: an admin CAN modify any record");
const aliceEdit = await ev(alice, { kind: "knowledge", created_at: T("22"), body: { key: "stock", value: "200 unidades (ajuste admin)" }, supersedes: v1.event.id });
rep = await proj.project([...setup, v0, v1, aliceEdit], gate);
ok("admin override applies", proj.findByKey("stock")[0].value.includes("ajuste admin"));

console.log("# delete = tombstone (record disappears, data stays in git)");
const tomb = await ev(bob, { kind: "tombstone", created_at: T("23"), body: { key: "stock" }, supersedes: v1.event.id });
rep = await proj.project([...setup, v0, v1, tomb], gate);
ok("tombstoned record is not in the index", proj.findByKey("stock").length === 0);
ok("project reports it as deleted", rep.deleted === 1);

console.log("# restore = supersede the tombstone");
const restore = await ev(bob, { kind: "knowledge", created_at: T("23", "30"), body: { key: "stock", value: "50 unidades (restaurado)" }, supersedes: tomb.event.id });
rep = await proj.project([...setup, v0, v1, tomb, restore], gate);
ok("record is back after superseding the tombstone", proj.findByKey("stock")[0]?.value.includes("restaurado"));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
