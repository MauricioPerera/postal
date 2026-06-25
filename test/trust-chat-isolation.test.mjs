// Web-of-trust chat isolation (MEDIA-3). Run: node test/trust-chat-isolation.test.mjs
// edgeKey is scoped per (from, subject, claim, chat_id): an attest-revoke in chat B
// can no longer cancel an attest of the same triple in chat A, and chatId filters
// resolution to a single chat. Backward compat: single-chat inputs behave as before.
import { resolveTrust, activeEdges } from "../src/trust.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

const A = "AAAA", B = "BBBB";
const CHAT_A = "chatA", CHAT_B = "chatB";
const T0 = "2026-06-16T10:00:00.000Z";
const TN = "2026-06-16T12:00:00.000Z";

// attest in a chat (later created_at than its sibling revoke so the replay is the
// realistic 'revoke from another chat arriving after' scenario).
const att = (from, subject, chat, { id, created_at, weight = 1, claim = "trusts" } = {}) => ({
  kind: "attest", from, id: id || `${from}-${subject}-${chat}-att`, created_at: created_at || T0,
  chat_id: chat, body: { subject, claim, weight, expires: null },
});
const rev = (from, subject, chat, { id, created_at, claim = "trusts" } = {}) => ({
  kind: "attest-revoke", from, id: id || `${from}-${subject}-${chat}-rev`, created_at: created_at || TN,
  chat_id: chat, body: { subject, claim },
});

console.log("# (a) revoke in chatB does NOT annul attest of same triple in chatA");
// A attests B in chatA; later, the SAME from/subject/claim is revoked — but in chatB.
// Without chat isolation the global 'last wins' would drop the edge. Now it must survive.
const resA = resolveTrust([att(A, B, CHAT_A), rev(A, B, CHAT_B)], { roots: { [A]: 1 }, decay: 0.5, now: TN });
ok("chatA attest survives cross-chat revoke (trustOf(B) > 0)", resA.trustOf(B) > 0);
ok("chatA edge present in edges", resA.edges.some((e) => e.from === A && e.to === B && e.chat_id === CHAT_A));
ok("no edge leaked from chatB revoke", !resA.edges.some((e) => e.chat_id === CHAT_B));

console.log("# (b) chatId=chatA counts only chatA attests");
// Two attests of the same (from, subject, claim) in different chats — both are valid edges
// (distinct by chat), but resolving with chatId=chatA must only see chatA's.
const both = [att(A, B, CHAT_A), att(A, B, CHAT_B)];
const filt = resolveTrust(both, { roots: { [A]: 1 }, decay: 0.5, now: TN, chatId: CHAT_A });
ok("only chatA edge when chatId=chatA", filt.edges.length === 1 && filt.edges[0].chat_id === CHAT_A);
ok("chatB attestation ignored under chatId=chatA", filt.attestationsOf(B).length === 1);
// activeEdges filter directly:
const aeFilt = activeEdges(both, { now: TN, chatId: CHAT_A }).edges;
ok("activeEdges chatId filter excludes chatB", aeFilt.length === 1 && aeFilt[0].chat_id === CHAT_A);

console.log("# (c) backward compat: single-chat inputs match old behavior");
// Legacy events with no chat_id all key to chat_id ?? null -> same single edge as before;
// the last-wins ordering within one chat is unchanged.
const legacy = [
  { kind: "attest", from: A, id: "l1", created_at: T0, body: { subject: B, claim: "trusts", weight: 1, expires: null } },
  { kind: "attest-revoke", from: A, id: "l2", created_at: TN, body: { subject: B, claim: "trusts" } },
];
const resC = resolveTrust(legacy, { roots: { [A]: 1 }, decay: 0.5, now: TN });
ok("legacy single-chat revoke still annuls the attest (last wins)", resC.trustOf(B) === 0);
ok("legacy edges carry chat_id:null", resC.edges.every((e) => e.chat_id === null));
// Two legacy attests of distinct triples still yield two edges (no spurious collision).
const legacy2 = activeEdges([
  { kind: "attest", from: A, id: "m1", created_at: T0, body: { subject: B, claim: null, weight: 1, expires: null } },
  { kind: "attest", from: A, id: "m2", created_at: T0, body: { subject: B, claim: "trusts", weight: 1, expires: null } },
], { now: TN }).edges;
ok("legacy distinct-claim edges still distinct (2 edges)", legacy2.length === 2);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);