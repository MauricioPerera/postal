// Shared web-of-trust resolver. Run: node test/trust.test.mjs
import { resolveTrust, validateAttestation, activeEdges } from "../src/trust.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

const A = "AAAA", B = "BBBB", C = "CCCC";
const att = (from, subject, extra = {}) => ({ kind: "attest", from, id: from + subject + (extra.expires || ""), created_at: "2026-06-16T10:00:00.000Z", body: { subject, claim: "trusts", weight: 1, expires: null, ...extra } });

console.log("# decay + roots");
let w = resolveTrust([att(A, B), att(B, C)], { roots: { [A]: 1 }, decay: 0.5 });
ok("B = 0.5, C = 0.25", w.trustOf(B) === 0.5 && Math.abs(w.trustOf(C) - 0.25) < 1e-9);
ok("unrelated id = 0", w.trustOf("ZZZZ") === 0);

console.log("# safety guards (shared)");
ok("weight clamped: 2.5 -> 1 (no inflation)",
  resolveTrust([{ ...att(A, B), body: { subject: B, claim: "trusts", weight: 2.5 } }], { roots: { [A]: 1 }, decay: 0.5 }).trustOf(B) === 0.5);
ok("expiry ON by default", resolveTrust([att(A, B, { expires: "2000-01-01T00:00:00.000Z" })], { roots: { [A]: 1 } }).trustOf(B) === 0);
ok("malformed weight surfaced in invalid",
  resolveTrust([{ ...att(A, B), body: { subject: B, weight: "x" } }], { roots: { [A]: 1 } }).invalid.some((i) => i.reasons.includes("bad-weight")));
ok("validateAttestation flags missing subject", !validateAttestation({ kind: "attest", body: {} }).ok);

console.log("# edgeKey collision safety (H7) — claim null vs string 'null' do NOT collide");
// activeEdges keys attestations by (from, subject, claim). The old keyer concatenated with '|',
// so claim:null (coerced to 'null') collided with the literal string 'null', and a '|' embedded
// in subject/claim could also collide. The key is Map identity only (never parsed), so JSON.stringify
// of the triple is a safe, unambiguous key.
const attNull = (from, subject, claim) => ({
  kind: "attest", from, id: from + subject + String(claim) + "1",
  created_at: "2026-06-16T10:00:00.000Z",
  body: { subject, claim, weight: 1, expires: null },
});
// Same from + subject, one attests with claim: null, the other with claim: "null" — distinct edges.
const edges = activeEdges([attNull(A, B, null), attNull(A, B, "null")], { now: "2026-06-16T12:00:00.000Z" }).edges;
ok("claim:null and claim:'null' yield TWO distinct edges (no collision)",
  edges.length === 2 && edges.some((e) => e.claim === null) && edges.some((e) => e.claim === "null"));
// A '|' embedded in subject vs a分隔 must not collide across triples either.
const edges2 = activeEdges([
  { kind: "attest", from: "a|b", subject: "c", id: "x1", created_at: "2026-06-16T10:00:00.000Z", body: { subject: "c", claim: null, weight: 1, expires: null } },
  { kind: "attest", from: "a", subject: "b|c", id: "x2", created_at: "2026-06-16T10:00:00.000Z", body: { subject: "b|c", claim: null, weight: 1, expires: null } },
], { now: "2026-06-16T12:00:00.000Z" }).edges;
ok("embedded '|' in from/subject does not collide ('a|b'|c vs a|'b|c' -> two edges)",
  edges2.length === 2);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
