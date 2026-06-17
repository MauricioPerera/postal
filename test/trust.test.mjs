// Shared web-of-trust resolver. Run: node test/trust.test.mjs
import { resolveTrust, validateAttestation } from "../src/trust.js";

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

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
