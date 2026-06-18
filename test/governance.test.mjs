// Governance / quorum tests. Run: node test/governance.test.mjs
import {
  createIdentity, publicIdentityDoc,
  buildMemberEvent, applyMemberEvent, verifyEvent, DEFAULT_GOVERNANCE,
} from "../src/postal.js";
import { canonical, importSignPrivate, sign } from "../src/crypto.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

const owner = await createIdentity("Owner");   // A
const admin = await createIdentity("Admin");   // B
const cand = await createIdentity("Cand");    // C (to be added/promoted)
const outsider = await createIdentity("Out"); // D (not authorized)

const directory = {};
for (const i of [owner, admin, cand, outsider]) directory[i.id] = await publicIdentityDoc(i);

// Initial membership: two authorized members (owner A, admin B).
let members = [{ id: owner.id, role: "owner" }, { id: admin.id, role: "admin" }];
const chat = "c1";
const base = { chat_id: chat };

console.log("# add member (quorum = 1)");
const addEv = await buildMemberEvent(owner, { ...base, created_at: "2026-06-16T21:00:00.000Z", rnd: "add001", op: "add", target: cand.id, role: "member" });
let r = await verifyEvent(addEv, { directory, members });
ok("owner alone can add a member (need 1)", r.ok);
members = applyMemberEvent(members, addEv);
ok("membership now includes the new member", members.some((m) => m.id === cand.id && m.role === "member"));

console.log("# promote to admin (quorum = 2)");
// Proposer alone (owner) = 1 approver -> insufficient.
const promoSolo = await buildMemberEvent(owner, { ...base, created_at: "2026-06-16T21:05:00.000Z", rnd: "pro001", op: "set_role", target: cand.id, role: "admin" });
r = await verifyEvent(promoSolo, { directory, members });
ok("one approver is rejected for set_role (need 2)", !r.ok && r.reasons.some((x) => x.startsWith("insufficient-quorum")));

// Owner proposes, admin attests -> 2 approvers -> ok.
const promo = await buildMemberEvent(owner, { ...base, created_at: "2026-06-16T21:06:00.000Z", rnd: "pro002", op: "set_role", target: cand.id, role: "admin" }, [admin]);
r = await verifyEvent(promo, { directory, members });
ok("owner + admin attestation passes set_role", r.ok);
members = applyMemberEvent(members, promo);
ok("candidate is now admin", members.find((m) => m.id === cand.id).role === "admin");

console.log("# attestations that must NOT count");
// Attestation by an outsider (not authorized) does not count toward quorum.
const byOutsider = await buildMemberEvent(owner, { ...base, created_at: "2026-06-16T21:10:00.000Z", rnd: "out001", op: "set_role", target: admin.id, role: "owner" }, [outsider]);
r = await verifyEvent(byOutsider, { directory, members });
ok("attestation by a non-authorized id does not count", !r.ok && r.reasons.some((x) => x.startsWith("insufficient-quorum")));

// Forged attestation: claim admin attested, but sign with outsider's key.
const forgedAtt = await buildMemberEvent(owner, { ...base, created_at: "2026-06-16T21:11:00.000Z", rnd: "frg001", op: "set_role", target: admin.id, role: "owner" });
const payload = canonical((({ sig, attestations, ...rest }) => rest)(forgedAtt));
forgedAtt.attestations = [{ by: admin.id, sig: await sign(await importSignPrivate(outsider.sign.privateJwk), payload) }];
r = await verifyEvent(forgedAtt, { directory, members });
ok("forged attestation (wrong key) is rejected", !r.ok && r.reasons.some((x) => x.startsWith("insufficient-quorum")));

console.log("# misc");
ok("default policy is add:1, remove:2, set_role:2",
  DEFAULT_GOVERNANCE.add === 1 && DEFAULT_GOVERNANCE.remove === 2 && DEFAULT_GOVERNANCE.set_role === 2);
const badOp = await buildMemberEvent(owner, { ...base, created_at: "2026-06-16T21:20:00.000Z", rnd: "bad001", op: "nuke", target: cand.id });
r = await verifyEvent(badOp, { directory, members });
ok("unknown member op rejected", !r.ok && r.reasons.includes("unknown-member-op"));

console.log("# root-of-trust invariants: no privilege escalation, owner is immutable");
// members here: owner A, admin B, admin C (candidate was promoted to admin above).
ok("setup: two admins + owner present",
  members.filter((m) => m.role === "admin").length === 2 && members.some((m) => m.role === "owner"));

// (b) a lone admin CANNOT add a complice admin (only the owner may promote).
const adminAddsAdmin = await buildMemberEvent(admin, { ...base, created_at: "2026-06-16T22:00:00.000Z", rnd: "esc001", op: "add", target: outsider.id, role: "admin" });
r = await verifyEvent(adminAddsAdmin, { directory, members });
ok("a non-owner promoting to admin is rejected (only-owner-promotes)", !r.ok && r.reasons.includes("only-owner-promotes"));

// a lone admin can still add a regular MEMBER (quorum 1) — only promotion is owner-gated.
const adminAddsMember = await buildMemberEvent(admin, { ...base, created_at: "2026-06-16T22:01:00.000Z", rnd: "mem001", op: "add", target: outsider.id, role: "member" });
ok("a non-owner can still add a plain member (quorum 1)", (await verifyEvent(adminAddsMember, { directory, members })).ok);

// (a) two admins CANNOT remove the genesis owner.
const removeOwner = await buildMemberEvent(admin, { ...base, created_at: "2026-06-16T22:02:00.000Z", rnd: "rmo001", op: "remove", target: owner.id }, [cand]);
r = await verifyEvent(removeOwner, { directory, members });
ok("two admins cannot remove the owner (cannot-depose-owner)", !r.ok && r.reasons.includes("cannot-depose-owner"));

// (a) two admins CANNOT downgrade the owner to member.
const downgradeOwner = await buildMemberEvent(admin, { ...base, created_at: "2026-06-16T22:03:00.000Z", rnd: "dno001", op: "set_role", target: owner.id, role: "member" }, [cand]);
r = await verifyEvent(downgradeOwner, { directory, members });
ok("two admins cannot downgrade the owner (cannot-depose-owner)", !r.ok && r.reasons.includes("cannot-depose-owner"));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
