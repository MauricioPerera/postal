// Signed chat meta tests. Run: node test/meta.test.mjs
import {
  createIdentity, publicIdentityDoc, buildChatMeta, verifyChatMeta, newChatId,
} from "../src/postal.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

const owner = await createIdentity("Owner");
const mallory = await createIdentity("Mallory");
const directory = { [owner.id]: await publicIdentityDoc(owner), [mallory.id]: await publicIdentityDoc(mallory) };

const chat = newChatId(owner.id, "x1");
const meta = await buildChatMeta(owner, { chat_id: chat, title: "Familia", created_at: "2026-06-16T10:00:00.000Z", governance: { set_role: 3 } });

console.log("# valid signed meta");
let r = await verifyChatMeta(meta, { directory, chatId: chat });
ok("signed meta verifies", r.ok);

console.log("# tampering is rejected");
r = await verifyChatMeta({ ...meta, created_by: mallory.id }, { directory, chatId: chat });
ok("swapping created_by is rejected (chat-id binding + signature)",
  !r.ok && (r.reasons.includes("chat-id-not-bound-to-creator") || r.reasons.includes("invalid-meta-signature")));

r = await verifyChatMeta({ ...meta, governance: { set_role: 1 } }, { directory, chatId: chat });
ok("weakening governance breaks the signature", !r.ok && r.reasons.includes("invalid-meta-signature"));

r = await verifyChatMeta({ ...meta, title: "Hacked" }, { directory, chatId: chat });
ok("editing the title breaks the signature", !r.ok && r.reasons.includes("invalid-meta-signature"));

console.log("# id binding and identity checks");
const unbound = await buildChatMeta(owner, { chat_id: "plain_chat", created_at: "2026-06-16T10:00:00.000Z" });
r = await verifyChatMeta(unbound, { directory, chatId: "plain_chat" });
ok("chat id not embedding the creator is rejected", !r.ok && r.reasons.includes("chat-id-not-bound-to-creator"));

r = await verifyChatMeta(meta, { directory: {}, chatId: chat });
ok("unknown creator is rejected", !r.ok && r.reasons.includes("unknown-chat-creator"));

// Mallory forges a meta for HER OWN chat id — that's legitimately hers, must pass.
const malloryChat = newChatId(mallory.id, "m1");
const malloryMeta = await buildChatMeta(mallory, { chat_id: malloryChat, created_at: "2026-06-16T10:00:00.000Z" });
r = await verifyChatMeta(malloryMeta, { directory, chatId: malloryChat });
ok("a creator can make a chat under their own id", r.ok);

console.log("# fail-closed on unparseable created_at (H4)");
// verifyChatMeta reaches verifyEventSig WITHOUT the bad-date guard verifyEvent has. A meta whose
// created_at is not parseable has a genuinely valid signature (signed over that exact string), so
// before H4 the NaN date bypassed the key validity windows and the signature validated against any
// non-revoked key. Now verifyEventSig returns false on NaN t -> meta rejected.
const badDateChat = newChatId(owner.id, "bad1");
const badDateMeta = await buildChatMeta(owner, { chat_id: badDateChat, created_at: "not-a-date" });
r = await verifyChatMeta(badDateMeta, { directory, chatId: badDateChat });
ok("meta with unparseable created_at is rejected (fail-closed, H4)",
  !r.ok && r.reasons.includes("invalid-meta-signature"));
// Sanity: the same meta with a valid created_at still verifies (the fix only flips on NaN).
const goodDateMeta = await buildChatMeta(owner, { chat_id: badDateChat, created_at: "2026-06-16T10:00:00.000Z" });
r = await verifyChatMeta(goodDateMeta, { directory, chatId: badDateChat });
ok("same chat with a valid created_at still verifies (H4 does not regress valid dates)", r.ok);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
