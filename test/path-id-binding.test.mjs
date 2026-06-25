// Path / id / field-format binding tests. Run: node test/path-id-binding.test.mjs
// Hardens the deterministic gate against three audit findings:
//  (H1) a valid event verifies at its real path (path binding was reverted: the
//       protocol intentionally decouples storage route from logical identity, so
//       append-only is enforced on the DERIVED eventPath, not on it.path);
//  (H2) an id whose free suffix carries '/' or '..' (poisoning eventPath) must be
//       rejected with 'bad-id-format' (the prefix check alone lets it through);
//  (H3) `from` and `chat_id` must match their runtime formats (the JSON schema is
//       not executed at runtime) -> 'bad-from-format' / 'bad-chat-id-format';
//  (H4) verifyChatMeta must require the canonical `c_<created_by>_` prefix, not a
//       loose substring match, on meta.id -> 'chat-id-not-bound-to-creator'.
import {
  createIdentity, publicIdentityDoc,
  buildEvent, buildChatMeta,
  eventPath, verifyEvent, verifyChat, verifyChatMeta, newChatId,
} from "../src/postal.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

const a = await createIdentity("Alice");
const b = await createIdentity("Bob");
const directory = {};
for (const i of [a, b]) directory[i.id] = await publicIdentityDoc(i);

const chat = newChatId(a.id, "pib1");
const members = [{ id: a.id, role: "owner" }, { id: b.id, role: "member" }];
const recipients = [{ id: b.id, encPublicKey: b.enc.publicKey }];

const item = (ev, path) => ({ path: path !== undefined ? path : eventPath(chat, ev), event: ev });

console.log("# H1: a valid event passes at its real path");
const msg = await buildEvent(a, {
  kind: "message", chat_id: chat, to: [b.id],
  created_at: "2026-06-16T22:00:00.000Z", rnd: "pib-msg",
  body: { text: "hola" }, recipients,
});
// Standalone verifyEvent: backward compatible (no path binding).
ok("verifyEvent is backward compatible (no path binding)",
  (await verifyEvent(msg, { directory })).ok);
// verifyChat: same event at its real path -> chat verifies.
let res = await verifyChat([item(msg)], { directory, genesisOwner: a.id, chatId: chat });
ok("verifyChat ok when the event lives at its derived path", res.ok);

console.log("# H2: id suffix with '/' or '..' is rejected (bad-id-format), prefix check preserved");
// Build a valid event, then tamper ONLY the id suffix to a path-poisoning value. The
// signature no longer matches, but we only assert the id-format rule fires. The prefix
// (created_at+from) is preserved so 'non-deterministic-id' does NOT fire; the suffix
// check must surface 'bad-id-format'.
const baseId = msg.id;
const prefix = "2026-06-16T22-00-00-000Z_" + a.id + "_";
ok("setup: the real id has the expected prefix", baseId.indexOf(prefix) === 0);
const poisonSlash = { ...msg, id: prefix + "../evil" };
const rSlash = await verifyEvent(poisonSlash, { directory });
ok("id suffix with '../' -> bad-id-format (and NOT non-deterministic-id)",
  !rSlash.ok && rSlash.reasons.includes("bad-id-format") && !rSlash.reasons.includes("non-deterministic-id"));
const poisonDot = { ...msg, id: prefix + "a/b" };
const rDot = await verifyEvent(poisonDot, { directory });
ok("id suffix with '/' -> bad-id-format", !rDot.ok && rDot.reasons.includes("bad-id-format"));
// Empty suffix (id == prefix exactly) -> bad-id-format (suffix must be non-empty).
const rEmpty = await verifyEvent({ ...msg, id: prefix }, { directory });
ok("id with empty suffix -> bad-id-format", !rEmpty.ok && rEmpty.reasons.includes("bad-id-format"));
// Prefix mismatch still surfaces 'non-deterministic-id' (the existing reason is kept).
const rPrefix = await verifyEvent({ ...msg, id: "whatever_random" }, { directory });
ok("wrong id prefix still -> non-deterministic-id (preserved)",
  !rPrefix.ok && rPrefix.reasons.includes("non-deterministic-id"));

console.log("# H3: from / chat_id runtime format checks");
// Bad from: not a 16-hex fingerprint.
const rFrom = await verifyEvent({ ...msg, from: "zz" }, { directory });
ok("malformed from ('zz') -> bad-from-format", !rFrom.ok && rFrom.reasons.includes("bad-from-format"));
// Bad chat_id: path-traversal chars.
const rChat = await verifyEvent({ ...msg, chat_id: "../etc" }, { directory, chatId: "../etc" });
ok("malformed chat_id ('../etc') -> bad-chat-id-format",
  !rChat.ok && rChat.reasons.includes("bad-chat-id-format"));
// Sanity: a canonical event still passes (no false positive from the new checks).
ok("a canonical event still passes the new format checks",
  (await verifyEvent(msg, { directory })).ok);

console.log("# H4: verifyChatMeta requires the c_<created_by>_ prefix, not a substring");
const meta = await buildChatMeta(a, { chat_id: chat, created_at: "2026-06-16T10:00:00.000Z" });
ok("canonical meta (c_<created_by>_<rnd>) verifies",
  (await verifyChatMeta(meta, { directory, chatId: chat })).ok);
// An id that CONTAINS created_by as a substring but does NOT start with c_<created_by>_.
// c_<other>_<created_by> tail: substring match passes, prefix match must fail.
const substringChat = "c_" + b.id + "_" + a.id;
const substringMeta = await buildChatMeta(a, { chat_id: substringChat, created_at: "2026-06-16T10:00:00.000Z" });
const rSub = await verifyChatMeta(substringMeta, { directory, chatId: substringChat });
ok("meta id containing created_by as substring but not c_<created_by>_ prefix -> chat-id-not-bound-to-creator",
  !rSub.ok && rSub.reasons.includes("chat-id-not-bound-to-creator"));
// A genuinely canonical chat under a different creator still passes (own id).
const ownChat = newChatId(b.id, "z1");
const ownMeta = await buildChatMeta(b, { chat_id: ownChat, created_at: "2026-06-16T10:00:00.000Z" });
ok("a creator's own canonical chat still verifies", (await verifyChatMeta(ownMeta, { directory, chatId: ownChat })).ok);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);