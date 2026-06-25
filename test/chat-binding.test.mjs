// Chat-binding guard tests. Run: node test/chat-binding.test.mjs
// An event signed for chat A must NOT pass the gate when a caller asks to verify
// chat B (anti cross-chat replay). verifyEvent and verifyChat take an optional
// `chatId`; when provided, ev.chat_id must match it or the event is rejected with
// 'chat-id-mismatch'. When omitted, behavior is unchanged (backward compatible).
import {
  createIdentity, publicIdentityDoc,
  buildEvent, buildMemberEvent, eventPath, verifyEvent, verifyChat,
} from "../src/postal.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

const a = await createIdentity("Owner");
const b = await createIdentity("Bob");

const directory = {};
for (const i of [a, b]) directory[i.id] = await publicIdentityDoc(i);

const chatA = "chat-a";
const chatB = "chat-b";
const members = [{ id: a.id, role: "owner" }, { id: b.id, role: "admin" }];

console.log("# message event bound to its chat");
// A valid message event for chat A.
const msg = await buildEvent(a, {
  kind: "message", chat_id: chatA, to: [b.id],
  created_at: "2026-06-16T22:00:00.000Z", rnd: "cb-msg",
  body: { text: "hola" },
  recipients: [{ id: b.id, encPublicKey: b.enc.publicKey }],
});
// Passes when the caller is replaying chat A.
ok("verifyEvent ok when chatId matches the event's chat",
  (await verifyEvent(msg, { directory, chatId: chatA })).ok);
// Fails when the caller is replaying chat B (cross-chat replay blocked).
const mm = await verifyEvent(msg, { directory, chatId: chatB });
ok("verifyEvent rejects a chat-A event under chatId=B (chat-id-mismatch)",
  !mm.ok && mm.reasons.includes("chat-id-mismatch"));
// Omitting chatId keeps backward-compatible behavior (no mismatch check).
ok("verifyEvent without chatId does NOT enforce chat binding (backward compat)",
  (await verifyEvent(msg, { directory })).ok);

console.log("# member event bound to its chat");
// A valid member event (add) for chat A — owner alone can add at quorum 1.
const addEv = await buildMemberEvent(a, {
  chat_id: chatA, created_at: "2026-06-16T22:01:00.000Z", rnd: "cb-add",
  op: "add", target: b.id, role: "member",
});
ok("verifyEvent ok for a member event when chatId matches",
  (await verifyEvent(addEv, { directory, members, chatId: chatA })).ok);
const mb = await verifyEvent(addEv, { directory, members, chatId: chatB });
ok("verifyEvent rejects a member event under the wrong chatId (chat-id-mismatch)",
  !mb.ok && mb.reasons.includes("chat-id-mismatch"));

console.log("# verifyChat threads chatId into every event");
// Replay chat A; the chat-A events pass.
const itemA = (ev) => ({ path: eventPath(chatA, ev), event: ev });
let res = await verifyChat([itemA(msg)], { directory, genesisOwner: a.id, chatId: chatA });
ok("verifyChat ok when all events belong to the replayed chat", res.ok);
// Replay chat B over chat-A events -> the mismatch is reported per-event.
res = await verifyChat([itemA(msg)], { directory, genesisOwner: a.id, chatId: chatB });
ok("verifyChat flags a cross-chat event (chat-id-mismatch)",
  !res.ok && res.failures.some((f) => f.reasons.includes("chat-id-mismatch")));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);