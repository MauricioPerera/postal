// Postal transport integration test against a REAL private GitHub repo.
//   GH_TOKEN=$(gh auth token) GH_OWNER=... GH_REPO=... node test/integration.test.mjs
import { createIdentity, eventPath } from "../src/postal.js";
import { canonical, importSignPrivate, sign } from "../src/crypto.js";
import { ghClient, publishIdentity, loadDirectory, postMessage, pollChat } from "../src/transport.js";

const owner = process.env.GH_OWNER, repo = process.env.GH_REPO, token = process.env.GH_TOKEN;
if (!owner || !repo || !token) { console.error("Set GH_OWNER, GH_REPO, GH_TOKEN"); process.exit(2); }

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

const client = ghClient({ owner, repo, token });
const tag = Date.now().toString(36);
const chat = "chat_" + tag;

const alice = await createIdentity("Alice " + tag);
const bob = await createIdentity("Bob " + tag);
const eve = await createIdentity("Eve " + tag);

console.log(`# Postal transport on ${owner}/${repo} (chat ${chat})`);

// 1. Publish identities (self-signed) to the repo.
await publishIdentity(client, alice);
await publishIdentity(client, bob);
await publishIdentity(client, eve);
const directory = await loadDirectory(client, [alice.id, bob.id, eve.id]);
ok("3 identities published + verified from repo", Object.keys(directory).length === 3);

const members = [{ id: alice.id, role: "owner" }, { id: bob.id, role: "member" }];

// 2. Alice posts a signed + sealed message to Bob.
const secret = "Bob: firmado por mí, ilegible para GitHub. " + tag;
const ev = await postMessage(client, alice, { chat_id: chat, to: [bob.id], text: secret, directory });
ok("message event committed", ev && ev.kind === "message");

// 3. What GitHub stores must be sealed + signed, no plaintext.
const stored = await client.getFile(eventPath(chat, ev));
ok("stored event exists on GitHub", !!stored);
ok("stored body is sealed (POSTAL1:)", stored && stored.content.includes("POSTAL1:"));
ok("stored event has a signature", stored && JSON.parse(stored.content).sig);
ok("stored event has NO plaintext", stored && !stored.content.includes(secret));

// 4. Bob polls with verify-on-read: gate passes, body decrypts.
const bobView = await pollChat(client, bob, chat, { directory, members });
const bobMsg = bobView.find((e) => e.text === secret);
ok("Bob: gate passed + decrypted", !!bobMsg && bobMsg.verdict.ok);

// 5. Eve (repo access, not a recipient): gate passes (it's a valid event) but she
//    cannot decrypt the body.
const eveView = await pollChat(client, eve, chat, { directory, members });
const eveMsg = eveView.find((e) => e.path === bobMsg?.path);
ok("Eve sees a valid event but cannot read it", eveMsg && eveMsg.verdict.ok && eveMsg.text === null);

// 6. ATTACK: forge an event from Alice without her private key (Eve signs it, then
//    relabels from=alice). Commit it directly, then poll — the gate must reject it.
const forged = await (async () => {
  const created_at = new Date().toISOString();
  const id = created_at.replace(/[:.]/g, "-") + "_" + alice.id + "_dead99";
  const base = {
    v: 1, kind: "message", chat_id: chat, from: alice.id, to: [bob.id],
    created_at, id, body: { sealed: "POSTAL1:ZmFrZQ==" },
  };
  // Eve signs it with HER key, but stamps from=alice.id.
  const evePriv = await importSignPrivate(eve.sign.privateJwk);
  base.sig = await sign(evePriv, canonical(base));
  return base;
})();
await client.putFile(eventPath(chat, forged), JSON.stringify(forged, null, 2), "postal: FORGED (attack)");

const afterAttack = await pollChat(client, bob, chat, { directory, members });
const forgedView = afterAttack.find((e) => e.event && e.event.id === forged.id);
ok("forged 'from=Alice' event is REJECTED by the gate",
  forgedView && !forgedView.verdict.ok && forgedView.verdict.reasons.includes("invalid-signature"));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
