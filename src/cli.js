// Postal — filesystem verifier (the HARD gate as a command).
//
// Walks a checked-out repo, builds the identity directory from .postal/users/,
// and runs verifyEvent on every event under .postal/chats/<chat>/events/.
// Exits non-zero if ANY event fails — this is what a CI required-check runs, and
// what branch protection uses to block a push that introduces forged/invalid events.
//
//   node src/cli.js verify [repoRoot]
//
// Node-only (uses node:fs). The protocol logic itself is the same isomorphic code.

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { verifyIdentityDoc, verifyChat, verifyChatMeta } from "./postal.js";
import { readLocalCommitIndex, attachCommitIndex } from "./commit-order.js";

function walk(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith(".json"))
    .map((e) => join(e.parentPath || e.path, e.name));
}

function readJson(path) {
  try { return JSON.parse(readFileSync(path, "utf8")); } catch { return undefined; }
}

export async function verifyRepo(repoRoot) {
  const root = repoRoot || process.cwd();
  const base = join(root, ".postal");
  const failures = [];
  let checked = 0;

  // 1. Build the verified identity directory.
  const directory = {};
  for (const path of walk(join(base, "users"))) {
    const doc = readJson(path);
    const rel = relative(root, path).split(sep).join("/");
    if (!doc) { failures.push({ path: rel, reasons: ["unparseable-identity"] }); continue; }
    if (await verifyIdentityDoc(doc)) directory[doc.id] = doc;
    else failures.push({ path: rel, reasons: ["invalid-identity-doc"] });
  }

  // 2. Verify every event in every chat.
  const chatsDir = join(base, "chats");
  const chats = existsSync(chatsDir)
    ? readdirSync(chatsDir, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name)
    : [];

  // Anchor cross-author order to commit order (the one thing the signer doesn't
  // control) instead of self-asserted created_at. Built once from the local git
  // clone; an empty map (no git) leaves items unchanged -> canonicalOrder falls
  // back to created_at, identical to the historical behavior.
  const commitIndex = await readLocalCommitIndex(root);

  for (const chat of chats) {
    const meta = readJson(join(chatsDir, chat, "meta.json"));
    // Trust created_by / governance ONLY from a meta.json that passes verification.
    const metaVerdict = await verifyChatMeta(meta, { directory, chatId: chat });
    let genesisOwner, governance;
    if (metaVerdict.ok) {
      genesisOwner = meta.created_by;
      governance = meta.governance;
    } else {
      failures.push({ path: `.postal/chats/${chat}/meta.json`, reasons: metaVerdict.reasons });
    }

    // Gather all events; membership is REPLAYED from genesis, not trusted from a snapshot.
    const items = [];
    for (const path of walk(join(chatsDir, chat, "events"))) {
      const rel = relative(root, path).split(sep).join("/");
      const event = readJson(path);
      checked++;
      if (!event) { failures.push({ path: rel, reasons: ["unparseable-event"] }); continue; }
      items.push({ path: rel, event });
    }

    const chatResult = await verifyChat(attachCommitIndex(items, commitIndex), { directory, genesisOwner, governance, chatId: chat });
    for (const f of chatResult.failures) failures.push(f);
  }

  return { ok: failures.length === 0, checked, identities: Object.keys(directory).length, failures };
}

// --- CLI entry ---------------------------------------------------------------
const isMain = import.meta.url === `file://${process.argv[1]}` ||
  import.meta.url.endsWith(process.argv[1]?.replace(/\\/g, "/") || "###");

if (isMain) {
  const cmd = process.argv[2];
  if (cmd !== "verify") {
    console.error("usage: node src/cli.js verify [repoRoot]");
    process.exit(2);
  }
  const result = await verifyRepo(process.argv[3]);
  console.log(`postal verify: ${result.checked} events, ${result.identities} identities`);
  if (result.ok) {
    console.log("OK — all events pass the gate");
    process.exit(0);
  }
  console.error(`BLOCKED — ${result.failures.length} invalid:`);
  for (const f of result.failures) console.error(`  [X] ${f.path}: ${f.reasons.join(", ")}`);
  process.exit(1);
}
