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
import { verifyIdentityDoc, verifyEvent } from "./postal.js";

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

  for (const chat of chats) {
    const membersDoc = readJson(join(chatsDir, chat, "members.json"));
    const members = membersDoc && Array.isArray(membersDoc.members) ? membersDoc.members : null;
    const meta = readJson(join(chatsDir, chat, "meta.json"));
    const governance = meta && meta.governance ? meta.governance : undefined;
    const seenPaths = new Set();

    for (const path of walk(join(chatsDir, chat, "events")).sort()) {
      const rel = relative(root, path).split(sep).join("/");
      const ev = readJson(path);
      checked++;
      if (!ev) { failures.push({ path: rel, reasons: ["unparseable-event"] }); continue; }
      const verdict = await verifyEvent(ev, { directory, members, seenPaths, governance });
      seenPaths.add(rel);
      if (!verdict.ok) failures.push({ path: rel, reasons: verdict.reasons });
    }
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
