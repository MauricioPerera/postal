// GitHub transport unit tests (mocked fetch — no network). Run: node test/transport.test.mjs
import { ghClient } from "../src/github.js";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

const origFetch = globalThis.fetch;
const mock = (body, status = 200) => {
  globalThis.fetch = async () => ({
    ok: status >= 200 && status < 300, status,
    json: async () => body, text: async () => "", headers: { get: () => null },
  });
};

const c = ghClient({ owner: "o", repo: "r", token: "t" });

console.log("# listTree must NOT silently return a truncated tree");
mock({ truncated: true, tree: [{ type: "blob", path: ".postal/chats/x/events/a.json" }] });
let threw = false;
try { await c.listTree(".postal/chats/"); } catch { threw = true; }
ok("a truncated tree throws (no silent partial read)", threw);

console.log("# a complete tree returns the blob paths under the prefix");
mock({ truncated: false, tree: [
  { type: "blob", path: ".postal/chats/x/events/a.json" },
  { type: "tree", path: ".postal/chats/x" },                 // non-blob: excluded
  { type: "blob", path: ".postal/users/other.json" },        // out of prefix: excluded
] });
const paths = await c.listTree(".postal/chats/");
ok("returns exactly the in-prefix blob paths", paths.length === 1 && paths[0] === ".postal/chats/x/events/a.json");

globalThis.fetch = origFetch;
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
