// Postal — the git-backed SOURCE of `commitIndex` for canonical ordering (src/order.js).
//
// `canonicalOrder` CONSUMES a `commitIndex` per item; this module PRODUCES it from the one
// place the signer doesn't control: the order in which commits introduced each event into the
// repo. `git log --reverse --diff-filter=A --name-only` lists, oldest-first, the commit that
// ADDED each path; the commit's ordinal in that list is the anchor.
//
// TRANSPORT SCOPE (honest): this reads a LOCAL git clone (CLI / a server with a working copy).
// The hosted GitHub-API transport (src/github.js) has no local git — a parallel adapter over
// the commits API is needed to anchor THAT path; until then the hosted live app falls back to
// `created_at` and `isCommitAnchored` reports false. The pure functions below are transport-
// agnostic: feed them adds from any source.
//
// LIMIT (same as order.js): commit order is operator-anchored (whoever commits/pushes), not
// Byzantine consensus. It raises the bar over self-asserted `created_at`; it is not absolute.

// Parse `git log --reverse --diff-filter=A --name-only --format=%x00%H` output into a
// path -> commitIndex map. Each commit is delimited by a NUL-prefixed sha line; the lines
// after it (until the next delimiter) are the paths that commit ADDED. First add wins, so a
// path re-added after a delete keeps its original (earliest) index. Pure — no I/O.
export function parseCommitAdds(text) {
  const byPath = new Map();
  let idx = -1;
  for (const raw of String(text).split("\n")) {
    if (raw.startsWith("\x00")) { idx++; continue; }      // new commit delimiter
    const path = raw.trim();
    if (path && idx >= 0 && !byPath.has(path)) byPath.set(path, idx);
  }
  return byPath;
}

// Attach `commitIndex` to items by looking up their path in `indexByPath`. Returns NEW items
// (does not mutate); items whose path is unknown are left without an index, so canonicalOrder
// falls them back to created_at. `pathOf` defaults to the { path, event } shape the app layers
// (postal-team, postal-coordination) already use.
export function attachCommitIndex(items, indexByPath, { pathOf = (it) => it && it.path } = {}) {
  return items.map((it) => {
    const p = pathOf(it);
    if (p == null || !indexByPath.has(p)) return it;
    return { ...it, commitIndex: indexByPath.get(p) };
  });
}

// Node-only runner: shell out to a LOCAL git clone and build the path -> commitIndex map.
// Injection-safe (argv array, no shell). Returns an empty map if `dir` is not a git repo.
// Async so this module stays importable in the browser (child_process is imported lazily).
export async function readLocalCommitIndex(dir) {
  const { execFileSync } = await import("node:child_process");
  let out;
  try {
    out = execFileSync(
      "git",
      ["-C", dir, "log", "--reverse", "--diff-filter=A", "--name-only", "--format=%x00%H"],
      { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"] },
    );
  } catch {
    return new Map();                                      // not a repo / git missing -> no anchor
  }
  return parseCommitAdds(out);
}
