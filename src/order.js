// Postal — canonical CROSS-AUTHOR ordering of events.
//
// Per-author order is already tamper-proof via the hash chain (seq/prev, both signed).
// What the signed event CANNOT fix on its own is the order BETWEEN different authors:
// `created_at` is a self-asserted field a member can backdate.
//
// Preference: when a git-backed reader attaches `commitIndex` (the position of the commit
// that introduced the event — an operator-anchored value the signer does NOT control),
// order by it. Otherwise fall back to `created_at` (id tiebreak), identical to the
// historical behavior, so callers that don't supply commitIndex are unaffected.
//
// HONEST LIMIT: commit order is controlled by whoever commits/pushes (`git commit --date`,
// rebase, merge order). It RAISES THE BAR over the freely-spoofable `created_at` — it is no
// longer a field inside the signed JSON — but it is NOT consensus. Cross-author total order
// without a trusted sequencer stays operator-anchored, not Byzantine-safe. (See spec §ordering.)

const NO_INDEX = Number.MAX_SAFE_INTEGER;

function eventOf(item) { return item && item.event ? item.event : item; }

function commitIndexOf(item) {
  const ci = item && (item.commitIndex ?? (item.event && item.event.commitIndex));
  return Number.isInteger(ci) ? ci : NO_INDEX;
}

// Stable canonical order. Items: `{ event, commitIndex? }` or raw events (optionally with a
// `commitIndex` property). Items carrying a commit index sort first, in commit order; the
// rest fall back to created_at, then id. Does not mutate the input.
export function canonicalOrder(items) {
  return [...items].filter((it) => eventOf(it)).sort((a, b) => {
    const ia = commitIndexOf(a), ib = commitIndexOf(b);
    if (ia !== ib) return ia - ib;
    const ea = eventOf(a), eb = eventOf(b);
    const ta = String(ea.created_at || ""), tb = String(eb.created_at || "");
    if (ta !== tb) return ta < tb ? -1 : 1;
    return String(ea.id || "") < String(eb.id || "") ? -1 : 1;
  });
}

// Whether every item carries a commit index (a fully git-anchored read). Lets a caller tell
// the user if the ordering is operator-anchored or fell back to self-asserted created_at.
export function isCommitAnchored(items) {
  return items.length > 0 && items.every((it) => Number.isInteger(it && (it.commitIndex ?? (it.event && it.event.commitIndex))));
}
