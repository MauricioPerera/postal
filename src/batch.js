// Postal — commit batching: blur send-time metadata without a server.
//
// One commit per message leaks each send's exact time (commit timestamp) and isolates
// each event. Batching accumulates events in a local outbox and writes them all in ONE
// commit at fixed wall-clock boundaries, so the host sees a burst of N events at the
// boundary instead of N timestamps. Quantizing `created_at` to the same boundary keeps
// the in-file time from leaking the real moment too.
//
// Honest limit: the host still sees the batch commit and its size (how many events in
// that window). Batching lowers TIME RESOLUTION; it does not hide that activity happened.

export const DEFAULT_PERIOD_MS = 10 * 60 * 1000; // 10 minutes

// Floor a millisecond timestamp to the period boundary.
export function boundary(ms, periodMs = DEFAULT_PERIOD_MS) {
  return Math.floor(ms / periodMs) * periodMs;
}

// Quantize an ISO time to its period boundary (e.g. 20:07:33 -> 20:00:00 for 10-min).
export function quantizeTime(iso, periodMs = DEFAULT_PERIOD_MS) {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  return new Date(boundary(t, periodMs)).toISOString();
}

// The next boundary at or after `ms` — when a client should flush.
export function nextBoundary(ms, periodMs = DEFAULT_PERIOD_MS) {
  const b = boundary(ms, periodMs);
  return b === ms ? ms : b + periodMs;
}

// A local outbox: queue files, then flush them as a single commit.
export function makeOutbox(client) {
  const queue = [];
  return {
    add(path, content) { queue.push({ path, content }); return queue.length; },
    size() { return queue.length; },
    pending() { return queue.slice(); },
    clear() { queue.length = 0; },
    // Commit everything queued in ONE commit. Returns { sha, count } or null if empty.
    async flush(message) {
      if (!queue.length) return null;
      const files = queue.slice();
      const sha = await client.commitFiles(files, message || `postal: batch of ${files.length}`);
      queue.length = 0;
      return { sha, count: files.length };
    },
  };
}
