// Tests for the commit retry helper (src/github.js withRetry / isRefConflict).
import { withRetry, isRefConflict } from "../src/github.js";

let p = 0, f = 0;
const ok = (n, c) => { if (c) { p++; console.log("  ok  - " + n); } else { f++; console.log("  FAIL - " + n); } };
const noSleep = () => Promise.resolve();
const err = (status) => Object.assign(new Error("gh " + status), { status });

console.log("# isRefConflict");
ok("422 is a ref conflict", isRefConflict(err(422)) === true);
ok("409 is a ref conflict", isRefConflict(err(409)) === true);
ok("401 is NOT", !isRefConflict(err(401)));
ok("undefined is NOT", !isRefConflict(undefined));

console.log("# withRetry");
let calls;
calls = 0;
const r1 = await withRetry(async () => { calls++; if (calls < 3) throw err(422); return "ok"; }, { retryable: isRefConflict, sleep: noSleep });
ok("retries past 422 then succeeds", r1 === "ok" && calls === 3);

calls = 0;
let threw = null;
try { await withRetry(async () => { calls++; throw err(401); }, { retryable: isRefConflict, sleep: noSleep }); } catch (e) { threw = e; }
ok("non-retryable (401) throws immediately, no retry", threw && threw.status === 401 && calls === 1);

calls = 0; threw = null;
try { await withRetry(async () => { calls++; throw err(422); }, { tries: 4, retryable: isRefConflict, sleep: noSleep }); } catch (e) { threw = e; }
ok("exhausts tries then throws the last error", threw && threw.status === 422 && calls === 4);

calls = 0;
const rDefault = await withRetry(async () => { calls++; if (calls < 6) throw err(422); return "ok"; }, { retryable: isRefConflict, sleep: noSleep });
ok("default tries (6) ride out a long collision streak", rDefault === "ok" && calls === 6);

calls = 0;
const r2 = await withRetry(async () => { calls++; return 42; }, { sleep: noSleep });
ok("succeeds first try -> called once", r2 === 42 && calls === 1);

let backoff = [];
calls = 0;
await withRetry(async () => { calls++; if (calls < 3) throw err(422); return 1; }, { base: 100, retryable: isRefConflict, rand: () => 0, sleep: (ms) => { backoff.push(ms); return Promise.resolve(); } });
ok("linear backoff between retries (100, 200) with jitter=0", JSON.stringify(backoff) === JSON.stringify([100, 200]));

console.log(`\n${p} passed, ${f} failed`);
if (f) process.exit(1);
