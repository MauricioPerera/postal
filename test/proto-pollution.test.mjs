// Prototype-pollution regression for vendor/js-doc-store applyUpdate.
// Run: node test/proto-pollution.test.mjs
import { applyUpdate } from "../vendor/js-doc-store.cjs";

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

// Clean any pre-existing pollution so the assertions are trustworthy.
delete Object.prototype.polluted;
delete Object.prototype.x;

applyUpdate({}, { $set: { "__proto__.polluted": true } });
ok("__proto__.polluted does not leak to Object.prototype", ({}).polluted === undefined);

applyUpdate({}, { $set: { "constructor.prototype.x": 1 } });
ok("constructor.prototype.x does not leak to Object.prototype", ({}).x === undefined);

// Sanity: legitimate nested writes still work after the guard.
const doc = applyUpdate({ a: 1 }, { $set: { "nested.value": 42 } });
ok("normal nested $set still works", doc.nested.value === 42);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);