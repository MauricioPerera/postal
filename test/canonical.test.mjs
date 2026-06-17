// RFC 8785 (JSON Canonicalization Scheme / JCS) conformance for src/crypto.js `canonical()`.
//
// canonical() IS the JCS recipe by construction: object keys sorted by UTF-16 code units
// (Array.prototype.sort default), ECMAScript JSON.stringify for primitives — which is exactly
// RFC 8785's string and number serialization — no insignificant whitespace, array order preserved.
// Pinned here against authoritative vectors (numbers from RFC 8785 §3.2.3; string/sorting rules
// from the spec). Special chars come from String.fromCharCode so the source is pure ASCII with no
// invisible bytes. Run: node test/canonical.test.mjs
import { canonical } from "../src/crypto.js";

let p = 0, f = 0;
const ok = (n, c) => { if (c) { p++; console.log("  ok  - " + n); } else { f++; console.log("  FAIL - " + n); } };
const cc = (n) => String.fromCharCode(n);
const EURO = cc(0x20AC), DEL = cc(0x7F), YDIA = cc(0xFF), GRIN = String.fromCodePoint(0x1F600), PUA = cc(0xE000);

console.log("# numbers (RFC 8785 §3.2.3 vector — the hard part)");
ok("RFC §3.2.3 number vector",
  canonical([333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001])
  === "[333333333.3333333,1e+30,4.5,0.002,1e-27]");
ok("integers stay integers; -0 normalizes to 0", canonical([0, -0, 1, -1, 100, 1.5]) === "[0,0,1,-1,100,1.5]");

console.log("# strings (minimal escaping, short forms, lowercase \\uXXXX, literal UTF-8)");
// input chars in order:  EURO  $  U+000F  LF  TAB  BS  FF  CR  A  '  B  "  \  /
const sIn = EURO + "$" + String.fromCharCode(0x0F, 0x0A, 0x09, 0x08, 0x0C, 0x0D) + "A'B\"\\/";
// expected JCS token, piece-by-piece (a "\\x" in source is the 2-char runtime escape):
const sExpect = '"' + EURO + "$" + "\\u000f" + "\\n" + "\\t" + "\\b" + "\\f" + "\\r" + "A'B" + "\\\"" + "\\\\" + "/" + '"';
ok("controls -> \\b\\t\\n\\f\\r / \\u000f; quote and backslash escaped; EURO and / literal", canonical(sIn) === sExpect);
ok("a non-control non-ASCII char (U+00FF) stays literal", canonical(YDIA) === '"' + YDIA + '"');
ok("DEL (U+007F) stays literal — only U+0000-U+001F are control-escaped", canonical(DEL) === '"' + DEL + '"');

console.log("# key ordering — UTF-16 code units, NOT code points (the JCS gotcha)");
// GRIN (U+1F600) is a surrogate pair whose first code unit is 0xD83D; it must sort BEFORE a BMP
// char at U+E000 (0xD83D < 0xE000). Code-point order would reverse them.
const obj = { [PUA]: 1, [GRIN]: 2, [EURO]: 3, "a": 4 };
const out = canonical(obj);
const expectOrder = '{"a":4,"' + EURO + '":3,"' + GRIN + '":2,"' + PUA + '":1}';
ok("sorted a < EURO < GRIN < U+E000 (UTF-16)", out === expectOrder);
ok("GRIN sorts before U+E000 (distinct from code-point order)", out.indexOf(GRIN) < out.indexOf(PUA));

console.log("# structure: sorted keys, preserved array order, no whitespace, recursion");
ok("top-level keys sorted, no spaces (RFC §3.2.3 shape)",
  canonical({ string: "x", numbers: [1, 2], literals: [null, true, false] })
  === '{"literals":[null,true,false],"numbers":[1,2],"string":"x"}');
ok("nested objects recursively canonical", canonical({ b: { d: 1, c: 2 }, a: 3 }) === '{"a":3,"b":{"c":2,"d":1}}');
ok("array order preserved (not sorted)", canonical([3, 1, 2]) === "[3,1,2]");

console.log(`\n${p} passed, ${f} failed`);
if (f) process.exit(1);
