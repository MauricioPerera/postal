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

console.log("# numbers — exponential boundaries (RFC 8785 §3.2.2.3 = ECMAScript Number-to-String)");
// JS switches to exponential at 1e21 (inclusive) upward and 1e-7 (inclusive) downward.
ok("1e21 -> exponential '1e+21' (boundary: >= 1e21 uses short form)", canonical(1e21) === "1e+21");
ok("1e20 -> decimal '100000000000000000000' (just below the boundary stays plain)", canonical(1e20) === "100000000000000000000");
ok("-1e21 -> '-1e+21' (sign preserved on the exponential boundary)", canonical(-1e21) === "-1e+21");
ok("1e-6 -> decimal '0.000001' (boundary: > 1e-7 stays plain)", canonical(1e-6) === "0.000001");
ok("1e-7 -> exponential '1e-7' (lower boundary flips to short form)", canonical(1e-7) === "1e-7");
ok("negative small exp '-1e-7'", canonical(-1e-7) === "-1e-7");

console.log("# numbers — trailing-zero decimals collapse (ECMAScript, hence JCS)");
ok("1.0 -> '1' (trailing .0 dropped)", canonical(1.0) === "1");
ok("100.0 -> '100' (trailing .0 dropped)", canonical(100.0) === "100");
ok("4.50 -> '4.5' (insignificant trailing zero dropped)", canonical(4.50) === "4.5");
ok("-0 -> '0' (negative zero normalizes, JCS §3.2.2.3)", canonical(-0) === "0");

console.log("# numbers — extremes and double rounding (the IEEE-754 reality JCS inherits)");
ok("5e-324 (Number.MIN_VALUE) -> '5e-324' (smallest denormal serializes)", canonical(5e-324) === "5e-324");
ok("Number.MAX_VALUE -> '1.7976931348623157e+308'", canonical(Number.MAX_VALUE) === "1.7976931348623157e+308");
ok("0.1 -> '0.1' (the nearest double rounds back to 0.1 on stringify)", canonical(0.1) === "0.1");
ok("0.2 -> '0.2'", canonical(0.2) === "0.2");
ok("0.1+0.2 -> '0.30000000000000004' (double rounding surfaced; canonical is faithful to the stored double)",
  canonical(0.1 + 0.2) === "0.30000000000000004");

console.log("# FAIL-CLOSED — NaN / Infinity / -Infinity: NOT valid JSON; canonical() THROWS (H6)");
// RFC 8785 scopes to JSON values; NaN/±Infinity are NOT valid JSON. JSON.stringify coerces them to the
// literal "null", so {x:NaN} and {x:null} would produce IDENTICAL signing bytes — silent corruption of a
// signed payload. canonical() is a SIGNING primitive, so it THROWS on non-finite numbers at any depth
// (root, array element, object property value), exactly like it does for undefined/function/symbol.
const throwsNf = (n, fn) => { try { fn(); ok(n, false); } catch (e) { ok(n + " :: " + e.message, e instanceof Error); } };
throwsNf("NaN at root throws", () => canonical(NaN));
throwsNf("Infinity at root throws", () => canonical(Infinity));
throwsNf("-Infinity at root throws", () => canonical(-Infinity));
throwsNf("NaN in array throws", () => canonical([1, NaN, 2]));
throwsNf("Infinity in array throws", () => canonical([1, Infinity, 2]));
throwsNf("NaN as object value throws (NOT silently coerced to null)", () => canonical({ a: 1, b: NaN, c: 2 }));
throwsNf("Infinity as object value throws", () => canonical({ a: 1, b: Infinity, c: 2 }));
throwsNf("nested non-finite deep in structure throws", () => canonical({ a: [1, { b: Infinity }] }));
ok("NaN no longer collides with null — null still serializes, NaN throws",
  canonical(null) === "null" && (() => { try { canonical(NaN); return false; } catch { return true; } })());
// Finite numbers are byte-identical to before the H6 fix (regression guard for valid inputs).
ok("finite numbers unchanged: 0 -> '0'", canonical(0) === "0");
ok("finite numbers unchanged: 1e30 -> '1e+30'", canonical(1e30) === "1e+30");
ok("finite numbers unchanged: 4.50 -> '4.5'", canonical(4.50) === "4.5");
ok("finite numbers unchanged: MAX_VALUE serializes", canonical(Number.MAX_VALUE) === "1.7976931348623157e+308");
ok("finite numbers unchanged: 0.1+0.2 -> '0.30000000000000004'", canonical(0.1 + 0.2) === "0.30000000000000004");

console.log("# HONEST LIMIT 2 — integers > 2^53 lose precision (inherent to IEEE-754 doubles, NOT JCS)");
// Number.MAX_SAFE_INTEGER + 1 and + 2 both round to the same even double. JCS faithfully serializes the
// stored double, so two distinct source literals collapse to one token. This is JS's limit, not canonical()'s.
ok("MAX_SAFE_INTEGER (2^53-1) -> '9007199254740991' (exact)", canonical(Number.MAX_SAFE_INTEGER) === "9007199254740991");
ok("MAX_SAFE_INTEGER+1 -> '9007199254740992' (rounds up to even)", canonical(Number.MAX_SAFE_INTEGER + 1) === "9007199254740992");
ok("MAX_SAFE_INTEGER+2 -> '9007199254740992' too (precision lost; +1 === +2 as doubles — documented limit)",
  canonical(Number.MAX_SAFE_INTEGER + 1) === canonical(Number.MAX_SAFE_INTEGER + 2));
ok("2^60 literal serializes without integer-precision loss as stored",
  canonical(1152921504606846976) === "1152921504606847000" && canonical(1152921504606846980) === "1152921504606847000");

console.log("# FAIL-CLOSED — undefined / function / symbol: NOT JSON values; canonical() THROWS");
// canonical() is a SIGNING primitive: a value JSON.stringify would not represent as valid JSON must not
// silently become a token. JSON.stringify omits undefined-valued object keys and nulls undefined array
// slots; canonical() instead THROWS at any depth (root, array element, object property value), so a
// non-JSON payload can never be signed. (null IS valid JSON — not thrown.) NaN/Infinity also throw —
// see the FAIL-CLOSED non-finite section above (H6).
const throws = (n, fn) => { try { fn(); ok(n, false); } catch (e) { ok(n + " :: " + e.message, e instanceof Error); } };
throws("undefined at root throws", () => canonical(undefined));
throws("undefined in array throws", () => canonical([1, undefined, 2]));
throws("undefined as object value throws (key NOT silently omitted)", () => canonical({ a: 1, b: undefined, c: 2 }));
throws("function at root throws", () => canonical(() => 1));
throws("function in array throws", () => canonical([1, () => 1, 2]));
throws("function as object value throws (key NOT silently omitted)", () => canonical({ a: 1, f: () => 1, c: 2 }));
throws("symbol at root throws", () => canonical(Symbol("x")));
throws("symbol in array throws", () => canonical([1, Symbol("x"), 2]));
throws("symbol as object value throws (key NOT silently omitted)", () => canonical({ a: 1, s: Symbol("x"), c: 2 }));
ok("null is valid JSON — NOT thrown (distinct from undefined)", canonical(null) === "null");
throws("nested non-JSON value deep in structure throws", () => canonical({ a: [1, { b: undefined }] }));

console.log("# structure — deep nesting, empties, no Unicode normalization, no duplicate keys");
ok("deeply nested objects canonicalize recursively",
  canonical({ a: { b: { c: { d: 1 } } } }) === '{"a":{"b":{"c":{"d":1}}}}');
ok("deeply nested arrays canonicalize recursively",
  canonical([[[[1]]]]) === "[[[[1]]]]");
ok("empty array -> '[]'", canonical([]) === "[]");
ok("empty object -> '{}'", canonical({}) === "{}");
ok("empty array and empty object are distinct tokens", canonical([]) !== canonical({}));
// JCS does NO Unicode normalization: the same grapheme as NFC (U+00F3) vs NFD (o + U+0301) are
// different UTF-16 code-unit sequences, so they sort and serialize differently. Asserted so nobody
// assumes canonical() "normalizes" — it does not, and must not, for signature stability.
const nfc = "ó", nfd = "ó"; // U+00F3 vs o + combining acute
ok("NFC and NFD of the same grapheme serialize to DIFFERENT tokens (no Unicode normalization — JCS by design)",
  canonical({ [nfc]: 1 }) === '{"ó":1}'
  && canonical({ [nfd]: 1 }) === '{"ó":1}'
  && canonical({ [nfc]: 1 }) !== canonical({ [nfd]: 1 }));
// Object literal keys are already unique by construction (later wins silently); Object.keys reflects one
// entry per name, so canonical() can never emit a duplicate key. Asserted to document the invariant.
ok("duplicate literal keys collapse to one (impossible to emit a duplicate key via Object.keys)",
  Object.keys({ x: 1, x: 2 }).length === 1 && canonical({ x: 1, x: 2 }) === '{"x":2}');

console.log(`\n${p} passed, ${f} failed`);
if (f) process.exit(1);
