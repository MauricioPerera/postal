// Drift guard between the on-disk JSON Schemas (schema/*.schema.json) and the
// inline schema-lite checks in src/postal.js (verifyEvent / verifyIdentityDoc).
// Schemas are NOT loaded in runtime, so they can silently drift from the gate.
// This test loads them from disk, validates real lib-produced examples against a
// tiny self-contained JSON Schema validator, and asserts that for every required
// field both the schema validator AND the inline gate reject the malformed object.
// Run: node test/schema.test.mjs
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  createIdentity, publicIdentityDoc, verifyIdentityDoc,
  buildEvent, verifyEvent,
} from "../src/postal.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const loadSchema = (rel) => JSON.parse(readFileSync(join(ROOT, rel), "utf8"));

let pass = 0, fail = 0;
const ok = (n, c) => { c ? (pass++, console.log("  ok  -", n)) : (fail++, console.error("  FAIL-", n)); };

// --- minimal JSON Schema validator (no deps) ---------------------------------
// Supports ONLY the subset used by schema/event.schema.json and
// schema/identity.schema.json. If a schema uses a keyword this validator does
// not implement, it THROWS so the test fails loudly and forces an update here.
const META_IGNORE = new Set(["$schema", "$id", "title", "description", "$comment", "examples", "default"]);

function actualType(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  return typeof v;
}

function matchesType(t, v, path) {
  switch (t) {
    case "object": return typeof v === "object" && v !== null && !Array.isArray(v);
    case "array": return Array.isArray(v);
    case "string": return typeof v === "string";
    case "integer": return typeof v === "number" && Number.isInteger(v);
    case "null": return v === null;
    // "number"/"boolean" are NOT used by the two schemas; if they appear, the
    // default branch throws below, forcing a deliberate validator update.
    default: throw new Error(`Unsupported type '${t}' at ${path || "<root>"} — update the test validator`);
  }
}

function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return a === b;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) {
    if (a.length !== b.length) return false;
    return a.every((x, i) => deepEqual(x, b[i]));
  }
  if (typeof a !== "object") return false;
  const ka = Object.keys(a), kb = Object.keys(b);
  if (ka.length !== kb.length) return false;
  return ka.every((k) => deepEqual(a[k], b[k]));
}

function validate(schema, value, path = "") {
  const errs = [];
  if (schema === true) return errs;
  if (schema === false) { errs.push(`${path || "<root>"}: schema === false`); return errs; }
  if (typeof schema !== "object" || Array.isArray(schema)) {
    throw new Error(`Invalid schema at ${path || "<root>"}`);
  }

  // if / then / else (handled together; then/else without if is rejected below).
  if (("then" in schema || "else" in schema) && !("if" in schema)) {
    throw new Error(`'then'/'else' without 'if' at ${path || "<root>"} — update the test validator`);
  }
  if ("if" in schema) {
    const ifErrs = validate(schema.if, value, path);
    if (ifErrs.length === 0) {
      if (schema.then) errs.push(...validate(schema.then, value, path));
    } else if (schema.else) {
      errs.push(...validate(schema.else, value, path));
    }
  }

  for (const key of Object.keys(schema)) {
    if (META_IGNORE.has(key) || key === "if" || key === "then" || key === "else") continue;
    switch (key) {
      case "type": {
        const types = Array.isArray(schema.type) ? schema.type : [schema.type];
        if (!types.some((t) => { try { return matchesType(t, value, path); } catch (e) { throw e; } })) {
          errs.push(`${path || "<root>"}: expected type ${types.join("|")}, got ${actualType(value)}`);
        }
        break;
      }
      case "required": {
        if (typeof value === "object" && value !== null && !Array.isArray(value)) {
          for (const k of schema.required) {
            if (!(k in value)) errs.push(`${path ? path + "." : ""}${k}: missing required`);
          }
        }
        break;
      }
      case "additionalProperties": {
        if (schema.additionalProperties !== false) {
          throw new Error(`additionalProperties (non-false) at ${path || "<root>"} — update the test validator`);
        }
        if (typeof value === "object" && value !== null && !Array.isArray(value)) {
          const allowed = new Set(Object.keys(schema.properties || {}));
          for (const k of Object.keys(value)) {
            if (!allowed.has(k)) errs.push(`${path ? path + "." : ""}${k}: additional property not allowed`);
          }
        }
        break;
      }
      case "properties": {
        if (typeof value === "object" && value !== null && !Array.isArray(value)) {
          for (const [k, sub] of Object.entries(schema.properties)) {
            if (k in value) errs.push(...validate(sub, value[k], path ? `${path}.${k}` : k));
          }
        }
        break;
      }
      case "const": {
        if (!deepEqual(value, schema.const)) errs.push(`${path || "<root>"}: const mismatch`);
        break;
      }
      case "minLength": {
        if (typeof value === "string" && value.length < schema.minLength) {
          errs.push(`${path || "<root>"}: shorter than minLength ${schema.minLength}`);
        }
        break;
      }
      case "maxLength": {
        if (typeof value === "string" && value.length > schema.maxLength) {
          errs.push(`${path || "<root>"}: longer than maxLength ${schema.maxLength}`);
        }
        break;
      }
      case "pattern": {
        if (typeof value === "string" && !new RegExp(schema.pattern).test(value)) {
          errs.push(`${path || "<root>"}: pattern ${schema.pattern} not matched`);
        }
        break;
      }
      case "minimum": {
        if (typeof value === "number" && value < schema.minimum) {
          errs.push(`${path || "<root>"}: below minimum ${schema.minimum}`);
        }
        break;
      }
      case "items": {
        if (Array.isArray(value)) {
          if (itemsSchemaIsFalse(schema.items)) {
            if (value.length) errs.push(`${path || "<root>"}: items forbidden`);
          } else if (typeof schema.items === "object") {
            value.forEach((v, i) => errs.push(...validate(schema.items, v, `${path}[${i}]`)));
          } else {
            throw new Error(`Unsupported items shape at ${path || "<root>"}`);
          }
        }
        break;
      }
      case "allOf": {
        for (const s of schema.allOf) errs.push(...validate(s, value, path));
        break;
      }
      case "format": {
        if (schema.format === "date-time") {
          if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
            errs.push(`${path || "<root>"}: invalid date-time`);
          }
        } else {
          throw new Error(`Unsupported format '${schema.format}' at ${path || "<root>"} — update the test validator`);
        }
        break;
      }
      default:
        throw new Error(`Unsupported schema keyword '${key}' at ${path || "<root>"} — update the test validator`);
    }
  }
  return errs;
}
const itemsSchemaIsFalse = (s) => s === false;
const valid = (schema, value) => validate(schema, value).length === 0;

// --- fixtures ----------------------------------------------------------------
const alice = await createIdentity("Alice");
const bob = await createIdentity("Bob");
const aliceDoc = await publicIdentityDoc(alice);
const bobDoc = await publicIdentityDoc(bob);
const directory = { [alice.id]: aliceDoc, [bob.id]: bobDoc };
const members = [{ id: alice.id, role: "owner" }, { id: bob.id, role: "member" }];
const recipients = [
  { id: alice.id, encPublicKey: alice.enc.publicKey },
  { id: bob.id, encPublicKey: bob.enc.publicKey },
];

const eventSchema = loadSchema("schema/event.schema.json");
const identitySchema = loadSchema("schema/identity.schema.json");

const nonMessageEv = await buildEvent(alice, {
  kind: "receipt", chat_id: "c1", to: [bob.id],
  created_at: "2026-06-16T20:00:00.000Z", rnd: "r1",
  body: { note: "seen" },
});
const messageEv = await buildEvent(alice, {
  kind: "message", chat_id: "c1", to: [bob.id],
  created_at: "2026-06-16T20:05:00.000Z", rnd: "m1",
  body: { text: "hi Bob" }, recipients,
});

console.log("# real examples validate against their schema");
ok("non-message event validates", valid(eventSchema, nonMessageEv));
ok("message event validates (body.sealed)", valid(eventSchema, messageEv));
ok("identity doc validates", valid(identitySchema, aliceDoc));

console.log("# validator fails loudly on unknown keywords");
let threwOnUnknown = false;
try { validate({ type: "string", minLength: 1, uniqueItems: true }, "x"); } catch { threwOnUnknown = true; }
ok("unknown keyword 'uniqueItems' throws", threwOnUnknown);
let threwOnFormat = false;
try { validate({ type: "string", format: "email" }, "x"); } catch { threwOnFormat = true; }
ok("unknown format 'email' throws", threwOnFormat);

console.log("# drift guard: event required fields rejected by BOTH schema and verifyEvent");
const eventRequired = eventSchema.required;
for (const field of eventRequired) {
  const broken = { ...messageEv };
  delete broken[field];
  const schemaRejects = !valid(eventSchema, broken);
  const gate = await verifyEvent(broken, { directory, members });
  const gateRejects = !gate.ok;
  ok(`event missing '${field}' rejected by schema`, schemaRejects);
  ok(`event missing '${field}' rejected by verifyEvent`, gateRejects);
}

console.log("# drift guard: message without body.sealed rejected by BOTH");
const unsealed = { ...messageEv, body: {} };
ok("message without sealed rejected by schema", !valid(eventSchema, unsealed));
const unsealedGate = await verifyEvent(unsealed, { directory, members });
ok("message without sealed rejected by verifyEvent", !unsealedGate.ok);

console.log("# drift guard: identity required fields rejected by BOTH schema and verifyIdentityDoc");
const idRequired = identitySchema.required;
for (const field of idRequired) {
  const broken = { ...aliceDoc };
  delete broken[field];
  const schemaRejects = !valid(identitySchema, broken);
  const docRejects = !(await verifyIdentityDoc(broken));
  ok(`identity missing '${field}' rejected by schema`, schemaRejects);
  ok(`identity missing '${field}' rejected by verifyIdentityDoc`, docRejects);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);