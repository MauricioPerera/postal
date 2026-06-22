// Mutation audit for the SIGNATURE-VERIFICATION oracle (D11).
//
// Puntual, sin deps. Inyecta mutantes puntuales en el oráculo de firma
// (src/crypto.js::verify + src/postal.js::verifyEventSig) y corre la suite
// completa ('npm test') por mutante. Si la suite sigue VERDE con el bug
// inyectado, el mutante SOBREVIVIÓ => agujero de cobertura del oráculo.
//
// SEGURIDAD: el contenido ORIGINAL de cada archivo se guarda en memoria
// ANTES de mutar y se RESTAURA en un finally SIEMPRE. Al final se re-lee
// cada archivo tocado y se asserta byte-idéntico al original. Ningún src/
// puede quedar mutado al terminar.
//
// Uso: node test/mutation-audit.mjs   (NO está en la cadena de 'npm test').

import { execSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const LOG = join(ROOT, "test", ".mutation-audit.log");

// Cada mutante: { name, file, find, replace }.
// `find` es una subcadena EXACTA (única) que existe hoy en el archivo.
// `find`/`replace` usan \r\n donde el archivo original usa CRLF.
const MUTANTS = [
  {
    name: "crypto.verify() always true",
    file: "src/crypto.js",
    find: "  return subtle.verify(SIGN, publicKey, base64ToBytes(sigB64), utf8Bytes(message));",
    replace: "  return true;",
  },
  {
    name: "verifyEventSig accepts revoked keys",
    file: "src/postal.js",
    find: "    if (k.revoked) continue;",
    replace: "    if (false) continue;",
  },
  {
    name: "verifyEventSig ignores signature",
    file: "src/postal.js",
    find: "    if (await verify(pub, sig, payload)) return true;",
    replace: "    if (true) return true;",
  },
  {
    name: "verifyEventSig flip lower window",
    file: "src/postal.js",
    find: "      if (k.from && t < Date.parse(k.from)) continue;",
    replace: "      if (k.from && t >= Date.parse(k.from)) continue;",
  },
  {
    name: "verifyEventSig flip upper window",
    file: "src/postal.js",
    find: "      if (k.until && t >= Date.parse(k.until)) continue;",
    replace: "      if (k.until && t < Date.parse(k.until)) continue;",
  },
  {
    name: "verifyEventSig final return false -> true",
    file: "src/postal.js",
    // find con contexto único (la línea `if (await verify(...))` solo aparece
    // una vez en postal.js) para mutar SOLO el return final de verifyEventSig.
    find: "    if (await verify(pub, sig, payload)) return true;\r\n  }\r\n  return false;\r\n}",
    replace: "    if (await verify(pub, sig, payload)) return true;\r\n  }\r\n  return true;\r\n}",
  },
];

// --- helpers -----------------------------------------------------------------

// Lee como Buffer (bytes crudos) y opera con latin1 (1:1 byte<->char) para
// garantizar byte-identidad al restaurar.
function readBuf(rel) {
  return readFileSync(join(ROOT, rel));
}
function countOccurrences(str, find) {
  let i = str.indexOf(find), n = 0;
  while (i >= 0) { n++; i = str.indexOf(find, i + 1); }
  return n;
}
function tailLog(lines = 30) {
  try {
    const s = readFileSync(LOG, "utf8");
    const arr = s.split(/\r?\n/);
    return arr.slice(Math.max(0, arr.length - lines)).join("\n");
  } catch { return "(no log)"; }
}

// Corre 'npm test' desviando stdout/stderr a un log (no hereda stdio ruidoso).
// Devuelve { ok, code, err }.
function runSuite() {
  const redir = `> "${LOG}" 2>&1`;
  try {
    execSync(`npm test ${redir}`, { cwd: ROOT, stdio: "ignore", shell: true });
    return { ok: true, code: 0 };
  } catch (e) {
    return { ok: false, code: e.status ?? null, err: e };
  }
}

// --- main --------------------------------------------------------------------

const results = []; // { name, file, verdict: KILLED|SURVIVED|DRIFT, detail }
// Snapshot ORIGINAL de cada archivo tocado (para restore + verificación final).
const originals = new Map();
for (const m of MUTANTS) {
  if (!originals.has(m.file)) originals.set(m.file, readBuf(m.file));
}

let hardAbort = false;

for (const m of MUTANTS) {
  const abs = join(ROOT, m.file);
  const origBuf = originals.get(m.file);
  const origStr = origBuf.toString("latin1");

  // 1. Drift check: `find` debe aparecer EXACTAMENTE 1 vez.
  const cnt = countOccurrences(origStr, m.find);
  if (cnt !== 1) {
    results.push({
      name: m.name, file: m.file,
      verdict: "DRIFT",
      detail: `find appears ${cnt}x (expected 1) — el código drifteó, actualizar el mutante`,
    });
    hardAbort = true;
    break; // abort ruidoso: no seguir mutando
  }

  try {
    // 2. Aplicar mutante (primera ocurrencia).
    const mutatedStr = origStr.replace(m.find, m.replace);
    writeFileSync(abs, Buffer.from(mutatedStr, "latin1"));

    // 3. Correr la suite.
    const r = runSuite();
    const verdict = r.ok ? "SURVIVED" : "KILLED";
    const detail = r.ok
      ? "suite VERDE con el bug inyectado — HUECO de cobertura"
      : `suite roja (exit=${r.code})`;
    results.push({ name: m.name, file: m.file, verdict, detail });
    if (r.ok) console.log(`\n--- tail de la suite (mutante ${m.name} SOBREVIVIÓ) ---\n${tailLog(40)}\n--- fin tail ---\n`);
  } finally {
    // RESTAURA el original SIEMPRE, aunque npm test lance.
    writeFileSync(abs, origBuf);
  }
}

// --- verificación final de byte-identidad ------------------------------------
let restoreOk = true;
const restoreReport = [];
for (const [rel, origBuf] of originals) {
  const now = readBuf(rel);
  const eq = now.equals(origBuf);
  restoreReport.push(`${rel}: ${eq ? "OK (byte-idéntico)" : "DIFFERS"}`);
  if (!eq) restoreOk = false;
}

// --- reporte -----------------------------------------------------------------
const killed = results.filter((r) => r.verdict === "KILLED").length;
const survived = results.filter((r) => r.verdict === "SURVIVED");
const drift = results.filter((r) => r.verdict === "DRIFT");
const total = results.length;

console.log("\n=== D11 mutation audit — signature-verification oracle ===\n");
console.log("mutante                                              | veredicto  | detalle");
console.log("-".repeat(120));
for (const r of results) {
  console.log(`${r.name.padEnd(52)} | ${r.verdict.padEnd(10)} | ${r.detail}`);
}
console.log("-".repeat(120));
console.log(`\nResumen: ${killed}/${total} killed; ${survived.length} survived; ${drift.length} drift.`);
console.log("\nRestore (byte-identidad de src/ al terminar):");
for (const line of restoreReport) console.log("  " + line);

if (!restoreOk) {
  console.log("\nFALLO CRÍTICO: algún archivo de src/ NO quedó byte-idéntico al original.");
  process.exit(1);
}
if (hardAbort || survived.length > 0 || drift.length > 0) {
  if (survived.length > 0) {
    console.log("\nHUECOS DE COBERTURA (mutantes que SOBREVIVIERON):");
    for (const s of survived) console.log(`  - ${s.name} [${s.file}]: ${s.detail}`);
  }
  process.exit(1);
}
console.log(`\nOK: todos los mutantes murieron (${killed}/${total}) y src/ quedó intacto.`);
process.exit(0);