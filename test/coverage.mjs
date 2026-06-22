// Coverage for src/ using Node's native NODE_V8_COVERAGE — zero dependencies.
//
// Strategy:
//   1. Clean a temp coverage dir (.coverage/ at repo root).
//   2. Run every test/*.mjs (except this file and mutation-audit.mjs) under
//      NODE_V8_COVERAGE=<dir> via execFileSync. A red test is reported but does
//      not stop accumulation; the script exits non-zero if any test failed.
//   3. Read every coverage-*.json dumped by V8, keep only scripts whose file://
//      url resolves inside <repo>/src/.
//   4. Per src file: function coverage (functions with >=1 range count>0 / total)
//      and approximate LINE coverage. Line coverage interprets V8 block coverage
//      with hole-subtraction: covered bytes = (union of count>0 ranges) minus
//      (union of count=0 ranges); a line is "executable" if it has any byte that
//      is non-whitespace and outside comments (strings are tracked so `//` inside
//      a string does not start a line comment); a line is "covered" if it has any
//      byte that is both executable and in the covered byte set.
//   5. Print a per-file table + an aggregate total.
//
// Run: node test/coverage.mjs   (also wired as `npm run coverage`).

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(fileURLToPath(import.meta.url), "..", "..");
const SRC = path.join(ROOT, "src");
const TEST_DIR = path.join(ROOT, "test");
const COV_DIR = path.join(ROOT, ".coverage");

// --- 1. clean coverage dir -------------------------------------------------
function cleanCovDir() {
  if (fs.existsSync(COV_DIR)) {
    for (const f of fs.readdirSync(COV_DIR)) {
      if (f.endsWith(".json")) fs.rmSync(path.join(COV_DIR, f), { force: true });
    }
  } else {
    fs.mkdirSync(COV_DIR, { recursive: true });
  }
}

// --- 2. run the suite under NODE_V8_COVERAGE -------------------------------
function listTestFiles() {
  // Excluded:
  //   coverage.mjs          — this tool
  //   mutation-audit.mjs    — opt-in mutation run (not part of `npm test`)
  //   integration.test.mjs  — credential-gated opt-in (needs GH_OWNER/GH_REPO/
  //                           GH_TOKEN; exits 2 without them), not in `npm test`
  const EXCLUDE = new Set([
    "coverage.mjs",
    "mutation-audit.mjs",
    "integration.test.mjs",
  ]);
  return fs
    .readdirSync(TEST_DIR)
    .filter((f) => f.endsWith(".mjs"))
    .filter((f) => !EXCLUDE.has(f))
    .map((f) => path.join(TEST_DIR, f))
    .sort();
}

function runSuite() {
  const files = listTestFiles();
  const failed = [];
  for (const file of files) {
    try {
      execFileSync(process.execPath, [file], {
        cwd: ROOT,
        stdio: "ignore",
        env: { ...process.env, NODE_V8_COVERAGE: COV_DIR },
        encoding: "utf8",
      });
    } catch (e) {
      failed.push(path.basename(file));
    }
  }
  return { ran: files.length, failed };
}

// --- 3. read V8 coverage dumps, filter to src/ -----------------------------
function readCoverage() {
  const dumps = fs
    .readdirSync(COV_DIR)
    .filter((f) => f.endsWith(".json"))
    .map((f) => path.join(COV_DIR, f));
  const byFile = new Map(); // abs src path -> merged ranges
  for (const dump of dumps) {
    let data;
    try {
      data = JSON.parse(fs.readFileSync(dump, "utf8"));
    } catch {
      continue;
    }
    if (!data || !Array.isArray(data.result)) continue;
    for (const entry of data.result) {
      if (!entry || !entry.url) continue;
      let abs;
      try {
        abs = path.resolve(fileURLToPath(entry.url));
      } catch {
        continue;
      }
      // keep only scripts inside <repo>/src/
      if (!abs.startsWith(SRC + path.sep)) continue;
      if (!Array.isArray(entry.functions)) continue;
      if (!byFile.has(abs)) byFile.set(abs, { functions: [], ranges: [] });
      const slot = byFile.get(abs);
      for (const fn of entry.functions) {
        slot.functions.push(fn);
        if (Array.isArray(fn.ranges)) {
          for (const r of fn.ranges) {
            if (
              r &&
              typeof r.startOffset === "number" &&
              typeof r.endOffset === "number" &&
              typeof r.count === "number"
            ) {
              slot.ranges.push({
                start: r.startOffset,
                end: r.endOffset,
                count: r.count,
              });
            }
          }
        }
      }
    }
  }
  return byFile;
}

// --- 4a. function coverage -------------------------------------------------
function functionStats(slot) {
  let total = 0;
  let covered = 0;
  for (const fn of slot.functions) {
    const ranges = Array.isArray(fn.ranges) ? fn.ranges : [];
    if (ranges.length === 0) continue;
    total++;
    if (ranges.some((r) => r.count > 0)) covered++;
  }
  return { covered, total };
}

// --- 4b. line coverage (approximate, hole-subtraction on V8 ranges) --------
// Build a per-byte "executable" mask (non-whitespace, outside comments).
function buildExecutableMask(buf) {
  const n = buf.length;
  const mask = new Uint8Array(n);
  let i = 0;
  let inBlock = false; // /* ... */
  let inLine = false; // //
  let str = 0; // 0 none, 34 ", 39 ', 96 `
  while (i < n) {
    const b = buf[i];
    const next = i + 1 < n ? buf[i + 1] : -1;
    if (inBlock) {
      if (b === 0x2a /* * */ && next === 0x2f /* / */) {
        inBlock = false;
        i += 2;
        continue;
      }
      i++;
      continue;
    }
    if (inLine) {
      if (b === 0x0a /* \n */) inLine = false;
      i++;
      continue;
    }
    if (str) {
      if (b === 0x5c /* \ */ && next !== -1) {
        i += 2; // escape: skip next
        continue;
      }
      if (b === str) {
        str = 0;
        i++;
        continue;
      }
      i++;
      continue;
    }
    // not in any comment/string
    if (b === 0x2f /* / */ && next === 0x2f) {
      inLine = true;
      i += 2;
      continue;
    }
    if (b === 0x2f /* / */ && next === 0x2a) {
      inBlock = true;
      i += 2;
      continue;
    }
    if (b === 0x22 || b === 0x27 || b === 0x60) {
      str = b;
      i++;
      continue;
    }
    if (b !== 0x09 && b !== 0x0a && b !== 0x0d && b !== 0x20) {
      mask[i] = 1; // executable byte
    }
    i++;
  }
  return mask;
}

// Line start offsets (in bytes).
function lineStarts(buf) {
  const starts = [0];
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] === 0x0a /* \n */) starts.push(i + 1);
  }
  return starts;
}

function offsetToLine(starts, off) {
  if (off <= 0) return 0;
  if (off >= starts[starts.length - 1]) return starts.length - 1;
  let lo = 0,
    hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= off) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

// Covered byte set = (union of count>0 ranges) minus (union of count=0 ranges).
function buildCoveredMask(slot, len) {
  const cov = new Uint8Array(len);
  const pos = [];
  const neg = [];
  for (const r of slot.ranges) {
    if (r.end <= r.start) continue;
    if (r.count > 0) pos.push([r.start, r.end]);
    else if (r.count === 0) neg.push([r.start, r.end]);
  }
  pos.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  // paint positive intervals
  for (const [s, e] of pos) {
    const a = Math.max(0, s);
    const b = Math.min(len, e);
    for (let i = a; i < b; i++) cov[i] = 1;
  }
  // subtract negative intervals
  for (const [s, e] of neg) {
    const a = Math.max(0, s);
    const b = Math.min(len, e);
    for (let i = a; i < b; i++) cov[i] = 0;
  }
  return cov;
}

function lineStats(slot, buf) {
  const exec = buildExecutableMask(buf);
  const cov = buildCoveredMask(slot, buf.length);
  const starts = lineStarts(buf);
  const totalLines = starts.length;
  let execLines = 0;
  let covLines = 0;
  for (let li = 0; li < totalLines; li++) {
    const s = starts[li];
    const e = li + 1 < totalLines ? starts[li + 1] : buf.length;
    let hasExec = false;
    let hasCov = false;
    for (let i = s; i < e; i++) {
      if (exec[i]) {
        hasExec = true;
        if (cov[i]) hasCov = true;
      }
    }
    if (hasExec) {
      execLines++;
      if (hasCov) covLines++;
    }
  }
  return { covLines, execLines };
}

// --- 5. report -------------------------------------------------------------
function pct(num, den) {
  if (den === 0) return null;
  return (num / den) * 100;
}

function fmt(p) {
  if (p === null) return "  -  ";
  return p.toFixed(1) + "%";
}

function main() {
  cleanCovDir();
  const { ran, failed } = runSuite();
  const byFile = readCoverage();

  // enumerate all src files so uncovered ones show up too
  const srcFiles = fs
    .readdirSync(SRC)
    .filter((f) => f.endsWith(".js"))
    .map((f) => path.join(SRC, f))
    .sort();

  const rows = [];
  let aggFcov = 0,
    aggFtot = 0,
    aggLcov = 0,
    aggLtot = 0;
  for (const abs of srcFiles) {
    const slot = byFile.get(abs);
    let fs_, ls_;
    if (slot) {
      fs_ = functionStats(slot);
      const buf = fs.readFileSync(abs);
      ls_ = lineStats(slot, buf);
    } else {
      fs_ = { covered: 0, total: 0 };
      ls_ = { covLines: 0, execLines: 0 };
    }
    const fp = pct(fs_.covered, fs_.total);
    const lp = pct(ls_.covLines, ls_.execLines);
    rows.push({
      file: path.relative(SRC, abs),
      fcov: fs_.covered,
      ftot: fs_.total,
      fp,
      lcov: ls_.covLines,
      ltot: ls_.execLines,
      lp,
    });
    aggFcov += fs_.covered;
    aggFtot += fs_.total;
    aggLcov += ls_.covLines;
    aggLtot += ls_.execLines;
  }

  const afp = pct(aggFcov, aggFtot);
  const alp = pct(aggLcov, aggLtot);

  const nameW = Math.max(8, ...rows.map((r) => r.file.length));
  const head =
    `${"archivo".padEnd(nameW)}  %funcs (cov/tot)  %líneas (cov/tot)\n` +
    `${"-".repeat(nameW)}  ${"-".repeat(15)}  ${"-".repeat(17)}`;
  console.log(head);
  for (const r of rows) {
    console.log(
      `${r.file.padEnd(nameW)}  ${fmt(r.fp).padStart(6)} (${String(r.fcov).padStart(3)}/${String(r.ftot).padStart(3)})  ${fmt(r.lp).padStart(6)} (${String(r.lcov).padStart(3)}/${String(r.ltot).padStart(3)})`,
    );
  }
  console.log(`${"-".repeat(nameW)}  ${"-".repeat(15)}  ${"-".repeat(17)}`);
  console.log(
    `${"TOTAL".padEnd(nameW)}  ${fmt(afp).padStart(6)} (${String(aggFcov).padStart(3)}/${String(aggFtot).padStart(3)})  ${fmt(alp).padStart(6)} (${String(aggLcov).padStart(3)}/${String(aggLtot).padStart(3)})`,
  );

  console.log("");
  console.log(`tests ejecutados: ${ran}  fallidos: ${failed.length}${failed.length ? " -> " + failed.join(", ") : ""}`);
  console.log(`funciones totales: ${aggFtot}, cubiertas: ${aggFcov}`);
  console.log(`líneas ejecutables (aprox): ${aggLtot}, cubiertas: ${aggLcov}`);

  // keep .coverage/ on disk (gitignored) for inspection; do not delete.
  const code = failed.length ? 1 : 0;
  process.exit(code);
}

main();