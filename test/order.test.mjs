// Tests for canonical cross-author ordering (src/order.js).
import { canonicalOrder, isCommitAnchored } from "../src/order.js";

let p = 0, f = 0;
const ok = (n, c) => { if (c) { p++; console.log("  ok  - " + n); } else { f++; console.log("  FAIL - " + n); } };
const ids = (arr) => canonicalOrder(arr).map((i) => (i.event || i).id).join();

console.log("# back-compat: sin commitIndex, orden por created_at (id desempata)");
const a = { event: { id: "x", created_at: "2026-01-02T00:00:00Z" } };
const b = { event: { id: "y", created_at: "2026-01-01T00:00:00Z" } };
ok("ordena por created_at ascendente", ids([a, b]) === "y,x");
ok("desempata por id cuando created_at es igual",
   ids([{ event: { id: "b", created_at: "T" } }, { event: { id: "a", created_at: "T" } }]) === "a,b");

console.log("# seguridad: commitIndex manda sobre un created_at antedatado");
const honest = { commitIndex: 0, event: { id: "h", created_at: "2026-01-02T00:00:00Z" } };   // commit primero, fecha posterior
const backdated = { commitIndex: 1, event: { id: "e", created_at: "2026-01-01T00:00:00Z" } }; // commit despues, fecha ANTEDATADA
ok("el antedatado NO se cuela al frente: gana el orden de commit", ids([backdated, honest]) === "h,e");

console.log("# isCommitAnchored");
ok("true cuando todos los items tienen commitIndex", isCommitAnchored([honest, backdated]) === true);
ok("false si a alguno le falta", isCommitAnchored([honest, a]) === false);
ok("false en lista vacia", isCommitAnchored([]) === false);

console.log("# detalles");
ok("lee commitIndex puesto en el evento crudo (no solo en el wrapper)",
   ids([{ id: "w", created_at: "2026-01-01T00:00:00Z" }, { id: "z", created_at: "2026-01-03T00:00:00Z", commitIndex: -1 }]) === "z,w");
const inp = [a, b]; canonicalOrder(inp);
ok("no muta el input", inp[0] === a && inp[1] === b);

console.log(`\n${p} passed, ${f} failed`);
if (f) process.exit(1);
