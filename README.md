# Postal

> Protocolo de **eventos firmados, sellados y append-only sobre git**. Mensajería sin
> backend con un **contrato híbrido** estilo [CCDD](https://github.com/MauricioPerera/ccdd):
> lo verificable lo comprueba una máquina, lo opinable lo decide un humano.

Protocolo independiente. No hereda código previo, solo la idea de "un archivo por evento".

## Qué aporta

| | Convención (protocolos "shape-only") | **Postal** |
|---|---|---|
| Identidad | id corto aleatorio (colisiona) | **huella de clave** (ECDSA P-256) |
| Autenticidad | `signature: null` | **firma ECDSA en cada evento** |
| Confidencialidad | texto en claro | **sellado por-destinatario** (ECDH P-256 + AES-256-GCM) |
| Integridad | "shape mínimo" | **gate determinista** (esquema + firma + append-only) |
| Gobernanza | ninguna | **quórum de atestaciones** (multi-firma, implementado) |
| Integridad de la historia | — | **hash-chain por autor** (orden + anti-borrado) |
| Ciclo de vida de claves | — | **rotación + revocación** con ventana temporal |

## El contrato híbrido (CCDD)

| **Duro** — `verifyEvent`, gate automático | **Blando** — humano decide |
|---|---|
| esquema, path determinista, firma válida, autorización por rol, append-only | confiar en una clave nueva (huella OOB), admitir miembros, el contenido del mensaje |

El gate corre **al leer** (el cliente ignora lo no firmado) y **en CI** (una Action
rechaza el push inválido). Detalle: [`postal-spec.md`](postal-spec.md).

## Probarlo

```bash
npm test    # 118 passed, 0 failed  (14 suites de protocolo, offline)

# transporte real contra un repo privado de GitHub:
GH_TOKEN=$(gh auth token) GH_OWNER=<owner> GH_REPO=<repo> node test/integration.test.mjs
# 9 passed, 0 failed
```

Cubre (entre otros): identidad auto-firmada y anti-suplantación, mensaje firmado+sellado
abierto solo por destinatario, rotación/revocación de claves, hash-chain (orden +
anti-borrado), quórum de gobernanza, replay de membresía, meta firmado, CRUD por
supersesión, modo privado y batching; y el gate rechazando firma forjada, campo
manipulado, autor no-miembro, autor desconocido, sobrescritura e id no determinista.

## Transporte sobre git (verificado contra repo privado real)

`src/github.js` (Contents/Trees API) + `src/transport.js` unen protocolo y git:

- `publishIdentity` → publica tu identidad auto-firmada en `.postal/users/<id>.json`
- `postMessage` → firma + sella y commitea el evento
- `pollChat` → lista, corre el **gate al leer** (`verifyEvent`) y descifra lo tuyo

**Probado contra un repo privado real** (9/9): GitHub almacena solo eventos sellados
(`POSTAL1:`) + firmados, sin texto plano; Bob pasa el gate y descifra; Eve ve un evento
válido pero no puede leerlo; y un **evento falso con `from=Alice` firmado por otra clave
es rechazado por el gate** (`invalid-signature`) aunque esté físicamente en el repo —
git es la verdad, el cliente verifica.

## Gate en CI (required-check) — demostrado en GitHub Actions real

`src/cli.js` es el gate como comando (lee el árbol de archivos):

```bash
node src/cli.js verify [repoRoot]   # exit 0 si todo pasa, 1 si algo falla
```

`.github/workflows/postal-verify.yml` lo corre en cada push/PR. **Demostrado en
`postal-test`** con el mismo cambio rojo→verde: con un evento falso `from=Alice`
firmado por otra clave presente en el repo, el run salió **failure** (`BLOCKED — 1
invalid: …invalid-signature`); al quitar el evento falso, **success**. Con branch
protection exigiendo este check, un push que introduzca eventos inválidos no puede
mergearse — el modelo CCDD en el lado de escritura.

## Estructura

```
postal-spec.md            contrato híbrido + layout + reglas del gate
docs/                     metadata.md (privacidad) · knowledge-base.md (projector/RAG)
schema/                   JSON Schema de identidad y evento (la parte dura)
src/crypto.js             primitivas: ECDSA, ECDH, canonical JSON, fingerprint, sellado
src/postal.js             identidad, rotación, eventos firmados/sellados, hash-chain,
                          gobernanza, verifyEvent + verifyChat (gate, replay), CRUD
src/trust.js              web-of-trust compartido: attest/attest-revoke, resolveTrust (§5.1)
src/private.js            modo privado: enrutado dentro del sobre (metadatos reducidos)
src/batch.js              batching de commits + cuantización de tiempo (difumina la cadencia)
src/github.js             transporte: Contents/Trees API (isomórfico)
src/transport.js          protocolo-sobre-git: publish, post, poll (verify-on-read)
src/projector.js          índice derivado (js-doc-store + js-vector-store) de lo verificado
src/cli.js                gate como comando (verify) para CI
vendor/                   js-doc-store + js-vector-store (MIT, vendored para el projector)
test/                     14 suites, 118 tests offline + integration.test.mjs (9, repo real)
```

## Alcance honesto

Postal cifra el **contenido**, no el **grafo social** (`from`/`to`/paths siguen visibles).
Confiar en una identidad nueva sigue siendo una decisión humana fuera de banda. Firmar
prueba *quién* lo dijo, no *si es cierto*. Ver [`postal-spec.md` §6](postal-spec.md).
