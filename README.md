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
| Gobernanza | ninguna | **quórum de atestaciones** (roadmap) |

## El contrato híbrido (CCDD)

| **Duro** — `verifyEvent`, gate automático | **Blando** — humano decide |
|---|---|
| esquema, path determinista, firma válida, autorización por rol, append-only | confiar en una clave nueva (huella OOB), admitir miembros, el contenido del mensaje |

El gate corre **al leer** (el cliente ignora lo no firmado) y **en CI** (una Action
rechaza el push inválido). Detalle: [`postal-spec.md`](postal-spec.md).

## Probarlo

```bash
node test/postal.test.mjs    # 16 passed, 0 failed  (protocolo, offline)

# transporte real contra un repo privado de GitHub:
GH_TOKEN=$(gh auth token) GH_OWNER=<owner> GH_REPO=<repo> node test/integration.test.mjs
# 9 passed, 0 failed
```

Cubre: identidad auto-firmada, anti-suplantación (id≠clave rechazado), mensaje
firmado+sellado, apertura solo por destinatario, y el gate rechazando firma forjada,
campo manipulado, autor no-miembro, autor desconocido, sobrescritura e id no determinista.

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

## Estructura

```
postal-spec.md            contrato híbrido + layout + reglas del gate
schema/                   JSON Schema de identidad y evento (la parte dura)
src/crypto.js             primitivas: ECDSA, ECDH, canonical JSON, fingerprint
src/postal.js             identidad, eventos firmados/sellados, verifyEvent (gate)
src/github.js             transporte: Contents/Trees API (isomórfico)
src/transport.js          protocolo-sobre-git: publish, post, poll (verify-on-read)
test/postal.test.mjs      16 tests de protocolo (offline)
test/integration.test.mjs 9 tests contra repo privado real
```

## Alcance honesto

Postal cifra el **contenido**, no el **grafo social** (`from`/`to`/paths siguen visibles).
Confiar en una identidad nueva sigue siendo una decisión humana fuera de banda. Firmar
prueba *quién* lo dijo, no *si es cierto*. Ver [`postal-spec.md` §6](postal-spec.md).
