# Postal — Protocol Spec v1 (draft)

> Eventos **firmados, sellados y append-only** sobre git. Mensajería (y coordinación
> de agentes) sin backend, donde **lo verificable lo comprueba una máquina y lo
> opinable lo decide un humano**.

Postal es un **contrato de contexto híbrido** al estilo
[CCDD](https://github.com/MauricioPerera/ccdd): el repositorio git es la fuente de
verdad; cada archivo es un evento; un **gate determinista** (`verifyEvent`) separa lo
que se *verifica* de lo que se *juzga*. No hereda nada de implementaciones previas más
que la idea de "un archivo por evento".

## 0. Principios

1. **Git es la verdad.** Todo lo demás (índices, caché) se reconstruye.
2. **Un evento = un archivo JSON inmutable.** Sin edición ni borrado in-place.
3. **Identidad = clave, no nombre.** El `id` es la huella de la clave de firma.
4. **Todo evento va firmado.** Sin firma válida, el gate lo descarta.
5. **El contenido va sellado.** El cuerpo de un mensaje se cifra por-destinatario.
6. **Híbrido CCDD:** lo duro a un gate, lo blando a una persona (ver §4).

## 1. Layout del repositorio

```text
.postal/
  protocol.json                                  # metadatos del protocolo
  users/<id>.json                                # identidad pública (auto-firmada)
  chats/<chat_id>/meta.json                      # creador + governance (FIRMADO)
  chats/<chat_id>/members.json                   # caché derivada (se reconstruye por replay)
  chats/<chat_id>/events/YYYY/MM/DD/<id>.json    # mensajes, recibos, cambios
```

Un evento puede ser `kind`: `message`, `receipt` o `member`. El `id` es
`<created_at con :. → ->_<from>_<rnd>`, así el **path es determinista** y verificable
sin abrir el archivo.

## 2. Identidad (`users/<id>.json`)

Cada identidad tiene **dos** claves P-256:

- **sign** (ECDSA P-256) → autenticidad. El `id` = primeros 64 bits de `SHA-256(sign_pub)`.
- **enc** (ECDH P-256) → confidencialidad (sellado por-destinatario).

```json
{
  "v": 1,
  "id": "A1B2C3D4E5F60718",
  "display_name": "Alice",
  "sign_key": { "alg": "ECDSA-P256", "pub": "<base64 raw>" },
  "enc_key":  { "alg": "ECDH-P256",  "pub": "<base64 raw>" },
  "sig": "<auto-firma ECDSA sobre el doc canónico sin sig>"
}
```

`verifyIdentityDoc` comprueba (HARD): el `id` ancla a la **clave génesis**, la cadena de
`rotations` está intacta y la auto-firma de la clave actual es válida → **nadie puede
reclamar un id que no corresponde a su cadena de claves**. *Confiar* en que esa identidad
es quien dice ser es SOFT: se verifica la `humanFingerprint` (de la clave génesis, estable)
fuera de banda (TOFU).

### Rotación de clave (el `id` no cambia)

El `id` ancla a la clave génesis, así que rotar la clave de firma/cifrado **no cambia el
id**. La identidad lleva una cadena `rotations`, donde cada entrada va **firmada por la
clave anterior**:

```json
"rotations": [
  { "seq": 1, "from_sign_pub": "<clave previa>", "to_sign_pub": "<clave nueva>",
    "to_enc_pub": "<enc nueva>", "created_at": "...", "sig": "<firma de la clave previa>" }
]
```

`verifyIdentityDoc` recorre la cadena: cada `from_sign_pub` encadena con el `to_sign_pub`
anterior (génesis al inicio), cada `sig` valida con la clave previa, y las claves actuales
del doc son el final de la cadena. Probado (`test/rotation.test.mjs`, 11/11): id estable,
cadena verificada, **secuestro rechazado** (rotación no firmada por la clave previa),
eventos firmados con una clave **antigua** siguen validando, y un mensaje sellado a una
clave de cifrado vieja se abre con `encHistory`.

**Ventana temporal y revocación** (`test/revocation.test.mjs`, 7/7): cada clave tiene una
ventana `[activa_desde, retirada_en)` derivada de la cadena. Una firma solo vale si el
`created_at` del evento cae en la ventana de la clave que firmó:

- **Rotación graceful:** la clave vieja solo firma eventos **fechados antes** de su
  rotación; un evento posterior firmado con ella se rechaza.
- **Rotación con `reason:"compromise"`:** la clave vieja queda **revocada para todo**
  evento, incluso uno **backdated** — porque una clave comprometida pudo fabricar fechas
  falsas. Solo la clave nueva (actual) sigue válida.

## 2.1 Meta del chat (`meta.json`, firmado)

`meta.json` define el **owner génesis** (`created_by`) y la **política de gobernanza**
(`governance`). Como el gate confía en esos dos campos, va **firmado por el creador** y el
`chat_id` **ancla al creador**: `chat_id = c_<created_by>_<rnd>`. Así nadie puede forjar un
meta con otro `created_by` para un chat ajeno.

```json
{
  "v": 1, "id": "c_<owner>_<rnd>", "title": "Familia",
  "created_by": "<owner id>", "created_at": "...",
  "governance": { "set_role": 3 },
  "sig": "<firma del owner sobre canonical(meta sin sig)>"
}
```

`verifyChatMeta` (HARD): forma, `id` == nombre del directorio, `chat_id` contiene
`created_by`, el creador existe en el directorio, y la firma valida (con ventana de clave).
Probado (`test/meta.test.mjs`, 7/7): cambiar `created_by`, `governance` o `title` rompe la
verificación; un `chat_id` que no embebe al creador se rechaza; un creador sí puede crear un
chat bajo su propio id. El gate de CI toma `created_by`/`governance` **solo** de un meta que
pase esta verificación.

## 3. Evento firmado (y, si es mensaje, sellado)

```json
{
  "v": 1,
  "kind": "message",
  "chat_id": "c1",
  "from": "A1B2C3D4E5F60718",
  "to": ["B0B0..."],
  "created_at": "2026-06-16T20:00:00.000Z",
  "id": "2026-06-16T20-00-00-000Z_A1B2..._a1b2c3",
  "body": { "sealed": "POSTAL1:<base64 del sobre cifrado>" },
  "sig": "<ECDSA sobre canonical(evento sin sig)>"
}
```

- **Firmar:** `sig = ECDSA(sign_priv, canonical(evento sin sig))`. La serialización
  canónica (claves ordenadas, recursiva) garantiza bytes idénticos para objetos iguales.
- **Sellar (solo `message`):** el cuerpo se cifra con clave de contenido AES-256-GCM,
  envuelta por-destinatario vía ECDH efímero (forward secrecy). AAD = metadatos del
  evento → el sobre no puede reubicarse a otro evento/chat.
- **Orden:** se **sella y luego se firma**: la firma cubre el ciphertext + metadatos.
  Cualquiera verifica la firma (público); solo los destinatarios abren el sobre.

## 4. El contrato híbrido (CCDD)

| Parte **dura** — `verifyEvent`, gate determinista | Parte **blanda** — humano (modelo informa, no decide) |
|---|---|
| Esquema del evento (shape, tipos, `v==1`) | **Confiar** en una identidad nueva (huella OOB) |
| **Path determinista** desde `created_at`+`from` | Admitir a un **miembro** nuevo |
| **Firma ECDSA** válida contra la clave publicada | **Contenido** del mensaje (texto: no se "verifica verdad") |
| **Autorización**: `from` ∈ `members` con rol válido | `display_name` (cosmético, no confiable) |
| **Append-only**: el path no existía | Moderación / política del chat |
| Sobre de cifrado bien formado | Cambios de política razonables |

**Regla de oro:** lo verificable → gate automático (exit≠0 lo bloquea); lo opinable →
una persona. El gate corre en **dos** sitios:

1. **Al leer (cliente):** git es la verdad; un evento que no pasa el gate se **ignora**.
2. **En CI (gate de git):** una GitHub Action + branch protection **rechaza** el push
   que introduce eventos inválidos. (Modelo análogo al `ccdd diff` required-check.)

## 4.1 Replay de membresía (sin confiar en un snapshot)

La autorización y el quórum dependen de la membresía **en el momento** de cada evento.
En vez de fiarse de un `members.json` (que podría estar obsoleto o ser falsificado), el
gate **reconstruye** la membresía: arranca del owner génesis (`meta.json.created_by`) y
aplica cada evento `member` **válido** en orden cronológico (`created_at`, desempate por
`id`). Cada evento se verifica contra la membresía vigente en su posición temporal —
`verifyChat(items, { directory, genesisOwner, governance })`.

**Regla de bootstrap:** `add` tiene quórum 1, así el owner génesis puede incorporar a los
primeros admins directamente (`op:"add", role:"admin"`); **promover** a un miembro
existente (`set_role`) exige el quórum completo. Evita el deadlock de un solo owner.

Probado (`test/replay.test.mjs`, 5/5): un mensaje de alguien aún no añadido se rechaza
(`author-not-member`); la línea temporal correcta (añadir → promover) replica limpio; el
owner solo arranca añadiendo un admin (quórum 1) pero no puede `set_role` solo (quórum 2).
`members.json` queda como **caché derivada**, no como fuente de verdad.

## 5. Gobernanza (quórum) — eventos `member`

Cambios sensibles son eventos `kind:"member"` con `body.op` ∈ `add` | `remove` |
`set_role`, que requieren **K atestaciones** (firmas ECDSA de owners/admins
existentes). El gate cuenta **aprobadores distintos autorizados** = el proponente (si
es owner/admin) más cada `attestation.by` cuya firma valida sobre el payload canónico.
Política por defecto: `{ add: 1, remove: 2, set_role: 2 }`, sobreescribible en
`meta.json.governance`. **Implementado y probado** (`test/governance.test.mjs`, 9/9):

- una sola aprobación es rechazada para `set_role` (`insufficient-quorum`);
- proponente + atestación de admin lo aprueba;
- una atestación de un id **no autorizado** no cuenta;
- una atestación **con la clave equivocada** no cuenta;
- `op` desconocido se rechaza.

El proponente y todos los atestadores firman el mismo **payload canónico** (`signedView`:
el evento sin `sig` ni `attestations`), así añadir atestaciones nunca invalida la firma
del autor.

```json
{
  "v": 1, "kind": "member", "chat_id": "c1",
  "from": "<proponente>", "to": [], "created_at": "...", "id": "..._...",
  "body": { "op": "set_role", "target": "<id>", "role": "admin" },
  "attestations": [ { "by": "<admin id>", "sig": "<ECDSA sobre signedView>" } ],
  "sig": "<firma del proponente sobre signedView>"
}
```

## 6. Alcance honesto (qué Postal **no** hace)

- **Metadatos expuestos.** `from`/`to`/`created_at` y la estructura de paths son visibles
  para quien tenga acceso al repo. Postal cifra el *contenido*, no el *grafo social*.
- **Distribución inicial de clave.** Confiar en una huella sigue siendo decisión humana OOB.
- **Modelo de escritura de git.** Cualquiera con write puede empujar; el enforcement real
  es branch-protection+Action (servidor) o verify-on-read (cliente). Elige según tu riesgo.
- **Veracidad del contenido.** Firmar prueba *quién* lo dijo, no *si es cierto*.

## 7. Roadmap

- Firma de receipts y de eventos de membresía con doble propósito (auditoría externa).
- Modo privado avanzado: distribución de claves fuera de banda (no publicar en `users/`).
- Cliente HTML de un archivo que hable el protocolo (identidad, rotación, huellas OOB,
  enviar/leer con gate).

## 8. Implementación de referencia

`src/crypto.js` (primitivas), `src/postal.js` (identidad, eventos, gate),
`test/postal.test.mjs` (16/16). Isomórfico: navegador + Node, solo WebCrypto.
