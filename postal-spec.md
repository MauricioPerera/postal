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

Un evento puede ser de cualquier `kind` (string firmado). Kinds **reservados** con semántica especial: `member` (gobernanza), `message` (sellado). Las apps definen los suyos (`task`, `claim`, `knowledge`...). El `id` es
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

- **Firmar:** `sig = ECDSA(sign_priv, canonical(evento sin sig))`. **Canonicalización
  (normativa):** la implementación de referencia usa claves ordenadas lexicográficamente,
  recursiva, con `JSON.stringify` para primitivas. **No está fijada formalmente como JCS /
  RFC 8785 todavía** — fijarlo (y añadir vectores cross-implementación) es roadmap; hasta
  entonces, la verificación de firma es interoperable solo entre implementaciones que
  compartan exactamente esta forma canónica. La canonicalización JSON es un *footgun* clásico
  (orden de claves, unicode, números) — **ver caveat de revisión cripto en §6**.
- **Sellar (solo `message`):** el cuerpo se cifra con clave de contenido AES-256-GCM,
  envuelta por-destinatario vía ECDH **efímero-estático** (clave efímera del emisor por
  mensaje, clave **estática** del destinatario). AAD = metadatos del evento → el sobre no
  puede reubicarse a otro evento/chat. **No hay forward secrecy** respecto al destinatario:
  si su clave de cifrado (actual o en `encHistory`) se filtra, **se lee todo el historial
  sellado a ella** (ver §6).
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

## 4.2 Hash-chain por autor (orden e integridad sin confiar en el tiempo)

Cada evento puede llevar `seq` (contador por autor-y-chat, desde 0) y `prev` (hash del
evento anterior del mismo autor). Ambos van **firmados**. Así:

- El **orden** lo define la cadena (`seq`/`prev`), no el `created_at` — que es
  falsificable. **Backdatear ya no reordena la historia.**
- **Borrar un evento del medio** rompe la cadena: el sucesor declara un `prev`/`seq` que
  no casa con lo presente → `chain-gap` / `chain-prev-mismatch`.
- **Manipular un evento** cambia su hash → el `prev` del siguiente deja de coincidir; la
  alteración se propaga y se detecta.

`verifyChat` agrupa por autor, ordena por `seq` y comprueba continuidad desde 0 y los
enlaces `prev`. Probado (`test/chain.test.mjs`, 5/5): cadena válida pasa, deleción del
medio detectada, manipulación propagada, y la cadena verifica en **cualquier** orden de
entrada (el `seq` manda).

**Límite honesto:** la **truncación de la cola** (borrar los últimos eventos de un autor)
no se detecta desde dentro — no hay sucesor que los referencie. Cerrarlo requiere un
**head firmado/checkpoint** publicado por el autor (roadmap).

### Registros: modificar y borrar (`supersedes`)

Un evento puede llevar `supersedes` (id del evento que reemplaza), firmado. Esto modela un
**registro** mutable como cadena de versiones: **modificar** = añadir una versión que
supersede a la anterior; **borrar** = un evento `tombstone` que supersede la cabeza (el dato
sigue en git); **restaurar** = superseder al tombstone. El valor vigente es la cabeza no
superseded; la resolución y la autorización (solo el autor original o un admin pueden
superseder) son de capa de aplicación. Detalle: [`docs/knowledge-base.md`](docs/knowledge-base.md).

## 4.3 Orden CROSS-author (`src/order.js`)

El hash-chain (§4.2) fija el orden **dentro de un autor** sin depender del tiempo. El orden
**entre autores distintos** es otra cosa: el único campo común es `created_at`, y es
**auto-aseverado** — un miembro puede antedatarlo (dentro de la ventana de su clave) para
colarse al frente. Eso afecta a "el primer claim gana", al trail de auditoría y al historial
de chat.

`canonicalOrder(items)` define el orden canónico cross-author y es **la única fuente** que
deben usar las capas de aplicación (en vez de ordenar por `created_at` cada una):

- Si un lector respaldado por git adjunta `commitIndex` (la posición del commit que introdujo
  el evento), ordena por él. `commitIndex` **no es un campo dentro del JSON firmado** → el
  firmante no lo controla con `created_at`.
- Si no hay `commitIndex` (transporte en vivo, sin git), cae a `created_at` + `id` — el
  comportamiento histórico. `isCommitAnchored(items)` dice si el orden está anclado a commit
  o cayó al tiempo auto-aseverado, para que la app no sobrevenda la garantía.

**La FUENTE de `commitIndex`** (`src/commit-order.js`). `canonicalOrder` lo *consume*; este
módulo lo *produce* desde el único lugar que el firmante no controla — el orden en que los
commits introdujeron cada evento: `git log --reverse --diff-filter=A --name-only` →
`parseCommitAdds` mapea `path → índice de commit`, y `attachCommitIndex(items, mapa)` lo
pega a los items antes del gate. Dos fuentes, una por transporte:
`readLocalCommitIndex(dir)` corre git sobre un **clon local** (CLI / server con working copy;
argv array, sin shell). `ghCommitIndex(client)` cubre el **transporte hosted vía GitHub API**
(`src/github.js`, sin git local): camina los commits oldest-first y mapea cada path añadido a su
ordinal de commit. Como la commits API no trae los archivos en el listado, cuesta O(commits)
llamadas, así que **cachea por HEAD sha** — el walk corre una vez por commit nuevo y cada poll
intermedio es un `getHeadSha()` + cache hit. Ambas devuelven el mismo `Map(path→índice)` que
`attachCommitIndex` consume; las funciones puras son agnósticas al transporte. (A muy gran escala,
preferir stamping en escritura sobre el walk.)

**LÍMITE HONESTO (no es consenso).** El orden de commit lo controla quien commitea/pushea
(`git commit --date`, rebase, orden de merge). **Sube la barra** sobre el `created_at` libre,
pero el orden total cross-author **sin un secuenciador de confianza sigue siendo anclado al
operador, no Bizantino-seguro.** Por eso "el primer claim gana" y "historial permanente
ordenado" son **mitigados y anclados a la historia del repo**, no garantías absolutas.

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

## 5.1 Web-of-trust (atestaciones) — `src/trust.js`

Distinto del quórum de §5 (que gobierna `members.json` *dentro* de un chat): el web-of-trust
es una capa de **reputación** sobre eventos firmados, para decidir *en quién/qué confiar*
(identidades, skills, datasets...). Eventos:

- `attest`        `{ subject, claim, weight, expires }` — "el autor avala a `subject`".
- `attest-revoke` `{ subject, claim }` — cancela un aval previo (gana el último por `created_at`).

`resolveTrust(events, { roots, decay, maxDepth, now })` propaga confianza por **camino de
máxima confianza** desde unas **raíces** ancladas fuera de banda, con **decaimiento
multiplicativo** y profundidad acotada. Reglas fail-safe (probado en `test/trust.test.mjs`):

- **expiración ON por defecto** (`now` = ahora si no se inyecta reloj);
- **`weight` acotado a `[0,1]`** (un peso fuera de rango no puede invertir el decaimiento ni
  superar la raíz; se clampa y se reporta);
- **sin fail-silent**: bodies malformados se reportan en `invalid`, no se descartan callados.

**Límite honesto:** es **reputación permisionada anclada a raíces**, no anti-Sybil ni
consenso. Una clique de identidades falsas que se avalan entre sí obtiene **cero** confianza
si ninguna raíz entra en ella; su garantía es "nadie no avalado por tus raíces gana
confianza", no "los avales son objetivamente ciertos".

## 6. Non-goals / Threat model (qué Postal **no** protege)

Esto **debe** leerse antes de confiar en Postal para confidencialidad:

- **Metadatos en claro.** `from`, `to`, `chat_id`, `created_at`, `kind` y el **path del
  archivo** quedan en texto plano en git. El **grafo social** (quién habla con quién, cuándo,
  cuánto) es observable por cualquiera con acceso al repo. Postal oculta el *qué*, no el
  *quién/cuándo*. *(El "modo privado" reduce esto pero no lo elimina — ver `docs/metadata.md`.)*
- **Sin forward secrecy.** El sellado usa ECDH efímero-estático: la clave de cifrado del
  **destinatario es estática** y se conserva en `encHistory` a través de rotaciones. Si una
  clave de cifrado (actual o vieja) se filtra, **se lee todo el historial sellado a ella**. La
  rotación protege hacia adelante, no hacia atrás. No hay ratchet/PFS.
- **Canonicalización de firma no fijada.** Ver §3: aún no es JCS/RFC 8785; interop de firma y
  hash solo garantizada dentro de la misma implementación de `canonical()`.
- **Necesita revisión cripto externa.** La composición (canonicalización, nonces GCM, cadena
  de rotación, ECDH efímero-estático) **no ha sido auditada por un criptógrafo**. Los tests
  verdes cubren ataques **conocidos**; no garantizan la ausencia de los desconocidos. **No
  uses esto para confidencialidad real hasta una revisión externa.**
- **Distribución inicial de clave.** Confiar en una huella sigue siendo decisión humana OOB.
- **Modelo de escritura de git.** Cualquiera con write puede empujar; el enforcement real
  es branch-protection+Action (servidor) o verify-on-read (cliente). Elige según tu riesgo.
- **Veracidad del contenido.** Firmar prueba *quién* lo dijo, no *si es cierto*.
- **Contención adversaria por tiempo.** `created_at` lo fija el autor; ordenar "primero" entre
  autores no es seguro contra antedatado (ver `postal-coordination`).

## 7. Roadmap

- **Fijar la canonicalización** como JCS / RFC 8785 + vectores de prueba cross-implementación.
- **Revisión criptográfica externa** de toda la composición antes de uso en producción.
- Forward secrecy (ratchet) para el sellado, si se quiere PFS real.
- Firma de receipts y de eventos de membresía con doble propósito (auditoría externa).
- Head firmado / checkpoint por autor: detectar truncación de la cola del hash-chain.
- Modo privado avanzado: distribución de claves fuera de banda (no publicar en `users/`).
- Cliente HTML de un archivo que hable el protocolo (identidad, rotación, huellas OOB,
  enviar/leer con gate).

## 8. Implementación de referencia

`src/crypto.js` (primitivas), `src/postal.js` (identidad, eventos, gate),
`test/postal.test.mjs` (18/18) + 12 suites más (112 tests offline). Isomórfico:
navegador + Node, solo WebCrypto.
