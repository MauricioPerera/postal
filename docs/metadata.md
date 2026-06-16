# Postal — Reducción de metadatos (análisis honesto)

El cifrado de Postal oculta el **contenido**. Este documento trata el **grafo social**:
quién habla con quién, cuándo, en qué grupo y cuánto. Es el flanco difícil, y conviene
ser tajante sobre qué se puede y qué **no**.

## Qué filtra el modo normal

Cada evento en claro lleva `from`, `to`, `chat_id`, `kind`, `created_at`, y el path
`.postal/chats/<chat_id>/events/YYYY/MM/DD/<id>.json` (existencia del chat + fecha). Los
ids de destinatario aparecen en el mapa `keys` del sobre. El host (GitHub) ve todo eso.

## Qué reduce el modo privado (`src/private.js`, probado 14/14)

Mueve **todo** el enrutado dentro del sobre cifrado. El archivo exterior solo tiene:

```json
{ "v": 1, "t": "psealed", "alg": "...", "epk": "...", "iv": "...", "ct": "...", "w": [ ... ] }
```

- **Sin `from`/`to`/`chat_id`/`created_at`/`kind`/texto** en claro.
- **Destinatarios sin id**: `w` es una lista de claves envueltas sin etiqueta; el
  destinatario encuentra la suya por *trial-unwrap*. El sobre no nombra a nadie.
- **Conteo de destinatarios oculto**: `w` se rellena con señuelos indistinguibles hasta
  un múltiplo (bucket), así el número solo filtra de forma gruesa.
- **Tamaño oculto**: el cuerpo se rellena a un bucket de longitud antes de cifrar.
- **Path opaco**: directorio = `hash(chat_id)`, nombre de archivo aleatorio, **sin fecha**.
- **Firma dentro**: el evento interno va firmado; un miembro lo verifica *tras* descifrar.

## El trade-off central (no es un bug)

Cifrar `from`/`to` rompe el **gate público de CI**: sin claves, no puede verificar firma
ni autorización. Consecuencia:

| | Modo normal | Modo privado |
|---|---|---|
| Verificación al leer (miembro, con claves) | ✅ | ✅ |
| Gate público de CI (sin claves) | ✅ firma + autz + quórum | ⚠️ solo estructura/append-only/tamaño |
| Metadatos ante el host | expuestos | reducidos |

Es decir: **privacidad de metadatos ↔ verificación pública**. No se puede tener ambas en
el mismo evento sin un tercero con claves. Elección por chat según el modelo de amenaza.

## Lo que el modo privado **NO** oculta (límite duro, sin servidor)

1. **Cadencia y volumen de commits.** GitHub registra cada commit: cuándo y cuántos. Un
   observador infiere actividad y picos de conversación aunque el contenido sea opaco.
2. **Quién empuja.** El push lo hace una cuenta autenticada; el host la ve.
3. **Existencia de un chat-tag y su volumen.** El directorio opaco agrupa eventos; su
   tamaño y crecimiento son visibles (cuántos mensajes, con qué ritmo).
4. **Conteo/tamaño aproximados.** El padding sube el coste del análisis, no lo elimina.
5. **`users/<id>.json`.** Publicar claves públicas revela qué identidades existen. En un
   modelo más estricto, las claves se distribuyen fuera de banda y no se publican.
6. **Correlación temporal.** Mensajes que aparecen juntos en el tiempo sugieren una
   conversación, aunque no se sepa entre quiénes.

Ocultar (1)–(6) requiere **cover traffic / mixnet / servidor** — y eso abandona el modelo
"solo un repo git, sin backend". Postal no lo promete.

## Recomendación

- **Chats que necesitan auditoría pública** (agentes, registros gobernados): modo normal,
  con el gate de CI.
- **Chats que necesitan ocultar el grafo**: modo privado + claves distribuidas OOB +
  asumir que cadencia/volumen siguen siendo observables.
- Para el ritmo de commits, lo único que ayuda sin servidor es **batching** (agrupar varios
  eventos por commit en horarios fijos) — reduce la resolución temporal, no la elimina.

## Batching (implementado, `src/batch.js` — probado offline + en repo real)

Mitiga el timing sin servidor:

- **Outbox local**: los eventos se acumulan y se escriben **todos en UN commit** vía la Git
  Data API (`commitFiles`). Verificado en `postal-test`: 3 eventos → 1 commit con 3 archivos,
  un solo parent.
- **Cuantización de tiempo**: `quantizeTime` redondea `created_at` (y el momento del flush) a
  la frontera del período (p. ej. 10 min). El host ve una ráfaga de N eventos en la frontera,
  no N timestamps reales.

**Qué mejora:** la resolución temporal baja de "segundo exacto por mensaje" a "ventana de N
minutos por lote", y los eventos del lote dejan de ser distinguibles por tiempo.
**Qué sigue filtrando:** que hubo un lote, su tamaño (cuántos eventos en la ventana) y la
cuenta que empujó. Es una mejora real de timing, no anonimato.
