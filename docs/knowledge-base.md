# Postal como banco de conocimiento confiable para agentes

Postal responde **"¿puedo confiar en esto?"** (firma, gate, hash-chain, revocación,
quórum). No responde **"¿cuál es el doc relevante, rápido?"** — no tiene índice. Esa
mitad la pone [`js-doc-store`](https://github.com/MauricioPerera/js-doc-store) (queries,
índices) y `js-vector-store` (semántica). El **projector** (`src/projector.js`) es el
pegamento.

## Arquitectura (es la filosofía "git es la verdad, lo demás es caché")

```
publicar hecho/skill  →  evento Postal FIRMADO (kind: knowledge | skill)
        │
        ▼
   gate (verifyChat): firma + autorización (miembro) + cadena + ventana de clave + quórum
        │  SOLO lo verificado
        ▼
  projector  →  colección js-doc-store (índices hash/text) [+ js-vector-store]
        │           cada doc lleva PROCEDENCIA: publisher, event_id, verified
        ▼
   agente consulta el índice (rápido) y puede CITAR la fuente
        │
        └─ revocan una clave / cae un publisher  →  reproyectar  →  sus docs desaparecen
```

## Garantías demostradas (`test/projector.test.mjs`, 9/9)

- **Solo entra lo verificado.** El projector corre el gate y proyecta únicamente los
  eventos válidos. Un evento `knowledge` **falsificado** (Mallory firma con su clave
  reclamando `from=Alice`) **es rechazado y nunca llega al índice** → anti-poisoning real.
- **Procedencia en cada resultado.** Todo doc indexado lleva `publisher`, `event_id`,
  `verified:true` → el agente sabe quién lo afirmó y puede citarlo.
- **Supersesión.** La cadena (`seq`) resuelve versiones: la consulta por clave devuelve la
  última versión válida.
- **Revocación efectiva.** Al revocar la clave de un publisher y reproyectar, su
  conocimiento **desaparece** del índice; el de los publishers confiables permanece.
- **Consulta real.** `findByKey`, `search` (índice de texto), `byPublisher`, `skills`.

## Modificar y borrar registros (append, nunca editar bytes)

Un **registro** es una `key` con una cadena de versiones enlazadas por `supersedes` (id de
la versión que reemplaza). "Modificar" = **añadir** una versión nueva firmada que supersede
a la anterior; el valor actual es la **cabeza** (la versión que nadie supersede). "Borrar" =
un evento `kind:"tombstone"` que supersede a la cabeza → el registro desaparece del índice
pero **sigue en git**. "Restaurar" = superseder al tombstone.

**Autorización** (probado en `test/update.test.mjs`, 8/8): solo el **autor original** del
registro o un **owner/admin** (override de gobernanza) pueden superseder. Un intento de un
tercero **se ignora** y el valor anterior permanece. Concurrencia optimista: un update debe
apuntar a la cabeza vigente; los *forks* se marcan como conflicto.

Esto es la "máquina del tiempo" confiable: todas las versiones existen como eventos
**firmados** (git guarda los bytes; el hash-chain detecta reescrituras), y el valor vigente
es una **proyección** de la cadena de versiones válidas.

## Frontera de confianza (importante)

`js-doc-store` y `js-vector-store` **no verifican firmas** ni deciden confianza: son store
puro. Si indexas archivos crudos, indexas veneno. Por eso el projector **solo** ingiere
eventos que pasaron `verifyChat`. El índice es una **caché derivada y desechable**; la
confianza vive en Postal y se reconstruye desde git.

> **Auditoría de la frontera (fuente, no afirmación).** Se verificó contra el árbol de ambas
> dependencias vendored que ninguna verifica firmas ni ejecuta código desde datos (sin
> `eval`/`Function`/`$where`). Dos *caveats genéricos* para consumidores que vayan **más allá
> del uso de Postal** (Postal no los toca):
> - **js-doc-store**: el operador `$regex` compila `new RegExp(value)` → posible ReDoS si una
>   app pasa input **no confiable** a un `$regex`. El projector usa `$text`/igualdad, no esto.
> - **js-vector-store**: la clase **`Reranker`** (opt-in) hace `fetch` a una API externa,
>   enviándole el texto del query y de los candidatos. Para datos sensibles es una fuga hacia
>   ese proveedor. El projector **no** instancia `Reranker` ni hace red (todo en memoria).

## Para skills

Idéntico con `kind:"skill"` (`{ name, description, version, ... }`): un catálogo de skills
**firmado, gobernado por quórum y revocable**, servible vía un bridge MCP que solo exponga
lo verificado. Es lo que el ecosistema de skills no tiene hoy: procedencia y revocación.

## Límite honesto

Solo se indexa lo que el indexador puede **leer**: contenido sellado E2EE para otros no es
indexable (la tensión metadatos/búsqueda de siempre). Para un KB consultable, el contenido
indexable va en claro (su confianza la da la firma, no el cifrado).

## Búsqueda semántica (RAG) — `js-vector-store`

El projector también construye un **índice vectorial** en paralelo: cada conocimiento
verificado se embebe y se indexa con su procedencia, y `semanticSearch(texto)` rankea por
coseno. Probado (`test/vector.test.mjs`, 7/7): una consulta ("animales mamíferos
domésticos") rankea los docs de animales sobre el de motores; el **veneno falsificado nunca
entra** al índice vectorial; revocar un publisher **elimina sus vectores** al reproyectar.

El embedder es **enchufable** (`makeProjector({ embed })`). Por defecto trae uno local
determinista (overlap léxico) para correr offline; en producción se pasa un modelo real
(`js-vector-store` ya soporta cuantización, IVF, BM25 híbrido, reranker). La regla con
Postal no cambia: **solo se vectoriza lo que pasa el gate**. El embedder por defecto es un
*placeholder* léxico, no semántico real — eso lo aporta el modelo que se enchufe.
