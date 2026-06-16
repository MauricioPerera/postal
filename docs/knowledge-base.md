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

## Frontera de confianza (importante)

`js-doc-store` **no verifica firmas**. Si indexas archivos crudos, indexas veneno. Por eso
el projector **solo** ingiere eventos que pasaron `verifyChat`. El índice es una **caché
derivada y desechable**; la confianza vive en Postal y se reconstruye desde git.

## Para skills

Idéntico con `kind:"skill"` (`{ name, description, version, ... }`): un catálogo de skills
**firmado, gobernado por quórum y revocable**, servible vía un bridge MCP que solo exponga
lo verificado. Es lo que el ecosistema de skills no tiene hoy: procedencia y revocación.

## Límite honesto

Solo se indexa lo que el indexador puede **leer**: contenido sellado E2EE para otros no es
indexable (la tensión metadatos/búsqueda de siempre). Para un KB consultable, el contenido
indexable va en claro (su confianza la da la firma, no el cifrado).
