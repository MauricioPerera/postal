# RFC 0002 — Metadata privacy / social graph (issue #22)

Status: **ACCEPTED — implemented**. Owner chose A+B; shipped in PR #28
(`buildEvent` seals anonymously by default + omittable `to`; `openMessage` opens
both formats). Sender anonymity (C) remains a non-goal. Reminder: full social-graph
privacy still requires a private/access-controlled repo.

## Problem
Postal encrypts message **content** but not **metadata**. In cleartext:
- `from`, `to`, `created_at`, `chat_id` on every event;
- the file path `.postal/chats/<chat>/events/<Y>/<M>/<D>/<id>.json` (chat + date);
- `sealForRecipients` labels the envelope `keys: { <recipientId>: ... }`, naming
  exactly who can read each message.

Anyone with read access to the repo reconstructs the social graph (who talks to
whom, when). `sealAnonymous` already exists (unlabeled wrap array + decoys + size
padding) and removes the recipient labels, but it is **not the default** and the
event still carries `to`/`from`/`created_at`.

## The transport reality (decides scope)
The data lives in a **Git repo (GitHub)**. GitHub — and anyone who can read the
repo — sees commit author, commit timestamps, and file paths **regardless of what
the protocol does**. So protocol-level metadata hiding is undermined unless the
repo itself is access-controlled (private repo, restricted collaborators). Some of
this is **out of protocol scope** and must be stated honestly.

## Options (composable)

### A. Make anonymous sealing the default
Use `sealAnonymous` for message bodies by default. Removes the explicit recipient
labels from the envelope. **Necessary but not sufficient** — `to` in the event
still lists recipients.

### B. Make `to` omittable (trial-decrypt routing)
Drop/omit `to`; recipients find their message by trial-unwrap (already how
`sealAnonymous`/`openAnonymous` work). **Catch:** the message AAD currently binds
the sealed body to the sorted `to` (`buildEvent`), and the signature covers `to`.
Removing it changes the AAD/signing scheme (a versioned change) and slightly weakens
context binding. Authorization/membership do **not** depend on `to`, so it is
feasible. Medium change, touches the gate's AAD.

### C. Hide the sender (`from`) — NOT recommended
The signature must verify against the author's published key, so the verifier needs
to know who signed. True sender anonymity needs ring/group signatures — heavy,
exotic, and at odds with the "humans verify fingerprints" trust model. **Out of
scope.**

### D. Coarsen timestamps — marginal
`created_at` drives ordering, key-time windows, and the path. Could bucket to the
day, but the path already exposes the date and ordering now leans on commit position
(RFC-independent work already landed). Low value.

## Compatibility
A + B change the event shape (optional `to`) and the default `alg` → a **breaking
change** for readers expecting `to`; needs a version bump and a read path that
accepts both shapes.

## Recommendation
1. **A** — anonymous sealing by default (low risk, real metadata reduction).
2. **B** — make `to` optional with trial-decrypt, behind a version bump.
3. **Reject C** (sender anonymity) as disproportionate.
4. **Document loudly** that sender identity, timing, and the existence/size of
   traffic are **not** hidden, and that the Git host sees commit metadata — so
   metadata privacy ultimately depends on a **private, access-controlled repo**.

## Decisions needed from the owner
1. Accept a **breaking change** (version bump) to make anonymous sealing + optional
   `to` the default? Or keep them opt-in and just document?
2. Is the threat model "hide content from repo readers" (current crypto already
   does this) or "hide the social graph from repo readers" (needs A+B **and** a
   private repo)? The latter is only achievable with transport-level access control.
3. Confirm sender anonymity (C) is explicitly a non-goal.
