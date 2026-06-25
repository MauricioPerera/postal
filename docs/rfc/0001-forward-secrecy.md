# RFC 0001 — Forward secrecy (issue #21)

Status: **ACCEPTED — implemented**. Owner chose Option C (epoch keys); shipped in
PR #27 as `pruneEncKeys` (`src/postal.js`, `test/forward-secrecy.test.mjs`). Known
follow-up: repeated prunes can over-drop history — always fail-safe (never retains a
key it should drop).

## Problem
Sealing uses ephemeral-static ECDH: the sender makes a fresh ephemeral key per
message (`newEphemeral` in `src/crypto.js`), but the recipient's encryption key is
**static** (`enc_key`, published in the user profile). If that static private key
leaks, **every past message** sealed for the recipient is decryptable — no forward
secrecy (FS) and no post-compromise security (PCS).

`rotateIdentity` rotates `enc_key` going forward, but `encHistory` deliberately
keeps old private keys so old messages stay readable — so the material that
enables retroactive decryption is retained by design.

## Constraint that shapes the options
Postal is **asynchronous, multi-writer, git-backed, sessionless**. There is no
presence, no ordered delivery channel, no per-pair session handshake. Anything that
assumes an ordered, stateful session is awkward here.

## Options

### A. X3DH + Double Ratchet (Signal-style) — strongest, worst fit
Full FS **and** PCS. But it needs per-pair session state, ordered message delivery,
and prekey bundles — all of which fight Postal's sessionless, concurrent,
git-as-mailbox model. Multi-device and out-of-order events make the ratchet state
hard to reconstruct from an append-only log. **High complexity, high risk.** Only
worth it if Postal pivots toward real-time 1:1 messaging.

### B. One-time prekeys (X3DH-lite, no ratchet)
Each identity publishes a pool of one-time prekeys; the sender consumes one to seal.
Gives FS for the first message of an exchange, no PCS, and no FS within a long
thread. **Problem:** consuming a prekey is a *mutating* op (remove-on-use) — clashes
with append-only + concurrent writers (two senders grab the same prekey). Needs
replenishment writes. Medium complexity, awkward semantics.

### C. Epoch encryption keys (recommended)
Recipient rotates `enc_key` on a schedule (e.g. weekly) using the **existing
`rotations` chain** (`keyTimeline`/`verifyIdentityDoc` already support signed key
rotation), and **deletes** the retired private key after a grace window. FS
granularity = one epoch: a key leak exposes only that epoch's messages, not all
history. Fits the current model, additive, cheap. Costs: coarse FS, no PCS, and it
**relies on recipients actually deleting** old private keys (operational, not
cryptographically enforced) — which directly contradicts today's `encHistory`
retention, so that policy would change.

### D. Do nothing — document the limit
Keep the current model; state plainly in the README that there is no FS.

## Compatibility
Any change to wrap-key derivation is **additive**: we already version the envelope
`alg` (`ECDH-P256+HKDF-SHA256+AES-256-GCM`), and `wrapKeyFor` dispatches by `alg`.
Old envelopes stay readable. So no hard break for reads; the change is in how *new*
messages are sealed and in key-lifecycle policy.

## Recommendation
**Option C (epoch keys)** as a pragmatic, protocol-aligned FS, with the limits
documented. Reserve Option A for a future real-time variant. Reject B (semantics
clash). 

## Decisions needed from the owner
1. Accept coarse (epoch-level) FS via C, or hold out for full ratchet (A)?
2. If C: epoch length, grace window, and — critically — change the `encHistory`
   retention policy to *delete* retired private keys (losing the ability to reopen
   very old messages). Is losing old-message readability acceptable for FS?
3. Threat model: are we defending against *future* key theft (C suffices) or against
   an adversary who already has the device (needs PCS → A)?
