# Design — stealth v2: an opening with no constant to match

**Status:** draft for review (2026-10-01). Candidate for ADR 0006 once accepted.
**Scope:** opt-in second wire format for the `stealth` transport. No change to
the default `stealth` format, to any other transport, or to the tunnel's trust
model.

## Context

`stealth` is a TCP tunnel wrapped in a Noise `NNpsk0` record layer
(`internal/utils/network/noise.go`). Its reason to exist is that the content is
unreadable *and* the shape is unremarkable, so deep packet inspection has
nothing to match. The record layer already pads inside the AEAD (v1), so a
record's length on the wire says little about its payload.

The front of the connection does not yet hold to the same standard. Three tells
survive at the opening, and the opening is what an observer classifies first:

1. **A near-constant first-flight size.** The initiator's first message is a
   fixed ~49 bytes, framed by a 2-byte length, so every stealth connection opens
   with the same handful of bytes (`00 31 …`). `TestStealthHandshakeOpeningIsUniform`
   measures the byte *after* the prefix and so does not see this.
2. **A readable length prefix.** The first two bytes on the wire are a plaintext
   big-endian length that equals the count of bytes that follow — a structural
   signature independent of size.
3. **A key with a fixed bit.** The message opens with an X25519 ephemeral public
   key. A representative sample confirmed the key's top bit is always 0 (0 set in
   5000 draws, versus ~2500 expected from uniform bytes), and every value lies on
   the curve — both are distinguishers from random.

These are the standard tells the anti-censorship literature addresses for
fully-encrypted protocols: the obfs4 specification (Tor Project) and the
Elligator paper (Bernstein, Hamburg, Krasnova, Lange, 2013). This design adopts
those established techniques rather than inventing wire tricks.

## Goals

- An opening whose size, structure, and byte values are, across many
  connections, indistinguishable from a uniform random stream — no constant
  prefix, no readable length, no biased key bit.
- Opt-in and reversible. Operators who do not enable it are unaffected.
- Keyed entirely from the tunnel token, as v1 is. No new key material to
  distribute.

## Non-goals

- Traffic-shape / timing camouflage (record-size buckets, dummy records, jitter).
  That is the separate "record-size / timing shape" track and is out of scope here.
- Active-probe resistance beyond what the token-keyed handshake already provides
  (a wrong token still yields silence — unchanged).
- Protocol *mimicry* (looking like TLS/HTTP). The goal is "looks like nothing,"
  not "looks like something specific."

## Decisions locked in (from brainstorming)

| Question | Decision |
|---|---|
| What to change | The framing/obfuscation — how bytes look on the wire |
| Which tell | The opening-packet fingerprint (plus the key tells it exposes) |
| Rollout | Opt-in; both ends switch once upgraded. Old `stealth` stays byte-for-byte unchanged. May sit first in a fallback chain with old `stealth` behind it. |
| Key tells | Elligator2 representative for the ephemeral key (fixes the fixed-bit and on-curve tells in this one wire break) |
| Config surface | A distinct transport name, `stealth2`, rather than a mode flag on `stealth` |
| Elligator2 impl | A vetted third-party library (`gitlab.com/yawning/edwards25519-extra/elligator2`, by the obfs4 author); not hand-rolled |

## Architecture

The change is contained to the `network` package and the two call sites that
select a transport mode. Boundaries:

- **`network` — key encoding.** A thin `noise.DHFunc` wrapper over the existing
  `DH25519` that, on the sender, emits the ephemeral public key as its
  Elligator2 representative, and on the receiver maps the representative back to
  the point before the DH. This is the obfs4 approach. It needs a vetted
  Elligator2 implementation (see Dependencies); we do not hand-roll the field
  arithmetic. The custom DHFunc is used *only* in v2 mode; v0/v1 keep stock
  `DH25519`.

- **`network` — opening framing.** In v2 the length prefix is not sent in the
  clear. The framing is replaced by an obfs4-style arrangement in which the
  bytes that would reveal a length are masked by a keystream derived at handshake
  time, so the prefix is not a value an observer can read or a constant they can
  match. The derivation must be per-connection (a fixed per-token mask would
  still produce a constant opening for a given tunnel) — it is keyed from the
  token *and* the ephemeral key already on the wire.

- **`network` — handshake padding.** The handshake payload carries random-length
  filler inside the AEAD (extending v1's payload-padding idea to the handshake),
  so first-flight size varies instead of being constant. Filler stays inside the
  AEAD, per the file's existing rule: padding an observer can subtract is not
  padding.

- **`config` + transport selection.** v2 is a distinct mode behind a config
  flag, negotiated nowhere on the wire — both ends are told to use it. The
  constructors (`NoiseClientConn`/`NoiseServerConn`, and the `Stealth` flags in
  `client/transport/tcp.go` and `server/transport/tcp.go`) gain a variant
  selector; `direct/session.go` passes it through.

Everything above the record layer — the token proof, the mux, the control loop —
is unchanged. v2 is purely a different skin on the same bytes.

## Wire format (v2), descriptively

- **First flight:** the Elligator2 representative of the ephemeral key (uniform
  bytes, no fixed bit), followed by AEAD-protected payload that carries the
  version marker and random-length filler. No cleartext length precedes it.
- **Framing of subsequent records:** length information is carried under the
  per-connection keystream rather than as a readable big-endian prefix; record
  bodies remain the v1 ChaCha20-Poly1305 records, including the existing inside-
  the-AEAD payload padding.
- **Ceilings:** the per-record plaintext ceiling is reduced as needed to keep the
  encoded record within the existing `noiseMaxFrame`, the same way v1 reserved
  space for its padding header.

Byte-level field layouts are deferred to the implementation plan; this document
fixes the properties, not the offsets.

## Negotiation, config, and rollout

- v2 is a **distinct transport name, `stealth2`**, selected like any other
  transport rather than a sub-flag on `stealth`. It joins the transport enums
  (`reverseTransports`, `fallbackCapable`, and every place a transport name is
  switched on). Validation lives beside the existing transport checks in
  `config/`. Chosen over a `stealth`+mode flag because it drops straight into the
  fallback chain and the existing selection code with no new concept — at the
  cost of adding a name everywhere transports are enumerated, which the
  source-reading parity tests already guard.
- No wire negotiation: v2 is incompatible with v0/v1 by construction (an old
  peer reads the first two bytes as a length and fails). This is why both ends
  must be set. Documented alongside the flag.
- **Fallback interaction:** `stealth2` is a distinct chain candidate. A chain of
  `[stealth2, stealth]` lets an operator prefer the hardened opening and fall
  back to today's format where the far end is older — consistent with
  `config/fallback.go`'s existing model. `ValidateFallbackTransports` must treat
  the two as distinct entries.
- **Compatibility stance:** this honours ADR 0005 / ADR 0001 — nothing on the
  default wire changes, mixed versions keep working, and the new behaviour waits
  on both ends opting in rather than being forced by an upgrade.

## Dependencies

- A vetted Elligator2 implementation for Curve25519 — **chosen:**
  `gitlab.com/yawning/edwards25519-extra/elligator2` (by the obfs4 author, used
  in production circumvention tooling). We do not implement the field arithmetic
  ourselves; a mistake there is a silent distinguisher, which is the whole thing
  we are removing. The first plan step pins the version against Go 1.26.6 and
  confirms its current API — this environment has no Go toolchain, so that
  verification happens where one is available.

## Security considerations

- **Keystream reuse.** The opening keystream must be unique per connection, or
  two connections of one tunnel open identically — reintroducing the constant.
  Derivation binds the token and the on-wire ephemeral key; the derivation and
  its uniqueness get a dedicated test.
- **No weakening of the channel.** Elligator2 changes only how the public key is
  *encoded* on the wire, not the DH or the AEAD. The `NNpsk0` guarantees
  (mutual auth as "holds the token", forward secrecy, silence to a wrong token)
  are unchanged, and the token proof still runs on top.
- **Downgrade.** Because selection is out-of-band config, there is no on-wire
  negotiation for an observer to strip to force v1. A fallback chain that lists
  v1 behind v2 is an operator's explicit choice, not an attacker's.

## Testing strategy (TDD; write the property tests first)

- **Opening uniformity, extended.** A sampling test over many connections
  asserting: first-flight *sizes* take many distinct values (today: one); the
  first on-wire byte ranges over the whole space with no dominant value; and the
  key-position bytes show no fixed bit. This is the regression guard for all
  three tells and should fail against the v1 opening.
- **Representative round-trip.** Encode→decode of the ephemeral key is identity,
  and the decoded point drives a successful DH (property/fuzz over many keys).
- **v2 round-trip, both directions**, including a record carrying no payload.
- **Isolation.** v0/v1 peers are untouched: the existing `noisepad_test.go` /
  `noise_test.go` legacy-peer tests must still pass, and a v2 end must *fail
  cleanly* against a v1 end (no corruption, no hang) — proving the "both ends
  must switch" contract.
- **Fuzz** the v2 frame reader (extend `frame_fuzz_test.go`) against truncation
  and garbage.
- **Alloc / race.** Keep the per-record no-allocation guarantee
  (`noisealloc_test.go`) and run the suite under `-race`.
- **e2e.** Add a v2-stealth row to the transport matrix (`internal/e2e`).

## Open questions

1. ~~Elligator2 library choice~~ — **resolved:**
   `gitlab.com/yawning/edwards25519-extra/elligator2`, added to `go.mod`.
   Version pinned and API confirmed as the first plan step.
2. ~~Config surface~~ — **resolved:** a distinct transport name, `stealth2`.
3. **ADR (follow-up)** — distil the accepted version into `docs/adr/0006-*` and
   add a row naming `stealth2` to ADR 0004's ingress table (opening
   timing/bounds are unchanged).
