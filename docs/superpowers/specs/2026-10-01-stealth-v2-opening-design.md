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
| Elligator2 impl | Vendor yawning's `x25519ell2` (GPL-3.0, compatible with our AGPL-3.0; both directions, ~180 LOC + its own test); deps `filippo.io/edwards25519` + `edwards25519-extra`. Not hand-rolled, not reimplemented from memory |
| Opening framing | obfs4-style mark/MAC (`m \| P \| M \| MAC`), token-keyed; no wire length. Data phase keeps channel-binding-keyed length masking. See "v2 opening framing" |

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

- **First flight:** an obfs4-style `m | P | M | MAC` frame (see "v2 opening
  framing" below). `m` is the Noise NNpsk0 message (Elligator-uniform `e` +
  fixed-length AEAD payload), `P` random padding, `M` a token-keyed mark that
  delimits `P`, `MAC` a token-keyed tag. No length, type, or constant on the
  wire — only random-looking bytes, located by a peer holding the token.
- **Framing of subsequent records:** length information is carried under the
  per-connection keystream rather than as a readable big-endian prefix; record
  bodies remain the v1 ChaCha20-Poly1305 records, including the existing inside-
  the-AEAD payload padding.
- **Ceilings:** the per-record plaintext ceiling is reduced as needed to keep the
  encoded record within the existing `noiseMaxFrame`, the same way v1 reserved
  space for its padding header.

Byte-level field layouts are deferred to the implementation plan; this document
fixes the properties, not the offsets.

## v2 opening framing (obfs4-style mark/MAC)

The opening cannot carry a readable length — the first bytes have only the
static token as shared key material. We adopt the obfs4 handshake framing (Tor
Project), keyed by the token in place of obfs4's server-identity/node-id.

**Key (both ends, from the token):**
`markKey = HKDF-SHA256(token, "backpack-stealth2-mark-v1", 32)`.

**Each handshake message `m`** — a raw Noise NNpsk0 message produced over the
Elligator suite from Task 1, so `e` is a uniform representative and, because the
Noise payload is a *fixed* length (the version byte; all size variation lives in
`P`), `len(m)` is a protocol constant both ends know — is sent as:

```
m | P | M | MAC
```

- `P` — random padding, length drawn in `[0, maxPad]`, bounding the whole first
  flight to `maxOpening` (obfs4 uses 8192 bytes).
- `M` (mark) = `HMAC-SHA256-128(markKey, m)` — 16 bytes.
- `MAC` = `HMAC-SHA256-128(markKey, m | P | M | E)` — 16 bytes, where
  `E = floor(unixtime / 3600)` (epoch hour), binding the frame loosely to the
  clock.

**Receiver:** reads the known constant `len(m)` bytes as `m`, computes
`M = HMAC(markKey, m)`, scans the following bytes (bounded by `maxOpening`) for
`M` to find where `P` ends, then verifies `MAC` over `m | P | M | E`, accepting
`E` and `E ± 1` for clock skew. On any failure it writes nothing back — the
dead-port property holds: a wrong token gives a wrong `markKey`, the mark is
never found, and a probe sees an unresponsive port.

**Replay:** the receiver keeps a short-lived, **bounded** filter of seen `MAC`s
within the epoch window (as obfs4 does), rejecting a replayed opening. This is
**included** (decided 2026-10-01), not deferred: without it a censor who
captures one genuine opening can replay it and observe the server answer —
confirming the endpoint by active probing, the exact attack this transport
exists to resist. The filter is bounded in size and time (per ADR 0004's rule
that an unproven peer holds only a bounded share and cannot evict a genuine
one), so the replay memory itself cannot be flooded to push out real entries.
The inner NNpsk0 + token proof still gate session establishment on top.

**Why it works:** `e` is Elligator-uniform, `P` is random, `M` and `MAC` are
HMAC outputs — the whole first flight is bytes indistinguishable from random, of
a size that varies with `P`, with nothing structural on the wire. Only a peer
holding the token can even locate the mark.

**Data phase.** The mark/MAC framing covers only the handshake. Once the Noise
handshake completes, both ends share the channel binding, so data records use
the Noise ChaCha20-Poly1305 record layer with the 2-byte length prefix masked by
a ChaCha20 keystream keyed from the channel binding (per-connection,
per-direction). The opening and the data phase thus use different keying domains
— token vs. channel binding — each matched to what is shared when.

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

- **Resolved by investigation (2026-10-01).** `edwards25519-extra/elligator2`
  provides only the decode direction (representative→point); the encode
  (point→representative) we need is in no importable standalone library
  (`agl/ed25519/extra25519` is gone from its module; obfs4's lives in an
  `internal/` package). The vetted both-direction implementation is yawning's
  `x25519ell2` (`ScalarBaseMult` encode with rejection sampling +
  `RepresentativeToPublicKey` decode), ~180 LOC, **GPL-3.0 — compatible with
  BackPack's AGPL-3.0** (the combined work is AGPL-3.0). Decision: **vendor**
  `x25519ell2.go` and its test into `internal/utils/x25519ell2/`, license header
  and attribution preserved, rather than reimplement the field arithmetic from
  memory — a mistake there is a silent distinguisher, the whole thing we are
  removing. It pulls `filippo.io/edwards25519` and
  `gitlab.com/yawning/edwards25519-extra`. A Go 1.26.6 toolchain is installed
  locally, so this builds and tests here.

## Security considerations

- **Opening uses no keystream.** The mark/MAC framing (token-keyed HMAC) carries
  the opening, so there is no opening keystream to reuse across connections — the
  per-connection variation comes from the Elligator-uniform `e`, the random `P`,
  and the HMAC outputs. The mark/MAC and the dead-port behaviour on a wrong token
  get dedicated tests.
- **Data-phase length mask is per-connection.** The data records' length mask is
  keyed from the Noise channel binding, which is unique per handshake, so two
  connections never share a data-phase keystream. Pinned by a test.
- **No weakening of the channel.** Elligator2 changes only how the public key is
  *encoded* on the wire, not the DH or the AEAD. The `NNpsk0` guarantees
  (mutual auth as "holds the token", forward secrecy, silence to a wrong token)
  are unchanged, and the token proof still runs on top. The vendored encoder does
  not cofactor-clear, so its public keys differ from stock X25519; both ends run
  the same encoder, so this is self-consistent and never leaves the handshake.
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

1. ~~Elligator2 library choice~~ — **resolved by investigation:** vendor
   yawning's GPL-3.0 `x25519ell2` (AGPL-compatible, both directions); deps
   `filippo.io/edwards25519` + `edwards25519-extra`. See Dependencies.
2. ~~Config surface~~ — **resolved:** a distinct transport name, `stealth2`.
3. **ADR (follow-up)** — distil the accepted version into `docs/adr/0006-*` and
   add a row naming `stealth2` to ADR 0004's ingress table (opening
   timing/bounds are unchanged).
