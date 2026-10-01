# ADR 0006 — stealth2: an opening with no constant to match

**Status:** proposed (2026-10-02). Adds a row to ADR 0004's table; keeps to
ADR 0001/0005's stance that nothing on an existing wire changes.

## Context

`stealth` is a TCP tunnel under a Noise `NNpsk0` record layer, and it exists so
that deep packet inspection has nothing to match: the content is unreadable and
the shape unremarkable, with padding inside the AEAD. The front of the
connection does not hold to that. Three tells survive at the opening, which is
what an observer classifies first:

1. **A near-constant first flight.** The initiator's first message is a fixed
   49 bytes or so, so every stealth connection opens with the same handful of
   bytes. `TestStealthHandshakeOpeningIsUniform` measures the byte *after* the
   length prefix and never saw it.
2. **A readable length.** The first two bytes are a plaintext big-endian count
   of the bytes that follow — a structure, whatever the size.
3. **A key with a fixed bit.** The message opens with an X25519 public key whose
   top bit is always 0 (none set in 5000 draws; about 2500 expected from random
   bytes), and which always lies on the curve.

Fixing any of them moves the first bytes on the wire, so they are fixed once,
together, as a second format. These are the tells the obfs4 specification and
the Elligator paper (Bernstein, Hamburg, Krasnova, Lange) already answer; this
takes those techniques rather than inventing others.

## Decision

`stealth2` is a transport of its own, selected by name like any other. It is
opt-in, both ends must run it, and the opening is the only thing that differs:
the Noise handshake, the token proof and the mux above it are `stealth`'s.

- **The key is an Elligator2 representative.** The sender puts its ephemeral key
  on the wire as a uniform representative and the receiver maps it back before
  the DH; only the `noise.DHFunc` is replaced. The encoder is yawning's
  `x25519ell2`, vendored into `internal/utils/x25519ell2` with its test and its
  GPL-3.0 header (combined under our AGPL-3.0) — no importable library does both
  directions, and a slip in hand-written field arithmetic is a silent
  distinguisher, the thing being removed. It does not clear the cofactor, so its
  keys differ from stock X25519; both ends run it and the key never leaves the
  handshake.
- **The handshake rides in an obfs4-style frame keyed from the token:**
  `m | P | M | MAC`. `m` is the Noise message, a fixed length because its
  payload is, so both ends know it; `P` is random padding that brings the whole
  opening to at most 8192 bytes; `M` = HMAC-SHA256-128 of `m` under a key
  derived from the token marks where `P` ends; `MAC` binds `m | P | M` to the
  epoch hour and is accepted for that hour and its neighbours. There is no length
  and no type on the wire: the receiver reads `m`, scans for `M`, checks the MAC.
  Only a holder of the token can find the mark, and nothing in the opening is a
  keystream to reuse.
- **A replayed opening is refused.** A censor that captured one genuine opening
  could replay it and watch the server answer — confirming the endpoint, which is
  the attack this transport is for. The receiver remembers the MACs it has
  accepted, for 4 hours and at most 4096 of them, oldest out first. Only a frame
  that verifies is remembered, so a peer without the token cannot push a genuine
  entry out (ADR 0004's rule).
- **Every failure ends the same way: the server reads and discards until the
  handshake deadline and sends nothing (`holdDeadPort`).** A wrong token never
  finds the mark, a bad MAC and a stale hour fail after it, a replay fails the
  instant its MAC checks. Closing on return would tell a prober which it hit by
  how long the port stayed open; draining to the one deadline makes them one
  observable: silence, then a close.
- **After the handshake the length prefix is masked too.** Both ends hold the
  channel binding, and each direction's two-byte prefix is XORed with a ChaCha20
  keystream keyed from it, so no connection shares a keystream with another. The
  mask is not forward-secret: the binding holds the token's contribution but no
  DH output, so a token-holder with a recorded transcript can recompute it. It
  hides the length bytes from an observer without the token, nothing more. The
  records are `stealth`'s ChaCha20-Poly1305 records, padding and all. Opening and
  data phase use different keys — token, then channel binding — each the one that
  is shared at that moment.
- **Selection is configuration.** `stealth2` is in `reverseTransports` and
  `fallbackCapable`, so it joins a fallback chain as a candidate distinct from
  `stealth`, and a chain may put it first with `stealth` behind. Nothing says
  "v2" on the wire, so an observer has no negotiation to strip to force a
  downgrade; a chain that lists `stealth` is the operator's choice. A sub-flag on
  `stealth` would have needed a new concept in every place a transport is
  chosen; a name needs only to be added where transports are listed. Nothing
  guards that: the parity tests are keyed per engine, and `stealth2` shares the
  `tcp` engine, so the wizard, panel, menu, share links and Link Test omitting it
  (see Consequences) failed no test. That omission is the deferred follow-up.

Not decided here: traffic-shape and timing camouflage (record-size buckets,
dummy records, jitter), and mimicry of TLS or HTTP. The goal is an opening that
looks like nothing, not like something.

## Consequences

- Nothing on the `stealth` wire changes, and no default changes. `stealth` and
  `stealth2` cannot read each other — a `stealth` peer reads the first two bytes
  as a length — so mixed versions keep working because neither end switches on
  upgrade: the new format waits for both to opt in.
- A failed probe is no longer closed at once: it is held to the 15 s handshake
  deadline. That costs a gate place for as long, and the gate bounds it — the
  handshake runs in the connection's own goroutine under `acceptloop.Gate`,
  never in the accept loop, so a probe flood fills the gate (128 per host, 1024
  in all) and a host that has proved the token still passes it. A flood can delay
  a client that has never connected from its address, as ADR 0004 already says
  of every ingress.
- The opening is bigger and varies: up to 8 KB, about 4 KB on average, where
  `stealth` sent about 50 bytes — in each direction, on every tunnel connection,
  pool refills included.
- The MAC carries the epoch hour, so ends whose clocks differ by more than about
  an hour fail the handshake silently, which looks like a wrong token. A
  `stealth2` tunnel that will not connect is a question about the time as well
  as the token.
- It is set in the config file only. The setup wizard, the web panel, the menu,
  the share links and the Link Test do not list it, and the direct tunnel's
  `stealth` stays v1. Follow-ups, none done: enumerate `stealth2` there;
  randomise how long a failed opening is held (a fixed hold equal to the deadline
  is itself a constant a prober can time); a `stealth2` direct tunnel.
