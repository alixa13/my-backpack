# stealth2 Opening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in reverse transport, `stealth2`, whose connection opening has no constant an observer can match — uniform-random key encoding, no cleartext length, and variable first-flight size — while leaving today's `stealth` byte-for-byte unchanged.

**Architecture:** A second Noise variant in `internal/utils/network`, reached through new `…V2` constructors so the v1 path is untouched. v2 encodes the X25519 ephemeral key as an Elligator2 representative (uniform bytes), pads the handshake payload inside the AEAD, and masks every record's 2-byte length prefix with a per-connection keystream derived from the handshake's channel binding. `stealth2` is a distinct transport name wired through config and the reverse client/server exactly as `stealth` is.

**Tech Stack:** Go 1.26.6, `github.com/flynn/noise` v1.1.0, `golang.org/x/crypto` (hkdf, chacha20, curve25519 — already present), vendored `x25519ell2` (GPL-3.0, AGPL-compatible), and its deps `filippo.io/edwards25519` + `gitlab.com/yawning/edwards25519-extra`.

**Spec:** `docs/superpowers/specs/2026-10-01-stealth-v2-opening-design.md` — read it alongside this plan.

## Global Constraints

- Go version floor: **1.26.6** (`go.mod`). The Elligator2 library must build against it.
- **Do not modify** the v1 wire path: `noiseSuite`, `noisePrologue`, `noisePSK`, `NoiseClientConn`, `NoiseServerConn`, the existing `noiseConn` framing, or any v0/v1 negotiation. v2 is additive.
- Keyed only from the tunnel token. No new key material, no new config secret.
- Elligator2 field arithmetic is **not** hand-rolled or reimplemented from memory — vendor yawning's `x25519ell2` (GPL-3.0; keep its license header and attribution, combined under AGPL-3.0). Our code only wraps it.
- `stealth2` must appear everywhere a transport name is enumerated, or the source-reading parity tests (`internal/client/transport/parity_test.go`) fail by design.
- Scope is the **reverse** transport. Direct-tunnel `stealth2` is an explicit follow-up, not in this plan.

## Review Focus

- **Cross-version contact:** a `stealth2` end meeting a v0/v1 `stealth` end (either direction) must fail cleanly — no hang past the handshake timeout, no silent corruption. Pinned in Task 3.
- **Keystream uniqueness:** two connections on the same token must not produce identical opening bytes; a per-connection mask that collapsed to a constant would reintroduce the tell. Pinned in Task 4.
- **Adversarial opening:** a garbage or wrong-token first flight (including a representative that decodes to a low-order point) must fail the handshake and send nothing back — the dead-port property — not panic. Pinned in Task 3.
- **Record-size ceiling:** a full-size write after masking + payload padding must still fit under `noiseMaxFrame`; the v2 plaintext ceiling must be computed, not assumed. Pinned in Task 4.
- **Fallback validation:** `[stealth2, stealth]` must validate as a chain and each must be a recognised reverse transport; a typo must still be rejected at load. Pinned in Task 5.

---

## Task 1: Elligator2 key-encoding DH wrapper

Vendor yawning's vetted both-direction X25519 Elligator2 implementation, then wrap it as a `noise.DHFunc` so the ephemeral public key on the wire is a uniform representative and the peer's representative is mapped back before the DH. Used only by the v2 suite.

**Why vendor:** no importable standalone library does the *encode* direction (`edwards25519-extra/elligator2` decodes only; `agl/ed25519/extra25519` is gone from its module; obfs4's lives in an `internal/` package Go won't let us import). The vetted implementation is yawning's `x25519ell2` (~180 LOC, GPL-3.0 — **compatible with BackPack's AGPL-3.0**, combined work stays AGPL-3.0). We copy it in with its header and attribution intact rather than reimplement field arithmetic, where a subtle bug is a silent distinguisher.

**Files:**
- Modify: `go.mod`, `go.sum` (add `filippo.io/edwards25519`, `gitlab.com/yawning/edwards25519-extra`)
- Create: `internal/utils/x25519ell2/x25519ell2.go` — vendored verbatim from `gitlab.com/yawning/obfs4.git/internal/x25519ell2@v0.0.0-20231012084234-c3e2d44b1033`, GPL-3.0 header preserved.
- Create: `internal/utils/x25519ell2/x25519ell2_test.go` — its vendored test, unmodified.
- Create: `internal/utils/x25519ell2/VENDOR.md` — upstream module, version, license note (GPL-3.0, combined under AGPL-3.0).
- Create: `internal/utils/network/elligator.go`
- Test: `internal/utils/network/elligator_test.go`

**Interfaces:**
- Consumes (from the vendored package): `func ScalarBaseMult(publicKey, representative, privateKey *[32]byte, tweak byte) bool` (encode; returns false ~50% of the time → caller retries) and `func RepresentativeToPublicKey(publicKey, representative *[32]byte)` (decode).
- Produces: `func newElligatorDH() noise.DHFunc` — `DHLen() == 32`, `DHName() == "25519"`, whose `GenerateKeypair` returns a `noise.DHKey` whose `Public` is the 32-byte uniform representative, and whose `DH(priv, peerRepr)` returns the X25519 shared secret.

- [ ] **Step 1: Vendor the implementation and pin deps.** The toolchain is installed (`~/go-toolchain/go`, on PATH):

```bash
# Cache the upstream WITHOUT adding it as a dependency, then copy the two files.
go mod download gitlab.com/yawning/obfs4.git@v0.0.0-20231012084234-c3e2d44b1033
MOD="$(go env GOMODCACHE)/gitlab.com/yawning/obfs4.git@v0.0.0-20231012084234-c3e2d44b1033/internal/x25519ell2"
mkdir -p internal/utils/x25519ell2
cp "$MOD/x25519ell2.go" "$MOD/x25519ell2_test.go" internal/utils/x25519ell2/
chmod u+w internal/utils/x25519ell2/*.go   # module-cache files are read-only
# The vendored file imports these two; make them real deps.
go get filippo.io/edwards25519@latest
go get gitlab.com/yawning/edwards25519-extra@latest
go mod tidy
go test ./internal/utils/x25519ell2/ -v    # the vendored test must pass unmodified
```

Then write `internal/utils/x25519ell2/VENDOR.md` naming the upstream module, version `v0.0.0-20231012084234-c3e2d44b1033`, the GPL-3.0 license, and that it is combined under BackPack's AGPL-3.0. Do not edit the vendored `.go` files (keep `package x25519ell2` and its imports).

- [ ] **Step 2: Write the failing test** `internal/utils/network/elligator_test.go`:

```go
package network

import (
	"crypto/rand"
	"testing"
)

// The representative on the wire must look like uniform random bytes: across
// many keypairs the top bit of the last byte is set about half the time (stock
// X25519 keys never set it).
func TestElligatorRepresentativeHasNoFixedTopBit(t *testing.T) {
	dh := newElligatorDH()
	const n = 2000
	set := 0
	for i := 0; i < n; i++ {
		kp, err := dh.GenerateKeypair(rand.Reader)
		if err != nil {
			t.Fatalf("keypair %d: %v", i, err)
		}
		if len(kp.Public) != 32 {
			t.Fatalf("representative is %d bytes, want 32", len(kp.Public))
		}
		set += int(kp.Public[31] >> 7)
	}
	if set < n/4 || set > 3*n/4 {
		t.Errorf("top bit set %d/%d times; representative is biased and distinguishable", set, n)
	}
}

// Two ends must agree on the shared secret through the representative: DH is
// symmetric when each side encodes its own public key and decodes the peer's.
func TestElligatorDHRoundTrips(t *testing.T) {
	dh := newElligatorDH()
	a, err := dh.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := dh.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ab, err := dh.DH(a.Private, b.Public)
	if err != nil {
		t.Fatal(err)
	}
	ba, err := dh.DH(b.Private, a.Public)
	if err != nil {
		t.Fatal(err)
	}
	if string(ab) != string(ba) {
		t.Error("DH disagreed across the Elligator2 encoding")
	}
}
```

- [ ] **Step 3: Run the tests, verify they fail** (`newElligatorDH` undefined):

```bash
go test ./internal/utils/network/ -run TestElligator -v
```

Expected: FAIL, build error `undefined: newElligatorDH`.

- [ ] **Step 4: Implement `internal/utils/network/elligator.go`:**

```go
package network

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"

	"github.com/backpack/backpack/internal/utils/x25519ell2"
)

// elligatorDH is noise.DH25519 with the ephemeral public key carried on the
// wire as a uniform Elligator2 representative instead of a raw X25519 point.
// Only the v2 suite uses it; v1 keeps stock DH25519. The representative math is
// the vendored, vetted x25519ell2 (see internal/utils/x25519ell2/VENDOR.md).
type elligatorDH struct{}

func newElligatorDH() noise.DHFunc { return elligatorDH{} }

func (elligatorDH) DHLen() int     { return 32 }
func (elligatorDH) DHName() string { return "25519" } // keep the suite name stable

func (elligatorDH) GenerateKeypair(rng io.Reader) (noise.DHKey, error) {
	if rng == nil {
		rng = rand.Reader
	}
	// Only ~half of keys have a representative; retry until one does. A random
	// tweak byte fills the representative's high bits so it is uniform over all
	// 32 bytes. The loop is bounded so a broken rng cannot spin forever.
	for i := 0; i < 64; i++ {
		var priv, pub, repr [32]byte
		if _, err := io.ReadFull(rng, priv[:]); err != nil {
			return noise.DHKey{}, err
		}
		var tweak [1]byte
		if _, err := io.ReadFull(rng, tweak[:]); err != nil {
			return noise.DHKey{}, err
		}
		if x25519ell2.ScalarBaseMult(&pub, &repr, &priv, tweak[0]) {
			return noise.DHKey{Private: priv[:], Public: repr[:]}, nil
		}
	}
	return noise.DHKey{}, fmt.Errorf("elligator: no representable key in 64 tries")
}

func (elligatorDH) DH(privkey, peerRepr []byte) ([]byte, error) {
	if len(peerRepr) != 32 {
		return nil, fmt.Errorf("elligator: peer representative is %d bytes", len(peerRepr))
	}
	var repr, peerPub [32]byte
	copy(repr[:], peerRepr)
	x25519ell2.RepresentativeToPublicKey(&peerPub, &repr)
	return curve25519.X25519(privkey, peerPub[:])
}
```

Note: `x25519ell2.ScalarBaseMult` deliberately does **not** cofactor-clear, so its public key differs from `curve25519.X25519(priv, base)` — never mix the two. Both ends run this same DHFunc, so the keys are self-consistent and `DH` agrees; `TestElligatorDHRoundTrips` is what proves it.

- [ ] **Step 5: Run the tests, verify they pass:**

```bash
go test ./internal/utils/network/ -run TestElligator -v
```

Expected: PASS.

- [ ] **Step 6: Commit:**

```bash
git add go.mod go.sum internal/utils/x25519ell2/ internal/utils/network/elligator.go internal/utils/network/elligator_test.go
git commit -m "feat(network): vendor x25519ell2 and wrap it as a noise DHFunc for stealth2"
```

---

## Task 2: v2 handshake — Elligator2 key + padded payload

A v2 handshake over the Elligator suite, with the handshake payload padded by random-length filler inside the AEAD so the first flight is not a constant size. Still NNpsk0, still token-keyed, still silent to a wrong token.

**Files:**
- Modify: `internal/utils/network/noise.go` (add constants + a variant-aware internal handshake; v1 entry points unchanged)
- Create: `internal/utils/network/noisev2.go` (v2 constructors + handshake padding)
- Test: `internal/utils/network/noisev2_test.go`

**Interfaces:**
- Consumes: `newElligatorDH()` (Task 1).
- Produces:
  - `func NoiseClientConnV2(raw net.Conn, token string, timeout time.Duration) (net.Conn, error)`
  - `func NoiseServerConnV2(raw net.Conn, token string, timeout time.Duration) (net.Conn, error)`
  - both returning a `net.Conn` whose `ChannelBinding() []byte` is reachable internally for Task 4's framing key.

- [ ] **Step 1: Write the failing test** `internal/utils/network/noisev2_test.go`:

```go
package network

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

const v2Token = "stealth2-token-0123456789abcdefghij"

// A v2 client and v2 server complete the handshake and carry a payload both ways.
func TestV2RoundTrip(t *testing.T) {
	c, s := net.Pipe()
	srvDone := make(chan net.Conn, 1)
	go func() {
		conn, err := NoiseServerConnV2(s, v2Token, 3*time.Second)
		if err != nil {
			t.Errorf("server: %v", err)
			srvDone <- nil
			return
		}
		srvDone <- conn
	}()
	cl, err := NoiseClientConnV2(c, v2Token, 3*time.Second)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	srv := <-srvDone
	if srv == nil {
		t.Fatal("server handshake failed")
	}
	want := []byte("hello over stealth2")
	go func() { _, _ = cl.Write(want) }()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(srv, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q want %q", got, want)
	}
}

// Sampled first flights must take many distinct sizes — the v1 opening took one.
func TestV2OpeningSizeVaries(t *testing.T) {
	if testing.Short() {
		t.Skip("sampling test")
	}
	sizes := map[int]int{}
	for i := 0; i < 400; i++ {
		sizes[len(captureV2FirstFlight(t))]++
	}
	if len(sizes) < 16 {
		t.Errorf("first flight took only %d distinct sizes; it is still near-constant", len(sizes))
	}
}

// captureV2FirstFlight returns the raw bytes the v2 initiator sends first.
func captureV2FirstFlight(t *testing.T) []byte {
	t.Helper()
	c, s := net.Pipe()
	out := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := s.Read(buf)
		out <- append([]byte(nil), buf[:n]...)
		s.Close()
	}()
	go func() { _, _ = NoiseClientConnV2(c, v2Token, time.Second) }()
	select {
	case b := <-out:
		return b
	case <-time.After(3 * time.Second):
		t.Fatal("timed out")
		return nil
	}
}
```

- [ ] **Step 2: Run, verify fail** (`NoiseClientConnV2` undefined):

```bash
go test ./internal/utils/network/ -run TestV2 -v
```

Expected: FAIL, `undefined: NoiseClientConnV2`.

- [ ] **Step 3: Implement the v2 handshake in `internal/utils/network/noisev2.go`.** Reuse the v1 NNpsk0 shape; change only the suite (Elligator), add payload filler, and build a `noiseConn` with `pad: true` plus the v2 framing hook from Task 4 (stub the hook as identity for now so this task is testable on its own):

```go
package network

import (
	"fmt"
	"math/rand/v2"
	"net"
	"time"

	"github.com/flynn/noise"
)

const (
	// noiseSuiteV2 is the v1 suite with the Elligator2-encoded DH. Both ends
	// run v2, so the encoding needs no negotiation on the wire.
	// (built in init to keep newElligatorDH in one place)
	noiseMaxHandshakePad = 1024 // keeps the first flight inside one segment
)

var noiseSuiteV2 = noise.NewCipherSuite(newElligatorDH(), noise.CipherChaChaPoly, noise.HashBLAKE2s)

func NoiseClientConnV2(raw net.Conn, token string, timeout time.Duration) (net.Conn, error) {
	return noiseHandshakeV2(raw, token, true, timeout)
}

func NoiseServerConnV2(raw net.Conn, token string, timeout time.Duration) (net.Conn, error) {
	return noiseHandshakeV2(raw, token, false, timeout)
}

// handshakePayload is the version marker followed by random-length zero filler,
// all carried inside the AEAD so only the record's length moves.
func handshakePayload() []byte {
	n := rand.IntN(noiseMaxHandshakePad + 1)
	p := make([]byte, 1+n)
	p[0] = noiseVersion
	return p
}
```

Write `noiseHandshakeV2` as a copy of `noiseHandshake`'s structure that: builds `noise.NewHandshakeState` with `CipherSuite: noiseSuiteV2`; sends `handshakePayload()` instead of `[]byte{noiseVersion}` on both the initiator's first message and the responder's reply; keeps the 15 s deadline; and on success returns a connection built inline as `&noiseConn{Conn: raw, send: sendCS, recv: recvCS, pad: true}`. Task 4 replaces that one inline construction with a call to `newNoiseConnV2(raw, sendCS, recvCS, hs.ChannelBinding(), initiator)`. A responder that fails `ReadMessage` returns the error and writes nothing — unchanged from v1.

- [ ] **Step 4: Run, verify pass:**

```bash
go test ./internal/utils/network/ -run TestV2 -v
```

Expected: PASS.

- [ ] **Step 5: Commit:**

```bash
git add internal/utils/network/noisev2.go internal/utils/network/noisev2_test.go internal/utils/network/noise.go
git commit -m "feat(network): v2 handshake with Elligator2 key and padded first flight"
```

---

## Task 3: v2 rejects wrong tokens and v0/v1 peers — cleanly

Prove two negative contracts: a wrong-token or garbage opening is rejected silently without a panic (the dead-port property), and the "both ends must switch" rule holds — a v2 end against a v1 end errors within the timeout rather than hanging or corrupting. This is a test-only task over Tasks 1–2.

**Files:**
- Test: `internal/utils/network/noisev2_test.go` (extend)

**Interfaces:**
- Consumes: `NoiseClientConnV2`, `NoiseServerConnV2` (Task 2); `NoiseClientConn`, `NoiseServerConn` (v1).

- [ ] **Step 1: Write the failing test** (append):

```go
// A wrong token is rejected and nothing is written back: a probe finds a dead
// port, and a garbage opening must not panic the responder.
func TestV2WrongTokenIsRejectedSilently(t *testing.T) {
	c, s := net.Pipe()
	wrote := make(chan int, 1)
	go func() {
		// Count any bytes the responder sends after a bad opening.
		n, _ := io.Copy(io.Discard, s)
		wrote <- int(n)
	}()
	go func() {
		conn, err := NoiseServerConnV2(s, v2Token, time.Second)
		if err == nil {
			t.Error("server accepted a wrong-token client")
			conn.Close()
		}
		s.Close()
	}()
	// A client with the wrong token (and, incidentally, arbitrary first bytes).
	_, err := NoiseClientConnV2(c, "the-wrong-token-xxxxxxxxxxxxxxxxxxxx", time.Second)
	if err == nil {
		t.Fatal("client reported success with a mismatched token")
	}
	if n := <-wrote; n != 0 {
		t.Errorf("responder wrote %d bytes to a wrong-token peer; the port is not dead", n)
	}
}

// A v2 client must not appear to succeed against a v1 server, and must give up
// within the handshake deadline rather than hang.
func TestV2ClientAgainstV1ServerFailsCleanly(t *testing.T) {
	c, s := net.Pipe()
	go func() { _, _ = NoiseServerConn(s, v2Token, time.Second) }() // v1 responder
	done := make(chan error, 1)
	go func() {
		_, err := NoiseClientConnV2(c, v2Token, time.Second)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("v2 client reported success against a v1 server")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("v2 client hung against a v1 server")
	}
}

// And the mirror: a v1 client against a v2 server.
func TestV1ClientAgainstV2ServerFailsCleanly(t *testing.T) {
	c, s := net.Pipe()
	go func() { _, _ = NoiseServerConnV2(s, v2Token, time.Second) }()
	done := make(chan error, 1)
	go func() {
		_, err := NoiseClientConn(c, v2Token, time.Second)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("v1 client reported success against a v2 server")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("v1 client hung against a v2 server")
	}
}
```

- [ ] **Step 2: Run all three:**

```bash
go test ./internal/utils/network/ -run "WrongToken|AgainstV" -v
```

Expected: PASS (wrong-token/garbage openings are rejected with nothing written back; the cross-version pairs decode each other's first flight as garbage and error, or time out into an error, within the deadline). If either hangs, the handshake deadline in Task 2 is not being set — fix there, not here.

- [ ] **Step 3: Commit:**

```bash
git add internal/utils/network/noisev2_test.go
git commit -m "test(network): stealth2 rejects wrong tokens and v1 peers cleanly"
```

---

## Task 4: v2 record framing — masked length prefix

Replace the cleartext 2-byte length on every v2 record with 2 bytes XORed against a per-connection, per-direction keystream derived from the handshake. The record body stays a standard Noise record (already padded, already random-looking); only the readable length goes away.

**Files:**
- Modify: `internal/utils/network/noisev2.go` (add `noiseConnV2`, `newNoiseConnV2`)
- Test: `internal/utils/network/noisev2_test.go` (extend)

**Interfaces:**
- Consumes: the handshake channel binding passed by Task 2.
- Produces: `func newNoiseConnV2(raw net.Conn, send, recv *noise.CipherState, binding []byte, initiator bool) (net.Conn, error)` returning a `net.Conn`. Task 2's handshake calls this instead of the temporary `&noiseConn{…}`.

- [ ] **Step 1: Write the failing tests** (append):

```go
// Two connections on the same token must not open with the same bytes — a mask
// that was constant per token would be as matchable as no mask at all.
func TestV2OpeningDiffersPerConnection(t *testing.T) {
	a := captureV2FirstFlight(t)
	b := captureV2FirstFlight(t)
	if bytes.Equal(a, b) {
		t.Fatal("two v2 openings were byte-identical")
	}
}

// A large write round-trips: the v2 plaintext ceiling must leave room for the
// payload-padding header and filler under the Noise frame ceiling.
func TestV2LargeWriteRoundTrips(t *testing.T) {
	c, s := net.Pipe()
	srvDone := make(chan net.Conn, 1)
	go func() {
		conn, err := NoiseServerConnV2(s, v2Token, 3*time.Second)
		if err != nil {
			t.Errorf("server: %v", err)
		}
		srvDone <- conn
	}()
	cl, err := NoiseClientConnV2(c, v2Token, 3*time.Second)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	srv := <-srvDone
	want := bytes.Repeat([]byte{0xAB}, 200*1024) // spans many records
	go func() { _, _ = cl.Write(want); _ = cl.Close() }()
	got, err := io.ReadAll(srv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("round trip mismatch: %d of %d bytes", len(got), len(want))
	}
}
```

- [ ] **Step 2: Run, verify fail:**

```bash
go test ./internal/utils/network/ -run "TestV2Opening|TestV2Large" -v
```

Expected: `TestV2OpeningDiffersPerConnection` may already pass (handshake payload is random-length); `TestV2LargeWriteRoundTrips` passes against the Task 2 stub. The failing case appears once Step 3 swaps in masked framing and the mask is wired wrong — these tests are the guard for that.

- [ ] **Step 3: Implement masked framing in `internal/utils/network/noisev2.go`:**

```go
import (
	"crypto/sha256"
	"encoding/binary"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

// framingKey derives a 32-byte key for one direction from the handshake's
// channel binding. Separate labels per direction so the two streams never
// share mask bytes.
func framingKey(binding []byte, label string) ([]byte, error) {
	k := make([]byte, chacha20.KeySize)
	r := hkdf.New(sha256.New, binding, []byte(label), nil)
	_, err := io.ReadFull(r, k)
	return k, err
}

// noiseConnV2 wraps noiseConn's record logic but masks the 2-byte length
// header of every record with a ChaCha20 keystream. The key is unique per
// connection (channel binding) so the stream needs no nonce management beyond
// advancing with each record; both ends advance in lockstep.
type noiseConnV2 struct {
	*noiseConn
	writeMask *chacha20.Cipher
	readMask  *chacha20.Cipher
	wMu, rMu  sync.Mutex
}

func newNoiseConnV2(raw net.Conn, send, recv *noise.CipherState, binding []byte, initiator bool) (net.Conn, error) {
	base := &noiseConn{Conn: raw, send: send, recv: recv, pad: true}
	// The initiator writes on the c2s stream and reads the s2c stream; the
	// responder is the mirror.
	c2s, err := framingKey(binding, "backpack-stealth2-framing-c2s-v1")
	if err != nil {
		return nil, err
	}
	s2c, err := framingKey(binding, "backpack-stealth2-framing-s2c-v1")
	if err != nil {
		return nil, err
	}
	wKey, rKey := c2s, s2c
	if !initiator {
		wKey, rKey = s2c, c2s
	}
	var nonce [chacha20.NonceSize]byte
	wc, err := chacha20.NewUnauthenticatedCipher(wKey, nonce[:])
	if err != nil {
		return nil, err
	}
	rc, err := chacha20.NewUnauthenticatedCipher(rKey, nonce[:])
	if err != nil {
		return nil, err
	}
	return &noiseConnV2{noiseConn: base, writeMask: wc, readMask: rc}, nil
}
```

Then override `Write` and `Read` on `noiseConnV2`: build the record exactly as `noiseConn` does, but XOR the 2 length-prefix bytes through `writeMask.XORKeyStream` before the write; on read, read 2 bytes, XOR through `readMask` to recover the length, then read and decrypt the body as `noiseConn.Read` does. Keep the per-record no-allocation path. Finally, change Task 2's handshake to call `newNoiseConnV2(raw, sendCS, recvCS, hs.ChannelBinding(), initiator)`.

- [ ] **Step 4: Run the whole network suite, with race:**

```bash
go test ./internal/utils/network/ -race -v
```

Expected: PASS, including Task 1–3 tests and `TestTheRecordLayerDoesNotAllocatePerRecord`.

- [ ] **Step 5: Commit:**

```bash
git add internal/utils/network/noisev2.go internal/utils/network/noisev2_test.go
git commit -m "feat(network): mask the record length prefix on stealth2"
```

---

## Task 5: `stealth2` transport name in config

Add `stealth2` as a recognised reverse transport and fallback candidate, validated at load.

**Files:**
- Modify: `config/config.go` (add the `STEALTH2` const + doc), `config/fallback.go` (add to `fallbackCapable` and `reverseTransports`)
- Test: `config/l3_test.go` or a new `config/stealth2_test.go`

**Interfaces:**
- Produces: `config.STEALTH2 TransportType = "stealth2"`.

- [ ] **Step 1: Write the failing test** `config/stealth2_test.go`:

```go
package config

import "testing"

func TestStealth2IsAReverseTransport(t *testing.T) {
	if !IsReverseTransport(STEALTH2) {
		t.Error("stealth2 is not recognised as a reverse transport")
	}
}

func TestStealth2CanLeadAFallbackChain(t *testing.T) {
	if err := ValidateFallbackTransports(STEALTH2, []TransportType{STEALTH}); err != nil {
		t.Errorf("[stealth2, stealth] should validate: %v", err)
	}
}
```

- [ ] **Step 2: Run, verify fail** (`STEALTH2` undefined):

```bash
go test ./config/ -run Stealth2 -v
```

Expected: FAIL, `undefined: STEALTH2`.

- [ ] **Step 3: Implement.** In `config/config.go`, beside `STEALTH`:

```go
// STEALTH2 is the stealth transport with the hardened opening: an Elligator2-
// encoded key, a padded first flight, and a masked length prefix, so the start
// of the connection carries no constant an observer can match. Opt-in; both
// ends must run it. See docs/superpowers/specs/2026-10-01-stealth-v2-opening-design.md.
STEALTH2 TransportType = "stealth2"
```

In `config/fallback.go`, add `STEALTH2: true` to both `fallbackCapable` and `reverseTransports`.

- [ ] **Step 4: Run, verify pass:**

```bash
go test ./config/ -run Stealth2 -v
```

Expected: PASS.

- [ ] **Step 5: Commit:**

```bash
git add config/config.go config/fallback.go config/stealth2_test.go
git commit -m "feat(config): recognise stealth2 as a reverse transport"
```

---

## Task 6: Wire `stealth2` through the reverse client and server

Make the reverse engine dial/accept `stealth2` by selecting the v2 constructors. Mirror exactly how `stealth` sets the `Stealth` flag today.

**Files:**
- Modify: `internal/client/client.go` (the transport switch at ~174 and ~369), `internal/client/transport/tcp.go` (the `Stealth bool` → a variant), `internal/server/transport/tcp.go` (the server mirror), `cmd/defaults.go` (the `proxy_protocol` transport list message)
- Test: `internal/client/client_test.go` (extend the transport→type map), `cmd/reload_test.go` (extend the transport pairing cases)

**Interfaces:**
- Consumes: `config.STEALTH2`; `network.NoiseClientConnV2`, `network.NoiseServerConnV2`.

- [ ] **Step 1: Write the failing test.** In `internal/client/client_test.go`, add `config.STEALTH2: "*transport.TcpTransport"` to the case map the existing test iterates, asserting `stealth2` builds a TCP transport like `stealth` does.

- [ ] **Step 2: Run, verify fail:**

```bash
go test ./internal/client/ -run Transport -v
```

Expected: FAIL (stealth2 unhandled → error or wrong type).

- [ ] **Step 3: Implement.** Replace the boolean `Stealth` on `transport.TcpTransport` (both client and server `tcp.go`) with a small variant, e.g.:

```go
// StealthMode selects the record layer wrapped over the TCP tunnel.
type StealthMode int

const (
	StealthOff StealthMode = iota // plain tcp
	StealthV1                     // Noise, v1 opening
	StealthV2                     // Noise, hardened opening
)
```

In `wrapStealth` (client `tcp.go`) switch on the mode: `StealthV1 → network.NoiseClientConn(...)`, `StealthV2 → network.NoiseClientConnV2(...)`, `StealthOff → conn`. Mirror in server `tcp.go` with the `…ServerConn…` calls. In `client.go`, extend both `case config.TCP, config.STEALTH:` sites to include `config.STEALTH2` and set `StealthV2`. In `cmd/defaults.go`, add `stealth2` to the `proxy_protocol … use tcp, tcpmux, stealth, …` list.

- [ ] **Step 4: Run, verify pass:**

```bash
go test ./internal/client/ ./internal/server/ ./cmd/ -v
```

Expected: PASS, including the parity tests.

- [ ] **Step 5: Commit:**

```bash
git add internal/client/ internal/server/ cmd/
git commit -m "feat: dial and accept stealth2 in the reverse engine"
```

---

## Task 7: End-to-end matrix row

Run a real `stealth2` tunnel in the e2e matrix so the whole path — dial, handshake, forward, teardown — is exercised on the binary.

**Files:**
- Modify: `internal/e2e/matrix_test.go` (add a `stealth2` case to the transport list the matrix iterates)

- [ ] **Step 1: Add `stealth2` to the matrix's transport cases**, following the existing `stealth` row (same assertions: a byte written at one end arrives at the other, the tunnel comes up and tears down clean).

- [ ] **Step 2: Run:**

```bash
go test ./internal/e2e/ -run Matrix -v
```

Expected: PASS for every transport including `stealth2`.

- [ ] **Step 3: Commit:**

```bash
git add internal/e2e/matrix_test.go
git commit -m "test(e2e): add stealth2 to the transport matrix"
```

---

## Task 8: Docs, CHANGELOG, ADR 0006

Document the transport and record the decision, matching repo conventions.

**Files:**
- Modify: `docs/transports.md`, `docs/choosing-a-transport.md`, `docs/config-reference.md` (add `stealth2` where `stealth` appears), `CHANGELOG.md`
- Create: `docs/adr/0006-stealth2-opening.md` (distil the spec), and add a `stealth2` row to ADR 0004's ingress table

- [ ] **Step 1: Add `stealth2` to the transport docs** — one paragraph per file mirroring `stealth`, noting it is opt-in, both-ends, and can lead a fallback chain with `stealth` behind it.

- [ ] **Step 2: Write `docs/adr/0006-stealth2-opening.md`** in the ADR voice (Context / Decision / Consequences), distilled from the design spec, and add to ADR 0004's table a row: `reverse … stealth2 — tunnel port | Noise handshake first, up to 25 s | the same acceptloop.Gate` (bounds unchanged from stealth).

- [ ] **Step 3: Add a CHANGELOG entry** under a new version heading.

- [ ] **Step 4: Commit:**

```bash
git add docs/ CHANGELOG.md
git commit -m "docs: document stealth2 and record ADR 0006"
```

---

## Notes for the executor

- **Go 1.26.6 is installed** at `~/go-toolchain/go`, symlinked into `~/.local/bin` (on PATH for plain non-login shells, which is how tool/subagent shells start). `go test` / `go get` work directly; `GOTOOLCHAIN=local` is set in the profile.
- **Task 1 vendors `x25519ell2`** (both-direction Elligator2). Its own vendored test must pass unmodified before wrapping it; everything downstream assumes `newElligatorDH()` works. Upstream is GPL-3.0, combined under our AGPL-3.0 — preserve the header.
- The module path for internal imports is `github.com/backpack/backpack` (see `go.mod`).
- Run `go test ./... -race` once after Task 6 and again after Task 7.
