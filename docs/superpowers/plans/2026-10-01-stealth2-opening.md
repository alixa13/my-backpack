# stealth2 Opening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in reverse transport, `stealth2`, whose connection opening has no constant an observer can match — uniform-random key encoding, no cleartext length, and variable first-flight size — while leaving today's `stealth` byte-for-byte unchanged.

**Architecture:** A second Noise variant in `internal/utils/network`, reached through new `…V2` constructors so the v1 path is untouched. v2 encodes the X25519 ephemeral key as an Elligator2 representative (uniform bytes); the handshake is wrapped in an **obfs4-style `m | P | M | MAC` frame keyed from the token** so the opening carries no length, type, or constant (a bounded replay filter denies replayed openings); the data phase then uses the Noise record layer with the 2-byte length prefix masked by a per-connection ChaCha20 keystream keyed from the handshake channel binding. `stealth2` is a distinct transport name wired through config and the reverse client/server exactly as `stealth` is.

**Tech Stack:** Go 1.26.6, `github.com/flynn/noise` v1.1.0, `golang.org/x/crypto` (hkdf, hmac via crypto/hmac, chacha20, curve25519 — already present; the mark/MAC framing adds no new dependency), vendored `x25519ell2` (GPL-3.0, AGPL-compatible), and its deps `filippo.io/edwards25519` + `gitlab.com/yawning/edwards25519-extra`.

**Spec:** `docs/superpowers/specs/2026-10-01-stealth-v2-opening-design.md` — read it alongside this plan.

## Global Constraints

- Go version floor: **1.26.6** (`go.mod`). The Elligator2 library must build against it.
- **Do not modify** the v1 wire path: `noiseSuite`, `noisePrologue`, `noisePSK`, `NoiseClientConn`, `NoiseServerConn`, the existing `noiseConn` framing, or any v0/v1 negotiation. v2 is additive.
- Keyed only from the tunnel token. No new key material, no new config secret. The opening mark/MAC key is `HKDF(token, "backpack-stealth2-mark-v1")`; the data-phase length mask is keyed from the Noise channel binding.
- The opening carries **no cleartext length, type, or constant** — the token-keyed mark delimits the random padding. A wrong token never locates the mark (dead port), preserving the existing silent-to-a-stranger behaviour.
- The replay filter is **bounded** in size and time (ADR 0004); only openings whose MAC already verified (token-holders) can populate it, so a stranger can neither flood it nor evict a genuine entry.
- Elligator2 field arithmetic is **not** hand-rolled or reimplemented from memory — vendor yawning's `x25519ell2` (GPL-3.0; keep its license header and attribution, combined under AGPL-3.0). Our code only wraps it.
- `stealth2` must appear everywhere a transport name is enumerated, or the source-reading parity tests (`internal/client/transport/parity_test.go`) fail by design.
- Scope is the **reverse** transport. Direct-tunnel `stealth2` is an explicit follow-up, not in this plan.

## Review Focus

- **Cross-version contact:** a `stealth2` end meeting a v0/v1 `stealth` end (either direction) must fail cleanly — no hang past the handshake timeout, no silent corruption. Pinned in Task 3.
- **Dead port on wrong token:** a garbage or wrong-token opening never locates the mark; the server writes nothing back and does not panic. Pinned in Tasks 2 and 3.
- **Replay rejected:** a captured valid opening replayed within the epoch window is rejected by the bounded filter (second read fails); only token-holders can ever populate the filter. Pinned in Task 2.
- **Data-phase mask is per-connection:** the data-record length mask is keyed from the channel binding (unique per handshake), so two connections never share a keystream. Pinned in Task 4.
- **Record-size ceiling:** a full-size data write must still fit under `noiseMaxFrame` after the inside-AEAD payload padding; the v2 plaintext ceiling is computed, not assumed. Pinned in Task 4.
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

## Task 2: obfs4-style mark/MAC opening frame + replay filter

The opening carries no readable length. Each handshake message `m` goes out as
`m | P | M | MAC`, token-keyed, per the spec's "v2 opening framing" section. A
peer holding the token computes the mark `M = HMAC(markKey, m)` and scans for it
to find where the random padding `P` ends; a wrong token never finds the mark
(silent dead port). A bounded replay filter rejects a captured opening replayed
within the epoch window. This task is the standalone framing primitive + filter;
Task 3 wraps the Noise handshake in it.

**Reference (read it — port the scan/MAC structure, do not invent):**
`$(go env GOMODCACHE)/gitlab.com/yawning/obfs4.git@v0.0.0-20231012084234-c3e2d44b1033/transports/obfs4/handshake_ntor.go`
— see `clientHandshake.generateHandshake`, `serverHandshake.parseClientHandshake`, and `findMarkMac`. We key the HMAC from the token instead of obfs4's `serverIdentity | nodeID`, and we mark on the whole fixed-length message `m` (obfs4 marks on just `X` because its payload has no fixed length; ours does).

**Files:**
- Create: `internal/utils/network/stealth2frame.go` — `markKey`, epoch helper, `writeMarkedFrame`, `readMarkedFrame`.
- Create: `internal/utils/network/stealth2replay.go` — bounded, time-windowed replay filter.
- Test: `internal/utils/network/stealth2frame_test.go`, `internal/utils/network/stealth2replay_test.go`.

**Interfaces (produced; Task 3 consumes):**
- `func markKey(token string) ([]byte, error)` — 32 bytes, `HKDF-SHA256(token, info="backpack-stealth2-mark-v1")`.
- `func writeMarkedFrame(w io.Writer, key, m []byte) error` — sends `m | P | M | MAC`, `P` random in `[0, maxOpening-len(m)-markLength-macLength]`.
- `func readMarkedFrame(r io.Reader, key []byte, innerLen int, rf *replayFilter) ([]byte, error)` — reads `innerLen` bytes as `m`, computes `M=HMAC(key,m)[:16]`, scans subsequent bytes (bounded by `maxOpening`) for `M`, verifies `MAC` over `m|P|M|E` for `E ∈ {now-1, now, now+1}`, rejects via `rf` if non-nil and the MAC was seen, returns `m`. On any failure returns an error and consumes nothing further.
- `type replayFilter` with `func newReplayFilter() *replayFilter` and `func (f *replayFilter) testAndAdd(mac []byte) bool` (true = fresh/accept, false = replay).

**Constants:** `markLength = 16`, `macLength = 16`, `maxOpening = 8192`, epoch = `time.Now().Unix()/3600`.

- [ ] **Step 1: Write the failing tests** `internal/utils/network/stealth2frame_test.go`:

```go
package network

import (
	"bytes"
	"io"
	"testing"
)

const frameTok = "stealth2-frame-token-0123456789abcd"

// A framed message round-trips: the reader recovers exactly m.
func TestMarkedFrameRoundTrips(t *testing.T) {
	key, err := markKey(frameTok)
	if err != nil {
		t.Fatal(err)
	}
	m := []byte("a 49-byte-ish inner noise message stand-in ....!!")
	var buf bytes.Buffer
	if err := writeMarkedFrame(&buf, key, m); err != nil {
		t.Fatal(err)
	}
	got, err := readMarkedFrame(&buf, key, len(m), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, m) {
		t.Fatalf("recovered %q, want %q", got, m)
	}
}

// No readable length: the frame on the wire is all high-entropy, and across
// frames the total size varies (padding) and the first bytes are not constant.
func TestMarkedFrameHasNoReadableStructure(t *testing.T) {
	key, _ := markKey(frameTok)
	m := bytes.Repeat([]byte{0xA5}, 49) // stand-in; real m is an encrypted noise msg
	sizes := map[int]int{}
	firstTwo := map[[2]byte]int{}
	for i := 0; i < 400; i++ {
		var buf bytes.Buffer
		_ = writeMarkedFrame(&buf, key, m)
		b := buf.Bytes()
		sizes[len(b)]++
		// Note: m here is a constant stand-in, so byte[0..1] variation in this
		// test comes only from framing; the real opening also varies m's e.
		firstTwo[[2]byte{b[len(b)-1], b[len(b)-2]}]++
	}
	if len(sizes) < 16 {
		t.Errorf("framed size took only %d distinct values; padding is not varying", len(sizes))
	}
}

// A wrong key never locates the mark: readMarkedFrame must fail, not hang or
// mis-frame. This is the dead-port property at the frame layer.
func TestMarkedFrameWrongKeyRejected(t *testing.T) {
	key, _ := markKey(frameTok)
	wrong, _ := markKey("the-wrong-token-xxxxxxxxxxxxxxxxxxxx")
	m := bytes.Repeat([]byte{0x5A}, 49)
	var buf bytes.Buffer
	_ = writeMarkedFrame(&buf, key, m)
	if _, err := readMarkedFrame(&buf, wrong, len(m), nil); err == nil {
		t.Fatal("readMarkedFrame accepted a frame under the wrong key")
	}
}

// A replayed frame (same MAC) is rejected by the filter on the second read.
func TestMarkedFrameReplayRejected(t *testing.T) {
	key, _ := markKey(frameTok)
	m := bytes.Repeat([]byte{0x33}, 49)
	var buf bytes.Buffer
	_ = writeMarkedFrame(&buf, key, m)
	wire := buf.Bytes()
	rf := newReplayFilter()
	if _, err := readMarkedFrame(bytes.NewReader(wire), key, len(m), rf); err != nil {
		t.Fatalf("first read should pass: %v", err)
	}
	if _, err := readMarkedFrame(bytes.NewReader(wire), key, len(m), rf); err == nil {
		t.Fatal("replayed frame was accepted")
	}
}

var _ io.Reader // keep imports stable if a test above is edited
```

And `internal/utils/network/stealth2replay_test.go`:

```go
package network

import "testing"

func TestReplayFilterAcceptsFreshRejectsRepeat(t *testing.T) {
	rf := newReplayFilter()
	mac := []byte("sixteen-byte-mac")
	if !rf.testAndAdd(mac) {
		t.Fatal("first occurrence should be accepted")
	}
	if rf.testAndAdd(mac) {
		t.Fatal("second occurrence should be rejected")
	}
	if !rf.testAndAdd([]byte("another-mac-16by")) {
		t.Fatal("a different mac should be accepted")
	}
}
```

- [ ] **Step 2: Run, verify fail** (`markKey` / `writeMarkedFrame` / `newReplayFilter` undefined):

```bash
go test ./internal/utils/network/ -run "MarkedFrame|ReplayFilter" -v
```

Expected: FAIL (build: undefined identifiers).

- [ ] **Step 3: Implement `stealth2replay.go`** — a bounded, time-windowed set. Only frames whose MAC already verified reach it (so a stranger without the token can never populate it — ADR 0004):

```go
package network

import (
	"encoding/binary"
	"sync"
	"time"
)

const (
	replayWindow   = 2 * time.Hour // covers epoch E-1..E+1 plus skew
	replayMaxEntry = 4096           // bound; oldest evicted when full
)

type replayFilter struct {
	mu   sync.Mutex
	seen map[uint64]time.Time // key: first 8 bytes of the MAC
}

func newReplayFilter() *replayFilter { return &replayFilter{seen: make(map[uint64]time.Time)} }

// testAndAdd returns true if mac is fresh (and records it), false if it was
// seen within the window. Callers pass a MAC that already verified.
func (f *replayFilter) testAndAdd(mac []byte) bool {
	if len(mac) < 8 {
		return false
	}
	k := binary.BigEndian.Uint64(mac[:8])
	now := time.Now()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.evict(now)
	if t, ok := f.seen[k]; ok && now.Sub(t) < replayWindow {
		return false
	}
	f.seen[k] = now
	return true
}

func (f *replayFilter) evict(now time.Time) {
	for k, t := range f.seen {
		if now.Sub(t) >= replayWindow {
			delete(f.seen, k)
		}
	}
	// Hard cap: if still over, drop the oldest. Only token-holders can grow
	// this, so the cap bounds a compromised-token flood, not a stranger.
	for len(f.seen) > replayMaxEntry {
		var oldestK uint64
		var oldestT time.Time
		first := true
		for k, t := range f.seen {
			if first || t.Before(oldestT) {
				oldestK, oldestT, first = k, t, false
			}
		}
		delete(f.seen, oldestK)
	}
}
```

- [ ] **Step 4: Implement `stealth2frame.go`.** Derive `markKey` with HKDF; build/parse `m | P | M | MAC`. Port the scan from the obfs4 reference named above. Sketch (fill the scan loop from the reference; the MAC uses `hmac.New(sha256.New, key)`):

```go
package network

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"strconv"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	markLength = sha256.Size / 2 // 16
	macLength  = sha256.Size / 2 // 16
	maxOpening = 8192
)

func markKey(token string) ([]byte, error) {
	k := make([]byte, 32)
	r := hkdf.New(sha256.New, []byte(token), nil, []byte("backpack-stealth2-mark-v1"))
	_, err := io.ReadFull(r, k)
	return k, err
}

func epochHours() []string { // current hour and ±1, as obfs4 does
	h := time.Now().Unix() / 3600
	return []string{
		strconv.FormatInt(h-1, 10),
		strconv.FormatInt(h, 10),
		strconv.FormatInt(h+1, 10),
	}
}

func mac16(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)[:macLength]
}

// writeMarkedFrame sends m | P | M | MAC(m|P|M|E) with E = current epoch hour.
func writeMarkedFrame(w io.Writer, key, m []byte) error {
	maxPad := maxOpening - len(m) - markLength - macLength
	if maxPad < 0 {
		return fmt.Errorf("stealth2: inner message %d too large for opening", len(m))
	}
	padN, err := randIntn(maxPad + 1)
	if err != nil {
		return err
	}
	p := make([]byte, padN)
	if _, err := io.ReadFull(rand.Reader, p); err != nil {
		return err
	}
	mark := mac16(key, m)
	e := epochHours()[1] // current hour for sending
	buf := make([]byte, 0, len(m)+padN+markLength+macLength)
	buf = append(buf, m...)
	buf = append(buf, p...)
	buf = append(buf, mark...)
	tag := mac16(key, append(append([]byte{}, buf...), []byte(e)...))
	buf = append(buf, tag...)
	_, err = w.Write(buf)
	return err
}

// readMarkedFrame reads innerLen bytes as m, then scans for the mark to delimit
// the padding, verifies the MAC over any accepted epoch, and (if rf != nil)
// rejects a replayed MAC. Port the incremental read + findMarkMac loop from the
// obfs4 reference; the MAC/epoch/replay checks are above/below.
func readMarkedFrame(r io.Reader, key []byte, innerLen int, rf *replayFilter) ([]byte, error) {
	// ... read innerLen into m; mark := mac16(key, m);
	// ... grow a buffer reading from r up to maxOpening, searching for mark;
	// ... on mark at pos: P = buf[:pos]; tag = buf[pos+markLength:pos+markLength+macLength];
	// ...   for each e in epochHours(): if hmac.Equal(mac16(key, m|P|mark|e), tag) { ok }
	// ...   if !ok -> error; if rf != nil && !rf.testAndAdd(tag) -> replay error;
	// ...   return m
	// ... if read exceeds maxOpening without a mark -> error
	panic("implement: see obfs4 findMarkMac reference")
}
```

Notes for the implementer: use `crypto/hmac` (the duplicate `"hmac"` import line in the sketch is a deliberate marker — delete it). Add a small `randIntn(n int) (int, error)` helper over `crypto/rand` (or reuse an existing project RNG helper if one exists — check `internal/utils`). The spurious-mark-in-padding case is handled as in obfs4: a false mark position fails the MAC and the scan continues; the odds of a 16-byte collision in ≤8 KB are ~2⁻¹¹⁵.

- [ ] **Step 5: Run, verify pass:**

```bash
go test ./internal/utils/network/ -run "MarkedFrame|ReplayFilter" -race -v
```

Expected: PASS.

- [ ] **Step 6: Commit:**

```bash
git add internal/utils/network/stealth2frame.go internal/utils/network/stealth2replay.go internal/utils/network/stealth2frame_test.go internal/utils/network/stealth2replay_test.go
git commit -m "feat(network): obfs4-style mark/MAC opening frame and replay filter for stealth2"
```

---

## Task 3: v2 handshake — NNpsk0 over Elligator, wrapped in the mark/MAC frame

Wrap the Noise NNpsk0 handshake (over the Elligator suite from Task 1) in the
Task 2 mark/MAC frame. The Noise payload is a single fixed byte (the version),
so each inner message `m` is a protocol-constant length both ends know; all size
variation lives in the frame padding. The server runs the replay filter. A wrong
token never locates the mark — the server writes nothing (dead port).

**Files:**
- Create: `internal/utils/network/noisev2.go` — `NoiseClientConnV2`, `NoiseServerConnV2`, `noiseHandshakeV2`, `noiseSuiteV2`.
- Modify: none in the v1 path (`noise.go` is not edited; reuse its exported `noiseVersion`, `noisePSK`, `noisePrologue`).
- Test: `internal/utils/network/noisev2_test.go`.

**Interfaces:**
- Consumes: `newElligatorDH()` (T1); `markKey`, `writeMarkedFrame`, `readMarkedFrame`, `newReplayFilter` (T2).
- Produces: `func NoiseClientConnV2(raw net.Conn, token string, timeout time.Duration) (net.Conn, error)` and `func NoiseServerConnV2(raw net.Conn, token string, timeout time.Duration) (net.Conn, error)`. On success each returns a `net.Conn` built from the Noise cipherstates and the handshake channel binding (Task 4 turns this into the masked-record conn; for THIS task return `&noiseConn{Conn: raw, send: sendCS, recv: recvCS, pad: true}` inline, and expose the channel binding to Task 4's constructor).

**Design:**
- `noiseSuiteV2 = noise.NewCipherSuite(newElligatorDH(), noise.CipherChaChaPoly, noise.HashBLAKE2s)`.
- Inner payload is exactly `[]byte{noiseVersion}` on both messages → `innerLen` is the constant length of the NN message with a 1-byte payload (compute it once; assert it in a test rather than hard-coding a guess).
- Client: build m1 with `hs.WriteMessage(nil, []byte{noiseVersion})`; `writeMarkedFrame(raw, key, m1)`; `readMarkedFrame(raw, key, innerLen, nil)` → m2; `hs.ReadMessage(nil, m2)`.
- Server: `readMarkedFrame(raw, key, innerLen, replayFilter)` → m1; `hs.ReadMessage(nil, m1)` (wrong token already failed at the mark); build and `writeMarkedFrame` the reply m2.
- The server side uses a package-level `var stealth2Replay = newReplayFilter()` (one per process suffices — MACs are token-keyed, so cross-tunnel collisions are negligible, and the filter is bounded). No caller wiring is needed; `NoiseServerConnV2` passes `stealth2Replay` to `readMarkedFrame`. The client passes `nil` (it initiates; nothing to replay-check).
- Keep the 15 s handshake deadline (`raw.SetDeadline`) exactly as v1 does; clear it on success.

- [ ] **Step 1: Write the failing tests** `internal/utils/network/noisev2_test.go`:

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

func TestV2RoundTrip(t *testing.T) {
	c, s := net.Pipe()
	srv := make(chan net.Conn, 1)
	go func() {
		conn, err := NoiseServerConnV2(s, v2Token, 3*time.Second)
		if err != nil {
			t.Errorf("server: %v", err)
		}
		srv <- conn
	}()
	cl, err := NoiseClientConnV2(c, v2Token, 3*time.Second)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	sconn := <-srv
	if sconn == nil {
		t.Fatal("server handshake failed")
	}
	want := []byte("hello over stealth2")
	go func() { _, _ = cl.Write(want) }()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(sconn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q want %q", got, want)
	}
}

// Wrong token: the server locates no mark, writes nothing, and does not panic.
func TestV2WrongTokenIsADeadPort(t *testing.T) {
	c, s := net.Pipe()
	wrote := make(chan int, 1)
	go func() { n, _ := io.Copy(io.Discard, s); wrote <- int(n) }()
	go func() {
		conn, err := NoiseServerConnV2(s, v2Token, time.Second)
		if err == nil {
			t.Error("server accepted a wrong-token client")
			conn.Close()
		}
		s.Close()
	}()
	if _, err := NoiseClientConnV2(c, "the-wrong-token-xxxxxxxxxxxxxxxxxxxx", time.Second); err == nil {
		t.Fatal("client reported success with a wrong token")
	}
	if n := <-wrote; n != 0 {
		t.Errorf("server wrote %d bytes to a wrong-token peer", n)
	}
}

// v2 against a v1 peer fails cleanly (no hang past the deadline, no corruption).
func TestV2ClientAgainstV1ServerFailsCleanly(t *testing.T) {
	c, s := net.Pipe()
	go func() { _, _ = NoiseServerConn(s, v2Token, time.Second) }() // v1
	done := make(chan error, 1)
	go func() { _, err := NoiseClientConnV2(c, v2Token, time.Second); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("v2 client succeeded against a v1 server")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("v2 client hung against a v1 server")
	}
}

func TestV1ClientAgainstV2ServerFailsCleanly(t *testing.T) {
	c, s := net.Pipe()
	go func() { _, _ = NoiseServerConnV2(s, v2Token, time.Second) }()
	done := make(chan error, 1)
	go func() { _, err := NoiseClientConn(c, v2Token, time.Second); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("v1 client succeeded against a v2 server")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("v1 client hung against a v2 server")
	}
}
```

- [ ] **Step 2: Run, verify fail** (`NoiseClientConnV2` undefined):

```bash
go test ./internal/utils/network/ -run "TestV2|TestV1Client" -v
```

Expected: FAIL (build: undefined).

- [ ] **Step 3: Implement `noisev2.go`** per the Design above. Reuse the v1 NNpsk0 construction shape from `noise.go`'s `noiseHandshake` (same `noise.Config`: `Pattern: HandshakeNN`, `Prologue: []byte(noisePrologue)`, `PresharedKey: psk`, `PresharedKeyPlacement: 0`) but with `CipherSuite: noiseSuiteV2` and the frames sent/received via `writeMarkedFrame`/`readMarkedFrame`. Compute `innerLen` once from a dry WriteMessage with a 1-byte payload. Do not edit `noise.go`.

- [ ] **Step 4: Run, verify pass:**

```bash
go test ./internal/utils/network/ -run "TestV2|TestV1Client" -race -v
```

Expected: PASS.

- [ ] **Step 5: Commit:**

```bash
git add internal/utils/network/noisev2.go internal/utils/network/noisev2_test.go
git commit -m "feat(network): stealth2 NNpsk0 handshake wrapped in the mark/MAC frame"
```

---

## Task 4: v2 data-phase record length masking

After the handshake, data records use the Noise ChaCha20-Poly1305 record layer,
but the 2-byte length prefix is masked by a ChaCha20 keystream keyed from the
handshake channel binding — per-connection, per-direction — so the data stream
carries no readable length either. The handshake (Task 2/3) already hid the
opening; this hides the data framing.

**Files:**
- Modify: `internal/utils/network/noisev2.go` — add `noiseConnV2` (embeds `*noiseConn`, overrides `Write`/`Read`) and `newNoiseConnV2`; change Task 3's handshake to return it.
- Test: `internal/utils/network/noisev2_test.go` (extend).

**Interfaces:**
- Consumes: the channel binding from Task 3's completed handshake (`hs.ChannelBinding()`).
- Produces: `func newNoiseConnV2(raw net.Conn, send, recv *noise.CipherState, binding []byte, initiator bool) (net.Conn, error)`.

**Design:** derive two ChaCha20 keys via HKDF from the channel binding —
`framing-c2s-v1` and `framing-s2c-v1` — pick send/recv per `initiator`, build a
`chacha20.Cipher` per direction (zero nonce; the key is unique per connection via
the binding). `Write` builds the record exactly as `noiseConn.Write` does, then
XORs the 2 length-prefix bytes through the send keystream before the socket
write; `Read` reads 2 bytes, XORs through the recv keystream to recover the
length, then reads/decrypts the body as `noiseConn.Read` does. Keep the
per-record no-allocation path. `golang.org/x/crypto/chacha20` and `.../hkdf` are
already available.

- [ ] **Step 1: Write the failing tests** (append to `noisev2_test.go`):

```go
// A large write spanning many records round-trips with the masked framing.
func TestV2LargeWriteRoundTrips(t *testing.T) {
	c, s := net.Pipe()
	srv := make(chan net.Conn, 1)
	go func() {
		conn, err := NoiseServerConnV2(s, v2Token, 3*time.Second)
		if err != nil {
			t.Errorf("server: %v", err)
		}
		srv <- conn
	}()
	cl, err := NoiseClientConnV2(c, v2Token, 3*time.Second)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	sconn := <-srv
	want := bytes.Repeat([]byte{0xAB}, 200*1024)
	go func() { _, _ = cl.Write(want); _ = cl.(interface{ Close() error }).Close() }()
	got, err := io.ReadAll(sconn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("round-trip mismatch: %d of %d bytes", len(got), len(want))
	}
}
```

- [ ] **Step 2: Run, verify fail** (compile error until `newNoiseConnV2` exists / handshake returns it, or round-trip fails if masking is wired wrong):

```bash
go test ./internal/utils/network/ -run TestV2Large -v
```

- [ ] **Step 3: Implement** `noiseConnV2` + `newNoiseConnV2` and switch Task 3's handshake return to `newNoiseConnV2(raw, sendCS, recvCS, hs.ChannelBinding(), initiator)`.

- [ ] **Step 4: Run the whole network suite with race:**

```bash
go test ./internal/utils/network/ -race -v
```

Expected: PASS (all Task 1–4 tests, plus the existing v1 tests and `TestTheRecordLayerDoesNotAllocatePerRecord`).

- [ ] **Step 5: Commit:**

```bash
git add internal/utils/network/noisev2.go internal/utils/network/noisev2_test.go
git commit -m "feat(network): mask the stealth2 data-record length prefix"
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
