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
