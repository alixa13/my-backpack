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
