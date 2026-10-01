package transport

import (
	"net"
	"testing"
	"time"

	"github.com/backpack/backpack/internal/utils"
	"github.com/backpack/backpack/internal/utils/network"
)

// admitTunnelConn has to complete the handshake of the record layer the
// transport's mode names, and file the connection only once it has. The pool
// nonce is announced through the layer, so a connection that reaches the pool
// has been read through it.
func TestAdmitTunnelConnCompletesTheHandshakeOfItsMode(t *testing.T) {
	const token = "a-token"
	for _, tc := range []struct {
		name   string
		mode   StealthMode
		client func(net.Conn, string, time.Duration) (net.Conn, error)
	}{
		{"v1", StealthV1, network.NoiseClientConn},
		{"v2", StealthV2, network.NoiseClientConnV2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, g := newTestTransport(token)
			s.config.Stealth = tc.mode

			nonce, err := network.NewPoolNonce()
			if err != nil {
				t.Fatalf("NewPoolNonce: %v", err)
			}
			s.poolNonce.Set(nonce)
			// The control channel is already up, so this connection is a pool
			// connection announcing itself.
			_, controlServerSide := connPair(t, "127.0.0.1")
			s.controlChannel.Set(controlServerSide)

			clientSide, serverSide := connPair(t, "127.0.0.1")
			go func() {
				c, err := tc.client(clientSide, token, 5*time.Second)
				if err != nil {
					return
				}
				_ = utils.SendBinaryTransportString(c, nonce, utils.SG_Pool)
			}()

			go s.admitTunnelConn(g, serverSide)

			select {
			case admitted := <-g.tunnelChannel:
				if admitted == serverSide {
					t.Fatalf("the %s pool connection was filed without the record layer over it", tc.name)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("a %s client that completed the handshake was not admitted", tc.name)
			}
		})
	}
}

// A peer of the other version is not a peer: stealth and stealth2 do not
// interoperate, so a v2 client reaching a v1 listener (or the reverse) is
// refused at the handshake, never filed.
func TestAdmitTunnelConnRefusesAPeerOfTheOtherVersion(t *testing.T) {
	const token = "a-token"
	s, g := newTestTransport(token)
	s.config.Stealth = StealthV1

	nonce, _ := network.NewPoolNonce()
	s.poolNonce.Set(nonce)
	_, controlServerSide := connPair(t, "127.0.0.1")
	s.controlChannel.Set(controlServerSide)

	clientSide, serverSide := connPair(t, "127.0.0.1")
	go func() {
		defer clientSide.Close()
		if c, err := network.NoiseClientConnV2(clientSide, token, 500*time.Millisecond); err == nil {
			_ = utils.SendBinaryTransportString(c, nonce, utils.SG_Pool)
		}
	}()

	done := make(chan struct{})
	go func() { defer close(done); s.admitTunnelConn(g, serverSide) }()

	select {
	case <-g.tunnelChannel:
		t.Fatal("a v2 client was admitted by a v1 listener")
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the v1 listener never gave up on a v2 opening")
	}
}
