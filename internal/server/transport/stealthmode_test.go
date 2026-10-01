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
// interoperate, so a v2 client reaching a v1 listener, and a v1 client reaching
// a v2 listener, are each refused at the handshake and never filed. Neither
// side is left waiting: the listener gives up on the connection (the v2
// listener only once the dialler hangs up, since it answers a failed opening
// with silence) and the dialler is told it did not connect.
func TestAdmitTunnelConnRefusesAPeerOfTheOtherVersion(t *testing.T) {
	const token = "a-token"
	for _, tc := range []struct {
		name     string
		listener StealthMode
		dial     func(net.Conn, string, time.Duration) (net.Conn, error)
	}{
		{"v2 client at a v1 listener", StealthV1, network.NoiseClientConnV2},
		{"v1 client at a v2 listener", StealthV2, network.NoiseClientConn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, g := newTestTransport(token)
			s.config.Stealth = tc.listener

			nonce, _ := network.NewPoolNonce()
			s.poolNonce.Set(nonce)
			_, controlServerSide := connPair(t, "127.0.0.1")
			s.controlChannel.Set(controlServerSide)

			clientSide, serverSide := connPair(t, "127.0.0.1")
			dialErr := make(chan error, 1)
			go func() {
				defer clientSide.Close()
				c, err := tc.dial(clientSide, token, 500*time.Millisecond)
				if err == nil {
					_ = utils.SendBinaryTransportString(c, nonce, utils.SG_Pool)
				}
				dialErr <- err
			}()

			done := make(chan struct{})
			go func() { defer close(done); s.admitTunnelConn(g, serverSide) }()

			select {
			case <-g.tunnelChannel:
				t.Fatal("a client of the other version was admitted")
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the listener never gave up on an opening of the other version")
			}

			select {
			case err := <-dialErr:
				if err == nil {
					t.Fatal("the client believes it completed a handshake with a listener of the other version")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the client was left waiting on a listener of the other version")
			}
			select {
			case <-g.tunnelChannel:
				t.Fatal("a client of the other version was filed after the refusal")
			default:
			}
		})
	}
}

// A mode the server does not know is not plain TCP either. The handshake has to
// refuse it, and admitTunnelConn has to close the connection instead of filing
// it, so a listener misconfigured for a layer it cannot speak never accepts
// tunnel traffic in the clear.
func TestAnUnknownStealthModeAdmitsNothing(t *testing.T) {
	const token = "a-token"
	s, g := newTestTransport(token)
	s.config.Stealth = StealthMode(99)

	t.Run("handshake", func(t *testing.T) {
		cli, srv := net.Pipe()
		defer cli.Close()
		defer srv.Close()
		conn, err := s.stealthHandshake(srv)
		if err == nil {
			t.Fatal("stealthHandshake accepted an unknown stealth mode")
		}
		if conn != nil {
			t.Fatalf("stealthHandshake returned a connection (%v) alongside the error for an unknown mode", conn)
		}
	})

	t.Run("admit", func(t *testing.T) {
		nonce, _ := network.NewPoolNonce()
		s.poolNonce.Set(nonce)
		_, controlServerSide := connPair(t, "127.0.0.1")
		s.controlChannel.Set(controlServerSide)

		clientSide, serverSide := connPair(t, "127.0.0.1")
		defer clientSide.Close()

		done := make(chan struct{})
		go func() { defer close(done); s.admitTunnelConn(g, serverSide) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("admitTunnelConn held a connection for a stealth mode it does not know")
		}
		select {
		case <-g.tunnelChannel:
			t.Fatal("a connection was filed under a stealth mode the server does not know")
		default:
		}
		// The server closed its side, so the peer reads EOF rather than waiting.
		_ = clientSide.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := clientSide.Read(make([]byte, 1)); err == nil {
			t.Fatal("the connection was left open for a stealth mode the server does not know")
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatalf("the connection was not closed: %v", err)
		}
	})
}
