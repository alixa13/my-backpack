package transport

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/backpack/backpack/internal/utils/network"
)

// wrapStealth has to pick the record layer the tunnel's transport name asked
// for, and the server has to be able to read it. stealth and stealth2 differ
// only in the opening: if the modes were swapped, or two of them shared a
// constructor, one pairing here would fail its handshake.
func TestWrapStealthSelectsTheRecordLayerForItsMode(t *testing.T) {
	const token = "a-token"
	for _, tc := range []struct {
		name   string
		mode   StealthMode
		server func(net.Conn, string, time.Duration) (net.Conn, error)
		wraps  bool
	}{
		{"off", StealthOff, nil, false},
		{"v1", StealthV1, network.NoiseServerConn, true},
		{"v2", StealthV2, network.NoiseServerConnV2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cli, srv := net.Pipe()
			defer cli.Close()
			defer srv.Close()

			type result struct {
				conn net.Conn
				err  error
			}
			peer := make(chan result, 1)
			go func() {
				if tc.server == nil {
					peer <- result{conn: srv}
					return
				}
				c, err := tc.server(srv, token, 5*time.Second)
				peer <- result{c, err}
			}()

			tr := &TcpTransport{config: &TcpConfig{Token: token, DialTimeOut: 5 * time.Second, Stealth: tc.mode}}
			wrapped, err := tr.wrapStealth(cli)
			if err != nil {
				t.Fatalf("wrapStealth(%s): %v", tc.name, err)
			}
			if (wrapped != cli) != tc.wraps {
				t.Fatalf("wrapStealth(%s) wrapped = %v, want %v", tc.name, wrapped != cli, tc.wraps)
			}

			p := <-peer
			if p.err != nil {
				t.Fatalf("the server could not complete the %s handshake: %v", tc.name, p.err)
			}

			go func() { _, _ = wrapped.Write([]byte("ping")) }()
			buf := make([]byte, 4)
			_ = p.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(p.conn, buf); err != nil || string(buf) != "ping" {
				t.Fatalf("a record written through the %s layer did not arrive: %q, %v", tc.name, buf, err)
			}
		})
	}
}

// A mode wrapStealth does not know is not plain TCP. If it fell through to
// returning the connection, a tunnel configured for a layer this code cannot
// speak would carry its traffic in the clear and look healthy; it has to
// refuse, and hand back no connection to use.
func TestWrapStealthRefusesAnUnknownMode(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()

	tr := &TcpTransport{config: &TcpConfig{Token: "a-token", DialTimeOut: time.Second, Stealth: StealthMode(99)}}
	conn, err := tr.wrapStealth(cli)
	if err == nil {
		t.Fatal("wrapStealth accepted an unknown stealth mode")
	}
	if conn != nil {
		t.Fatalf("wrapStealth returned a connection (%v) alongside the error for an unknown mode", conn)
	}
}
