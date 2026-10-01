package network

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/flynn/noise"
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

// writeCounter counts the bytes a conn is asked to write, whether or not the
// peer ever reads them, so a test can assert "the server sent nothing".
type writeCounter struct {
	net.Conn
	n atomic.Int64
}

func (w *writeCounter) Write(p []byte) (int, error) {
	w.n.Add(int64(len(p)))
	return w.Conn.Write(p)
}

// Wrong token: the server locates no mark, writes nothing, and does not panic.
//
// The server end is wrapped in a writeCounter. (The brief's version of this test
// drained s with io.Copy and asserted on the count, but s is the server's end:
// that goroutine competes with the server for the client's bytes and its count is
// bytes the *client* sent, not bytes the server wrote.)
func TestV2WrongTokenIsADeadPort(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	sc := &writeCounter{Conn: s}
	srvErr := make(chan error, 1)
	go func() {
		conn, err := NoiseServerConnV2(sc, v2Token, time.Second)
		if err == nil {
			conn.Close()
		}
		s.Close()
		srvErr <- err
	}()
	if _, err := NoiseClientConnV2(c, "the-wrong-token-xxxxxxxxxxxxxxxxxxxx", time.Second); err == nil {
		t.Fatal("client reported success with a wrong token")
	}
	if err := <-srvErr; err == nil {
		t.Error("server accepted a wrong-token client")
	}
	if n := sc.n.Load(); n != 0 {
		t.Errorf("server wrote %d bytes to a wrong-token peer", n)
	}
}

// The inner message length is measured, not guessed: it must equal what a real
// handshake puts on the wire in BOTH directions, and equal DHLen + 1-byte
// payload + AEAD tag.
func TestV2InnerLen(t *testing.T) {
	got, err := noiseInnerLenV2()
	if err != nil {
		t.Fatal(err)
	}
	const tag = 16
	if want := newElligatorDH().DHLen() + 1 + tag; got != want {
		t.Errorf("innerLen = %d, want DHLen+1+tag = %d", got, want)
	}

	psk, _ := noisePSK(v2Token)
	ini, err := noise.NewHandshakeState(noiseConfigV2(psk, true))
	if err != nil {
		t.Fatal(err)
	}
	rsp, err := noise.NewHandshakeState(noiseConfigV2(psk, false))
	if err != nil {
		t.Fatal(err)
	}
	m1, _, _, err := ini.WriteMessage(nil, []byte{noiseVersion})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := rsp.ReadMessage(nil, m1); err != nil {
		t.Fatal(err)
	}
	m2, _, _, err := rsp.WriteMessage(nil, []byte{noiseVersion})
	if err != nil {
		t.Fatal(err)
	}
	if len(m1) != got || len(m2) != got {
		t.Errorf("wire messages are %d and %d bytes, innerLen is %d", len(m1), len(m2), got)
	}
}

// Both ends of a completed handshake hold the same channel binding, and it is
// reachable from the handshake's result for the record layer to use.
func TestV2ChannelBindingAgrees(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	type res struct {
		k   *noiseKeysV2
		err error
	}
	srv := make(chan res, 1)
	go func() {
		k, err := noiseHandshakeV2(s, v2Token, false, 3*time.Second)
		srv <- res{k, err}
	}()
	ck, err := noiseHandshakeV2(c, v2Token, true, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r := <-srv
	if r.err != nil {
		t.Fatal(r.err)
	}
	if len(ck.binding) == 0 || !bytes.Equal(ck.binding, r.k.binding) {
		t.Errorf("channel bindings differ or are empty: %x vs %x", ck.binding, r.k.binding)
	}
}

// recordConn remembers what is written through it, so a test can capture the
// client's opening and replay it.
type recordConn struct {
	net.Conn
	mu  sync.Mutex
	buf []byte
}

func (r *recordConn) Write(p []byte) (int, error) {
	r.mu.Lock()
	r.buf = append(r.buf, p...)
	r.mu.Unlock()
	return r.Conn.Write(p)
}

// probe feeds opening to a fresh v2 server, holds the client end open, and
// reports what the server did: how long until it gave up, how many bytes it
// sent, and why it failed.
func probe(t *testing.T, opening []byte, timeout time.Duration) (elapsed time.Duration, wrote int64, err error) {
	t.Helper()
	c, s := net.Pipe()
	defer c.Close()
	sc := &writeCounter{Conn: s}
	type result struct {
		err     error
		elapsed time.Duration
	}
	done := make(chan result, 1)
	go func() {
		start := time.Now()
		conn, err := NoiseServerConnV2(sc, v2Token, timeout)
		if err == nil {
			conn.Close()
		}
		done <- result{err, time.Since(start)}
	}()
	// The prober sends its opening and then just waits, reading nothing.
	go func() { _, _ = c.Write(opening) }()
	select {
	case r := <-done:
		s.Close()
		return r.elapsed, sc.n.Load(), r.err
	case <-time.After(timeout + 5*time.Second):
		t.Fatal("server did not give up")
		return
	}
}

// M1 (Task 2 review): a replayed opening must be indistinguishable on the wire
// from a wrong-token one -- no reply, and the port held open for the same time
// before it is dropped. Returning the instant a replay is detected would let a
// prober tell the two apart by timing.
func TestV2ReplayLooksLikeWrongToken(t *testing.T) {
	// Capture a genuine opening by running a real handshake.
	c, s := net.Pipe()
	rec := &recordConn{Conn: c}
	srv := make(chan error, 1)
	go func() {
		conn, err := NoiseServerConnV2(s, v2Token, 3*time.Second)
		if err == nil {
			conn.Close()
		}
		srv <- err
	}()
	cl, err := NoiseClientConnV2(rec, v2Token, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-srv; err != nil {
		t.Fatal(err)
	}
	cl.Close()
	s.Close()
	rec.mu.Lock()
	opening := append([]byte(nil), rec.buf...)
	rec.mu.Unlock()
	if len(opening) == 0 {
		t.Fatal("captured no opening")
	}

	// The same bytes, replayed; a well-formed frame under the wrong token; and
	// pure noise of the same length.
	wrongKey, _ := markKey("the-wrong-token-xxxxxxxxxxxxxxxxxxxx")
	m := make([]byte, 49)
	_, _ = rand.Read(m)
	var wrongFrame bytes.Buffer
	if err := writeMarkedFrame(&wrongFrame, wrongKey, m); err != nil {
		t.Fatal(err)
	}
	junk := make([]byte, len(opening))
	_, _ = rand.Read(junk)

	const timeout = 500 * time.Millisecond
	cases := []struct {
		name    string
		opening []byte
		wantErr error
	}{
		{"replay", opening, errOpeningReplay},
		{"wrong-token", wrongFrame.Bytes(), errOpeningNoMark},
		{"noise", junk, errOpeningNoMark},
	}
	for _, tc := range cases {
		elapsed, wrote, err := probe(t, tc.opening, timeout)
		if !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: err = %v, want %v (the probe is not exercising the intended path)", tc.name, err, tc.wantErr)
		}
		if wrote != 0 {
			t.Errorf("%s: server wrote %d bytes", tc.name, wrote)
		}
		// Held until the handshake deadline, not dropped early.
		if elapsed < timeout*8/10 {
			t.Errorf("%s: server gave up after %v, well before the %v deadline", tc.name, elapsed, timeout)
		}
		t.Logf("%s: held %v, wrote %d, err %v", tc.name, elapsed.Round(time.Millisecond), wrote, err)
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
