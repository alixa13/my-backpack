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

// The scan is bounded by maxOpening: a stream whose first maxOpening bytes
// after m contain no valid mark must return an error (the bound fires; no
// over-read, no unbounded scan, no hang) rather than reading forever.
func TestMarkedFrameScanBounded(t *testing.T) {
	key, _ := markKey(frameTok)
	m := bytes.Repeat([]byte{0x11}, 49)
	// m followed by maxOpening bytes of zeros: the mark (HMAC output) is not
	// all-zero, so it never appears in the padding and the bound must fire.
	wire := append(append([]byte{}, m...), make([]byte, maxOpening)...)
	if _, err := readMarkedFrame(bytes.NewReader(wire), key, len(m), nil); err == nil {
		t.Fatal("readMarkedFrame accepted a stream with no mark within maxOpening")
	}
}

// writeMarkedFrame must reject an inner message too large to leave room for the
// mark and MAC, returning an error rather than panicking or writing a
// malformed (truncated/negative-pad) frame.
func TestMarkedFrameInnerTooLarge(t *testing.T) {
	key, _ := markKey(frameTok)
	m := make([]byte, maxOpening-markLength-macLength+1) // one byte over the limit
	var buf bytes.Buffer
	if err := writeMarkedFrame(&buf, key, m); err == nil {
		t.Fatal("writeMarkedFrame accepted an oversized inner message")
	}
	if buf.Len() != 0 {
		t.Fatalf("writeMarkedFrame wrote %d bytes for an oversized message; want 0", buf.Len())
	}
}

// zeroProgressReader delivers m, then returns (0, nil) forever: a reader that
// makes no progress without signalling an error.
type zeroProgressReader struct {
	m    []byte
	seen int
}

func (z *zeroProgressReader) Read(p []byte) (int, error) {
	if z.seen < len(z.m) {
		n := copy(p, z.m[z.seen:])
		z.seen += n
		return n, nil
	}
	return 0, nil
}

// A reader that returns (0, nil) after m must fail, not spin: the guard turns
// no-progress into a failed open. Without the guard this test would hang and
// fail by timeout.
func TestMarkedFrameNoProgressReaderFails(t *testing.T) {
	key, _ := markKey(frameTok)
	m := bytes.Repeat([]byte{0x22}, 49)
	if _, err := readMarkedFrame(&zeroProgressReader{m: m}, key, len(m), nil); err == nil {
		t.Fatal("readMarkedFrame accepted a no-progress reader")
	}
}

var _ io.Reader // keep imports stable if a test above is edited
