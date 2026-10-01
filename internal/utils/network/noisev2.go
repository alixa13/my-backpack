package network

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/hkdf"
)

// The stealth2 handshake: Noise NNpsk0 over an Elligator suite, each message
// carried in the token-keyed mark/MAC opening frame.
//
// v1 (noise.go) opens with a 2-byte length prefix and a raw X25519 point, both
// of which are statistically distinguishable from random bytes. v2 removes both
// tells. The ephemeral keys go out as uniform Elligator2 representatives
// (elligator.go), and the length prefix is gone: every handshake message is a
// fixed, protocol-constant length that both ends compute, so the frame
// (stealth2frame.go) can hide all size variation in its random padding.
//
// The Noise construction is otherwise v1's: same pattern, same prologue, same
// PSK derivation, same cipher and hash. Only the DH function differs.

// noiseSuiteV2 is noiseSuite with the Elligator DH. Like v1's it is fixed, not
// negotiated.
var noiseSuiteV2 = noise.NewCipherSuite(newElligatorDH(), noise.CipherChaChaPoly, noise.HashBLAKE2s)

// stealth2Replay remembers the openings this process has accepted so a recorded
// opening replayed at the server is refused. One filter per process is enough:
// the MACs are keyed by the token, so two tunnels colliding is negligible, and
// the filter is bounded in size and time (stealth2replay.go).
var stealth2Replay = newReplayFilter()

// noiseInnerLenV2 is the length of each inner handshake message m. Both messages
// carry exactly a one-byte payload (the version), so each is DHLen + 1 byte of
// payload + 16 bytes of AEAD tag; rather than hard-code that sum it is measured
// once from a dry handshake, which also proves the two directions agree (the
// frame reader takes a single length for both).
var noiseInnerLenV2 = sync.OnceValues(measureInnerLenV2)

func measureInnerLenV2() (int, error) {
	psk, err := noisePSK("stealth2-inner-length-probe")
	if err != nil {
		return 0, err
	}
	newHS := func(initiator bool) (*noise.HandshakeState, error) {
		return noise.NewHandshakeState(noiseConfigV2(psk, initiator))
	}
	ini, err := newHS(true)
	if err != nil {
		return 0, err
	}
	rsp, err := newHS(false)
	if err != nil {
		return 0, err
	}
	m1, _, _, err := ini.WriteMessage(nil, []byte{noiseVersion})
	if err != nil {
		return 0, err
	}
	if _, _, _, err = rsp.ReadMessage(nil, m1); err != nil {
		return 0, err
	}
	m2, _, _, err := rsp.WriteMessage(nil, []byte{noiseVersion})
	if err != nil {
		return 0, err
	}
	if len(m1) != len(m2) {
		return 0, fmt.Errorf("stealth2: handshake messages differ in length (%d, %d)", len(m1), len(m2))
	}
	return len(m1), nil
}

// noiseConfigV2 is v1's NNpsk0 configuration with the Elligator suite.
func noiseConfigV2(psk []byte, initiator bool) noise.Config {
	return noise.Config{
		CipherSuite:           noiseSuiteV2,
		Pattern:               noise.HandshakeNN,
		Initiator:             initiator,
		Prologue:              []byte(noisePrologue),
		PresharedKey:          psk,
		PresharedKeyPlacement: 0,
	}
}

// noiseKeysV2 is what a completed v2 handshake yields.
type noiseKeysV2 struct {
	send, recv *noise.CipherState
	// binding is the handshake hash: identical at both ends, unique to this
	// session. The masked-record layer derives its per-direction length mask
	// from it, so it must be kept alongside the cipher states.
	binding []byte
}

// NoiseClientConnV2 performs the initiator side of the stealth2 handshake over
// raw and, on success, returns an encrypted net.Conn.
func NoiseClientConnV2(raw net.Conn, token string, timeout time.Duration) (net.Conn, error) {
	k, err := noiseHandshakeV2(raw, token, true, timeout)
	if err != nil {
		return nil, err
	}
	return newNoiseConnV2(raw, k, true)
}

// NoiseServerConnV2 is the responder side of NoiseClientConnV2.
func NoiseServerConnV2(raw net.Conn, token string, timeout time.Duration) (net.Conn, error) {
	k, err := noiseHandshakeV2(raw, token, false, timeout)
	if err != nil {
		return nil, err
	}
	return newNoiseConnV2(raw, k, false)
}

// newNoiseConnV2 builds the post-handshake conn: v1's padded record layer with
// the length prefix of every record masked (noiseConnV2). initiator says which
// end this is, which decides which of the two directional masks sends and which
// receives.
func newNoiseConnV2(raw net.Conn, k *noiseKeysV2, initiator bool) (net.Conn, error) {
	sendMask, recvMask, err := newFramingMasks(k.binding, initiator)
	if err != nil {
		return nil, err
	}
	return &noiseConnV2{
		noiseConn: &noiseConn{Conn: raw, send: k.send, recv: k.recv, pad: true},
		sendMask:  sendMask,
		recvMask:  recvMask,
	}, nil
}

// The data phase hides its record lengths too.
//
// The opening carries no length at all (stealth2frame.go), but a Noise record
// layer puts a two-byte big-endian length in front of every record, and that is
// as recognisable as the handshake's was: the value is small and structured, it
// is readable straight off the wire, and a run of them is a faithful transcript
// of the record sizes. So the prefix is XORed with a ChaCha20 keystream before it
// is sent, and the receiver XORs it back. The keystream is not a second cipher
// over the record -- the AEAD still protects that -- it is only a mask over these
// two bytes, so what an observer sees at each record boundary is uniform.
//
// The mask is keyed from the handshake's channel binding, which is unique to this
// connection, so the nonce can be left at zero without ever reusing a (key,
// nonce) pair. There is one key per direction: with a shared keystream, XORing a
// client prefix with a server prefix would cancel it and leave the XOR of the two
// lengths.
const (
	framingLabelC2S = "backpack-stealth2-framing-c2s-v1"
	framingLabelS2C = "backpack-stealth2-framing-s2c-v1"
)

// newFramingMask returns the keystream for one direction of one session.
func newFramingMask(binding []byte, label string) (*chacha20.Cipher, error) {
	key := make([]byte, chacha20.KeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, binding, nil, []byte(label)), key); err != nil {
		return nil, err
	}
	return chacha20.NewUnauthenticatedCipher(key, make([]byte, chacha20.NonceSize))
}

// newFramingMasks returns the send and receive masks for an end of the
// connection. The initiator sends client-to-server and receives server-to-client;
// the responder is the mirror, so each end's send mask is the other's receive
// mask.
func newFramingMasks(binding []byte, initiator bool) (send, recv *chacha20.Cipher, err error) {
	if len(binding) == 0 {
		return nil, nil, fmt.Errorf("stealth2: no channel binding to key the record framing")
	}
	c2s, err := newFramingMask(binding, framingLabelC2S)
	if err != nil {
		return nil, nil, err
	}
	s2c, err := newFramingMask(binding, framingLabelS2C)
	if err != nil {
		return nil, nil, err
	}
	if initiator {
		return c2s, s2c, nil
	}
	return s2c, c2s, nil
}

// noiseConnV2 is noiseConn with the record length prefix masked. It reuses
// everything else -- the cipher states, the padding, the reused frame buffer --
// and overrides only the two methods that touch the prefix.
//
// The masks are stateful: each record consumes two bytes of keystream per
// direction, so the n-th record in a direction is always masked with the n-th two
// bytes of that direction's stream. That holds because records go out and come in
// in order under writeMu and readMu, and the mask is advanced under the same lock
// as the wire write / read it belongs to.
type noiseConnV2 struct {
	*noiseConn

	sendMask *chacha20.Cipher // guarded by writeMu
	recvMask *chacha20.Cipher // guarded by readMu
}

// Write is noiseConn.Write with the length prefix masked on its way out. The
// record is still built in place in frameBuf and sent with a single write, so
// masking adds no allocation.
func (c *noiseConnV2) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	limit := noiseMaxPayload
	if c.pad {
		limit = noisePaddedMaxPayload
	}

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > limit {
			chunk = chunk[:limit]
		}
		c.frameBuf = append(c.frameBuf[:0], 0, 0)
		frame, err := c.send.Encrypt(c.frameBuf, nil, c.plaintext(chunk))
		if err != nil {
			return total, err
		}
		c.frameBuf = frame
		if len(frame)-noiseLenPrefix > noiseMaxFrame {
			return total, fmt.Errorf("noise: message too large (%d bytes)", len(frame)-noiseLenPrefix)
		}
		binary.BigEndian.PutUint16(frame[:noiseLenPrefix], uint16(len(frame)-noiseLenPrefix))
		// Masked last, immediately before the write, so every failure above
		// leaves the keystream where the peer expects it.
		c.sendMask.XORKeyStream(frame[:noiseLenPrefix], frame[:noiseLenPrefix])
		if _, err := c.Conn.Write(frame); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// Read is noiseConn.Read with the length prefix unmasked on its way in.
func (c *noiseConnV2) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.readBuf) == 0 {
		frame, err := c.readRecord()
		if err != nil {
			return 0, err
		}
		plain, err := c.recv.Decrypt(nil, nil, frame)
		if err != nil {
			return 0, fmt.Errorf("noise: record failed authentication: %w", err)
		}
		if plain, err = c.unpad(plain); err != nil {
			return 0, err
		}
		c.readBuf = plain
	}

	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

// readRecord reads one record's ciphertext: the masked length, then that many
// bytes. The caller holds readMu. The mask advances only once the whole prefix
// has been read, so an error before then leaves it in step with the peer.
func (c *noiseConnV2) readRecord() ([]byte, error) {
	var hdr [noiseLenPrefix]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		return nil, err
	}
	c.recvMask.XORKeyStream(hdr[:], hdr[:])
	n := binary.BigEndian.Uint16(hdr[:])
	if n == 0 {
		return nil, fmt.Errorf("noise: empty frame")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.Conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func noiseHandshakeV2(raw net.Conn, token string, initiator bool, timeout time.Duration) (*noiseKeysV2, error) {
	psk, err := noisePSK(token)
	if err != nil {
		return nil, err
	}
	key, err := markKey(token)
	if err != nil {
		return nil, err
	}
	innerLen, err := noiseInnerLenV2()
	if err != nil {
		return nil, err
	}
	hs, err := noise.NewHandshakeState(noiseConfigV2(psk, initiator))
	if err != nil {
		return nil, err
	}

	if timeout <= 0 {
		timeout = noiseHandshakeTimeout
	}
	// A deadline for the whole handshake, as in v1; cleared once it completes.
	_ = raw.SetDeadline(time.Now().Add(timeout))

	var k *noiseKeysV2
	if initiator {
		k, err = clientHandshakeV2(raw, hs, key, innerLen)
	} else {
		k, err = serverHandshakeV2(raw, hs, key, innerLen)
		if err != nil {
			// The responder fails the same way whatever went wrong. See
			// holdDeadPort.
			holdDeadPort(raw)
		}
	}
	if err != nil {
		return nil, err
	}

	_ = raw.SetDeadline(time.Time{})
	return k, nil
}

// clientHandshakeV2 runs the initiator's half. The client talks first and has
// nothing to replay-check, so it reads with no replay filter.
func clientHandshakeV2(raw net.Conn, hs *noise.HandshakeState, key []byte, innerLen int) (*noiseKeysV2, error) {
	// -> psk, e
	m1, _, _, err := hs.WriteMessage(nil, []byte{noiseVersion})
	if err != nil {
		return nil, fmt.Errorf("noise: build first message: %w", err)
	}
	if err := writeMarkedFrame(raw, key, m1); err != nil {
		return nil, err
	}
	// <- e, ee
	m2, err := readMarkedFrame(raw, key, innerLen, nil)
	if err != nil {
		return nil, err
	}
	payload, cs0, cs1, err := hs.ReadMessage(nil, m2)
	if err != nil {
		return nil, fmt.Errorf("noise: handshake rejected: %w", err)
	}
	if err := checkPayloadV2(payload); err != nil {
		return nil, err
	}
	if cs0 == nil || cs1 == nil {
		return nil, fmt.Errorf("noise: handshake did not complete")
	}
	// The initiator sends with cs0 and receives with cs1.
	return &noiseKeysV2{send: cs0, recv: cs1, binding: append([]byte(nil), hs.ChannelBinding()...)}, nil
}

// serverHandshakeV2 runs the responder's half. It writes to raw exactly once,
// and only after the opening has been located, authenticated and found fresh
// and the Noise message has been accepted: every earlier failure returns
// without a byte having gone back to the peer.
func serverHandshakeV2(raw net.Conn, hs *noise.HandshakeState, key []byte, innerLen int) (*noiseKeysV2, error) {
	// -> psk, e
	//
	// readMarkedFrame fails identically for no mark, a bad MAC and a replay.
	// Nothing here inspects which it was.
	m1, err := readMarkedFrame(raw, key, innerLen, stealth2Replay)
	if err != nil {
		return nil, err
	}
	payload, _, _, err := hs.ReadMessage(nil, m1)
	if err != nil {
		return nil, fmt.Errorf("noise: handshake rejected: %w", err)
	}
	if err := checkPayloadV2(payload); err != nil {
		return nil, err
	}
	// <- e, ee
	m2, cs0, cs1, err := hs.WriteMessage(nil, []byte{noiseVersion})
	if err != nil {
		return nil, fmt.Errorf("noise: build reply: %w", err)
	}
	if cs0 == nil || cs1 == nil {
		return nil, fmt.Errorf("noise: handshake did not complete")
	}
	if err := writeMarkedFrame(raw, key, m2); err != nil {
		return nil, err
	}
	// The responder sends with cs1 and receives with cs0.
	return &noiseKeysV2{send: cs1, recv: cs0, binding: append([]byte(nil), hs.ChannelBinding()...)}, nil
}

// checkPayloadV2 requires the peer's handshake payload to be the single version
// byte this build speaks. The payload is already authenticated by the time this
// runs; this only keeps the two ends in step on the one thing it carries.
func checkPayloadV2(payload []byte) error {
	if len(payload) != 1 || payload[0] != noiseVersion {
		return fmt.Errorf("noise: unexpected handshake payload")
	}
	return nil
}

// holdDeadPort is how the responder ends every failed opening: it reads and
// discards whatever the peer sends until the handshake deadline passes or the
// peer hangs up, and sends nothing.
//
// It is the same for every failure on purpose. readMarkedFrame returns at
// different moments for different failures -- a replay the instant its MAC
// verifies, a wrong token only once it has run out of bytes or time -- so
// returning straight away (and letting the caller close the connection) would
// let a prober tell a replayed opening from a wrong-token one by how long the
// port stayed open. Draining until the one deadline set at the top of the
// handshake gives them all the same observable behaviour: silence, then a close
// at the timeout (or sooner only if the peer closes first).
func holdDeadPort(raw net.Conn) {
	_, _ = io.Copy(io.Discard, raw)
}
