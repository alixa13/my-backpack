package network

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"time"

	"golang.org/x/crypto/hkdf"
)

// stealth2 opening frame: m | P | M | MAC
//
// Each opening handshake message m is sent as a token-keyed frame that carries
// no readable length, type or constant on the wire:
//
//	m    the fixed-length inner message (its length innerLen is known to a peer
//	     holding the token; it is NOT encoded anywhere in the frame)
//	P    [0, maxOpening-len(m)-markLength-macLength] bytes of random padding
//	M    the mark, HMAC-SHA256-128(markKey, m)
//	MAC  HMAC-SHA256-128(markKey, m | P | M | E), E = current epoch hour string
//
// A peer holding the token derives the same markKey, computes M, and scans the
// bytes after m to find where P ends; it then verifies the MAC over epoch
// E and E±1. A wrong token yields a wrong markKey, so M is never found and the
// port looks dead (ADR 0004). This structure is ported from the vetted obfs4
// handshake (gitlab.com/yawning/obfs4.git .../handshake_ntor.go:
// clientHandshake.generateHandshake, serverHandshake.parseClientHandshake,
// findMarkMac). Differences from obfs4: the HMAC is keyed from the token
// (markKey) rather than serverIdentity|nodeID, and the mark is computed over
// the whole fixed-length message m rather than just the representative X
// (obfs4 marks on X because its payload has no fixed length; ours does).
const (
	markLength = sha256.Size / 2 // 16
	macLength  = sha256.Size / 2 // 16
	maxOpening = 8192
)

var (
	// errOpeningNoMark is returned whenever a frame cannot be validated: no
	// mark located within maxOpening, or the mark was found but no accepted
	// epoch's MAC matched. The two cases are deliberately folded into one
	// error so the caller cannot (and does not) distinguish them and respond
	// differently -- the port stays dead regardless of which check failed.
	errOpeningNoMark = errors.New("stealth2: opening mark/MAC not found")
	// errOpeningReplay is returned when a frame's MAC verified but was already
	// seen inside the replay window.
	errOpeningReplay = errors.New("stealth2: opening replay detected")
)

// markKey derives the 32-byte HMAC key for the opening mark/MAC from the token
// via HKDF-SHA256 with a fixed info string. A different token yields an
// unrelated key, so an observer without the token can neither locate the mark
// nor forge a MAC.
func markKey(token string) ([]byte, error) {
	k := make([]byte, 32)
	r := hkdf.New(sha256.New, []byte(token), nil, []byte("backpack-stealth2-mark-v1"))
	if _, err := io.ReadFull(r, k); err != nil {
		return nil, err
	}
	return k, nil
}

// epochHours returns the current UNIX epoch hour and its ±1 neighbours as
// decimal strings, computed from a single clock read so all three are
// consistent across an hour boundary. Index 1 is the current hour (used when
// sending); a receiver accepts any of the three (as obfs4 does) to tolerate
// clock skew around the boundary.
func epochHours() []string {
	h := time.Now().Unix() / 3600
	return []string{
		strconv.FormatInt(h-1, 10),
		strconv.FormatInt(h, 10),
		strconv.FormatInt(h+1, 10),
	}
}

// mark computes the 16-byte mark HMAC-SHA256-128(key, data).
func mark(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)[:markLength]
}

// frameMAC computes HMAC-SHA256-128(key, m | pm | epoch), where pm is the
// P | M region of the frame (so m|pm == m|P|M, the body the MAC covers). The
// writes are incremental to avoid allocating the concatenation, matching the
// reference's hs.mac.Write sequence.
func frameMAC(key, m, pm, epoch []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(m)
	h.Write(pm)
	h.Write(epoch)
	return h.Sum(nil)[:macLength]
}

// randIntn returns a uniform random int in [0, n) using crypto/rand. For
// n <= 0 it returns 0. (The project has no shared crypto-rand int helper; this
// mirrors the rand.Int(rand.Reader, big.NewInt(...)) pattern used elsewhere.)
func randIntn(n int) (int, error) {
	if n <= 0 {
		return 0, nil
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(v.Int64()), nil
}

// writeMarkedFrame writes m | P | M | MAC(m|P|M|E) to w, where P is random
// padding chosen so the whole frame fits within maxOpening, M = mark(key, m),
// and E is the current epoch hour. It returns an error (and may have written
// nothing) if m is too large to leave room for the mark and MAC.
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

	mk := mark(key, m)

	// body = m | P | M. The MAC covers body | E.
	body := make([]byte, 0, len(m)+padN+markLength)
	body = append(body, m...)
	body = append(body, p...)
	body = append(body, mk...)

	e := epochHours()[1] // current hour for sending
	tag := frameMAC(key, m, body[len(m):], []byte(e))

	frame := make([]byte, 0, len(body)+macLength)
	frame = append(frame, body...)
	frame = append(frame, tag...)

	_, err = w.Write(frame)
	return err
}

// readMarkedFrame reads innerLen bytes as m, then scans the following bytes
// (bounded by maxOpening) for the mark M = mark(key, m) to find where the
// padding P ends. At each mark position it verifies the MAC over m|P|M|E for
// E in {now-1, now, now+1}; a position whose MAC fails all three epochs is
// treated as a spurious match in the random padding and the scan continues
// (the odds of a real 16-byte collision in <=8 KB are ~2^-115). On the first
// position that verifies, if rf != nil the MAC is offered to the replay filter
// and a replay is rejected; otherwise m is returned.
//
// On ANY failure (short read, no mark/MAC within maxOpening, or replay) it
// returns an error and writes nothing back anywhere: the dead-port property.
// It reads only as far as the verified MAC, so it never consumes bytes past
// the frame (nothing follows the opening until the peer responds).
func readMarkedFrame(r io.Reader, key []byte, innerLen int, rf *replayFilter) ([]byte, error) {
	if innerLen < 0 || innerLen+markLength+macLength > maxOpening {
		return nil, fmt.Errorf("stealth2: invalid inner length %d", innerLen)
	}

	m := make([]byte, innerLen)
	if _, err := io.ReadFull(r, m); err != nil {
		return nil, errOpeningNoMark
	}
	mk := mark(key, m)

	// rest holds everything after m: P | M | MAC, bounded by maxRest. We grow
	// it one byte at a time so we stop exactly at the verified MAC and never
	// over-read into whatever the peer sends next (reading ahead on a live
	// connection would block, since the peer waits for our response).
	maxRest := maxOpening - innerLen
	rest := make([]byte, 0, markLength+macLength)
	searchFrom := 0
	one := make([]byte, 1)

	for {
		// Locate the next mark candidate that already has its full trailing
		// MAC in the buffer, continuing past any spurious match.
		for searchFrom <= len(rest)-markLength {
			idx := bytes.Index(rest[searchFrom:], mk)
			if idx < 0 {
				// No full candidate left in the current buffer. Keep only the
				// last markLength-1 bytes as the rescan window: a mark can
				// still straddle into the next byte we read.
				searchFrom = len(rest) - (markLength - 1)
				break
			}
			pos := searchFrom + idx
			if pos+markLength+macLength > len(rest) {
				// Mark found but its MAC is not fully buffered yet; keep
				// searchFrom here so we re-find it after reading more.
				searchFrom = pos
				break
			}
			tag := rest[pos+markLength : pos+markLength+macLength]
			if verifyOpeningMAC(key, m, rest[:pos+markLength], tag) {
				if rf != nil && !rf.testAndAdd(tag) {
					return nil, errOpeningReplay
				}
				return m, nil
			}
			// Spurious mark in the padding: keep scanning.
			searchFrom = pos + 1
		}
		if searchFrom < 0 {
			searchFrom = 0
		}

		if len(rest) >= maxRest {
			return nil, errOpeningNoMark
		}
		n, err := r.Read(one)
		if n > 0 {
			rest = append(rest, one[0])
		}
		if err != nil {
			// EOF or read error before a valid mark+MAC: dead port.
			return nil, errOpeningNoMark
		}
	}
}

// verifyOpeningMAC reports whether tag is a valid MAC for body (= m|P|M, passed
// as m plus pm = P|M) under any accepted epoch. All three epochs are evaluated
// without an early break, to keep the timing independent of which epoch (if
// any) matched, and hmac.Equal is used for the constant-time comparison.
func verifyOpeningMAC(key, m, pm, tag []byte) bool {
	ok := false
	for _, e := range epochHours() {
		cmp := frameMAC(key, m, pm, []byte(e))
		if hmac.Equal(cmp, tag) {
			ok = true
		}
	}
	return ok
}
