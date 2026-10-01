package network

import (
	"encoding/binary"
	"sync"
	"time"
)

// Replay protection for the stealth2 opening frame.
//
// Only a MAC that has already verified under the token-derived markKey ever
// reaches this filter (see readMarkedFrame): a stranger without the token can
// never forge a valid mark+MAC, so they can never populate it (ADR 0004). The
// filter is therefore bounded in both size and time against, at worst, a
// compromised-token flood -- not against arbitrary network input.
const (
	// replayWindow must outlast the full wall-clock span over which a frame is
	// accepted, or an entry could be evicted while the same frame is still
	// acceptable and would then replay as "fresh". A frame labelled with epoch
	// hour w is accepted whenever the receiver's own clock-hour is in
	// {w-1, w, w+1}, i.e. across the ~3h span [(w-1)*3600, (w+2)*3600). In the
	// skew case the first legitimate receipt can be as early as receiver-hour
	// w-1, so the entry must survive ~3h from first-seen; 4h covers that span
	// plus margin. (The brief's 2h was an illustrative sketch; the binding
	// constraint is only that the filter be bounded in time.)
	replayWindow   = 4 * time.Hour
	replayMaxEntry = 4096 // hard bound; oldest evicted when full
)

type replayFilter struct {
	mu   sync.Mutex
	seen map[uint64]time.Time // key: first 8 bytes of the MAC
}

func newReplayFilter() *replayFilter {
	return &replayFilter{seen: make(map[uint64]time.Time)}
}

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

// evict drops entries older than the window and, if still over the hard cap,
// drops the oldest entries until within the cap. Caller holds f.mu.
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
