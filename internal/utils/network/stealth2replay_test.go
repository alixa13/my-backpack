package network

import "testing"

func TestReplayFilterAcceptsFreshRejectsRepeat(t *testing.T) {
	rf := newReplayFilter()
	mac := []byte("sixteen-byte-mac")
	if !rf.testAndAdd(mac) {
		t.Fatal("first occurrence should be accepted")
	}
	if rf.testAndAdd(mac) {
		t.Fatal("second occurrence should be rejected")
	}
	if !rf.testAndAdd([]byte("another-mac-16by")) {
		t.Fatal("a different mac should be accepted")
	}
}
