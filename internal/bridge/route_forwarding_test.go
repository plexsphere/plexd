package bridge

import "testing"

var (
	bridgePair = forwardingPair{"plexd0", "en1"}
	accessPair = forwardingPair{"wg-access", "en1"}
)

func TestForwardingLedger_FirstHolderSavesState(t *testing.T) {
	l := newForwardingLedger[string]()

	l.acquire("forwarding", bridgePair, "0")
	if !l.held("forwarding") {
		t.Fatal("held() = false after acquire, want true")
	}

	before, last := l.release("forwarding", bridgePair)
	if !last {
		t.Fatal("release() last = false for the only holder, want true")
	}
	if before != "0" {
		t.Errorf("release() before = %q, want %q", before, "0")
	}
	if l.held("forwarding") {
		t.Error("held() = true after the last holder released, want false")
	}
}

func TestForwardingLedger_SecondHolderKeepsSavedState(t *testing.T) {
	l := newForwardingLedger[string]()

	l.acquire("forwarding", bridgePair, "0")
	// The second pair reads the knob after the first already switched it on,
	// so its "before" is the value the first pair wrote. Keeping it would
	// restore forwarding to on, never off.
	l.acquire("forwarding", accessPair, "1")

	before, last := l.release("forwarding", bridgePair)
	if last {
		t.Error("release() last = true while another pair holds the knob, want false")
	}
	if before != "" {
		t.Errorf("release() before = %q for a non-last holder, want the zero value", before)
	}
	if !l.held("forwarding") {
		t.Error("held() = false while a pair still holds the knob, want true")
	}

	before, last = l.release("forwarding", accessPair)
	if !last {
		t.Fatal("release() last = false for the final holder, want true")
	}
	if before != "0" {
		t.Errorf("release() before = %q, want the first holder's %q", before, "0")
	}
}

func TestForwardingLedger_RepeatedAcquireIsOnce(t *testing.T) {
	l := newForwardingLedger[string]()

	l.acquire("forwarding", bridgePair, "0")
	l.acquire("forwarding", bridgePair, "1")

	before, last := l.release("forwarding", bridgePair)
	if !last {
		t.Fatal("release() last = false after a repeated acquire by one pair, want true")
	}
	if before != "0" {
		t.Errorf("release() before = %q, want the first acquire's %q", before, "0")
	}
}

func TestForwardingLedger_ReleaseUnknownPair(t *testing.T) {
	l := newForwardingLedger[string]()

	before, last := l.release("forwarding", bridgePair)
	if last || before != "" {
		t.Errorf("release() on an empty ledger = (%q, %v), want (\"\", false)", before, last)
	}

	l.acquire("forwarding", bridgePair, "0")

	before, last = l.release("forwarding", accessPair)
	if last || before != "" {
		t.Errorf("release() of a pair that never acquired = (%q, %v), want (\"\", false)", before, last)
	}
	if !l.held("forwarding") {
		t.Error("held() = false after releasing an unrelated pair, want true")
	}
}

func TestForwardingLedger_ReacquireAfterReleaseSavesAgain(t *testing.T) {
	l := newForwardingLedger[string]()

	l.acquire("forwarding", bridgePair, "0")
	if _, last := l.release("forwarding", bridgePair); !last {
		t.Fatal("release() last = false for the only holder, want true")
	}

	l.acquire("forwarding", bridgePair, "1")

	before, last := l.release("forwarding", bridgePair)
	if !last {
		t.Fatal("release() last = false after reacquiring, want true")
	}
	if before != "1" {
		t.Errorf("release() before = %q, want the state the second acquire found (%q)", before, "1")
	}
}

func TestForwardingLedger_KnobsAreIndependent(t *testing.T) {
	l := newForwardingLedger[bool]()

	l.acquire("plexd0", bridgePair, true)
	l.acquire("en1", bridgePair, false)

	before, last := l.release("plexd0", bridgePair)
	if !last {
		t.Fatal("release() last = false for the only holder of plexd0, want true")
	}
	if !before {
		t.Error("release() before = false, want the saved true")
	}
	if !l.held("en1") {
		t.Error("held(en1) = false after releasing plexd0, want true")
	}
}
