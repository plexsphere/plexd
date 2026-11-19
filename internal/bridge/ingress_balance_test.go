package bridge

import (
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

// balancerOf returns a balancer of n targets, the i-th on 10.0.1.i, counted
// from 1, and port 9000+i.
func balancerOf(n int) *ingressBalancer {
	return newIngressBalancer(planTargets(n))
}

// pickUnits lets n units pick a target at now, each dial succeeding, and
// returns the target of each unit in order.
func pickUnits(t *testing.T, b *ingressBalancer, n int, now time.Time) []int {
	t.Helper()
	got := make([]int, 0, n)
	for range n {
		idx, ok := b.pick(0, now)
		if !ok {
			t.Fatalf("pick with nothing tried = (%d, false), want a target", idx)
		}
		b.dialled(idx, false, "", now)
		got = append(got, idx)
	}
	return got
}

// failUnit lets one unit dial targets at now until a dial succeeds, the dials
// to the targets of failing failing with refused, and returns the targets it
// dialled in order and whether one took it.
func failUnit(b *ingressBalancer, now time.Time, failing ...int) (dialled []int, taken bool) {
	var tried uint8
	for {
		idx, ok := b.pick(tried, now)
		if !ok {
			return dialled, false
		}
		tried |= 1 << idx
		dialled = append(dialled, idx)
		if !slices.Contains(failing, idx) {
			b.dialled(idx, false, "", now)
			return dialled, true
		}
		b.dialled(idx, true, IngressDialReasonRefused, now)
	}
}

func TestIngressBalancer_RoundRobin(t *testing.T) {
	b := newIngressBalancer([]api.IngressTarget{
		{NodeID: "node-a", Address: "10.0.0.7", Port: 9001},
		{NodeID: "node-b", Address: "fd00::8", Port: 9002},
		{NodeID: "node-a", Address: "10.0.0.7", Port: 9003},
	})
	if got := pickUnits(t, b, 6, relayStart); !slices.Equal(got, []int{0, 1, 2, 0, 1, 2}) {
		t.Errorf("six units went to %v, want 0, 1, 2, 0, 1, 2", got)
	}
	for addr, want := range map[string]int{"10.0.0.7:9001": 0, "[fd00::8]:9002": 1, "10.0.0.7:9003": 2, "10.0.0.7:9002": -1, "fd00::8:9002": -1} {
		if got := b.index(addr); got != want {
			t.Errorf("index(%q) = %d, want %d", addr, got, want)
		}
	}
}

func TestIngressBalancer_PassesOverAnOutTarget(t *testing.T) {
	b := balancerOf(3)
	if got := pickUnits(t, b, 1, relayStart); !slices.Equal(got, []int{0}) {
		t.Fatalf("the first unit went to %v, want 0", got)
	}
	if dialled, taken := failUnit(b, relayStart, 1); !taken || !slices.Equal(dialled, []int{1, 2}) {
		t.Errorf("the unit whose dial to target 1 failed dialled %v (taken %v), want 1 and then 2", dialled, taken)
	}
	if got := pickUnits(t, b, 4, relayStart.Add(time.Second)); !slices.Equal(got, []int{0, 2, 0, 2}) {
		t.Errorf("the next four units went to %v, want 0, 2, 0, 2", got)
	}
}

func TestIngressBalancer_HoldOutEnds(t *testing.T) {
	b := balancerOf(3)
	pickUnits(t, b, 1, relayStart)
	if dialled, _ := failUnit(b, relayStart, 1); !slices.Equal(dialled, []int{1, 2}) {
		t.Fatalf("the unit whose dial to target 1 failed dialled %v, want 1 and then 2", dialled)
	}

	before := relayStart.Add(ingressTargetHoldOut - time.Millisecond)
	if got := pickUnits(t, b, 4, before); !slices.Equal(got, []int{0, 2, 0, 2}) {
		t.Errorf("units at 29.999 s went to %v, want 0, 2, 0, 2", got)
	}
	// Target 0 has its turn first; the unit after it is the first whose turn
	// target 1 is.
	if got := pickUnits(t, b, 3, relayStart.Add(ingressTargetHoldOut)); !slices.Equal(got, []int{0, 1, 2}) {
		t.Errorf("units at 30 s went to %v, want 0, 1, 2", got)
	}
}

func TestIngressBalancer_AllOutDialsAll(t *testing.T) {
	b := balancerOf(3)
	pickUnits(t, b, 1, relayStart)
	for i := range 3 {
		b.dialled(i, true, IngressDialReasonRefused, relayStart)
	}
	if b.otherIn(0, relayStart) {
		t.Error("otherIn(0) with every target out = true, want false")
	}

	now := relayStart.Add(time.Second)
	dialled, taken := failUnit(b, now, 0, 1, 2)
	if taken || !slices.Equal(dialled, []int{1, 2, 0}) {
		t.Errorf("a unit with every target out dialled %v (taken %v), want 1, 2, 0 and then none", dialled, taken)
	}
	if idx, ok := b.pick(0b111, now); ok {
		t.Errorf("pick with every target tried = (%d, true), want ok false", idx)
	}
}

func TestIngressBalancer_SuccessBringsATargetIn(t *testing.T) {
	b := balancerOf(3)
	for i := range 3 {
		b.dialled(i, true, IngressDialReasonRefused, relayStart)
	}
	now := relayStart.Add(time.Second)
	if dialled, taken := failUnit(b, now); !taken || !slices.Equal(dialled, []int{0}) {
		t.Fatalf("a unit with every target out dialled %v (taken %v), want 0, which answers", dialled, taken)
	}
	if !b.otherIn(1, now) || b.otherIn(0, now) {
		t.Errorf("otherIn(1), otherIn(0) = %v, %v, want true for target 0 back in and false for the two out", b.otherIn(1, now), b.otherIn(0, now))
	}
	// The next unit starts at target 1 and passes 1 and 2 over.
	if got := pickUnits(t, b, 2, now); !slices.Equal(got, []int{0, 0}) {
		t.Errorf("the next units went to %v, want 0, 0", got)
	}
	unit, targets := b.snapshot()
	if unit.failed || unit.at != now {
		t.Errorf("unit = %+v, want succeeded at %v", unit, now)
	}
	if !targets[1].failed || !targets[2].failed || targets[0].failed {
		t.Errorf("targets = %+v, want 0 succeeded and 1 and 2 failed", targets)
	}
}

func TestIngressBalancer_OneTarget(t *testing.T) {
	b := balancerOf(1)
	now := relayStart
	for _, failing := range []bool{true, true, false, true} {
		if b.otherIn(0, now) {
			t.Errorf("at %v: otherIn(0) = true, want false for the only target", now)
		}
		idx, ok := b.pick(0, now)
		if !ok || idx != 0 {
			t.Fatalf("at %v: pick = (%d, %v), want (0, true)", now, idx, ok)
		}
		reason := ""
		if failing {
			reason = IngressDialReasonRefused
		}
		b.dialled(0, failing, reason, now)
		if idx, ok := b.pick(1, now); ok {
			t.Errorf("at %v: pick with the target tried = (%d, true), want ok false", now, idx)
		}
		now = now.Add(time.Second)
	}
	if b.otherIn(0, now) {
		t.Error("otherIn(0) = true for the only target, out, want false")
	}
}

func TestIngressBalancer_ConcurrentPicks(t *testing.T) {
	b := balancerOf(4)
	var mu sync.Mutex
	units := make(map[int]int)
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			idx, ok := b.pick(0, relayStart)
			if !ok {
				t.Error("pick with nothing tried = ok false, want a target")
				return
			}
			b.dialled(idx, false, "", relayStart)
			b.otherIn(idx, relayStart)
			b.snapshot()
			mu.Lock()
			units[idx]++
			mu.Unlock()
		})
	}
	wg.Wait()
	for i := range 4 {
		if units[i] != 16 {
			t.Errorf("target %d took %d units, want 16: %v", i, units[i], units)
		}
	}

	// Failures recorded concurrently with picks leave every target out.
	for i := range 64 {
		wg.Go(func() {
			idx, _ := b.pick(0, relayStart)
			b.dialled(idx, true, IngressDialReasonRefused, relayStart)
			b.unitFailed(IngressDialReasonRefused, relayStart)
			b.index(b.targets[i%4].addr)
		})
	}
	wg.Wait()
	if b.otherIn(-1, relayStart) {
		t.Error("a target is in after every target failed, want all out")
	}
	if unit, _ := b.snapshot(); !unit.failed || unit.reason != IngressDialReasonRefused {
		t.Errorf("unit = %+v, want failed with refused", unit)
	}
}
