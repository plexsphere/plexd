package metrics

import "testing"

func TestSumIfCounters_Empty(t *testing.T) {
	rx, tx, found := sumIfCounters(nil, "")
	if rx != 0 || tx != 0 || found {
		t.Errorf("sumIfCounters(nil, \"\") = %d, %d, %v, want 0, 0, false", rx, tx, found)
	}
}

func TestSumIfCounters_LoopbackOnly(t *testing.T) {
	rows := []ifCounters{{name: "lo0", loopback: true, rx: 100, tx: 200}}

	rx, tx, found := sumIfCounters(rows, "")
	if rx != 0 || tx != 0 || found {
		t.Errorf("sumIfCounters(loopback only, \"\") = %d, %d, %v, want 0, 0, false", rx, tx, found)
	}
}

func TestSumIfCounters_SumsNonLoopback(t *testing.T) {
	rows := []ifCounters{
		{name: "lo0", loopback: true, rx: 100, tx: 200},
		{name: "en0", rx: 10, tx: 20},
		{name: "plexd0", rx: 3, tx: 4},
	}

	rx, tx, found := sumIfCounters(rows, "")
	if rx != 13 || tx != 24 || !found {
		t.Errorf("sumIfCounters(rows, \"\") = %d, %d, %v, want 13, 24, true", rx, tx, found)
	}
}

func TestSumIfCounters_NamedInterface(t *testing.T) {
	rows := []ifCounters{
		{name: "lo0", loopback: true, rx: 100, tx: 200},
		{name: "en0", rx: 10, tx: 20},
		{name: "plexd0", rx: 3, tx: 4},
	}

	rx, tx, found := sumIfCounters(rows, "plexd0")
	if rx != 3 || tx != 4 || !found {
		t.Errorf("sumIfCounters(rows, \"plexd0\") = %d, %d, %v, want 3, 4, true", rx, tx, found)
	}
}

func TestSumIfCounters_NamedInterfaceMissing(t *testing.T) {
	rows := []ifCounters{
		{name: "lo0", loopback: true, rx: 100, tx: 200},
		{name: "en0", rx: 10, tx: 20},
	}

	rx, tx, found := sumIfCounters(rows, "eth7")
	if rx != 0 || tx != 0 || found {
		t.Errorf("sumIfCounters(rows, \"eth7\") = %d, %d, %v, want 0, 0, false", rx, tx, found)
	}
}
