package metrics

// ifCounters is one interface's cumulative byte counters, the platform-neutral
// form the readers reduce their interface tables to.
type ifCounters struct {
	name     string
	loopback bool
	rx, tx   uint64
}

// sumIfCounters adds up the rx and tx counters of rows. Loopback rows never
// count. An empty iface sums every remaining row, otherwise only the rows named
// iface count. found reports whether at least one row was counted, which tells
// a quiet interface apart from a missing one.
func sumIfCounters(rows []ifCounters, iface string) (rx, tx uint64, found bool) {
	for _, row := range rows {
		if row.loopback {
			continue
		}
		if iface != "" && row.name != iface {
			continue
		}
		rx += row.rx
		tx += row.tx
		found = true
	}
	return rx, tx, found
}
