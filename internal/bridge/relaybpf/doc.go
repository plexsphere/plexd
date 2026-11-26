// Package relaybpf loads the eBPF program that forwards the WireGuard
// transport datagrams of the relay's placed sessions at tc ingress on Linux,
// and reads and writes its session table and its counters.
//
// The program's source is relay.bpf.c. `make bpf` compiles it with a pinned
// toolchain into relay_bpfel.o, which is committed, so a build needs no
// clang. Only the files built for Linux import github.com/cilium/ebpf; this
// file has no build tag, so the package, and CounterNames with it, exist on
// every platform.
package relaybpf

// CounterNames are the keys Counters returns, in the program's slot order.
var CounterNames = [...]string{"forwarded", "no_session", "mismatch", "fib_fwd_disabled",
	"fib_frag_needed", "fib_no_neigh", "fib_other", "route_changed", "gso"}
