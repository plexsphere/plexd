package bridge

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	// namedpipe.ioCompletionProcessor is the IO-completion dispatcher
	// wireguard-go's named-pipe transport starts on first use. It loops on
	// GetQueuedCompletionStatus forever by design and the package offers no
	// way to stop it, so it outlives any test that opened a real UAPI pipe on
	// Windows. In this package that is TestWGControllers_RealWintun alone:
	// everything else drives a fake WGController. The exemption names that one
	// function, so a goroutine this package actually leaks still fails the run.
	//
	// It has to be IgnoreAnyFunction: the goroutine is parked in the
	// GetQueuedCompletionStatus syscall, so the top of its stack is
	// syscall.syscalln and ioCompletionProcessor sits below it. Matching the
	// top frame would mean exempting every syscall-blocked goroutine.
	goleak.VerifyTestMain(m,
		goleak.IgnoreAnyFunction("golang.zx2c4.com/wireguard/ipc/namedpipe.ioCompletionProcessor"),
	)
}
