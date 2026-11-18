//go:build !windows

package bridge

import (
	"context"
	"testing"
	"time"
)

// TestStdCommandExecutor_StopReapsTheProcess wants Stop to return only once
// the process was waited for, and a second Stop to be no error. A process
// that is killed and never waited for stays a zombie of plexd, one per
// openvpn tunnel that is torn down.
func TestStdCommandExecutor_StopReapsTheProcess(t *testing.T) {
	handle, err := NewStdCommandExecutor().Start(context.Background(), "sleep", "30")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	h := handle.(*execHandle)

	if err := h.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if h.cmd.ProcessState == nil {
		t.Fatal("after Stop the process was not waited for")
	}
	if err := h.Stop(); err != nil {
		t.Errorf("second Stop: %v", err)
	}
}

// TestStdCommandExecutor_ReapsAProcessThatExits wants a process that ends by
// itself to be waited for without a Stop: an openvpn that exits after its
// start is torn down only with its tunnel.
func TestStdCommandExecutor_ReapsAProcessThatExits(t *testing.T) {
	handle, err := NewStdCommandExecutor().Start(context.Background(), "true")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	h := handle.(*execHandle)

	select {
	case <-h.done:
	case <-time.After(10 * time.Second):
		t.Fatal("10 s after its start, the exited process was not waited for")
	}
	if h.cmd.ProcessState == nil || !h.cmd.ProcessState.Exited() {
		t.Fatalf("ProcessState = %v, want an exited process", h.cmd.ProcessState)
	}
	if err := h.Stop(); err != nil {
		t.Errorf("Stop after the exit: %v", err)
	}
}
