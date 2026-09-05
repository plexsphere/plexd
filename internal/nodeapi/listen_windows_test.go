//go:build windows

package nodeapi

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestPipeSecurityDescriptor_Parses(t *testing.T) {
	sd, err := windows.SecurityDescriptorFromString(pipeSecurityDescriptor)
	if err != nil {
		t.Fatalf("SecurityDescriptorFromString(%q): %v", pipeSecurityDescriptor, err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL: %v", err)
	}
	if dacl == nil {
		t.Fatal("DACL() = nil, want the parsed access control list")
	}

	got := sd.String()
	for _, want := range []string{";;;SY)", ";;;BA)"} {
		if !strings.Contains(got, want) {
			t.Errorf("descriptor %q does not grant %q", got, want)
		}
	}

	// Opening the pipe authorizes every route but the secret ones, so no ACE
	// may name a trustee other than LocalSystem and Administrators: an
	// Authenticated Users grant would put POST /v1/actions/run and the report
	// writes in reach of any signed-in account, and its generic-write half
	// would let one add an instance of the pipe name. The ACEs are walked
	// rather than matched against a list of SDDL aliases, so a trustee nobody
	// thought to blocklist -- NU, LS, SO, or the same SID written raw -- is
	// caught too.
	allowed := map[string]bool{
		"S-1-5-18":     true, // SY, LocalSystem
		"S-1-5-32-544": true, // BA, Administrators
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatalf("GetAce(%d): %v", i, err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !allowed[sid.String()] {
			t.Errorf("ACE %d grants %s, which reaches the action and report routes", i, sid)
		}
	}

	// A protected DACL keeps an ACE off the pipe that the object would
	// otherwise inherit; without D:P the walk above judges only what this
	// descriptor spells out.
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("Control: %v", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("descriptor %q is not DACL-protected, so an inherited ACE would widen it", got)
	}
}

func TestListenLocal_PipeInUse(t *testing.T) {
	path := shortSocketPath(t)

	ln, err := ListenLocal(path, discardLogger())
	if err != nil {
		t.Fatalf("ListenLocal: %v", err)
	}
	defer ln.Close()

	second, err := ListenLocal(path, discardLogger())
	if err == nil {
		second.Close()
		t.Fatal("ListenLocal() on a name already served = nil error, want a failure")
	}
	if !strings.HasPrefix(err.Error(), "nodeapi: listen pipe") {
		t.Errorf("error = %q, want it to start with %q", err, "nodeapi: listen pipe")
	}
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		t.Errorf("error %v does not wrap *os.PathError", err)
	}
}

func TestDialLocal_NoServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := DialLocal(ctx, shortSocketPath(t))
	if err == nil {
		conn.Close()
		t.Fatal("DialLocal() to a name nobody serves = nil error, want a failure")
	}
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("error %v does not wrap *os.PathError", err)
	}
	if !errors.Is(pathErr.Err, windows.ERROR_FILE_NOT_FOUND) {
		t.Errorf("error = %v, want ERROR_FILE_NOT_FOUND", pathErr.Err)
	}
}

func TestValidateSocketPath(t *testing.T) {
	const wantErr = `nodeapi: config: SocketPath must name a Windows named pipe (\\.\pipe\<name>)`

	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "default pipe", path: `\\.\pipe\plexd`, want: true},
		{name: "pipe keyword is case insensitive", path: `\\.\PIPE\x`, want: true},
		{name: "file path", path: `C:\ProgramData\plexd\run\api.sock`, want: false},
		{name: "empty", path: "", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				DataDir:         `C:\x`,
				SocketPath:      tc.path,
				DebouncePeriod:  time.Second,
				ShutdownTimeout: time.Second,
			}
			err := validateSocketPath(tc.path)
			cfgErr := cfg.Validate()

			if tc.want {
				if err != nil {
					t.Errorf("validateSocketPath(%q) = %v, want nil", tc.path, err)
				}
				if cfgErr != nil {
					t.Errorf("Validate() with SocketPath %q = %v, want nil", tc.path, cfgErr)
				}
				return
			}
			if err == nil || err.Error() != wantErr {
				t.Errorf("validateSocketPath(%q) = %v, want %q", tc.path, err, wantErr)
			}
			if cfgErr == nil || cfgErr.Error() != wantErr {
				t.Errorf("Validate() with SocketPath %q = %v, want %q", tc.path, cfgErr, wantErr)
			}
		})
	}
}
