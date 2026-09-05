package nodeapi

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

func TestContextPeerCredGetter(t *testing.T) {
	getter := contextPeerCredGetter{}

	// Request without peer creds in context.
	req := httptest.NewRequest(http.MethodGet, "/v1/state/secrets/key", nil)
	_, err := getter.GetPeerCredentials(req)
	if err == nil {
		t.Fatal("GetPeerCredentials() = nil error, want one when the context holds no credentials")
	}
	if err.Error() != "nodeapi: peer credentials not available" {
		t.Errorf("error = %q, want %q", err, "nodeapi: peer credentials not available")
	}

	// Request with peer creds in context.
	cred := &PeerCredentials{}
	req = req.WithContext(context.WithValue(req.Context(), peerCredKey{}, cred))

	got, err := getter.GetPeerCredentials(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != cred {
		t.Errorf("GetPeerCredentials() = %p, want the credentials stored in the context (%p)", got, cred)
	}
}

func TestGetPeerCredentials_NotLocalConn(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	_, err := GetPeerCredentials(a)
	if err == nil {
		t.Fatal("GetPeerCredentials() on an in-memory pipe = nil error, want a failure")
	}

	want := "not a Unix socket connection"
	if runtime.GOOS == "windows" {
		want = "not a named pipe connection"
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want it to contain %q", err, want)
	}
}

func TestConnContextWithPeerCred_Unreadable(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	var buf bytes.Buffer
	fn := connContextWithPeerCred(bufferLogger(&buf))

	ctx := fn(context.Background(), a)
	if cred := ctx.Value(peerCredKey{}); cred != nil {
		t.Errorf("context carries %v, want no credentials for an unreadable peer", cred)
	}

	logged := buf.String()
	for _, want := range []string{"level=DEBUG", "failed to get peer credentials"} {
		if !strings.Contains(logged, want) {
			t.Errorf("log %q does not contain %q", logged, want)
		}
	}
}
