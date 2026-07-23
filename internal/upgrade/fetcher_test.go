package upgrade

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// setGOOS overrides the goos seam for the duration of the test.
func setGOOS(t *testing.T, value string) {
	t.Helper()
	prev := goos
	goos = value
	t.Cleanup(func() { goos = prev })
}

// recordingServer returns an httptest server that records request paths and
// responds with the given status. A 2xx status also writes a short body.
func recordingServer(t *testing.T, status int) (*httptest.Server, *[]string) {
	t.Helper()
	var (
		mu    sync.Mutex
		paths []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(status)
		if status < 300 {
			_, _ = io.WriteString(w, "binary-body")
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &paths
}

func wantAsset() string { return "plexd-linux-" + runtime.GOARCH }

func TestFetchBinary_RequestPath(t *testing.T) {
	setGOOS(t, "linux")
	srv, paths := recordingServer(t, http.StatusOK)

	tests := []struct {
		name    string
		version string
	}{
		{name: "bare version gets v prefix", version: "0.2.0"},
		{name: "v-prefixed version unchanged", version: "v0.2.0"},
	}

	wantPath := "/v0.2.0/" + wantAsset()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFetcher(Config{ReleaseBaseURL: srv.URL})
			rc, err := f.FetchBinary(context.Background(), tt.version)
			if err != nil {
				t.Fatalf("FetchBinary() = %v, want nil", err)
			}
			t.Cleanup(func() { _ = rc.Close() })
			if _, err := io.ReadAll(rc); err != nil {
				t.Fatalf("read body: %v", err)
			}
			last := (*paths)[len(*paths)-1]
			if last != wantPath {
				t.Errorf("request path = %q, want %q", last, wantPath)
			}
		})
	}
}

func TestFetchBinary_CapsBody(t *testing.T) {
	setGOOS(t, "linux")
	// Serve a body larger than a temporarily lowered cap; the reader must stop
	// at the cap so a hostile mirror cannot fill the disk.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "0123456789abcdef")
	}))
	t.Cleanup(srv.Close)

	prev := maxBinaryBytes
	maxBinaryBytes = 4
	t.Cleanup(func() { maxBinaryBytes = prev })

	f := NewFetcher(Config{ReleaseBaseURL: srv.URL})
	rc, err := f.FetchBinary(context.Background(), "0.2.0")
	if err != nil {
		t.Fatalf("FetchBinary() = %v, want nil", err)
	}
	t.Cleanup(func() { _ = rc.Close() })

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(got) != 4 {
		t.Errorf("read %d bytes, want cap of 4", len(got))
	}
}

func TestFetch_RejectsInvalidVersion(t *testing.T) {
	setGOOS(t, "linux")
	srv, paths := recordingServer(t, http.StatusOK)
	f := NewFetcher(Config{ReleaseBaseURL: srv.URL})

	tests := []struct {
		name    string
		version string
	}{
		{name: "path traversal", version: "v1/../../../etc/passwd"},
		{name: "leading traversal", version: "../../../../etc/passwd"},
		{name: "not a version", version: "latest"},
		{name: "empty", version: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := f.FetchBinary(context.Background(), tt.version); err == nil {
				t.Errorf("FetchBinary(%q) = nil, want invalid-version error", tt.version)
			}
			if _, err := f.FetchBundle(context.Background(), tt.version); err == nil {
				t.Errorf("FetchBundle(%q) = nil, want invalid-version error", tt.version)
			}
		})
	}

	if len(*paths) != 0 {
		t.Errorf("server received %d requests, want 0 for rejected versions", len(*paths))
	}
}

func TestFetchBundle_RequestPath(t *testing.T) {
	setGOOS(t, "linux")
	srv, paths := recordingServer(t, http.StatusOK)

	f := NewFetcher(Config{ReleaseBaseURL: srv.URL})
	data, err := f.FetchBundle(context.Background(), "0.2.0")
	if err != nil {
		t.Fatalf("FetchBundle() = %v, want nil", err)
	}
	if len(data) == 0 {
		t.Fatal("FetchBundle() returned empty body")
	}

	wantPath := "/v0.2.0/" + wantAsset() + ".sigstore.json"
	if got := (*paths)[len(*paths)-1]; got != wantPath {
		t.Errorf("request path = %q, want %q", got, wantPath)
	}
}

func TestFetch_RefusesNonLinux(t *testing.T) {
	setGOOS(t, "darwin")
	srv, paths := recordingServer(t, http.StatusOK)
	f := NewFetcher(Config{ReleaseBaseURL: srv.URL})

	if _, err := f.FetchBinary(context.Background(), "0.2.0"); err == nil {
		t.Error("FetchBinary() = nil, want refusal on darwin")
	} else if !strings.Contains(err.Error(), "darwin") {
		t.Errorf("FetchBinary() error = %q, want to contain %q", err.Error(), "darwin")
	}

	if _, err := f.FetchBundle(context.Background(), "0.2.0"); err == nil {
		t.Error("FetchBundle() = nil, want refusal on darwin")
	} else if !strings.Contains(err.Error(), "darwin") {
		t.Errorf("FetchBundle() error = %q, want to contain %q", err.Error(), "darwin")
	}

	if len(*paths) != 0 {
		t.Errorf("server received %d requests, want 0", len(*paths))
	}
}

func TestFetch_Non200(t *testing.T) {
	setGOOS(t, "linux")
	srv, _ := recordingServer(t, http.StatusNotFound)
	f := NewFetcher(Config{ReleaseBaseURL: srv.URL})

	_, err := f.FetchBinary(context.Background(), "0.2.0")
	if err == nil {
		t.Fatal("FetchBinary() = nil, want error on 404")
	}
	if !strings.Contains(err.Error(), wantAsset()) {
		t.Errorf("error = %q, want to name asset %q", err.Error(), wantAsset())
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error = %q, want to contain status 404", err.Error())
	}
}

func TestFetch_ContextCancelled(t *testing.T) {
	setGOOS(t, "linux")
	srv, _ := recordingServer(t, http.StatusOK)
	f := NewFetcher(Config{ReleaseBaseURL: srv.URL})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := f.FetchBinary(ctx, "0.2.0")
	if err == nil {
		t.Fatal("FetchBinary() = nil, want error on cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want errors.Is(context.Canceled)", err)
	}
	if !strings.Contains(err.Error(), "download release asset:") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "download release asset:")
	}
}
