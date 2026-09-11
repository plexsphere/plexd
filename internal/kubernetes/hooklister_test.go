package kubernetes

import (
	"context"
	"encoding/pem"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newFakeAPIServer starts a TLS server standing in for the Kubernetes API
// server and returns a HookLister wired to it the way NewInClusterHookLister
// wires the real one: the server's certificate as the cluster CA bundle and a
// ServiceAccount token file on disk. The token path comes back so a test can
// rewrite or remove the file.
func newFakeAPIServer(t *testing.T, handler http.HandlerFunc) (*HookLister, string) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("sa-token-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	lister, err := newHookLister(host, port, caPath, &KubernetesEnvironment{InCluster: true, ServiceAccountToken: tokenPath})
	if err != nil {
		t.Fatalf("newHookLister: %v", err)
	}
	return lister, tokenPath
}

// plexdHookRequest is what the fake API server saw of one request.
type plexdHookRequest struct {
	method, path, authorization string
}

// plexdHookListBody is a PlexdHookList as the API server serves it: the object
// metadata nests under metadata, which PlexdHook keeps flat.
const plexdHookListBody = `{
  "apiVersion": "plexd.plexsphere.com/v1alpha1",
  "kind": "PlexdHookList",
  "metadata": {"resourceVersion": "4711"},
  "items": [
    {
      "apiVersion": "plexd.plexsphere.com/v1alpha1",
      "kind": "PlexdHook",
      "metadata": {
        "name": "nightly-backup",
        "namespace": "plexd-system",
        "uid": "5b9e2a7c-3f1d-4c2e-9a8b-0c1d2e3f4a5b",
        "resourceVersion": "4710",
        "labels": {"app.kubernetes.io/part-of": "storage"}
      },
      "spec": {
        "hookName": "backup",
        "jobTemplate": {
          "image": "registry.example/backup@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "command": ["/bin/backup"],
          "args": ["--full"]
        },
        "parameters": [{"name": "retention", "value": "7d"}],
        "privileged": true
      },
      "status": {"jobName": "plexdhook-nightly-backup", "phase": "Succeeded"}
    }
  ]
}`

func TestHookLister_ListDecodesEnvelope(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []plexdHookRequest
	)
	lister, _ := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, plexdHookRequest{r.Method, r.URL.Path, r.Header.Get("Authorization")})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(plexdHookListBody))
	})

	hooks, err := lister.ListPlexdHooks(context.Background(), "plexd-system")
	if err != nil {
		t.Fatalf("ListPlexdHooks: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	// One GET, with the token trimmed of the newline the file ends in.
	wantRequests := []plexdHookRequest{{
		method:        http.MethodGet,
		path:          "/apis/plexd.plexsphere.com/v1alpha1/namespaces/plexd-system/plexdhooks",
		authorization: "Bearer sa-token-1",
	}}
	if !reflect.DeepEqual(seen, wantRequests) {
		t.Errorf("requests = %+v, want %+v", seen, wantRequests)
	}

	if len(hooks) != 1 {
		t.Fatalf("got %d hooks, want 1: %+v", len(hooks), hooks)
	}
	want := PlexdHook{
		Name:            "nightly-backup",
		Namespace:       "plexd-system",
		UID:             "5b9e2a7c-3f1d-4c2e-9a8b-0c1d2e3f4a5b",
		ResourceVersion: "4710",
		Labels:          map[string]string{"app.kubernetes.io/part-of": "storage"},
		Spec: PlexdHookSpec{
			HookName: "backup",
			JobTemplate: &PlexdHookJobTemplate{
				Image:   "registry.example/backup@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				Command: []string{"/bin/backup"},
				Args:    []string{"--full"},
			},
			Parameters: []PlexdHookParam{{Name: "retention", Value: "7d"}},
			Privileged: true,
		},
		Status: PlexdHookStatus{JobName: "plexdhook-nightly-backup", Phase: "Succeeded"},
	}
	if !reflect.DeepEqual(hooks[0], want) {
		t.Errorf("hook = %+v\nwant   %+v", hooks[0], want)
	}
}

func TestHookLister_EmptyList(t *testing.T) {
	lister, _ := newFakeAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[]}`))
	})

	hooks, err := lister.ListPlexdHooks(context.Background(), "plexd-system")
	if err != nil {
		t.Fatalf("ListPlexdHooks: %v", err)
	}
	if hooks == nil || len(hooks) != 0 {
		t.Errorf("hooks = %#v, want an empty, non-nil slice", hooks)
	}
}

// Callers tell a missing grant from a missing CRD by the sentinel, and anything
// else by the status the error names.
func TestHookLister_StatusMapping(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   error // nil: an error naming the status, wrapping neither sentinel
	}{
		{status: http.StatusUnauthorized, want: ErrUnauthorized},
		{status: http.StatusForbidden, want: ErrUnauthorized},
		{status: http.StatusNotFound, want: ErrNotFound},
		{status: http.StatusInternalServerError},
	} {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			lister, _ := newFakeAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			})

			hooks, err := lister.ListPlexdHooks(context.Background(), "plexd-system")
			if err == nil {
				t.Fatalf("ListPlexdHooks = %+v, want an error", hooks)
			}
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Errorf("error = %v, want it to wrap %v", err, tc.want)
				}
				return
			}
			if errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrNotFound) {
				t.Errorf("error = %v, want neither sentinel for status %d", err, tc.status)
			}
			if !strings.Contains(err.Error(), strconv.Itoa(tc.status)) {
				t.Errorf("error = %v, want it to name status %d", err, tc.status)
			}
		})
	}
}

// ServiceAccount tokens rotate, so the file is read on every call, not once at
// construction.
func TestHookLister_RereadsToken(t *testing.T) {
	var (
		mu   sync.Mutex
		auth []string
	)
	lister, tokenPath := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = append(auth, r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = w.Write([]byte(`{"items":[]}`))
	})

	if _, err := lister.ListPlexdHooks(context.Background(), "plexd-system"); err != nil {
		t.Fatalf("first ListPlexdHooks: %v", err)
	}
	if err := os.WriteFile(tokenPath, []byte("sa-token-2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := lister.ListPlexdHooks(context.Background(), "plexd-system"); err != nil {
		t.Fatalf("second ListPlexdHooks: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if want := []string{"Bearer sa-token-1", "Bearer sa-token-2"}; !reflect.DeepEqual(auth, want) {
		t.Errorf("Authorization headers = %q, want %q", auth, want)
	}
}

func TestHookLister_MissingTokenSendsNothing(t *testing.T) {
	var requests atomic.Int32
	lister, tokenPath := newFakeAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"items":[]}`))
	})
	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}

	_, err := lister.ListPlexdHooks(context.Background(), "plexd-system")
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("error = %v, want a wrapped *fs.PathError", err)
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("the API server saw %d requests, want none", n)
	}
}

func TestHookLister_ContextDeadline(t *testing.T) {
	lister, _ := newFakeAPIServer(t, func(_ http.ResponseWriter, r *http.Request) {
		// Stall until the client gives up; the bound only keeps a broken
		// cancellation from hanging the test.
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := lister.ListPlexdHooks(ctx, "plexd-system")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want it to wrap context.DeadlineExceeded", err)
	}
}

func TestNewHookLister_Errors(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "not-a-ca.crt")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := &KubernetesEnvironment{InCluster: true, ServiceAccountToken: filepath.Join(dir, "token")}

	for _, tc := range []struct {
		name, host, port, caPath string
		env                      *KubernetesEnvironment
		want                     string
	}{
		{name: "no host", port: "443", caPath: notPEM, env: env, want: "KUBERNETES_SERVICE_HOST"},
		{name: "no port", host: "10.96.0.1", caPath: notPEM, env: env, want: "KUBERNETES_SERVICE_PORT"},
		{name: "nil environment", host: "10.96.0.1", port: "443", caPath: notPEM, want: "service account token"},
		{name: "no token path", host: "10.96.0.1", port: "443", caPath: notPEM, env: &KubernetesEnvironment{InCluster: true}, want: "service account token"},
		{name: "missing CA bundle", host: "10.96.0.1", port: "443", caPath: filepath.Join(dir, "absent.crt"), env: env, want: "read cluster CA"},
		{name: "CA bundle without a certificate", host: "10.96.0.1", port: "443", caPath: notPEM, env: env, want: "no certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, err := newHookLister(tc.host, tc.port, tc.caPath, tc.env)
			if err == nil {
				t.Fatalf("newHookLister = %+v, want an error", l)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// The API server address comes from the variables the kubelet injects into
// every pod; without one of them there is nothing to connect to.
func TestNewInClusterHookLister_RequiresServiceEnv(t *testing.T) {
	env := &KubernetesEnvironment{InCluster: true, ServiceAccountToken: DefaultTokenPath}

	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	if _, err := NewInClusterHookLister(env); err == nil {
		t.Error("NewInClusterHookLister without KUBERNETES_SERVICE_HOST succeeded, want an error")
	}

	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	if _, err := NewInClusterHookLister(env); err == nil {
		t.Error("NewInClusterHookLister without KUBERNETES_SERVICE_PORT succeeded, want an error")
	}
}
