package kubernetes

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
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

// An API server that restarts mid-response answers 200 and then stops. Only the
// error tells that from a list of nothing, and a list of nothing would take every
// PlexdHook off the control plane's row.
func TestHookLister_TruncatedListIsAnError(t *testing.T) {
	lister, _ := newFakeAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"nightly-backup"`))
	})

	hooks, err := lister.ListPlexdHooks(context.Background(), "plexd-system")
	if err == nil {
		t.Fatalf("ListPlexdHooks = %#v, want an error", hooks)
	}
	if hooks != nil {
		t.Errorf("hooks = %#v, want nil alongside the error", hooks)
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
			if !strings.Contains(err.Error(), "list plexdhooks") {
				t.Errorf("error = %v, want it to say list plexdhooks", err)
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

// watchWaitLimit only turns a stream that never ends into a failure instead of a
// hung test. A passing run stays far below it, so it assumes nothing about load.
const watchWaitLimit = 30 * time.Second

// watchedHook is the PlexdHook that plexdHookFrame nests on the wire.
func watchedHook(name, resourceVersion string) *PlexdHook {
	return &PlexdHook{
		Name:            name,
		Namespace:       "plexd-system",
		UID:             "uid-" + name,
		ResourceVersion: resourceVersion,
		Labels:          map[string]string{"app.kubernetes.io/part-of": "storage"},
		Spec: PlexdHookSpec{
			HookName: "backup",
			JobTemplate: &PlexdHookJobTemplate{
				Image:   "registry.example/backup@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				Command: []string{"/bin/backup"},
			},
			Parameters: []PlexdHookParam{{Name: "retention", Value: "7d"}},
			Privileged: true,
		},
		Status: PlexdHookStatus{JobName: "plexdhook-" + name, Phase: "Succeeded"},
	}
}

// plexdHookFrame is one watch frame as the API server serves it: a JSON object
// on its own line, with the resource's metadata nested under metadata.
func plexdHookFrame(eventType, name, resourceVersion string) string {
	return fmt.Sprintf(`{"type":%q,"object":{
		"apiVersion": "plexd.plexsphere.com/v1alpha1",
		"kind": "PlexdHook",
		"metadata": {
			"name": %q,
			"namespace": "plexd-system",
			"uid": "uid-%s",
			"resourceVersion": %q,
			"labels": {"app.kubernetes.io/part-of": "storage"}
		},
		"spec": {
			"hookName": "backup",
			"jobTemplate": {
				"image": "registry.example/backup@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				"command": ["/bin/backup"]
			},
			"parameters": [{"name": "retention", "value": "7d"}],
			"privileged": true
		},
		"status": {"jobName": "plexdhook-%s", "phase": "Succeeded"}
	}}`+"\n", eventType, name, name, resourceVersion, name)
}

// writeWatchStream answers 200 and writes frames. The headers are flushed first
// because WatchPlexdHooks returns only once it has them, and each frame is
// flushed so the client sees it while the handler is still running. Write errors
// are dropped: a client that already left is what several tests are after.
func writeWatchStream(w http.ResponseWriter, frames ...string) {
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = rc.Flush()
	for _, frame := range frames {
		_, _ = io.WriteString(w, frame)
		_ = rc.Flush()
	}
}

// clientLeft holds a handler until the client is gone and says whether it went.
// The server ends r.Context() when the connection drops, so a stream that was
// not cancelled ends it only through the client closing the response body.
func clientLeft(r *http.Request) bool {
	select {
	case <-r.Context().Done():
		return true
	case <-time.After(watchWaitLimit):
		return false
	}
}

// awaitSignal fails the test when signal does not close before watchWaitLimit.
func awaitSignal(t *testing.T, signal <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(watchWaitLimit):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// nextWatchEvent is one receive from a watch channel; ok is false once it closed.
func nextWatchEvent(t *testing.T, events <-chan PlexdHookEvent) (event PlexdHookEvent, ok bool) {
	t.Helper()
	select {
	case event, ok = <-events:
		return event, ok
	case <-time.After(watchWaitLimit):
		t.Fatal("timed out with neither an event nor a closed channel")
		return PlexdHookEvent{}, false
	}
}

// requireWatchEvent receives one event and fails the test unless it is want.
func requireWatchEvent(t *testing.T, events <-chan PlexdHookEvent, want PlexdHookEvent) {
	t.Helper()
	event, ok := nextWatchEvent(t, events)
	if !ok {
		t.Fatalf("channel closed, want event %s", want.Type)
	}
	if !reflect.DeepEqual(event, want) {
		t.Fatalf("event = %+v (hook %+v)\nwant    %+v (hook %+v)", event, event.Hook, want, want.Hook)
	}
}

// requireWatchClosed fails the test unless the next receive finds events closed.
func requireWatchClosed(t *testing.T, events <-chan PlexdHookEvent) {
	t.Helper()
	if event, ok := nextWatchEvent(t, events); ok {
		t.Fatalf("got event %+v, want a closed channel", event)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// observedBody wraps a response body to show what the client did with it, which
// the API server cannot see: a cancelled request drops the connection whether or
// not the goroutine reading the stream is still alive.
type observedBody struct {
	io.ReadCloser
	unread    int           // bytes left before reached closes; only the reader touches it
	reached   chan struct{} // closes once the client has read the bytes asked for
	closed    chan struct{} // closes on the first Close
	closeOnce sync.Once
}

func (b *observedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if b.unread > 0 {
		if b.unread -= n; b.unread <= 0 {
			close(b.reached)
		}
	}
	return n, err
}

func (b *observedBody) Close() error {
	b.closeOnce.Do(func() { close(b.closed) })
	return b.ReadCloser.Close()
}

// observeBody wraps the body of the one response lister's next request gets.
// reached closes after the client has read readBytes of it.
func observeBody(lister *HookLister, readBytes int) *observedBody {
	body := &observedBody{unread: readBytes, reached: make(chan struct{}), closed: make(chan struct{})}
	base := lister.client.Transport
	lister.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		resp, err := base.RoundTrip(r)
		if err == nil {
			body.ReadCloser = resp.Body
			resp.Body = body
		}
		return resp, err
	})
	return body
}

func TestHookLister_WatchDeliversEvents(t *testing.T) {
	var (
		mu    sync.Mutex
		seen  []plexdHookRequest
		query url.Values
	)
	lister, _ := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, plexdHookRequest{r.Method, r.URL.Path, r.Header.Get("Authorization")})
		query = r.URL.Query()
		mu.Unlock()
		writeWatchStream(w,
			plexdHookFrame("ADDED", "nightly-backup", "4711"),
			plexdHookFrame("MODIFIED", "nightly-backup", "4712"),
			plexdHookFrame("DELETED", "nightly-backup", "4713"),
		)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, err := lister.WatchPlexdHooks(ctx, "plexd-system")
	if err != nil {
		t.Fatalf("WatchPlexdHooks: %v", err)
	}

	requireWatchEvent(t, events, PlexdHookEvent{Type: "ADDED", Hook: watchedHook("nightly-backup", "4711")})
	requireWatchEvent(t, events, PlexdHookEvent{Type: "MODIFIED", Hook: watchedHook("nightly-backup", "4712")})
	requireWatchEvent(t, events, PlexdHookEvent{Type: "DELETED", Hook: watchedHook("nightly-backup", "4713")})
	requireWatchClosed(t, events)

	mu.Lock()
	defer mu.Unlock()
	// One GET of the list path, with the token trimmed of the newline the file
	// ends in.
	wantRequests := []plexdHookRequest{{
		method:        http.MethodGet,
		path:          "/apis/plexd.plexsphere.com/v1alpha1/namespaces/plexd-system/plexdhooks",
		authorization: "Bearer sa-token-1",
	}}
	if !reflect.DeepEqual(seen, wantRequests) {
		t.Errorf("requests = %+v, want %+v", seen, wantRequests)
	}
	if got := query.Get("watch"); got != "true" {
		t.Errorf("watch = %q, want true", got)
	}
	// Without a resourceVersion the API server has nothing to answer 410 Gone to.
	if query.Has("resourceVersion") {
		t.Errorf("query = %v, want no resourceVersion", query)
	}
}

// The API server sends bookmarks only on request and plexd makes none, so one
// that arrives anyway is no change to a resource.
func TestHookLister_WatchIgnoresBookmark(t *testing.T) {
	lister, _ := newFakeAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeWatchStream(w,
			plexdHookFrame("ADDED", "nightly-backup", "4711"),
			`{"type":"BOOKMARK","object":{"kind":"PlexdHook","metadata":{"resourceVersion":"4712"}}}`+"\n",
			plexdHookFrame("DELETED", "nightly-backup", "4713"),
		)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, err := lister.WatchPlexdHooks(ctx, "plexd-system")
	if err != nil {
		t.Fatalf("WatchPlexdHooks: %v", err)
	}

	requireWatchEvent(t, events, PlexdHookEvent{Type: "ADDED", Hook: watchedHook("nightly-backup", "4711")})
	requireWatchEvent(t, events, PlexdHookEvent{Type: "DELETED", Hook: watchedHook("nightly-backup", "4713")})
	requireWatchClosed(t, events)
}

func TestHookLister_WatchClosesOnStreamEnd(t *testing.T) {
	lister, _ := newFakeAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeWatchStream(w, plexdHookFrame("ADDED", "nightly-backup", "4711"))
	})
	body := observeBody(lister, 0)

	// The context stays live, so only the end of the stream can close the channel.
	events, err := lister.WatchPlexdHooks(context.Background(), "plexd-system")
	if err != nil {
		t.Fatalf("WatchPlexdHooks: %v", err)
	}

	requireWatchEvent(t, events, PlexdHookEvent{Type: "ADDED", Hook: watchedHook("nightly-backup", "4711")})
	requireWatchClosed(t, events)
	awaitSignal(t, body.closed, "the response body to close")
}

// A frame that ends the watch must end the connection too, so each of these
// holds the stream open with a live context and checks that the client left. The
// frame after the failing one shows the watch stopped there and not at the end
// of the stream.
func requireWatchEndsAtFrame(t *testing.T, frame string) {
	t.Helper()
	gone := make(chan struct{})
	lister, _ := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeWatchStream(w,
			plexdHookFrame("ADDED", "before", "4711"),
			frame,
			plexdHookFrame("ADDED", "after", "4712"),
		)
		if clientLeft(r) {
			close(gone)
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, err := lister.WatchPlexdHooks(ctx, "plexd-system")
	if err != nil {
		t.Fatalf("WatchPlexdHooks: %v", err)
	}

	requireWatchEvent(t, events, PlexdHookEvent{Type: "ADDED", Hook: watchedHook("before", "4711")})
	requireWatchClosed(t, events)
	awaitSignal(t, gone, "the handler's request context to end")
}

func TestHookLister_WatchClosesOnErrorFrame(t *testing.T) {
	for _, tc := range []struct{ name, frame string }{
		{
			// The shape a real API server sends. Its string status does not fit
			// PlexdHookStatus, so the type has to be looked at before the object.
			name:  "status object",
			frame: `{"type":"ERROR","object":{"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"too old resource version","reason":"Expired","code":410}}` + "\n",
		},
		{
			// This object decodes cleanly as a PlexdHook, so only the type check
			// keeps it from being delivered as an event.
			name:  "object that fits a PlexdHook",
			frame: `{"type":"ERROR","object":{"kind":"Status","metadata":{},"message":"internal error","code":500}}` + "\n",
		},
		{name: "no object", frame: `{"type":"ERROR"}` + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireWatchEndsAtFrame(t, tc.frame)
		})
	}
}

func TestHookLister_WatchClosesOnUndecodableFrame(t *testing.T) {
	for _, tc := range []struct{ name, frame string }{
		{name: "not JSON", frame: "{not json\n"},
		{name: "not an object", frame: "42\n"},
		{name: "no object", frame: `{"type":"ADDED"}` + "\n"},
		{name: "object is a string", frame: `{"type":"ADDED","object":"nope"}` + "\n"},
		{name: "spec is a string", frame: `{"type":"ADDED","object":{"spec":"nope"}}` + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireWatchEndsAtFrame(t, tc.frame)
		})
	}
}

func TestHookLister_WatchClosesOnContextCancel(t *testing.T) {
	gone := make(chan struct{})
	lister, _ := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeWatchStream(w)
		if clientLeft(r) {
			close(gone)
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, err := lister.WatchPlexdHooks(ctx, "plexd-system")
	if err != nil {
		t.Fatalf("WatchPlexdHooks: %v", err)
	}

	cancel()
	requireWatchClosed(t, events)
	awaitSignal(t, gone, "the handler's request context to end")
}

// A cancelled context drops the connection on its own, so the handler's context
// says nothing about the goroutine. The body does: the goroutine closes it on the
// way out, and nothing receives from the channel until it has, so a send that
// does not select on ctx never gets there.
func TestHookLister_WatchCancelWithUnreadFrame(t *testing.T) {
	frame := plexdHookFrame("ADDED", "nightly-backup", "4711")
	gone := make(chan struct{})
	lister, _ := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		writeWatchStream(w, frame)
		if clientLeft(r) {
			close(gone)
		}
	})
	// The decoder has the whole frame without the newline that ends it.
	body := observeBody(lister, len(frame)-1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, err := lister.WatchPlexdHooks(ctx, "plexd-system")
	if err != nil {
		t.Fatalf("WatchPlexdHooks: %v", err)
	}

	awaitSignal(t, body.reached, "the frame to reach the client")
	cancel()

	awaitSignal(t, body.closed, "the response body to close with the event unsent")
	awaitSignal(t, gone, "the handler's request context to end")
	requireWatchClosed(t, events)
}

func TestHookLister_WatchStatusMapping(t *testing.T) {
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
				_, _ = w.Write([]byte(`{"kind":"Status","status":"Failure"}`))
			})
			body := observeBody(lister, 0)

			events, err := lister.WatchPlexdHooks(context.Background(), "plexd-system")
			if err == nil {
				t.Fatal("WatchPlexdHooks succeeded, want an error")
			}
			if events != nil {
				t.Error("WatchPlexdHooks returned a channel along with the error")
			}
			select {
			case <-body.closed:
			default:
				t.Error("response body left open")
			}
			if !strings.Contains(err.Error(), "watch plexdhooks") {
				t.Errorf("error = %v, want it to say watch plexdhooks", err)
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

// A watch reopens for as long as the pod lives, well past a token's lifetime, so
// each open reads the file.
func TestHookLister_WatchRereadsToken(t *testing.T) {
	var (
		mu   sync.Mutex
		auth []string
	)
	lister, tokenPath := newFakeAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = append(auth, r.Header.Get("Authorization"))
		mu.Unlock()
		writeWatchStream(w)
	})

	openAndDrain := func() {
		t.Helper()
		events, err := lister.WatchPlexdHooks(context.Background(), "plexd-system")
		if err != nil {
			t.Fatalf("WatchPlexdHooks: %v", err)
		}
		requireWatchClosed(t, events)
	}

	openAndDrain()
	if err := os.WriteFile(tokenPath, []byte("sa-token-2"), 0o600); err != nil {
		t.Fatal(err)
	}
	openAndDrain()

	mu.Lock()
	defer mu.Unlock()
	if want := []string{"Bearer sa-token-1", "Bearer sa-token-2"}; !reflect.DeepEqual(auth, want) {
		t.Errorf("Authorization headers = %q, want %q", auth, want)
	}
}

func TestHookLister_WatchMissingTokenSendsNothing(t *testing.T) {
	var requests atomic.Int32
	lister, tokenPath := newFakeAPIServer(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		writeWatchStream(w)
	})
	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}

	events, err := lister.WatchPlexdHooks(context.Background(), "plexd-system")
	var pathErr *fs.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("error = %v, want a wrapped *fs.PathError", err)
	}
	if events != nil {
		t.Error("WatchPlexdHooks returned a channel along with the error")
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("the API server saw %d requests, want none", n)
	}
}

// The values are written out rather than taken from the constant, so a change to
// it shows up here. An overall client timeout would cut every healthy stream.
func TestHookLister_WatchTransportTimeouts(t *testing.T) {
	lister, _ := newFakeAPIServer(t, func(http.ResponseWriter, *http.Request) {})

	transport, ok := lister.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", lister.client.Transport)
	}
	if got, want := transport.TLSHandshakeTimeout, 10*time.Second; got != want {
		t.Errorf("TLSHandshakeTimeout = %v, want %v", got, want)
	}
	if got, want := transport.ResponseHeaderTimeout, 10*time.Second; got != want {
		t.Errorf("ResponseHeaderTimeout = %v, want %v", got, want)
	}
	if lister.client.Timeout != 0 {
		t.Errorf("client Timeout = %v, want none", lister.client.Timeout)
	}
}

// The context of a real open runs for minutes, so the transport is what ends an
// open the API server never answers.
func TestHookLister_WatchOpenFailsWithoutHeaders(t *testing.T) {
	lister, _ := newFakeAPIServer(t, func(_ http.ResponseWriter, r *http.Request) {
		clientLeft(r)
	})
	transport, ok := lister.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", lister.client.Transport)
	}
	transport.ResponseHeaderTimeout = 50 * time.Millisecond

	// This context is only a backstop for a timeout that does not fire.
	ctx, cancel := context.WithTimeout(context.Background(), watchWaitLimit)
	defer cancel()
	events, err := lister.WatchPlexdHooks(ctx, "plexd-system")
	if err == nil {
		t.Fatal("WatchPlexdHooks succeeded, want an error")
	}
	if events != nil {
		t.Error("WatchPlexdHooks returned a channel along with the error")
	}
	if ctx.Err() != nil {
		t.Errorf("the open ended on the test's backstop: %v", err)
	}
	if !strings.Contains(err.Error(), "watch plexdhooks") {
		t.Errorf("error = %v, want it to say watch plexdhooks", err)
	}
}
