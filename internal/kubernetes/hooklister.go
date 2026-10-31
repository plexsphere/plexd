package kubernetes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// plexdHookListPath is the collection path of the PlexdHook resources in one
// namespace; %s takes the path-escaped namespace name.
const plexdHookListPath = "/apis/plexd.plexsphere.com/v1alpha1/namespaces/%s/plexdhooks"

// plexdHookTransportTimeout bounds the TLS handshake and the wait for response
// headers on every request. The client has no overall timeout and a watch runs
// under a context of minutes, so without this bound a stalled API server would
// hold an open for all of that time with nothing to report it.
const plexdHookTransportTimeout = 10 * time.Second

// HookLister reads PlexdHook resources through the Kubernetes API server with
// the pod's ServiceAccount credentials. ListPlexdHooks is one GET,
// WatchPlexdHooks is one GET held open as a stream, and neither ever writes.
type HookLister struct {
	baseURL   string
	tokenPath string
	client    *http.Client
}

// NewInClusterHookLister builds a HookLister for the API server a pod reaches
// through the KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT variables,
// trusting the cluster CA at DefaultCACertPath and authenticating with the
// ServiceAccount token at env.ServiceAccountToken. The client carries no overall
// timeout, because a watch response lasts as long as its stream: the context
// passed to ListPlexdHooks or WatchPlexdHooks bounds each call, and the
// transport bounds only how long an API server may take to start answering.
func NewInClusterHookLister(env *KubernetesEnvironment) (*HookLister, error) {
	return newHookLister(os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT"), DefaultCACertPath, env)
}

// newHookLister is NewInClusterHookLister with the API server address and the
// CA bundle path supplied, so a test can point it at a fake API server.
//
// A CA bundle that cannot be read or holds no certificate is an error here
// rather than a fallback to the system roots: the API server's certificate
// chains to the cluster CA, so that fallback only fails later, as a TLS error
// that no longer names the cause.
func newHookLister(host, port, caPath string, env *KubernetesEnvironment) (*HookLister, error) {
	if host == "" || port == "" {
		return nil, errors.New("kubernetes: hook lister: KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must both be set")
	}
	if env == nil || env.ServiceAccountToken == "" {
		return nil, errors.New("kubernetes: hook lister: no service account token path")
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: hook lister: read cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("kubernetes: hook lister: no certificate in cluster CA bundle %s", caPath)
	}

	return &HookLister{
		baseURL:   "https://" + net.JoinHostPort(host, port),
		tokenPath: env.ServiceAccountToken,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
				TLSHandshakeTimeout:   plexdHookTransportTimeout,
				ResponseHeaderTimeout: plexdHookTransportTimeout,
			},
		},
	}, nil
}

// ListPlexdHooks returns the PlexdHook resources in namespace, or an empty
// slice when there are none.
//
// The ServiceAccount token is read from disk on every call, because the kubelet
// rotates it. A 401 or 403 wraps ErrUnauthorized (the ServiceAccount lacks the
// read grant), a 404 wraps ErrNotFound (the CRD is not installed), and any other
// status is an error naming it. A context that runs out surfaces as an error
// wrapping the context's own error.
func (l *HookLister) ListPlexdHooks(ctx context.Context, namespace string) ([]PlexdHook, error) {
	resp, err := l.getPlexdHooks(ctx, "list", namespace, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var list plexdHookList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, fmt.Errorf("kubernetes: list plexdhooks: decode response: %w", err)
	}
	hooks := make([]PlexdHook, 0, len(list.Items))
	for _, item := range list.Items {
		hooks = append(hooks, item.toPlexdHook())
	}
	return hooks, nil
}

// WatchPlexdHooks opens a watch on the PlexdHook resources in namespace and
// returns a channel of their changes. The request carries no resourceVersion,
// so the API server starts by replaying every existing resource as ADDED, and a
// version that has gone stale (410 Gone) cannot occur.
//
// An open fails the way ListPlexdHooks does, with the same token handling and
// the same mapping of a 401 or 403 to ErrUnauthorized and a 404 to ErrNotFound,
// and it returns no channel.
//
// The channel closes when the stream ends, a frame does not decode, a frame has
// type ERROR, or ctx ends. It carries no reason, because the answer to each of
// these is the same: open a new watch. A caller that stops receiving must cancel
// ctx, which is what releases the goroutine feeding the channel.
func (l *HookLister) WatchPlexdHooks(ctx context.Context, namespace string) (<-chan PlexdHookEvent, error) {
	resp, err := l.getPlexdHooks(ctx, "watch", namespace, "watch=true")
	if err != nil {
		return nil, err
	}

	events := make(chan PlexdHookEvent)
	go streamPlexdHooks(ctx, resp.Body, events)
	return events, nil
}

// getPlexdHooks sends one GET of the PlexdHook collection in namespace, with
// query as the raw query string when it is not empty, and returns the response
// to a 200. Every other outcome is an error whose text names verb, with the
// response body already closed. The token is read here because the kubelet
// rotates it, so each call and each watch open presents the current one.
func (l *HookLister) getPlexdHooks(ctx context.Context, verb, namespace, query string) (*http.Response, error) {
	token, err := os.ReadFile(l.tokenPath)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: %s plexdhooks: read service account token: %w", verb, err)
	}

	endpoint := l.baseURL + fmt.Sprintf(plexdHookListPath, url.PathEscape(namespace))
	if query != "" {
		endpoint += "?" + query
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: %s plexdhooks: create request: %w", verb, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))

	resp, err := l.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: %s plexdhooks: %w", verb, err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return resp, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		err = fmt.Errorf("kubernetes: %s plexdhooks in %q: status %d: %w", verb, namespace, resp.StatusCode, ErrUnauthorized)
	case http.StatusNotFound:
		err = fmt.Errorf("kubernetes: %s plexdhooks in %q: status %d: %w", verb, namespace, resp.StatusCode, ErrNotFound)
	default:
		err = fmt.Errorf("kubernetes: %s plexdhooks in %q: unexpected status %d", verb, namespace, resp.StatusCode)
	}
	resp.Body.Close()
	return nil, err
}

// streamPlexdHooks feeds events from the watch stream in body until the stream
// is over, then closes body and events. It owns both. The send selects on ctx
// because a cancelled context only fails the next read of body: a goroutine
// parked on a send nobody receives would never get to that read.
func streamPlexdHooks(ctx context.Context, body io.ReadCloser, events chan<- PlexdHookEvent) {
	defer close(events)
	defer body.Close()

	decoder := json.NewDecoder(body)
	for {
		var frame plexdHookWatchFrame
		if err := decoder.Decode(&frame); err != nil {
			return
		}
		switch frame.Type {
		case "ERROR":
			return
		case "BOOKMARK":
			continue
		}

		var item plexdHookItem
		if err := json.Unmarshal(frame.Object, &item); err != nil {
			return
		}
		hook := item.toPlexdHook()
		select {
		case events <- PlexdHookEvent{Type: frame.Type, Hook: &hook}:
		case <-ctx.Done():
			return
		}
	}
}

// plexdHookWatchFrame is one frame of a watch stream. The object stays raw until
// the type is known, because an ERROR frame carries a metav1.Status, whose
// status member is a string where a PlexdHook has an object.
type plexdHookWatchFrame struct {
	Type   string          `json:"type"`
	Object json.RawMessage `json:"object"`
}

// plexdHookList is the Kubernetes list envelope a PlexdHook collection GET
// answers with.
type plexdHookList struct {
	Items []plexdHookItem `json:"items"`
}

// plexdHookItem is a PlexdHook as the API server serves it, in a list and in a
// watch frame. PlexdHook keeps the metadata fields flat, where the wire nests
// them under metadata, so the wire form cannot decode into it directly.
type plexdHookItem struct {
	Metadata struct {
		Name            string            `json:"name"`
		Namespace       string            `json:"namespace"`
		UID             string            `json:"uid"`
		ResourceVersion string            `json:"resourceVersion"`
		Labels          map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec   PlexdHookSpec   `json:"spec"`
	Status PlexdHookStatus `json:"status"`
}

// toPlexdHook unnests the metadata.
func (i plexdHookItem) toPlexdHook() PlexdHook {
	return PlexdHook{
		Name:            i.Metadata.Name,
		Namespace:       i.Metadata.Namespace,
		UID:             i.Metadata.UID,
		ResourceVersion: i.Metadata.ResourceVersion,
		Labels:          i.Metadata.Labels,
		Spec:            i.Spec,
		Status:          i.Status,
	}
}
