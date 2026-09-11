package kubernetes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// plexdHookListPath is the collection path of the PlexdHook resources in one
// namespace; %s takes the path-escaped namespace name.
const plexdHookListPath = "/apis/plexd.plexsphere.com/v1alpha1/namespaces/%s/plexdhooks"

// HookLister lists PlexdHook resources through the Kubernetes API server with
// the pod's ServiceAccount credentials. Each call is one GET: it never watches
// and never writes.
type HookLister struct {
	baseURL   string
	tokenPath string
	client    *http.Client
}

// NewInClusterHookLister builds a HookLister for the API server a pod reaches
// through the KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT variables,
// trusting the cluster CA at DefaultCACertPath and authenticating with the
// ServiceAccount token at env.ServiceAccountToken. The client carries no
// timeout of its own: the context passed to ListPlexdHooks bounds each call.
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
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
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
	token, err := os.ReadFile(l.tokenPath)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: list plexdhooks: read service account token: %w", err)
	}

	endpoint := l.baseURL + fmt.Sprintf(plexdHookListPath, url.PathEscape(namespace))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: list plexdhooks: create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))

	resp, err := l.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: list plexdhooks: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("kubernetes: list plexdhooks in %q: status %d: %w", namespace, resp.StatusCode, ErrUnauthorized)
	case http.StatusNotFound:
		return nil, fmt.Errorf("kubernetes: list plexdhooks in %q: status %d: %w", namespace, resp.StatusCode, ErrNotFound)
	default:
		return nil, fmt.Errorf("kubernetes: list plexdhooks in %q: unexpected status %d", namespace, resp.StatusCode)
	}

	var list plexdHookList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, fmt.Errorf("kubernetes: list plexdhooks: decode response: %w", err)
	}
	hooks := make([]PlexdHook, 0, len(list.Items))
	for _, item := range list.Items {
		hooks = append(hooks, PlexdHook{
			Name:            item.Metadata.Name,
			Namespace:       item.Metadata.Namespace,
			UID:             item.Metadata.UID,
			ResourceVersion: item.Metadata.ResourceVersion,
			Labels:          item.Metadata.Labels,
			Spec:            item.Spec,
			Status:          item.Status,
		})
	}
	return hooks, nil
}

// plexdHookList is the Kubernetes list envelope a PlexdHook collection GET
// answers with. PlexdHook keeps the metadata fields flat, where the wire nests
// them under metadata, so the envelope cannot decode into it directly.
type plexdHookList struct {
	Items []struct {
		Metadata struct {
			Name            string            `json:"name"`
			Namespace       string            `json:"namespace"`
			UID             string            `json:"uid"`
			ResourceVersion string            `json:"resourceVersion"`
			Labels          map[string]string `json:"labels"`
		} `json:"metadata"`
		Spec   PlexdHookSpec   `json:"spec"`
		Status PlexdHookStatus `json:"status"`
	} `json:"items"`
}
