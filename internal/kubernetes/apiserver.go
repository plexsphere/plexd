package kubernetes

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

// apiServerTransportTimeout bounds the TLS handshake and the wait for response
// headers on every request. The client has no overall timeout and a watch runs
// under a context of minutes, so without this bound a stalled API server would
// hold an open for all of that time with nothing to report it.
const apiServerTransportTimeout = 10 * time.Second

// maxStatusMessageBytes caps the message of a metav1.Status body that an error
// for an unexpected status quotes. An admission webhook can answer with a
// message of any length, and the error ends up in an execution callback.
const maxStatusMessageBytes = 512

// maxStatusBodyBytes caps how much of an error response is read to find its
// metav1.Status message. A Status is a few hundred bytes; anything longer is
// not one worth quoting.
const maxStatusBodyBytes = 64 << 10

// apiServer is the Kubernetes API server a pod reaches with its ServiceAccount
// credentials: the server's base URL, the path of the ServiceAccount token, and
// an HTTP client that trusts the cluster CA. HookLister and JobClient embed it.
type apiServer struct {
	baseURL   string
	tokenPath string
	client    *http.Client
}

// newAPIServer builds the connection to the API server at host and port,
// trusting the CA bundle at caPath and authenticating with the token at
// env.ServiceAccountToken. Its errors name only the cause; each caller says
// which client it was building.
//
// A CA bundle that cannot be read or holds no certificate is an error here
// rather than a fallback to the system roots: the API server's certificate
// chains to the cluster CA, so that fallback only fails later, as a TLS error
// that no longer names the cause.
//
// The client carries no overall timeout, because a watch response lasts as
// long as its stream: the context of each call bounds it, and the transport
// bounds only how long an API server may take to start answering.
func newAPIServer(host, port, caPath string, env *KubernetesEnvironment) (*apiServer, error) {
	if host == "" || port == "" {
		return nil, errors.New("KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must both be set")
	}
	if env == nil || env.ServiceAccountToken == "" {
		return nil, errors.New("no service account token path")
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no certificate in cluster CA bundle %s", caPath)
	}

	return &apiServer{
		baseURL:   "https://" + net.JoinHostPort(host, port),
		tokenPath: env.ServiceAccountToken,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
				TLSHandshakeTimeout:   apiServerTransportTimeout,
				ResponseHeaderTimeout: apiServerTransportTimeout,
			},
		},
	}, nil
}

// do sends one request to path, with rawQuery as the query string when it is
// not empty and body as a JSON request body when it is not nil, and returns the
// response to any 2xx status. The caller closes its body.
//
// The ServiceAccount token is read on every call, because the kubelet rotates
// it. A 401 or 403 wraps ErrUnauthorized, a 404 ErrNotFound and a 409
// ErrAlreadyExists. Any other status is an error that quotes the message of the
// metav1.Status the API server answers with. Every error names the call by
// what, such as `create job in "plexd-system"`, and comes back with the
// response body already closed.
//
// The Accept header is the one kubectl get --raw sends. It admits the text a
// pods/log request answers with as well as JSON, and was measured to work for
// pods/log.
func (s *apiServer) do(ctx context.Context, what, method, path, rawQuery string, body []byte) (*http.Response, error) {
	token, err := os.ReadFile(s.tokenPath)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: %s: read service account token: %w", what, err)
	}

	endpoint := s.baseURL + path
	if rawQuery != "" {
		endpoint += "?" + rawQuery
	}
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reqBody)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: %s: create request: %w", what, err)
	}
	req.Header.Set("Accept", "application/json, */*")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kubernetes: %s: %w", what, err)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp, nil
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, fmt.Errorf("kubernetes: %s: status %d: %w", what, resp.StatusCode, ErrUnauthorized)
	case http.StatusNotFound:
		return nil, fmt.Errorf("kubernetes: %s: status %d: %w", what, resp.StatusCode, ErrNotFound)
	case http.StatusConflict:
		return nil, fmt.Errorf("kubernetes: %s: status %d: %w", what, resp.StatusCode, ErrAlreadyExists)
	}
	if msg := statusMessage(resp.Body); msg != "" {
		return nil, fmt.Errorf("kubernetes: %s: unexpected status %d: %s", what, resp.StatusCode, msg)
	}
	return nil, fmt.Errorf("kubernetes: %s: unexpected status %d", what, resp.StatusCode)
}

// statusMessage returns the message of the metav1.Status in body, cut to
// maxStatusMessageBytes at the start of the rune that crosses the limit, or ""
// when body is not a Status.
func statusMessage(body io.Reader) string {
	var status struct {
		Kind    string `json:"kind"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(io.LimitReader(body, maxStatusBodyBytes)).Decode(&status); err != nil || status.Kind != "Status" {
		return ""
	}
	msg := status.Message
	if len(msg) <= maxStatusMessageBytes {
		return msg
	}
	cut := maxStatusMessageBytes
	for i := 1; i < utf8.UTFMax && !utf8.RuneStart(msg[cut]); i++ {
		cut--
	}
	return msg[:cut]
}
