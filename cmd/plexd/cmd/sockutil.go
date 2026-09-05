package cmd

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/plexsphere/plexd/internal/nodeapi"
)

// newSocketClient creates an HTTP client that connects to the local node API
// endpoint: a Unix socket, or a named pipe on Windows.
func newSocketClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return nodeapi.DialLocal(ctx, socketPath)
			},
		},
	}
}

// socketURL returns a URL for the given path using the Unix socket.
func socketURL(path string) string {
	return "http://localhost" + path
}

// socketGet performs a GET request to the local agent via Unix socket.
func socketGet(socketPath, path string) (*http.Response, error) {
	client := newSocketClient(socketPath)
	resp, err := client.Get(socketURL(path))
	if err != nil {
		return nil, fmt.Errorf("agent not running or socket unavailable at %s: %w", socketPath, err)
	}
	return resp, nil
}

// socketPost performs a POST request to the local agent via Unix socket.
func socketPost(socketPath, path, contentType string, body io.Reader) (*http.Response, error) {
	client := newSocketClient(socketPath)
	resp, err := client.Post(socketURL(path), contentType, body)
	if err != nil {
		return nil, fmt.Errorf("agent not running or socket unavailable at %s: %w", socketPath, err)
	}
	return resp, nil
}

// socketPathOverride allows tests to redirect socket-based commands to a
// temporary Unix socket. Production code leaves this empty.
var socketPathOverride string

// defaultSocketPath returns the configured or default socket path.
func defaultSocketPath() string {
	if socketPathOverride != "" {
		return socketPathOverride
	}
	return nodeapi.DefaultSocketPath
}
