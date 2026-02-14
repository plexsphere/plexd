package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/plexsphere/plexd/internal/nodeapi"
)

// newSocketClient creates an HTTP client that connects via Unix socket.
func newSocketClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
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

// defaultSocketPath returns the configured or default socket path.
func defaultSocketPath() string {
	return nodeapi.DefaultSocketPath
}
