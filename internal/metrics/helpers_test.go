package metrics

import (
	"log/slog"
	"testing"

	"github.com/plexsphere/plexd/internal/api"
)

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(nopWriter{}, nil))
}

// mustNewLocalReporter returns NewLocalReporter's reporter and fails the test
// on an error, for the tests whose configuration is meant to be usable.
func mustNewLocalReporter(t testing.TB, cfg api.LocalEndpointConfig, fetcher SecretFetcher, nsk []byte, nodeID string, logger *slog.Logger) *LocalReporter {
	t.Helper()
	r, err := NewLocalReporter(cfg, fetcher, nsk, nodeID, logger)
	if err != nil {
		t.Fatalf("NewLocalReporter: %v", err)
	}
	return r
}
