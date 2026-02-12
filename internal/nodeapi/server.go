package nodeapi

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// NodeAPIClient combines the control plane methods needed by the node API server.
type NodeAPIClient interface {
	SecretFetcher
	ReportSyncClient
}

// Server is the local node API server. It serves HTTP over a Unix socket and
// optionally over TCP with bearer token authentication.
type Server struct {
	cfg    Config
	client NodeAPIClient
	nsk    []byte
	logger *slog.Logger
	cache  *StateCache
}

// NewServer creates a new Server. Config defaults are applied automatically.
// The cache is initialized eagerly so that RegisterEventHandlers and
// ReconcileHandler can be called before Start.
func NewServer(cfg Config, client NodeAPIClient, nsk []byte, logger *slog.Logger) *Server {
	cfg.ApplyDefaults()
	if logger == nil {
		logger = slog.Default()
	}
	lg := logger.With("component", "nodeapi")
	return &Server{
		cfg:    cfg,
		client: client,
		nsk:    nsk,
		logger: lg,
		cache:  NewStateCache(cfg.DataDir, lg),
	}
}

// Start initializes and runs the server. It blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context, nodeID string) error {
	if err := s.cfg.Validate(); err != nil {
		return err
	}

	// Load cache from disk (directories created if needed).
	if err := s.cache.Load(); err != nil {
		return fmt.Errorf("nodeapi: load cache: %w", err)
	}

	// Start report syncer.
	syncer := NewReportSyncer(s.client, nodeID, s.cfg.DebouncePeriod, s.logger)

	// Set up HTTP handler.
	handler := NewHandler(s.cache, s.client, nodeID, s.nsk, s.logger)
	mux := handler.Mux()

	// Wrap mux with a report-sync notifier.
	wrappedMux := reportNotifyMiddleware(mux, s.cache, syncer)

	// Remove stale socket.
	os.Remove(s.cfg.SocketPath)

	// Ensure socket directory exists.
	if dir := filepath.Dir(s.cfg.SocketPath); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("nodeapi: create socket dir: %w", err)
		}
	}

	// Open Unix socket listener.
	unixLn, err := net.Listen("unix", s.cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("nodeapi: listen unix %s: %w", s.cfg.SocketPath, err)
	}

	unixServer := &http.Server{Handler: wrappedMux}

	var tcpServer *http.Server
	var tcpLn net.Listener

	if s.cfg.HTTPEnabled {
		// Read token from file.
		token, err := readTokenFile(s.cfg.HTTPTokenFile)
		if err != nil {
			unixLn.Close()
			os.Remove(s.cfg.SocketPath)
			return fmt.Errorf("nodeapi: read token file: %w", err)
		}

		// TCP mux wraps with auth middleware.
		authMiddleware := BearerAuthMiddleware(token)
		tcpHandler := authMiddleware(wrappedMux)

		tcpLn, err = net.Listen("tcp", s.cfg.HTTPListen)
		if err != nil {
			unixLn.Close()
			os.Remove(s.cfg.SocketPath)
			return fmt.Errorf("nodeapi: listen tcp %s: %w", s.cfg.HTTPListen, err)
		}
		tcpServer = &http.Server{Handler: tcpHandler}
	}

	s.logger.Info("server started",
		"socket", s.cfg.SocketPath,
		"http_enabled", s.cfg.HTTPEnabled,
		"http_listen", s.cfg.HTTPListen,
		"node_id", nodeID,
	)

	// Run goroutines.
	var wg sync.WaitGroup

	// Report syncer goroutine.
	syncCtx, syncCancel := context.WithCancel(ctx)
	wg.Add(1)
	go func() {
		defer wg.Done()
		syncer.Run(syncCtx)
	}()

	// Unix socket serve goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := unixServer.Serve(unixLn); err != http.ErrServerClosed {
			s.logger.Error("unix server error", "error", err)
		}
	}()

	// TCP serve goroutine.
	if tcpServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := tcpServer.Serve(tcpLn); err != http.ErrServerClosed {
				s.logger.Error("tcp server error", "error", err)
			}
		}()
	}

	// Wait for context cancellation.
	<-ctx.Done()

	s.logger.Info("server shutting down")

	// Graceful shutdown with timeout.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
	defer shutdownCancel()

	unixServer.Shutdown(shutdownCtx)
	if tcpServer != nil {
		tcpServer.Shutdown(shutdownCtx)
	}

	// Stop syncer.
	syncCancel()

	// Remove socket file.
	os.Remove(s.cfg.SocketPath)

	// Wait for all goroutines.
	wg.Wait()

	s.logger.Info("server stopped")

	return ctx.Err()
}

// RegisterEventHandlers registers SSE event handlers with the given dispatcher.
func (s *Server) RegisterEventHandlers(dispatcher *api.EventDispatcher) {
	RegisterEventHandlers(dispatcher, s.cache, s.logger)
}

// ReconcileHandler returns a reconcile.ReconcileHandler that updates the cache
// when drift is detected in metadata, data, or secret refs.
func (s *Server) ReconcileHandler() reconcile.ReconcileHandler {
	return func(ctx context.Context, desired *api.StateResponse, diff reconcile.StateDiff) error {
		if diff.MetadataChanged {
			s.cache.UpdateMetadata(desired.Metadata)
		}
		if diff.DataChanged {
			s.cache.UpdateData(desired.Data)
		}
		if diff.SecretRefsChanged {
			s.cache.UpdateSecretIndex(desired.SecretRefs)
		}
		return nil
	}
}

// reportNotifyMiddleware wraps a handler to notify the syncer after report mutations.
func reportNotifyMiddleware(next http.Handler, cache *StateCache, syncer *ReportSyncer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture report state before the request for mutation detection.
		isPutReport := r.Method == http.MethodPut && isReportPath(r.URL.Path)
		isDeleteReport := r.Method == http.MethodDelete && isReportPath(r.URL.Path)

		// Use a response recorder to detect status.
		rw := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rw, r)

		if isPutReport && rw.status == http.StatusOK {
			key := extractReportKey(r.URL.Path)
			if entry, ok := cache.GetReport(key); ok {
				syncer.NotifyChange([]api.ReportEntry{
					{
						Key:         entry.Key,
						ContentType: entry.ContentType,
						Payload:     entry.Payload,
						Version:     entry.Version,
						UpdatedAt:   entry.UpdatedAt,
					},
				}, nil)
			}
		}
		if isDeleteReport && rw.status == http.StatusNoContent {
			key := extractReportKey(r.URL.Path)
			syncer.NotifyChange(nil, []string{key})
		}
	})
}

// isReportPath checks if the path matches /v1/state/report/{key}.
func isReportPath(path string) bool {
	return strings.HasPrefix(path, "/v1/state/report/") && strings.Count(path, "/") == 4
}

// extractReportKey extracts the key from /v1/state/report/{key}.
func extractReportKey(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

// statusRecorder captures the HTTP status code written to the response.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// readTokenFile reads and trims a bearer token from a file.
func readTokenFile(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("token file path is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("token file is empty")
	}
	return token, nil
}
