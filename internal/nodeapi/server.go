package nodeapi

import (
	"context"
	"encoding/json"
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
	syncer *ReportSyncer

	actionProvider ActionProvider
	hookReloader   HookReloader
	peerProvider   PeerProvider
	policyProvider PolicyProvider
	logStatus      ForwarderStatusProvider
	auditStatus    ForwarderStatusProvider
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
		// The syncer is built here (before the node ID is known) so PublishReport
		// works ahead of Start; Run receives the node ID when the server starts.
		syncer: NewReportSyncer(client, cfg.DebouncePeriod, lg),
	}
}

// SetActionProvider sets the action provider for action/hook endpoints.
// Must be called before Start.
func (s *Server) SetActionProvider(provider ActionProvider) {
	s.actionProvider = provider
}

// SetHookReloader sets the hook reloader for the reload endpoint.
// Must be called before Start.
func (s *Server) SetHookReloader(reloader HookReloader) {
	s.hookReloader = reloader
}

// SetPeerProvider sets the peer status provider. Must be called before Start.
func (s *Server) SetPeerProvider(p PeerProvider) {
	s.peerProvider = p
}

// SetPolicyProvider sets the policy provider. Must be called before Start.
func (s *Server) SetPolicyProvider(p PolicyProvider) {
	s.policyProvider = p
}

// SetLogStatus sets the log forwarder status provider. Must be called before Start.
func (s *Server) SetLogStatus(p ForwarderStatusProvider) {
	s.logStatus = p
}

// SetAuditStatus sets the audit forwarder status provider. Must be called before Start.
func (s *Server) SetAuditStatus(p ForwarderStatusProvider) {
	s.auditStatus = p
}

// Cache returns the server's state cache for use by SSE event handlers.
func (s *Server) Cache() *StateCache {
	return s.cache
}

// PublishReport writes a report entry through the cache and notifies the syncer
// so it converges to the control plane. It is the seam through which internal
// producers publish status blocks, and it holds key and payload to the same
// grammar and 4096-byte value cap as the local HTTP API. content_type and the
// resulting version stay local-only; the syncer ships only the payload value.
func (s *Server) PublishReport(key, contentType string, payload json.RawMessage) error {
	if !validReportKey(key) {
		return fmt.Errorf("nodeapi: invalid report key %q", key)
	}
	if len(payload) > maxReportValueBytes {
		return fmt.Errorf("nodeapi: report payload for key %q exceeds the %d-byte limit", key, maxReportValueBytes)
	}
	entry, err := s.cache.PutReport(key, contentType, payload, nil)
	if err != nil {
		return fmt.Errorf("nodeapi: publish report %q: %w", key, err)
	}
	s.syncer.NotifyChange([]ReportEntry{entry}, nil)
	return nil
}

// ReportPayload returns the payload currently stored under key, and whether the
// key exists. Internal producers use it to compare what is actually published
// against what they would publish, so a report another local caller overwrote or
// deleted is re-asserted rather than assumed to still hold their last value.
func (s *Server) ReportPayload(key string) (json.RawMessage, bool) {
	entry, ok := s.cache.GetReport(key)
	if !ok {
		return nil, false
	}
	return entry.Payload, true
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

	// A report persisted under the older, laxer key grammar is unreachable
	// through the local routes, so its upstream copy would stay pinned on the
	// control plane forever. Queue a delete for each; DeleteStateReport is
	// idempotent, so a key that was never synced simply answers 404
	// report_not_found.
	if orphaned := s.cache.OrphanedReportKeys(); len(orphaned) > 0 {
		s.syncer.NotifyChange(nil, orphaned)
	}

	// Set up HTTP handler.
	handler := NewHandler(s.cache, s.client, nodeID, s.nsk, s.logger)
	handler.SetActionProvider(s.actionProvider)
	handler.SetHookReloader(s.hookReloader)
	handler.SetPeerProvider(s.peerProvider)
	handler.SetPolicyProvider(s.policyProvider)
	handler.SetLogStatus(s.logStatus)
	handler.SetAuditStatus(s.auditStatus)
	mux := handler.Mux()

	// Wrap mux with a report-sync notifier.
	wrappedMux := reportNotifyMiddleware(mux, s.cache, s.syncer)

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

	// Set socket ownership and permissions (Linux: root:plexd 0660).
	applySocketPermissions(s.cfg.SocketPath, s.logger)

	// Wrap secret routes with peer credential auth (Linux: SO_PEERCRED).
	// Only enabled when SecretAuthEnabled is set (requires root to set socket perms).
	var unixHandler http.Handler = wrappedMux
	if s.cfg.SecretAuthEnabled {
		unixHandler = wrapSecretAuth(wrappedMux, s.logger)
	}

	unixServer := &http.Server{
		Handler:     unixHandler,
		ConnContext: connContextWithPeerCred(s.logger),
	}

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
		_ = s.syncer.Run(syncCtx, nodeID)
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

	_ = unixServer.Shutdown(shutdownCtx)
	if tcpServer != nil {
		_ = tcpServer.Shutdown(shutdownCtx)
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
// when the desired state block changes. The block's metadata bucket becomes the
// cache metadata map (both representations are a faithful map[string]string, so
// the pull round-trips it). A nil state block authoritatively clears the
// metadata map.
//
// The versioned data store (GET /v1/state/data, api.DataEntry with a real
// content_type and version) is owned by the node_state_updated SSE feed, not by
// this pull path. The snapshot's data bucket carries only opaque key/value
// strings (api.StateEntry) — it has no source for content_type or version, so
// converting it here would have to fabricate both, pinning every entry to
// version 1 and clobbering the SSE-delivered content_type/version that consumers
// poll for change detection. The pull therefore leaves the data store to its SSE
// owner, mirroring how secret refs already ride the node_secrets_updated feed.
func (s *Server) ReconcileHandler() reconcile.ReconcileHandler {
	return func(ctx context.Context, desired *api.NodeStateSnapshot, diff reconcile.StateDiff) error {
		if !diff.StateChanged {
			return nil
		}

		if desired.State == nil {
			// Authoritative clear of the metadata map the pull owns; the
			// SSE-owned data store is left intact.
			s.cache.UpdateMetadata(map[string]string{})
			return nil
		}

		metadata := make(map[string]string, len(desired.State.Metadata))
		for _, e := range desired.State.Metadata {
			metadata[e.Key] = e.Value
		}
		s.cache.UpdateMetadata(metadata)
		return nil
	}
}

// reportNotifyMiddleware wraps a handler to notify the syncer after report
// mutations. The notification derives from what the cache holds after the
// handler returned, not from the method that ran: the notify happens outside the
// cache lock, so a PUT and a DELETE of the same key racing on the socket can
// notify in the opposite order to the one they mutated the cache in. Deriving
// the change from the cache makes whichever notification lands last carry the
// cache's actual state, instead of a stale "put" overwriting a pending delete
// and leaving the report on the control plane after it was removed locally.
func reportNotifyMiddleware(next http.Handler, cache *StateCache, syncer *ReportSyncer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture report state before the request for mutation detection.
		isPutReport := r.Method == http.MethodPut && isReportPath(r.URL.Path)
		isDeleteReport := r.Method == http.MethodDelete && isReportPath(r.URL.Path)

		// Use a response recorder to detect status.
		rw := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rw, r)

		if !isPutReport && !isDeleteReport {
			return
		}
		if rw.status != http.StatusOK && rw.status != http.StatusNoContent {
			return
		}
		key := extractReportKey(r.URL.Path)
		if entry, ok := cache.GetReport(key); ok {
			syncer.NotifyChange([]ReportEntry{entry}, nil)
		} else {
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
