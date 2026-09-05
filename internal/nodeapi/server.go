package nodeapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/plexsphere/plexd/internal/api"
	"github.com/plexsphere/plexd/internal/reconcile"
)

// NodeAPIClient combines the control plane methods needed by the node API server.
type NodeAPIClient interface {
	SecretFetcher
	ReportSyncClient
}

// Server is the local node API server. It serves HTTP over the local listener
// (a Unix socket, or a named pipe on Windows) and optionally over TCP with
// bearer token authentication.
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
// The cache is initialized eagerly so that ReconcileHandler can be called
// before Start.
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

	// Open the local listener (Unix socket, or a named pipe on Windows).
	localLn, err := ListenLocal(s.cfg.SocketPath, s.logger)
	if err != nil {
		return err
	}

	// Wrap the secret routes with peer-credential auth: SO_PEERCRED on Linux,
	// LOCAL_PEERCRED on macOS, the pipe client's token on Windows. Only when
	// SecretAuthEnabled is set. That middleware is the only reader of what
	// ConnContext stores, so the credentials are resolved only alongside it:
	// otherwise every accepted connection pays for a result nothing consumes,
	// a process handle and a token query on Windows, and a lookup that cannot
	// succeed on the Unix platforms without an implementation.
	var localHandler http.Handler = wrappedMux
	var localConnContext func(context.Context, net.Conn) context.Context
	if s.cfg.SecretAuthEnabled {
		localHandler = wrapSecretAuth(wrappedMux, newSecretPolicy(), s.logger)
		localConnContext = connContextWithPeerCred(s.logger)
	}

	localServer := &http.Server{
		Handler:     localHandler,
		ConnContext: localConnContext,
	}

	var tcpServer *http.Server
	var tcpLn net.Listener

	if s.cfg.HTTPEnabled {
		// Read token from file.
		token, err := readTokenFile(s.cfg.HTTPTokenFile)
		if err != nil {
			localLn.Close()
			removeLocal(s.cfg.SocketPath)
			return fmt.Errorf("nodeapi: read token file: %w", err)
		}

		// TCP mux wraps with auth middleware.
		authMiddleware := BearerAuthMiddleware(token)
		tcpHandler := authMiddleware(wrappedMux)

		tcpLn, err = net.Listen("tcp", s.cfg.HTTPListen)
		if err != nil {
			localLn.Close()
			removeLocal(s.cfg.SocketPath)
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

	// Local listener serve goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := localServer.Serve(localLn); err != http.ErrServerClosed {
			s.logger.Error("local server error", "error", err)
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

	_ = localServer.Shutdown(shutdownCtx)
	if tcpServer != nil {
		_ = tcpServer.Shutdown(shutdownCtx)
	}

	// Stop syncer.
	syncCancel()

	// Remove the socket file (a no-op where the listener is a pipe).
	removeLocal(s.cfg.SocketPath)

	// Wait for all goroutines.
	wg.Wait()

	s.logger.Info("server stopped")

	return ctx.Err()
}

// ReconcileHandler returns a reconcile.ReconcileHandler that refreshes the cache
// from the desired state block whenever it changes. The block's metadata bucket
// becomes the cache metadata map, and its opaque data bucket feeds the versioned
// data store (GET /v1/state/data): each api.StateEntry value is JSON-encoded into
// an api.DataEntry payload under dataStateContentType. A nil state block
// authoritatively clears both buckets.
//
// The secret index is not fed here: secret references no longer ride the
// snapshot and secret values are always fetched live, so the pull leaves it
// untouched.
func (s *Server) ReconcileHandler() reconcile.ReconcileHandler {
	return func(ctx context.Context, desired *api.NodeStateSnapshot, diff reconcile.StateDiff) error {
		if !diff.StateChanged {
			return nil
		}

		if desired.State == nil {
			// Authoritative clear of both buckets the pull owns.
			s.cache.UpdateMetadata(map[string]string{})
			s.cache.UpdateData(nil)
			return nil
		}

		metadata := make(map[string]string, len(desired.State.Metadata))
		for _, e := range desired.State.Metadata {
			metadata[e.Key] = e.Value
		}
		s.cache.UpdateMetadata(metadata)

		entries, err := s.dataEntriesFromSnapshot(desired.State.Data)
		if err != nil {
			return err
		}
		s.cache.UpdateData(entries)
		return nil
	}
}

// dataStateContentType is stamped on every data entry the pull derives from the
// snapshot. The opaque data bucket carries no content type of its own, so each
// value is wrapped as a JSON string payload under this fixed text type.
const dataStateContentType = "text/plain; charset=utf-8"

// dataEntriesFromSnapshot converts the snapshot's opaque data bucket
// (api.StateEntry key/value pairs) into the versioned api.DataEntry values the
// GET /v1/state/data routes serve. The snapshot has no content_type or version,
// so each value is JSON-encoded into a payload under dataStateContentType and
// its version is carried forward from the current cache entry, bumped only when
// a key's payload actually changes — a consumer polling the version therefore
// sees a monotonic change signal instead of every entry pinned to 1.
func (s *Server) dataEntriesFromSnapshot(bucket []api.StateEntry) ([]api.DataEntry, error) {
	prev := s.cache.GetData()
	now := time.Now()
	entries := make([]api.DataEntry, 0, len(bucket))
	for _, e := range bucket {
		payload, err := json.Marshal(e.Value)
		if err != nil {
			return nil, fmt.Errorf("nodeapi: encode data value for key %q: %w", e.Key, err)
		}
		entry := api.DataEntry{
			Key:         e.Key,
			ContentType: dataStateContentType,
			Payload:     payload,
			Version:     1,
			UpdatedAt:   now,
		}
		if p, ok := prev[e.Key]; ok {
			if p.ContentType == entry.ContentType && bytes.Equal(p.Payload, payload) {
				// Unchanged: carry the version and timestamp forward.
				entry.Version = p.Version
				entry.UpdatedAt = p.UpdatedAt
			} else {
				entry.Version = p.Version + 1
			}
		}
		entries = append(entries, entry)
	}
	return entries, nil
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
