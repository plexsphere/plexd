package nodeapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"

	"github.com/plexsphere/plexd/internal/api"
)

// SecretFetcher abstracts the control plane client for secret retrieval.
type SecretFetcher interface {
	FetchSecret(ctx context.Context, nodeID, name string, version int) (*api.SecretEnvelope, error)
}

// ActionProvider supplies action and hook information to the local API.
type ActionProvider interface {
	Capabilities() ([]api.ActionInfo, []api.HookInfo)
}

// HookReloader triggers a re-scan of hooks from the filesystem.
type HookReloader interface {
	Hooks() []api.HookInfo
}

// PeerStatus describes a single mesh peer's status.
type PeerStatus struct {
	ID       string `json:"id"`
	PublicKey string `json:"public_key"`
	MeshIP   string `json:"mesh_ip"`
	Endpoint string `json:"endpoint"`
}

// PeerProvider supplies mesh peer information.
type PeerProvider interface {
	PeerStatuses() []PeerStatus
}

// PolicyProvider supplies the active merged network policy.
type PolicyProvider interface {
	ActivePolicy() *api.PolicySnapshot
}

// ForwarderStatus describes the operational status of a log or audit forwarder.
type ForwarderStatus struct {
	Enabled      bool   `json:"enabled"`
	BufferSize   int    `json:"buffer_size"`
	SourceCount  int    `json:"source_count"`
	ErrorCount   int    `json:"error_count"`
	LastReportAt string `json:"last_report_at,omitempty"`
}

// ForwarderStatusProvider supplies forwarder status information.
type ForwarderStatusProvider interface {
	ForwarderStatus() ForwarderStatus
}

// Handler provides HTTP handlers for the local node API.
type Handler struct {
	cache          *StateCache
	secretFetcher  SecretFetcher
	actionProvider ActionProvider
	hookReloader   HookReloader
	peerProvider   PeerProvider
	policyProvider PolicyProvider
	logStatus      ForwarderStatusProvider
	auditStatus    ForwarderStatusProvider
	nodeID         string
	nsk            []byte
	logger         *slog.Logger
}

// NewHandler creates a new Handler.
func NewHandler(cache *StateCache, secretFetcher SecretFetcher, nodeID string, nsk []byte, logger *slog.Logger) *Handler {
	return &Handler{
		cache:         cache,
		secretFetcher: secretFetcher,
		nodeID:        nodeID,
		nsk:           nsk,
		logger:        logger.With("component", "nodeapi"),
	}
}

// SetActionProvider sets the action provider for action/hook endpoints.
func (h *Handler) SetActionProvider(provider ActionProvider) {
	h.actionProvider = provider
}

// SetHookReloader sets the hook reloader for the reload endpoint.
func (h *Handler) SetHookReloader(reloader HookReloader) {
	h.hookReloader = reloader
}

// SetPeerProvider sets the peer status provider.
func (h *Handler) SetPeerProvider(p PeerProvider) {
	h.peerProvider = p
}

// SetPolicyProvider sets the policy provider.
func (h *Handler) SetPolicyProvider(p PolicyProvider) {
	h.policyProvider = p
}

// SetLogStatus sets the log forwarder status provider.
func (h *Handler) SetLogStatus(p ForwarderStatusProvider) {
	h.logStatus = p
}

// SetAuditStatus sets the audit forwarder status provider.
func (h *Handler) SetAuditStatus(p ForwarderStatusProvider) {
	h.auditStatus = p
}

// Mux returns a configured ServeMux with all local node API routes.
func (h *Handler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/state", h.handleGetState)
	mux.HandleFunc("GET /v1/state/metadata", h.handleGetMetadataAll)
	mux.HandleFunc("GET /v1/state/metadata/{key}", h.handleGetMetadataKey)
	mux.HandleFunc("GET /v1/state/data", h.handleGetDataAll)
	mux.HandleFunc("GET /v1/state/data/{key}", h.handleGetDataKey)
	mux.HandleFunc("GET /v1/state/secrets", h.handleGetSecretsList)
	mux.HandleFunc("GET /v1/state/secrets/{key}", h.handleGetSecretValue)
	mux.HandleFunc("GET /v1/state/report", h.handleGetReportAll)
	mux.HandleFunc("GET /v1/state/report/{key}", h.handleGetReportKey)
	mux.HandleFunc("PUT /v1/state/report/{key}", h.handlePutReport)
	mux.HandleFunc("DELETE /v1/state/report/{key}", h.handleDeleteReport)
	mux.HandleFunc("GET /v1/actions", h.handleGetActions)
	mux.HandleFunc("POST /v1/actions/run", h.handleRunAction)
	mux.HandleFunc("GET /v1/hooks", h.handleGetHooks)
	mux.HandleFunc("POST /v1/hooks/reload", h.handleReloadHooks)
	mux.HandleFunc("GET /v1/peers", h.handleGetPeers)
	mux.HandleFunc("GET /v1/policies", h.handleGetPolicies)
	mux.HandleFunc("GET /v1/log-status", h.handleGetLogStatus)
	mux.HandleFunc("GET /v1/audit/status", h.handleGetAuditStatus)
	return mux
}

// StateSummary is the response for GET /v1/state.
type StateSummary struct {
	Metadata   map[string]string  `json:"metadata"`
	DataKeys   []dataKeySummary   `json:"data_keys"`
	SecretKeys []secretKeySummary `json:"secret_keys"`
	ReportKeys []reportKeySummary `json:"report_keys"`
}

type dataKeySummary struct {
	Key         string `json:"key"`
	Version     int    `json:"version"`
	ContentType string `json:"content_type"`
}

type secretKeySummary struct {
	Key     string `json:"key"`
	Version int    `json:"version"`
}

type reportKeySummary struct {
	Key     string `json:"key"`
	Version int    `json:"version"`
}

type reportPutRequest struct {
	ContentType string          `json:"content_type"`
	Payload     json.RawMessage `json:"payload"`
}

func (h *Handler) handleGetState(w http.ResponseWriter, r *http.Request) {
	metadata := h.cache.GetMetadata()
	data := h.cache.GetData()
	secrets := h.cache.GetSecretIndex()
	reports := h.cache.GetReports()

	dataKeys := make([]dataKeySummary, 0, len(data))
	for _, d := range data {
		dataKeys = append(dataKeys, dataKeySummary{
			Key:         d.Key,
			Version:     d.Version,
			ContentType: d.ContentType,
		})
	}

	secretKeys := make([]secretKeySummary, 0, len(secrets))
	for _, s := range secrets {
		secretKeys = append(secretKeys, secretKeySummary{
			Key:     s.Key,
			Version: s.Version,
		})
	}

	reportKeys := make([]reportKeySummary, 0, len(reports))
	for _, rp := range reports {
		reportKeys = append(reportKeys, reportKeySummary{
			Key:     rp.Key,
			Version: rp.Version,
		})
	}

	writeJSON(w, http.StatusOK, StateSummary{
		Metadata:   metadata,
		DataKeys:   dataKeys,
		SecretKeys: secretKeys,
		ReportKeys: reportKeys,
	})
}

func (h *Handler) handleGetMetadataAll(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.cache.GetMetadata())
}

func (h *Handler) handleGetMetadataKey(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	val, ok := h.cache.GetMetadataKey(key)
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"key": key, "value": val})
}

func (h *Handler) handleGetDataAll(w http.ResponseWriter, r *http.Request) {
	data := h.cache.GetData()
	summaries := make([]dataKeySummary, 0, len(data))
	for _, d := range data {
		summaries = append(summaries, dataKeySummary{
			Key:         d.Key,
			Version:     d.Version,
			ContentType: d.ContentType,
		})
	}
	writeJSON(w, http.StatusOK, summaries)
}

func (h *Handler) handleGetDataKey(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	entry, ok := h.cache.GetDataEntry(key)
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

func (h *Handler) handleGetSecretsList(w http.ResponseWriter, r *http.Request) {
	index := h.cache.GetSecretIndex()
	if index == nil {
		index = []api.SecretRef{}
	}
	writeJSON(w, http.StatusOK, index)
}

func (h *Handler) handleGetSecretValue(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")

	version := 0
	if r.URL.Query().Has("version") {
		v, err := strconv.Atoi(r.URL.Query().Get("version"))
		if err != nil || v < 1 {
			writeError(w, http.StatusBadRequest, "invalid version")
			return
		}
		version = v
	}

	resp, err := h.secretFetcher.FetchSecret(r.Context(), h.nodeID, key, version)
	if err != nil {
		switch {
		case errors.Is(err, api.ErrSecretNameInvalid):
			writeError(w, http.StatusBadRequest, "invalid secret key")
		case errors.Is(err, api.ErrNotFound):
			writeError(w, http.StatusNotFound, "not found")
		case errors.Is(err, api.ErrForbidden):
			writeError(w, http.StatusForbidden, "forbidden")
		case errors.Is(err, api.ErrRateLimit):
			var apiErr *api.APIError
			if errors.As(err, &apiErr) && apiErr.RetryAfter > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(int(apiErr.RetryAfter.Seconds())))
			}
			writeError(w, http.StatusTooManyRequests, "rate limited")
		default:
			h.logger.Error("secret fetch failed", "key", key, "error", err)
			writeError(w, http.StatusServiceUnavailable, "control plane unavailable")
		}
		return
	}

	plaintext, err := DecryptSecret(h.nsk, resp.Data)
	if err != nil {
		h.logger.Error("secret decryption failed", "key", key, "kid", resp.KID, "version", resp.Version, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"key":     key,
		"value":   plaintext,
		"version": resp.Version,
	})
}

func (h *Handler) handleGetReportAll(w http.ResponseWriter, r *http.Request) {
	reports := h.cache.GetReports()
	summaries := make([]reportKeySummary, 0, len(reports))
	for _, rp := range reports {
		summaries = append(summaries, reportKeySummary{
			Key:     rp.Key,
			Version: rp.Version,
		})
	}
	writeJSON(w, http.StatusOK, summaries)
}

func (h *Handler) handleGetReportKey(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !validReportKey(key) {
		writeError(w, http.StatusBadRequest, "invalid report key")
		return
	}
	entry, ok := h.cache.GetReport(key)
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

// maxReportBodyBytes is the maximum allowed request body size for report
// PUT requests (1 MiB). Prevents memory exhaustion from oversized payloads.
const maxReportBodyBytes = 1 << 20

// maxReportValueBytes caps the serialized report payload at 4 KiB, matching the
// control plane's per-key value limit. The MaxBytesReader guarding the request
// body is transport-level protection; this is the semantic cap the ingest API
// enforces on the payload itself.
const maxReportValueBytes = 4096

func (h *Handler) handlePutReport(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !validReportKey(key) {
		writeError(w, http.StatusBadRequest, "invalid report key")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxReportBodyBytes)

	var req reportPutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if req.ContentType == "" {
		writeError(w, http.StatusBadRequest, "content_type is required")
		return
	}
	if len(req.Payload) == 0 || !json.Valid(req.Payload) {
		writeError(w, http.StatusBadRequest, "payload must be valid JSON")
		return
	}
	if len(req.Payload) > maxReportValueBytes {
		writeError(w, http.StatusBadRequest, "payload exceeds the 4096-byte limit")
		return
	}

	var ifMatch *int
	if ifMatchStr := r.Header.Get("If-Match"); ifMatchStr != "" {
		v, err := strconv.Atoi(ifMatchStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "If-Match must be an integer")
			return
		}
		ifMatch = &v
	}

	entry, err := h.cache.PutReport(key, req.ContentType, req.Payload, ifMatch)
	if err != nil {
		if errors.Is(err, ErrVersionConflict) {
			writeError(w, http.StatusConflict, "version conflict")
			return
		}
		h.logger.Error("put report failed", "key", key, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, entry)
}

func (h *Handler) handleDeleteReport(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !validReportKey(key) {
		writeError(w, http.StatusBadRequest, "invalid report key")
		return
	}

	if err := h.cache.DeleteReport(key); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		h.logger.Error("delete report failed", "key", key, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// reportKeyPattern is the control-plane wire grammar for report keys: a leading
// lowercase letter followed by up to 127 more lowercase letters, digits, '.',
// '_' or '-'. Holding local keys to this grammar keeps them in lockstep with
// what the ingest API accepts and, as a side effect, bars path separators and
// '.'/'..' traversal from the on-disk report store.
var reportKeyPattern = regexp.MustCompile("^[a-z][a-z0-9._-]{0,127}$")

// validReportKey reports whether key satisfies the wire report key grammar. The
// local GET/PUT/DELETE report handlers share it so a key the node API accepts is
// one the control plane will accept too.
func validReportKey(key string) bool {
	return reportKeyPattern.MatchString(key)
}

// actionsResponse is the response for GET /v1/actions.
type actionsResponse struct {
	BuiltinActions []api.ActionInfo `json:"builtin_actions"`
	Hooks          []api.HookInfo   `json:"hooks"`
}

func (h *Handler) handleGetActions(w http.ResponseWriter, _ *http.Request) {
	if h.actionProvider == nil {
		writeJSON(w, http.StatusOK, actionsResponse{
			BuiltinActions: []api.ActionInfo{},
			Hooks:          []api.HookInfo{},
		})
		return
	}
	actions, hooks := h.actionProvider.Capabilities()
	if actions == nil {
		actions = []api.ActionInfo{}
	}
	if hooks == nil {
		hooks = []api.HookInfo{}
	}
	writeJSON(w, http.StatusOK, actionsResponse{
		BuiltinActions: actions,
		Hooks:          hooks,
	})
}

// maxRunActionBodyBytes is the maximum allowed request body for POST /v1/actions/run.
const maxRunActionBodyBytes = 64 << 10 // 64 KiB

// runActionRequest is the request body for POST /v1/actions/run.
type runActionRequest struct {
	Action     string            `json:"action"`
	Parameters map[string]string `json:"parameters,omitempty"`
	Timeout    string            `json:"timeout,omitempty"`
}

// runActionResponse is the response for POST /v1/actions/run.
type runActionResponse struct {
	Status   string `json:"status"`
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// LocalActionRunner runs a built-in action synchronously and returns output.
type LocalActionRunner interface {
	RunLocal(ctx context.Context, action string, params map[string]string) (stdout, stderr string, exitCode int, err error)
}

func (h *Handler) handleRunAction(w http.ResponseWriter, r *http.Request) {
	if h.actionProvider == nil {
		writeError(w, http.StatusServiceUnavailable, "actions not available")
		return
	}

	runner, ok := h.actionProvider.(LocalActionRunner)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "local action execution not available")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRunActionBodyBytes)

	var req runActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Action == "" {
		writeError(w, http.StatusBadRequest, "action is required")
		return
	}

	stdout, stderr, exitCode, err := runner.RunLocal(r.Context(), req.Action, req.Parameters)
	if err != nil {
		writeJSON(w, http.StatusOK, runActionResponse{
			Status:   "error",
			ExitCode: exitCode,
			Stdout:   stdout,
			Stderr:   err.Error(),
		})
		return
	}

	status := "success"
	if exitCode != 0 {
		status = "failed"
	}
	writeJSON(w, http.StatusOK, runActionResponse{
		Status:   status,
		ExitCode: exitCode,
		Stdout:   stdout,
		Stderr:   stderr,
	})
}

func (h *Handler) handleGetHooks(w http.ResponseWriter, _ *http.Request) {
	if h.actionProvider == nil {
		writeJSON(w, http.StatusOK, []api.HookInfo{})
		return
	}
	_, hooks := h.actionProvider.Capabilities()
	if hooks == nil {
		hooks = []api.HookInfo{}
	}
	writeJSON(w, http.StatusOK, hooks)
}

// hooksReloadResponse is the response for POST /v1/hooks/reload.
type hooksReloadResponse struct {
	Status string         `json:"status"`
	Hooks  []api.HookInfo `json:"hooks"`
}

func (h *Handler) handleReloadHooks(w http.ResponseWriter, _ *http.Request) {
	if h.hookReloader == nil {
		writeError(w, http.StatusServiceUnavailable, "hook reloader not available")
		return
	}
	hooks := h.hookReloader.Hooks()
	if hooks == nil {
		hooks = []api.HookInfo{}
	}
	writeJSON(w, http.StatusOK, hooksReloadResponse{
		Status: "reloaded",
		Hooks:  hooks,
	})
}

func (h *Handler) handleGetPeers(w http.ResponseWriter, _ *http.Request) {
	if h.peerProvider == nil {
		writeJSON(w, http.StatusOK, []PeerStatus{})
		return
	}
	peers := h.peerProvider.PeerStatuses()
	if peers == nil {
		peers = []PeerStatus{}
	}
	writeJSON(w, http.StatusOK, peers)
}

func (h *Handler) handleGetPolicies(w http.ResponseWriter, _ *http.Request) {
	if h.policyProvider == nil {
		writeJSON(w, http.StatusOK, struct{}{})
		return
	}
	policy := h.policyProvider.ActivePolicy()
	if policy == nil {
		writeJSON(w, http.StatusOK, struct{}{})
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (h *Handler) handleGetLogStatus(w http.ResponseWriter, _ *http.Request) {
	if h.logStatus == nil {
		writeError(w, http.StatusServiceUnavailable, "log status not available")
		return
	}
	writeJSON(w, http.StatusOK, h.logStatus.ForwarderStatus())
}

func (h *Handler) handleGetAuditStatus(w http.ResponseWriter, _ *http.Request) {
	if h.auditStatus == nil {
		writeError(w, http.StatusServiceUnavailable, "audit status not available")
		return
	}
	writeJSON(w, http.StatusOK, h.auditStatus.ForwarderStatus())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
