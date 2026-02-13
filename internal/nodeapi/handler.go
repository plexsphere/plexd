package nodeapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/plexsphere/plexd/internal/api"
)

// SecretFetcher abstracts the control plane client for secret retrieval.
type SecretFetcher interface {
	FetchSecret(ctx context.Context, nodeID, key string) (*api.SecretResponse, error)
}

// Handler provides HTTP handlers for the local node API.
type Handler struct {
	cache         *StateCache
	secretFetcher SecretFetcher
	nodeID        string
	nsk           []byte
	logger        *slog.Logger
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

	resp, err := h.secretFetcher.FetchSecret(r.Context(), h.nodeID, key)
	if err != nil {
		if errors.Is(err, api.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		h.logger.Error("secret fetch failed", "key", key, "error", err)
		writeError(w, http.StatusServiceUnavailable, "control plane unavailable")
		return
	}

	plaintext, err := DecryptSecret(h.nsk, resp.Ciphertext, resp.Nonce)
	if err != nil {
		h.logger.Error("secret decryption failed", "key", key, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"key":     resp.Key,
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

// validReportKey returns true if key is safe to use in file paths.
// It rejects empty keys, path separators, '..' sequences, and the current
// directory reference '.'.
func validReportKey(key string) bool {
	return key != "" && key != "." && key != ".." && !strings.ContainsAny(key, "/\\")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
