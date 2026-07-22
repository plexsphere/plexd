package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// APIError is the base error type for HTTP API errors.
// It supports errors.Is matching by status code and errors.As extraction.
type APIError struct {
	StatusCode int
	Message    string
	// Code carries the machine-readable code member of an RFC 9457
	// problem+json response. It is empty when the response carries no
	// code (or is not a problem+json body).
	Code       string
	RetryAfter time.Duration // only set for 429
}

// Error returns the formatted error string.
func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("api: HTTP %d (%s): %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("api: HTTP %d: %s", e.StatusCode, e.Message)
}

// Is supports errors.Is matching by status code.
// ErrServer (500) matches any 5xx status code.
// All other sentinels require an exact status code match.
func (e *APIError) Is(target error) bool {
	t, ok := target.(*APIError)
	if !ok {
		return false
	}
	// ErrServer matches any 5xx
	if t.StatusCode == 500 && e.StatusCode >= 500 && e.StatusCode < 600 {
		return true
	}
	return e.StatusCode == t.StatusCode
}

// Sentinel errors for common HTTP error status codes.
var (
	ErrBadRequest      = &APIError{StatusCode: 400, Message: "bad request"}
	ErrUnauthorized    = &APIError{StatusCode: 401, Message: "unauthorized"}
	ErrForbidden       = &APIError{StatusCode: 403, Message: "forbidden"}
	ErrNotFound        = &APIError{StatusCode: 404, Message: "not found"}
	ErrConflict        = &APIError{StatusCode: 409, Message: "conflict"}
	ErrPayloadTooLarge = &APIError{StatusCode: 413, Message: "payload too large"}
	ErrUnprocessable   = &APIError{StatusCode: 422, Message: "unprocessable entity"}
	ErrRateLimit       = &APIError{StatusCode: 429, Message: "rate limit exceeded"}
	ErrServer          = &APIError{StatusCode: 500, Message: "server error"}
)

// ErrSecretNameInvalid is returned by FetchSecret before any HTTP request
// when the requested secret name is outside the contract's name grammar.
var ErrSecretNameInvalid = fmt.Errorf("secret name is outside the grammar %s", secretNamePattern)

// IsIngestNotProvisioned reports whether err is the control plane's refusal to
// accept observability ingest because it is not provisioned for the node: a 501
// carrying the observability_ingest_not_provisioned problem code.
func IsIngestNotProvisioned(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) &&
		apiErr.StatusCode == http.StatusNotImplemented &&
		apiErr.Code == "observability_ingest_not_provisioned"
}

// IsIngestPermanentlyRefused reports whether err is a refusal of an
// observability ingest batch that no retry can fix: a 400 carrying the
// ingest_batch_malformed problem code, which is a verdict on the batch bytes
// themselves. Re-sending them would draw the identical status forever, so a
// PlatformReporter drops such a batch rather than returning it for re-buffering.
//
// The sibling refusals are deliberately not permanent. A 400
// ingest_sent_at_invalid faults the X-Plexsphere-Sent-At header, which is
// re-stamped from the wall clock on every attempt, so it clears once the node's
// clock converges. A 415 faults the Content-Encoding, a transport property of
// the deployment rather than of the batch, so it clears once the gateway that
// rejects gzip is fixed. Both are returned to the caller for re-buffering. A 413
// is classified by IsIngestTooLarge and answered by splitting the batch, and a
// 501 not-provisioned refusal by IsIngestNotProvisioned.
func IsIngestPermanentlyRefused(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == http.StatusBadRequest && apiErr.Code == "ingest_batch_malformed"
}

// IsIngestTooLarge reports whether err is the control plane's refusal of an
// observability ingest batch for exceeding its size limit: a 413. The batch
// content is acceptable, only its size is not, so the caller answers by
// splitting the batch and re-sending the halves rather than dropping it.
func IsIngestTooLarge(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusRequestEntityTooLarge
}

// maxErrorBody is the maximum number of bytes read from an error response body.
const maxErrorBody = 4096

// problemBody is the RFC 9457 application/problem+json representation used by
// the control plane. The optional code member carries a machine-readable
// taxonomy that plexd classifies alongside the HTTP status.
type problemBody struct {
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Code   string `json:"code"`
}

// errorFromResponse creates an *APIError from an HTTP response.
// It reads up to 4KB of the response body.
func errorFromResponse(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	msg := string(body)

	apiErr := &APIError{
		StatusCode: resp.StatusCode,
		Message:    msg,
	}

	if isProblemJSON(resp.Header.Get("Content-Type")) {
		var problem problemBody
		if err := json.Unmarshal(body, &problem); err == nil {
			apiErr.Code = problem.Code
			switch {
			case problem.Detail != "":
				apiErr.Message = problem.Detail
			case problem.Title != "":
				apiErr.Message = problem.Title
			}
		}
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if seconds, err := strconv.Atoi(ra); err == nil {
				apiErr.RetryAfter = time.Duration(seconds) * time.Second
			}
		}
	}

	return apiErr
}

// RedactURLError strips the request URL from a *url.Error, keeping only the
// operation and the underlying cause. url.Error.Error() renders the full URL
// including its query string, and a presigned upload URL carries its credential
// there — logging such an error verbatim would publish a live write capability
// against the object it points at. Errors of any other type pass through.
func RedactURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Errorf("%s: %w", urlErr.Op, urlErr.Err)
	}
	return err
}

// isProblemJSON reports whether the given Content-Type header value denotes an
// RFC 9457 application/problem+json body. Media-type parameters such as
// "; charset=utf-8" are tolerated.
func isProblemJSON(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mediaType == "application/problem+json"
}
