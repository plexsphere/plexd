package api

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
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
