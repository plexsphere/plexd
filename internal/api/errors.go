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
	"strings"
	"time"
	"unicode"
)

// APIError is the base error type for HTTP API errors.
// It supports errors.Is matching by status code and errors.As extraction.
type APIError struct {
	StatusCode int
	Message    string
	// Code carries the machine-readable code member of an RFC 9457
	// problem+json response. It is empty when the response carries no
	// code (or is not a problem+json body).
	Code string
	// CorrelationID carries the correlation_id member of an RFC 9457
	// problem+json response, falling back to the X-Correlation-Id header
	// of that same response. Both sources are read only from a response
	// that presents itself as a problem document, and that is the whole
	// of what the gate buys: a response an intermediary substituted for
	// the control plane's contributes no id. It does not authenticate the
	// header, so a tracing proxy that passes a genuine problem document
	// through and stamps its own X-Correlation-Id on it is read by the
	// fallback. It is empty when neither source carries a usable id.
	CorrelationID string
	RetryAfter    time.Duration // only set for 429
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

// ErrIntegrityViolationsEmpty and ErrIntegrityViolationsTooMany are returned by
// ReportIntegrityViolations before any HTTP request when the batch is outside
// the contract's 1..MaxIntegrityViolationsPerBatch bounds.
var (
	ErrIntegrityViolationsEmpty   = errors.New("integrity violation batch is empty")
	ErrIntegrityViolationsTooMany = fmt.Errorf("integrity violation batch exceeds %d entries", MaxIntegrityViolationsPerBatch)
)

// IsIngestNotProvisioned reports whether err is the control plane's refusal to
// accept observability ingest because it is not provisioned for the node: a 501
// carrying the observability_ingest_not_provisioned problem code.
func IsIngestNotProvisioned(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) &&
		apiErr.StatusCode == http.StatusNotImplemented &&
		apiErr.Code == "observability_ingest_not_provisioned"
}

// IsEventBusNotProvisioned reports whether err is the control plane's long-term
// descope of the signed event stream for the node: a 501 carrying the
// signed_event_bus_not_provisioned problem code. Unlike a transient 5xx, this is
// a durable verdict — the endpoint stays unavailable until the node is
// re-provisioned — so it is answered by switching to pull-only delivery rather
// than by retrying against a channel that is not there.
func IsEventBusNotProvisioned(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) &&
		apiErr.StatusCode == http.StatusNotImplemented &&
		apiErr.Code == "signed_event_bus_not_provisioned"
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

// maxCorrelationID is the longest correlation id plexd is willing to render.
// The endpoint contract states no bound of its own, so this is plexd's limit on
// what it splices into an error string, not a mirror of a server-side one.
const maxCorrelationID = 256

// maxProblemCode is the longest problem code plexd is willing to render. The
// taxonomy the endpoint contract documents is far shorter than this, so the
// bound only keeps a hostile code from riding maxErrorBody bytes into every
// error string.
const maxProblemCode = 128

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
			apiErr.Code = sanitizeCode(problem.Code)
			switch {
			case problem.Detail != "":
				apiErr.Message = problem.Detail
			case problem.Title != "":
				apiErr.Message = problem.Title
			}
		}

		// The id is decoded on its own so that a correlation_id of an
		// unexpected JSON type — a numeric trace id, say — fails only
		// the id, not the code member plexd classifies the failure on.
		var id struct {
			CorrelationID string `json:"correlation_id"`
		}
		if err := json.Unmarshal(body, &id); err == nil {
			apiErr.CorrelationID = sanitizeCorrelationID(id.CorrelationID)
		}
		if apiErr.CorrelationID == "" {
			apiErr.CorrelationID = sanitizeCorrelationID(resp.Header.Get("X-Correlation-Id"))
		}
	}

	// Every branch above derives Message from response bytes — the problem
	// document's detail or title, or the raw body — so the sanitizer runs
	// once here rather than at each of them.
	apiErr.Message = sanitizeMessage(apiErr.Message)

	if resp.StatusCode == http.StatusTooManyRequests {
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if seconds, err := strconv.Atoi(ra); err == nil {
				apiErr.RetryAfter = time.Duration(seconds) * time.Second
			}
		}
	}

	return apiErr
}

// sanitizeCode accepts a problem document's code member only in the shape plexd
// renders and classifies on. Unlike sanitizeMessage it rejects rather than
// scrubs: Code drives the IsXxx classifiers and the switch in
// internal/actions/executor.go, so removing an unprintable rune could collapse a
// hostile "clock\x00_skew" onto the live "clock_skew" branch. Rejection cannot.
// An unsanitized code would otherwise reach APIError.Error, which cobra prints
// to stderr unescaped — the same exposure sanitizeMessage closes for the message
// and sanitizeCorrelationID for the id.
//
// It needs no ToValidUTF8 step of its own: unlike a raw body or a response
// header, the code reaches this point only through json.Unmarshal, which has
// already replaced every invalid byte with a printable U+FFFD.
func sanitizeCode(s string) string {
	if len(s) > maxProblemCode {
		return ""
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return ""
		}
	}
	return s
}

// sanitizeCorrelationID accepts a response-derived id only in the shape plexd
// is prepared to render: it trims surrounding whitespace, rejects an id longer
// than maxCorrelationID bytes outright, and drops invalid UTF-8 as well as
// every unprintable rune. An oversized id is dropped rather than truncated
// because a truncated id keys nothing in the control-plane log yet still reads
// like a quotable identifier, sending the operator after a false lead. Dropping
// unprintable runes is what stops a broken or hostile intermediary from forging
// a log line or clearing the operator's screen: APIError.Error splices the id
// into a string that cobra prints to stderr unescaped. ToValidUTF8 runs first
// because strings.Map would otherwise turn each invalid byte into U+FFFD, which
// is printable and would survive.
func sanitizeCorrelationID(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxCorrelationID {
		return ""
	}
	s = strings.ToValidUTF8(s, "")
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
}

// sanitizeMessage bounds a response-derived message the way
// sanitizeCorrelationID bounds an id: APIError.Error splices the message into
// the same string cobra prints to stderr unescaped, so an unprintable rune in
// the problem document's detail or title — or anywhere in a raw non-problem
// body, which is taken verbatim — would otherwise clear the operator's screen
// or forge a log line. Each unprintable rune becomes a space rather than being
// dropped, so a multi-line body renders as one readable line instead of running
// its words together. The length needs no bound of its own: the body is read
// through maxErrorBody. ToValidUTF8 runs first for the same reason it does
// there: strings.Map would otherwise turn each invalid byte into a printable
// U+FFFD that survives the map.
func sanitizeMessage(s string) string {
	s = strings.ToValidUTF8(s, "")
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return ' '
	}, s)
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
