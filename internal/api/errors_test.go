package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode"
)

// newResponse creates a minimal *http.Response for testing errorFromResponse.
func newResponse(statusCode int, body string, headers map[string]string) *http.Response {
	resp := &http.Response{
		StatusCode: statusCode,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
	for k, v := range headers {
		resp.Header.Set(k, v)
	}
	return resp
}

func TestErrorMapping_401_ErrUnauthorized(t *testing.T) {
	resp := newResponse(401, "invalid token", nil)
	err := errorFromResponse(resp)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected errors.Is(err, ErrUnauthorized) to be true, got false")
	}
}

func TestErrorMapping_429_ErrRateLimitWithRetryAfter(t *testing.T) {
	resp := newResponse(429, "slow down", map[string]string{"Retry-After": "30"})
	err := errorFromResponse(resp)

	if !errors.Is(err, ErrRateLimit) {
		t.Fatalf("expected errors.Is(err, ErrRateLimit) to be true, got false")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected errors.As to extract *APIError")
	}
	if apiErr.RetryAfter != 30*time.Second {
		t.Fatalf("expected RetryAfter=30s, got %v", apiErr.RetryAfter)
	}
}

func TestErrorMapping_5xx_ErrServer(t *testing.T) {
	for _, code := range []int{500, 502, 503, 504} {
		resp := newResponse(code, "server error", nil)
		err := errorFromResponse(resp)
		if !errors.Is(err, ErrServer) {
			t.Errorf("expected errors.Is(err, ErrServer) for status %d, got false", code)
		}
	}
}

func TestErrorMapping_UnknownStatus_APIError(t *testing.T) {
	resp := newResponse(418, "i'm a teapot", nil)
	err := errorFromResponse(resp)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected errors.As to extract *APIError")
	}
	if apiErr.StatusCode != 418 {
		t.Fatalf("expected StatusCode=418, got %d", apiErr.StatusCode)
	}
}

func TestErrorMapping_400_ErrBadRequest(t *testing.T) {
	resp := newResponse(400, "bad request body", nil)
	err := errorFromResponse(resp)
	if !errors.Is(err, ErrBadRequest) {
		t.Fatalf("expected errors.Is(err, ErrBadRequest) to be true, got false")
	}
}

func TestErrorMapping_403_ErrForbidden(t *testing.T) {
	resp := newResponse(403, "access denied", nil)
	err := errorFromResponse(resp)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected errors.Is(err, ErrForbidden) to be true, got false")
	}
}

func TestErrorMapping_404_ErrNotFound(t *testing.T) {
	resp := newResponse(404, "not found", nil)
	err := errorFromResponse(resp)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected errors.Is(err, ErrNotFound) to be true, got false")
	}
}

func TestErrorMapping_409_ErrConflict(t *testing.T) {
	resp := newResponse(409, "resource conflict", nil)
	err := errorFromResponse(resp)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected errors.Is(err, ErrConflict) to be true, got false")
	}
}

func TestErrorMapping_413_ErrPayloadTooLarge(t *testing.T) {
	resp := newResponse(413, "payload too large", nil)
	err := errorFromResponse(resp)
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("expected errors.Is(err, ErrPayloadTooLarge) to be true, got false")
	}
}

func TestAPIError_ErrorMessage(t *testing.T) {
	err := &APIError{StatusCode: 404, Message: "not found"}
	expected := "api: HTTP 404: not found"
	if err.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, err.Error())
	}
}

func TestAPIError_ErrorMessage_WithCode(t *testing.T) {
	err := &APIError{StatusCode: 403, Message: "enrollment token has expired", Code: "token_expired"}
	expected := "api: HTTP 403 (token_expired): enrollment token has expired"
	if err.Error() != expected {
		t.Fatalf("expected %q, got %q", expected, err.Error())
	}
}

// problemJSON builds an RFC 9457 problem+json body for tests.
func problemJSON(status int, detail, code string) string {
	return fmt.Sprintf(
		`{"type":"about:blank","title":"error","status":%d,"detail":%q,"instance":"/v1/register","code":%q}`,
		status, detail, code,
	)
}

func TestErrorFromResponse_ProblemJSON_TaxonomyCodes(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		code       string
		detail     string
	}{
		{"public_key_invalid", 400, "public_key_invalid", "public key is malformed"},
		{"kind_mismatch", 403, "kind_mismatch", "node kind does not match token"},
		{"project_mismatch", 403, "project_mismatch", "token belongs to a different project"},
		{"token_consumed", 403, "token_consumed", "enrollment token already consumed"},
		{"token_expired", 403, "token_expired", "enrollment token has expired"},
		{"token_revoked", 403, "token_revoked", "enrollment token was revoked"},
		{"nonce_collision", 403, "nonce_collision", "nonce already seen"},
		{"resource_not_found", 404, "resource_not_found", "project not found"},
		{"pool_exhausted", 503, "pool_exhausted", "address pool exhausted"},
		{"subrange_exhausted", 503, "subrange_exhausted", "subrange exhausted"},
		{"allocator_contention", 503, "allocator_contention", "allocator contention, retry"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := problemJSON(tt.statusCode, tt.detail, tt.code)
			resp := newResponse(tt.statusCode, body, map[string]string{"Content-Type": "application/problem+json"})
			err := errorFromResponse(resp)

			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("expected errors.As to extract *APIError")
			}
			if apiErr.StatusCode != tt.statusCode {
				t.Errorf("expected StatusCode=%d, got %d", tt.statusCode, apiErr.StatusCode)
			}
			if apiErr.Code != tt.code {
				t.Errorf("expected Code=%q, got %q", tt.code, apiErr.Code)
			}
			if apiErr.Message != tt.detail {
				t.Errorf("expected Message=%q (from detail), got %q", tt.detail, apiErr.Message)
			}
		})
	}
}

func TestErrorFromResponse_ProblemJSON_CorrelationID(t *testing.T) {
	body := `{"type":"about:blank","title":"error","status":403,"detail":"enrollment token has expired","instance":"/v1/register","code":"token_expired","correlation_id":"3f2a"}`
	resp := newResponse(403, body, map[string]string{"Content-Type": "application/problem+json"})
	err := errorFromResponse(resp)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected errors.As to extract *APIError")
	}
	if apiErr.CorrelationID != "3f2a" {
		t.Errorf("expected CorrelationID=3f2a, got %q", apiErr.CorrelationID)
	}
	if apiErr.Code != "token_expired" {
		t.Errorf("expected Code=token_expired, got %q", apiErr.Code)
	}
}

// TestErrorFromResponse_ProblemJSON_NonStringCorrelationID guards the code
// member — which the IsXxx classifiers branch on — against an id of an
// unexpected JSON type. Numeric trace ids are common; decoding one into a
// string field yields an *json.UnmarshalTypeError that must not discard the
// rest of the problem document.
func TestErrorFromResponse_ProblemJSON_NonStringCorrelationID(t *testing.T) {
	body := `{"type":"about:blank","title":"error","status":501,"detail":"event bus not provisioned","code":"signed_event_bus_not_provisioned","correlation_id":8749203847}`
	resp := newResponse(501, body, map[string]string{"Content-Type": "application/problem+json"})
	err := errorFromResponse(resp)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected errors.As to extract *APIError")
	}
	if apiErr.Code != "signed_event_bus_not_provisioned" {
		t.Errorf("expected Code=signed_event_bus_not_provisioned, got %q", apiErr.Code)
	}
	if apiErr.Message != "event bus not provisioned" {
		t.Errorf("expected Message from detail, got %q", apiErr.Message)
	}
	if apiErr.CorrelationID != "" {
		t.Errorf("expected empty CorrelationID for a non-string member, got %q", apiErr.CorrelationID)
	}
	if !IsEventBusNotProvisioned(err) {
		t.Error("expected IsEventBusNotProvisioned to classify the response")
	}
}

func TestErrorFromResponse_CorrelationID_HeaderFallback(t *testing.T) {
	body := problemJSON(403, "enrollment token has expired", "token_expired")
	resp := newResponse(403, body, map[string]string{
		"Content-Type":     "application/problem+json",
		"X-Correlation-Id": "3f2a",
	})
	err := errorFromResponse(resp)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected errors.As to extract *APIError")
	}
	if apiErr.CorrelationID != "3f2a" {
		t.Errorf("expected CorrelationID=3f2a from the header, got %q", apiErr.CorrelationID)
	}
}

func TestErrorFromResponse_CorrelationID_EmptyMemberFallsBackToHeader(t *testing.T) {
	body := `{"type":"about:blank","title":"error","status":403,"detail":"denied","code":"token_expired","correlation_id":""}`
	resp := newResponse(403, body, map[string]string{
		"Content-Type":     "application/problem+json",
		"X-Correlation-Id": "3f2a",
	})
	err := errorFromResponse(resp)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected errors.As to extract *APIError")
	}
	if apiErr.CorrelationID != "3f2a" {
		t.Errorf("expected CorrelationID=3f2a from the header, got %q", apiErr.CorrelationID)
	}
}

func TestErrorFromResponse_CorrelationID_AbsentLeavesFieldEmpty(t *testing.T) {
	body := problemJSON(403, "enrollment token has expired", "token_expired")
	resp := newResponse(403, body, map[string]string{"Content-Type": "application/problem+json"})
	err := errorFromResponse(resp)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected errors.As to extract *APIError")
	}
	if apiErr.CorrelationID != "" {
		t.Errorf("expected empty CorrelationID, got %q", apiErr.CorrelationID)
	}
}

// errReader is a response body that fails on the first read.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestErrorFromResponse_UnreadableBody_HeaderCorrelationID(t *testing.T) {
	resp := &http.Response{
		StatusCode: 500,
		Header:     http.Header{},
		Body:       io.NopCloser(errReader{}),
	}
	resp.Header.Set("Content-Type", "application/problem+json")
	resp.Header.Set("X-Correlation-Id", "3f2a")
	err := errorFromResponse(resp)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected errors.As to extract *APIError")
	}
	if apiErr.CorrelationID != "3f2a" {
		t.Errorf("expected CorrelationID=3f2a from the header, got %q", apiErr.CorrelationID)
	}
}

func TestErrorFromResponse_CorrelationID_Sanitized(t *testing.T) {
	oversized := strings.Repeat("a", 300)
	tests := []struct {
		name    string
		header  string
		want    string
		wantLen int
	}{
		{"oversized id is dropped, not truncated", oversized, "", 0},
		{"id at the size bound is kept", oversized[:256], oversized[:256], 256},
		{"invalid UTF-8 is dropped", "abc\xff\xfedef", "abcdef", 6},
		{"surrounding whitespace is trimmed", "  3f2a  ", "3f2a", 4},
		{"newline is dropped", "3f2a\nlevel=info msg=\"registration succeeded\"", `3f2alevel=info msg="registration succeeded"`, 43},
		{"ANSI escape is dropped", "3f2a\x1b[2J\x1b[1;1H", "3f2a[2J[1;1H", 12},
		{"NUL and carriage return are dropped", "3f\x002a\r", "3f2a", 4},
		{"bidi override is dropped", "3f2a\u202e", "3f2a", 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := problemJSON(400, "public key is malformed", "public_key_invalid")
			resp := newResponse(400, body, map[string]string{
				"Content-Type":     "application/problem+json",
				"X-Correlation-Id": tt.header,
			})
			err := errorFromResponse(resp)

			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("expected errors.As to extract *APIError")
			}
			if apiErr.CorrelationID != tt.want {
				t.Errorf("expected CorrelationID=%q, got %q", tt.want, apiErr.CorrelationID)
			}
			if len(apiErr.CorrelationID) != tt.wantLen {
				t.Errorf("expected CorrelationID of %d bytes, got %d", tt.wantLen, len(apiErr.CorrelationID))
			}
		})
	}
}

// TestErrorFromResponse_Message_Sanitized guards the message the way
// TestErrorFromResponse_CorrelationID_Sanitized guards the id: APIError.Error
// splices both into the one string cobra prints to stderr unescaped, so a
// detail, a title or a raw body carrying terminal escapes must not reach the
// operator's screen through the message either.
func TestErrorFromResponse_Message_Sanitized(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		want        string
	}{
		{
			name:        "escape sequence and newline in detail",
			contentType: "application/problem+json",
			body:        `{"type":"about:blank","title":"error","status":500,"detail":"\u001b[2J\u001b[1;1Hplexd: registration succeeded\n","code":"internal"}`,
			want:        " [2J [1;1Hplexd: registration succeeded ",
		},
		{
			name:        "bell in the title the message falls back to",
			contentType: "application/problem+json",
			body:        `{"type":"about:blank","title":"denied\u0007","status":422,"detail":""}`,
			want:        "denied ",
		},
		{
			name:        "raw non-problem body is taken verbatim but sanitized",
			contentType: "text/plain",
			body:        "boom\x1b[2J\r\nlevel=info msg=\"registration succeeded\"",
			want:        "boom [2J  level=info msg=\"registration succeeded\"",
		},
		{
			name:        "invalid UTF-8 in a raw body is dropped",
			contentType: "text/plain",
			body:        "boom\xff\xfe",
			want:        "boom",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := newResponse(500, tt.body, map[string]string{"Content-Type": tt.contentType})
			err := errorFromResponse(resp)

			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("expected errors.As to extract *APIError")
			}
			if apiErr.Message != tt.want {
				t.Errorf("expected Message=%q, got %q", tt.want, apiErr.Message)
			}
			if strings.ContainsFunc(apiErr.Error(), func(r rune) bool { return !unicode.IsPrint(r) }) {
				t.Errorf("expected a printable error string, got %q", apiErr.Error())
			}
		})
	}
}

// TestErrorFromResponse_Code_Sanitized guards the code member the way
// TestErrorFromResponse_Message_Sanitized guards the message: APIError.Error
// splices the code into that same string cobra prints to stderr unescaped. The
// code is rejected whole rather than scrubbed because the IsXxx classifiers and
// internal/actions/executor.go compare it for equality — stripping the NUL out
// of a forged "clock\x00_skew" would hand it the live "clock_skew" branch.
func TestErrorFromResponse_Code_Sanitized(t *testing.T) {
	tests := []struct {
		name string
		code string
		want string
	}{
		{"a taxonomy code passes through", "token_expired", "token_expired"},
		{"ANSI escape is rejected whole", "x\x1b[2Jplexd: ok", ""},
		{"NUL that would collapse onto a live code is rejected whole", "clock\x00_skew", ""},
		{"newline is rejected whole", "token_expired\nlevel=info msg=\"registration succeeded\"", ""},
		{"bidi override is rejected whole", "token_expired\u202e", ""},
		{"oversized code is rejected whole", strings.Repeat("a", 129), ""},
		{"code at the size bound is kept", strings.Repeat("a", 128), strings.Repeat("a", 128)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The code is marshalled rather than interpolated so that a
			// control character reaches the decoder as the \u00xx escape
			// JSON requires, not as a raw byte that would fail the parse
			// and send Message down the raw-body branch instead.
			encoded, marshalErr := json.Marshal(tt.code)
			if marshalErr != nil {
				t.Fatalf("marshalling the code: %v", marshalErr)
			}
			body := fmt.Sprintf(
				`{"type":"about:blank","title":"error","status":500,"detail":"failed","code":%s}`,
				encoded,
			)
			resp := newResponse(500, body, map[string]string{"Content-Type": "application/problem+json"})
			err := errorFromResponse(resp)

			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("expected errors.As to extract *APIError")
			}
			if apiErr.Code != tt.want {
				t.Errorf("expected Code=%q, got %q", tt.want, apiErr.Code)
			}
			// The rest of the document must survive a rejected code —
			// dropping the code must not cost the operator the detail.
			if apiErr.Message != "failed" {
				t.Errorf("expected Message=%q, got %q", "failed", apiErr.Message)
			}
			if strings.ContainsFunc(apiErr.Error(), func(r rune) bool { return !unicode.IsPrint(r) }) {
				t.Errorf("expected a printable error string, got %q", apiErr.Error())
			}
		})
	}
}

func TestErrorFromResponse_ProblemJSON_CharsetParameter(t *testing.T) {
	body := problemJSON(400, "public key is malformed", "public_key_invalid")
	resp := newResponse(400, body, map[string]string{"Content-Type": "application/problem+json; charset=utf-8"})
	err := errorFromResponse(resp)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected errors.As to extract *APIError")
	}
	if apiErr.Code != "public_key_invalid" {
		t.Errorf("expected Code=public_key_invalid, got %q", apiErr.Code)
	}
	if apiErr.Message != "public key is malformed" {
		t.Errorf("expected Message from detail, got %q", apiErr.Message)
	}
}

func TestErrorFromResponse_ProblemJSON_NoCode(t *testing.T) {
	body := `{"type":"about:blank","title":"Unprocessable Entity","status":422,"detail":"validation failed"}`
	resp := newResponse(422, body, map[string]string{"Content-Type": "application/problem+json"})
	err := errorFromResponse(resp)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected errors.As to extract *APIError")
	}
	if apiErr.Code != "" {
		t.Errorf("expected empty Code, got %q", apiErr.Code)
	}
	if apiErr.Message != "validation failed" {
		t.Errorf("expected Message from detail, got %q", apiErr.Message)
	}
}

func TestErrorFromResponse_ProblemJSON_EmptyDetailFallsBackToTitle(t *testing.T) {
	body := `{"type":"about:blank","title":"Unprocessable Entity","status":422,"detail":""}`
	resp := newResponse(422, body, map[string]string{"Content-Type": "application/problem+json"})
	err := errorFromResponse(resp)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected errors.As to extract *APIError")
	}
	if apiErr.Message != "Unprocessable Entity" {
		t.Errorf("expected Message to fall back to title, got %q", apiErr.Message)
	}
}

func TestErrorFromResponse_ProblemJSON_EmptyDetailAndTitleFallsBackToRawBody(t *testing.T) {
	body := `{"type":"about:blank","status":422,"code":"some_code"}`
	resp := newResponse(422, body, map[string]string{"Content-Type": "application/problem+json"})
	err := errorFromResponse(resp)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected errors.As to extract *APIError")
	}
	if apiErr.Code != "some_code" {
		t.Errorf("expected Code=some_code, got %q", apiErr.Code)
	}
	if apiErr.Message != body {
		t.Errorf("expected Message to fall back to raw body, got %q", apiErr.Message)
	}
}

func TestErrorFromResponse_MalformedProblemJSON_FallsBackToRawBody(t *testing.T) {
	body := `{"detail": "oops"` // truncated, invalid JSON
	resp := newResponse(400, body, map[string]string{
		"Content-Type":     "application/problem+json",
		"X-Correlation-Id": "3f2a",
	})
	err := errorFromResponse(resp)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected errors.As to extract *APIError")
	}
	if apiErr.Code != "" {
		t.Errorf("expected empty Code on malformed body, got %q", apiErr.Code)
	}
	if apiErr.Message != body {
		t.Errorf("expected raw body Message, got %q", apiErr.Message)
	}
	if apiErr.CorrelationID != "3f2a" {
		t.Errorf("expected CorrelationID=3f2a from the header, got %q", apiErr.CorrelationID)
	}
}

func TestErrorFromResponse_NonProblemContentType_RawBody(t *testing.T) {
	body := `{"detail":"not parsed","code":"nope"}`
	resp := newResponse(400, body, map[string]string{
		"Content-Type":     "text/plain",
		"X-Correlation-Id": "3f2a",
	})
	err := errorFromResponse(resp)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected errors.As to extract *APIError")
	}
	if apiErr.Code != "" {
		t.Errorf("expected empty Code for non-problem content type, got %q", apiErr.Code)
	}
	if apiErr.Message != body {
		t.Errorf("expected raw body Message, got %q", apiErr.Message)
	}
	// The response does not present itself as a control-plane problem
	// document, so its X-Correlation-Id is an intermediary's id. Rendering
	// it would send the operator to the control-plane log with a key that
	// was never issued there.
	if apiErr.CorrelationID != "" {
		t.Errorf("expected empty CorrelationID for non-problem content type, got %q", apiErr.CorrelationID)
	}
}

func TestErrorFromResponse_ProblemJSON_429RetryAfter(t *testing.T) {
	body := problemJSON(429, "slow down", "rate_limited")
	resp := newResponse(429, body, map[string]string{
		"Content-Type": "application/problem+json",
		"Retry-After":  "42",
	})
	err := errorFromResponse(resp)

	if !errors.Is(err, ErrRateLimit) {
		t.Fatalf("expected errors.Is(err, ErrRateLimit) to be true, got false")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected errors.As to extract *APIError")
	}
	if apiErr.RetryAfter != 42*time.Second {
		t.Errorf("expected RetryAfter=42s, got %v", apiErr.RetryAfter)
	}
	if apiErr.Message != "slow down" {
		t.Errorf("expected Message from detail, got %q", apiErr.Message)
	}
}

func TestIsIngestPermanentlyRefused(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"400 malformed", &APIError{StatusCode: 400, Code: "ingest_batch_malformed"}, true},
		{"wrapped 400 malformed", fmt.Errorf("post logs: %w", &APIError{StatusCode: 400, Code: "ingest_batch_malformed"}), true},
		{"400 invalid sent-at clears once the clock converges", &APIError{StatusCode: 400, Code: "ingest_sent_at_invalid"}, false},
		{"400 without a code is not a batch verdict", &APIError{StatusCode: 400}, false},
		{"413 too large is split, not dropped", &APIError{StatusCode: 413}, false},
		{"415 unsupported encoding is a transport fault", &APIError{StatusCode: 415, Code: "ingest_encoding_unsupported"}, false},
		{"429 rate limited is retryable", &APIError{StatusCode: 429}, false},
		{"500 server error is retryable", &APIError{StatusCode: 500}, false},
		{"501 not provisioned handled elsewhere", &APIError{StatusCode: 501, Code: "observability_ingest_not_provisioned"}, false},
		{"503 unavailable is retryable", &APIError{StatusCode: 503}, false},
		{"non-API error is retryable", errors.New("dial tcp: timeout"), false},
		{"nil is not a refusal", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsIngestPermanentlyRefused(tt.err); got != tt.want {
				t.Errorf("IsIngestPermanentlyRefused(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestErrSecretNameInvalid(t *testing.T) {
	const want = "secret name is outside the grammar ^[a-z][a-z0-9_-]{0,62}$"
	if got := ErrSecretNameInvalid.Error(); got != want {
		t.Errorf("ErrSecretNameInvalid.Error() = %q, want %q", got, want)
	}

	wrapped := fmt.Errorf("api: fetch secret %q: %w", "X", ErrSecretNameInvalid)
	if !errors.Is(wrapped, ErrSecretNameInvalid) {
		t.Errorf("errors.Is(wrapped, ErrSecretNameInvalid) = false, want true")
	}
}

func TestIsEventBusNotProvisioned(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"501 with the descope code", &APIError{StatusCode: 501, Code: "signed_event_bus_not_provisioned"}, true},
		{"wrapped 501 with the descope code", fmt.Errorf("connect SSE: %w", &APIError{StatusCode: 501, Code: "signed_event_bus_not_provisioned"}), true},
		{"501 with another code is a plain not-implemented", &APIError{StatusCode: 501, Code: "observability_ingest_not_provisioned"}, false},
		{"501 without a code", &APIError{StatusCode: 501}, false},
		{"503 with the descope code is transient", &APIError{StatusCode: 503, Code: "signed_event_bus_not_provisioned"}, false},
		{"500 with the descope code is transient", &APIError{StatusCode: 500, Code: "signed_event_bus_not_provisioned"}, false},
		{"400 with the descope code", &APIError{StatusCode: 400, Code: "signed_event_bus_not_provisioned"}, false},
		{"non-API error", errors.New("dial tcp: timeout"), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsEventBusNotProvisioned(tt.err); got != tt.want {
				t.Errorf("IsEventBusNotProvisioned(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestIsIngestTooLarge(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"413", &APIError{StatusCode: 413}, true},
		{"wrapped 413", fmt.Errorf("post metrics: %w", &APIError{StatusCode: 413}), true},
		{"400 malformed", &APIError{StatusCode: 400, Code: "ingest_batch_malformed"}, false},
		{"415 unsupported encoding", &APIError{StatusCode: 415}, false},
		{"non-API error", errors.New("dial tcp: timeout"), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsIngestTooLarge(tt.err); got != tt.want {
				t.Errorf("IsIngestTooLarge(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
