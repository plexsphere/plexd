package api

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
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
	resp := newResponse(400, body, map[string]string{"Content-Type": "application/problem+json"})
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
}

func TestErrorFromResponse_NonProblemContentType_RawBody(t *testing.T) {
	body := `{"detail":"not parsed","code":"nope"}`
	resp := newResponse(400, body, map[string]string{"Content-Type": "text/plain"})
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
