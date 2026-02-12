package api

import (
	"bytes"
	"errors"
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
