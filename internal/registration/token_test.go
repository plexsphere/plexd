package registration

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type mockMetadataProvider struct {
	token    string
	err      error
	lastPath string
}

func (m *mockMetadataProvider) ReadValue(_ context.Context, path string) (string, error) {
	m.lastPath = path
	return m.token, m.err
}

func TestTokenResolver_DirectValue(t *testing.T) {
	cfg := &Config{
		TokenValue: "my-direct-token",
	}
	r := NewTokenResolver(cfg, nil)
	result, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Value != "my-direct-token" {
		t.Fatalf("got value %q, want %q", result.Value, "my-direct-token")
	}
	if result.FilePath != "" {
		t.Fatalf("got FilePath %q, want empty", result.FilePath)
	}
}

func TestTokenResolver_FromFile(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("  file-token\n  "), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		TokenFile: tokenFile,
	}
	r := NewTokenResolver(cfg, nil)
	result, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Value != "file-token" {
		t.Fatalf("got value %q, want %q", result.Value, "file-token")
	}
	if result.FilePath != tokenFile {
		t.Fatalf("got FilePath %q, want %q", result.FilePath, tokenFile)
	}
}

func TestTokenResolver_FromEnvVar(t *testing.T) {
	envName := "PLEXD_TEST_TOKEN_ENV"
	t.Setenv(envName, "env-token")

	cfg := &Config{
		TokenEnv: envName,
	}
	r := NewTokenResolver(cfg, nil)
	result, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Value != "env-token" {
		t.Fatalf("got value %q, want %q", result.Value, "env-token")
	}
	if result.FilePath != "" {
		t.Fatalf("got FilePath %q, want empty", result.FilePath)
	}
}

func TestTokenResolver_FromMetadata(t *testing.T) {
	meta := &mockMetadataProvider{token: "metadata-token"}
	cfg := &Config{
		UseMetadata: true,
	}
	r := NewTokenResolver(cfg, meta)
	result, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Value != "metadata-token" {
		t.Fatalf("got value %q, want %q", result.Value, "metadata-token")
	}
}

func TestTokenResolver_PriorityOrder(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("file-token"), 0o600); err != nil {
		t.Fatal(err)
	}

	envName := "PLEXD_TEST_TOKEN_PRIORITY"
	t.Setenv(envName, "env-token")

	cfg := &Config{
		TokenFile: tokenFile,
		TokenEnv:  envName,
	}
	r := NewTokenResolver(cfg, nil)
	result, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Value != "file-token" {
		t.Fatalf("got value %q, want %q (file should take priority over env)", result.Value, "file-token")
	}
}

func TestTokenResolver_DirectValueOverridesFile(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("file-token"), 0o600); err != nil {
		t.Fatal(err)
	}

	envName := "PLEXD_TEST_TOKEN_DIRECT_PRIORITY"
	t.Setenv(envName, "env-token")

	meta := &mockMetadataProvider{token: "metadata-token"}

	cfg := &Config{
		TokenValue:  "direct-token",
		TokenFile:   tokenFile,
		TokenEnv:    envName,
		UseMetadata: true,
	}
	r := NewTokenResolver(cfg, meta)
	result, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Value != "direct-token" {
		t.Fatalf("got value %q, want %q (direct value should override all other sources)", result.Value, "direct-token")
	}
	if result.FilePath != "" {
		t.Fatalf("got FilePath %q, want empty for direct value", result.FilePath)
	}
}

func TestTokenResolver_NoSourceAvailable(t *testing.T) {
	cfg := &Config{
		TokenFile: "/nonexistent/path/token",
		TokenEnv:  "PLEXD_TEST_TOKEN_NOSOURCE",
	}
	r := NewTokenResolver(cfg, nil)
	_, err := r.Resolve(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "no bootstrap token found") {
		t.Fatalf("error should mention 'no bootstrap token found', got: %s", msg)
	}
	if !strings.Contains(msg, cfg.TokenFile) {
		t.Fatalf("error should list file path, got: %s", msg)
	}
	if !strings.Contains(msg, cfg.TokenEnv) {
		t.Fatalf("error should list env var name, got: %s", msg)
	}
}

func TestTokenResolver_FileNotFoundFallsThrough(t *testing.T) {
	envName := "PLEXD_TEST_TOKEN_FALLTHROUGH"
	t.Setenv(envName, "env-fallback-token")

	cfg := &Config{
		TokenFile: "/nonexistent/path/token",
		TokenEnv:  envName,
	}
	r := NewTokenResolver(cfg, nil)
	result, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Value != "env-fallback-token" {
		t.Fatalf("got value %q, want %q", result.Value, "env-fallback-token")
	}
}

func TestTokenResolver_FileReadError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced on windows")
	}
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tokenFile, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(tokenFile, 0o600) // restore so TempDir cleanup works
	})

	cfg := &Config{
		TokenFile: tokenFile,
	}
	r := NewTokenResolver(cfg, nil)
	_, err := r.Resolve(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "read token file") {
		t.Fatalf("error should mention 'read token file', got: %s", msg)
	}
	if !strings.Contains(msg, tokenFile) {
		t.Fatalf("error should contain file path, got: %s", msg)
	}
}

func TestTokenResolver_InvalidFormat_TooLong(t *testing.T) {
	cfg := &Config{
		TokenValue: strings.Repeat("a", 513),
	}
	r := NewTokenResolver(cfg, nil)
	_, err := r.Resolve(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum length") {
		t.Fatalf("error should mention 'exceeds maximum length', got: %s", err.Error())
	}
}

func TestTokenResolver_InvalidFormat_NonPrintable(t *testing.T) {
	cfg := &Config{
		TokenValue: "token\x01value",
	}
	r := NewTokenResolver(cfg, nil)
	_, err := r.Resolve(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "non-printable characters") {
		t.Fatalf("error should mention 'non-printable characters', got: %s", err.Error())
	}
}

func TestTokenResolver_WhitespaceTrimming(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("\n  \t trimmed-token \t \n\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		TokenFile: tokenFile,
	}
	r := NewTokenResolver(cfg, nil)
	result, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Value != "trimmed-token" {
		t.Fatalf("got value %q, want %q", result.Value, "trimmed-token")
	}
}

// The token is the one input whose absence stops registration, so a genuine
// metadata read error (a transient IMDS failure, a misconfigured path) must
// surface — not be reported as "no token found", which sends the operator to
// audit the wrong thing.
func TestTokenResolver_MetadataError(t *testing.T) {
	meta := &mockMetadataProvider{err: errors.New("metadata unavailable")}
	cfg := &Config{
		UseMetadata: true,
	}
	r := NewTokenResolver(cfg, meta)
	_, err := r.Resolve(context.Background())
	if err == nil {
		t.Fatal("expected error for failed metadata read, got nil")
	}
	if !strings.Contains(err.Error(), "read token from metadata") {
		t.Fatalf("error should name the metadata token read, got: %s", err.Error())
	}
	if !strings.Contains(err.Error(), "metadata unavailable") {
		t.Fatalf("error should wrap the provider error, got: %s", err.Error())
	}
	if strings.Contains(err.Error(), "no bootstrap token found") {
		t.Fatalf("a real read error must not be reported as a missing token, got: %s", err.Error())
	}
}

// ErrMetadataNotFound means the service serves no token at the path ("not
// provisioned"), so it falls through to the terminal no-source error rather
// than surfacing as a read failure.
func TestTokenResolver_MetadataNotFoundFallsThrough(t *testing.T) {
	meta := &mockMetadataProvider{err: ErrMetadataNotFound}
	cfg := &Config{UseMetadata: true}
	r := NewTokenResolver(cfg, meta)
	_, err := r.Resolve(context.Background())
	if err == nil {
		t.Fatal("expected error when no sources available, got nil")
	}
	if !strings.Contains(err.Error(), "no bootstrap token found") {
		t.Fatalf("error should mention 'no bootstrap token found', got: %s", err.Error())
	}
}

func TestResolveValue_DirectWins(t *testing.T) {
	meta := &mockMetadataProvider{token: "metadata-value"}
	cfg := &Config{UseMetadata: true}
	r := NewTokenResolver(cfg, meta)

	v, err := r.ResolveValue(context.Background(), "project_id", "  direct-value  ", "/plexd/project-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != "direct-value" {
		t.Fatalf("got value %q, want %q (trimmed direct value)", v, "direct-value")
	}
	if meta.lastPath != "" {
		t.Fatalf("provider should not be consulted when a direct value is set, got path %q", meta.lastPath)
	}
}

func TestResolveValue_MetadataFallback(t *testing.T) {
	meta := &mockMetadataProvider{token: "  metadata-value\n"}
	cfg := &Config{UseMetadata: true}
	r := NewTokenResolver(cfg, meta)

	v, err := r.ResolveValue(context.Background(), "resource_handle", "", "/plexd/resource-handle")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != "metadata-value" {
		t.Fatalf("got value %q, want %q (trimmed metadata value)", v, "metadata-value")
	}
	if meta.lastPath != "/plexd/resource-handle" {
		t.Fatalf("provider received path %q, want %q", meta.lastPath, "/plexd/resource-handle")
	}
}

func TestResolveValue_MetadataDisabled(t *testing.T) {
	meta := &mockMetadataProvider{token: "metadata-value"}
	cfg := &Config{UseMetadata: false}
	r := NewTokenResolver(cfg, meta)

	v, err := r.ResolveValue(context.Background(), "project_id", "", "/plexd/project-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != "" {
		t.Fatalf("got value %q, want empty when metadata disabled", v)
	}
	if meta.lastPath != "" {
		t.Fatalf("provider should not be consulted when metadata disabled, got path %q", meta.lastPath)
	}
}

func TestResolveValue_NilProvider(t *testing.T) {
	cfg := &Config{UseMetadata: true}
	r := NewTokenResolver(cfg, nil)

	v, err := r.ResolveValue(context.Background(), "project_id", "", "/plexd/project-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != "" {
		t.Fatalf("got value %q, want empty when provider is nil", v)
	}
}

// A failing metadata read must surface as an error. Collapsing it to an empty
// string reports a transient IMDS outage as a missing config setting and skips
// the retry loop entirely.
func TestResolveValue_MetadataReadError(t *testing.T) {
	meta := &mockMetadataProvider{err: errors.New("metadata unavailable")}
	cfg := &Config{UseMetadata: true}
	r := NewTokenResolver(cfg, meta)

	_, err := r.ResolveValue(context.Background(), "project_id", "", "/plexd/project-id")
	if err == nil {
		t.Fatal("expected error for failed metadata read, got nil")
	}
	if !strings.Contains(err.Error(), "read project_id from metadata") {
		t.Fatalf("error should name the field being read, got: %s", err.Error())
	}
	if !strings.Contains(err.Error(), "metadata unavailable") {
		t.Fatalf("error should wrap the provider error, got: %s", err.Error())
	}
}

// A path the metadata service does not serve means "not provisioned", so
// optional inputs such as requested_resource_id stay optional.
func TestResolveValue_MetadataNotFound(t *testing.T) {
	meta := &mockMetadataProvider{err: ErrMetadataNotFound}
	cfg := &Config{UseMetadata: true}
	r := NewTokenResolver(cfg, meta)

	v, err := r.ResolveValue(context.Background(), "requested_resource_id", "", "/plexd/requested-resource-id")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != "" {
		t.Fatalf("got value %q, want empty when metadata serves no value", v)
	}
}

// validateValue is shared by project_id, resource_handle, and
// requested_resource_id — the message must name the field that actually failed
// rather than sending the operator to audit their bootstrap token.
func TestResolveValue_ErrorNamesField(t *testing.T) {
	cfg := &Config{}
	r := NewTokenResolver(cfg, nil)

	_, err := r.ResolveValue(context.Background(), "resource_handle", "bad\x00handle", "/plexd/resource-handle")
	if err == nil {
		t.Fatal("expected error for non-printable value, got nil")
	}
	if !strings.Contains(err.Error(), "resource_handle") {
		t.Fatalf("error should name resource_handle, got: %s", err.Error())
	}
	if strings.Contains(err.Error(), "token") {
		t.Fatalf("error must not blame the bootstrap token, got: %s", err.Error())
	}
}

func TestResolveValue_OversizedDirect(t *testing.T) {
	cfg := &Config{}
	r := NewTokenResolver(cfg, nil)

	_, err := r.ResolveValue(context.Background(), "project_id", strings.Repeat("a", maxValueLength+1), "/plexd/project-id")
	if err == nil {
		t.Fatal("expected error for oversized direct value, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum length") {
		t.Fatalf("error should mention 'exceeds maximum length', got: %s", err.Error())
	}
}

func TestResolveValue_NonPrintableDirect(t *testing.T) {
	cfg := &Config{}
	r := NewTokenResolver(cfg, nil)

	_, err := r.ResolveValue(context.Background(), "resource_handle", "value\x01here", "/plexd/project-id")
	if err == nil {
		t.Fatal("expected error for non-printable direct value, got nil")
	}
	if !strings.Contains(err.Error(), "non-printable characters") {
		t.Fatalf("error should mention 'non-printable characters', got: %s", err.Error())
	}
}
