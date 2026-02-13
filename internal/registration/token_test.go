package registration

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type mockMetadataProvider struct {
	token string
	err   error
}

func (m *mockMetadataProvider) ReadToken(ctx context.Context) (string, error) {
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

func TestTokenResolver_MetadataError(t *testing.T) {
	meta := &mockMetadataProvider{err: errors.New("metadata unavailable")}
	cfg := &Config{
		UseMetadata: true,
	}
	r := NewTokenResolver(cfg, meta)
	_, err := r.Resolve(context.Background())
	if err == nil {
		t.Fatal("expected error when no sources available, got nil")
	}
	if !strings.Contains(err.Error(), "no bootstrap token found") {
		t.Fatalf("error should mention 'no bootstrap token found', got: %s", err.Error())
	}
}
