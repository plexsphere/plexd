package kubernetes

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestPlexdNodeState_JSONRoundTrip(t *testing.T) {
	ts := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	state := PlexdNodeState{
		Name:            "node-n-abc123",
		Namespace:       "plexd-system",
		UID:             "uid-1",
		ResourceVersion: "123",
		Labels:          map[string]string{"plexd.plexsphere.com/node-id": "abc123"},
		Spec: PlexdNodeStateSpec{
			NodeID:   "abc123",
			MeshIP:   "10.99.0.1",
			Metadata: map[string]string{"region": "us-east-1"},
			Data: []DataEntry{
				{Key: "role", ContentType: "text/plain", Payload: "worker", Version: 1, UpdatedAt: "2025-06-15T12:00:00Z"},
			},
			SecretRefs: []SecretRef{
				{Key: "tls-cert", SecretName: "plexd-secret-abc123-tls-cert", Version: 1},
			},
		},
		Status: PlexdNodeStateStatus{
			Report: []DataEntry{
				{Key: "health", ContentType: "application/json", Payload: map[string]any{"ok": true}, Version: 1},
			},
		},
		LastUpdate: ts,
	}

	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	var got PlexdNodeState
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if got.Name != state.Name {
		t.Errorf("Name = %q, want %q", got.Name, state.Name)
	}
	if got.Namespace != state.Namespace {
		t.Errorf("Namespace = %q, want %q", got.Namespace, state.Namespace)
	}
	if got.UID != state.UID {
		t.Errorf("UID = %q, want %q", got.UID, state.UID)
	}
	if got.ResourceVersion != state.ResourceVersion {
		t.Errorf("ResourceVersion = %q, want %q", got.ResourceVersion, state.ResourceVersion)
	}
	if got.Spec.NodeID != state.Spec.NodeID {
		t.Errorf("Spec.NodeID = %q, want %q", got.Spec.NodeID, state.Spec.NodeID)
	}
	if got.Spec.MeshIP != state.Spec.MeshIP {
		t.Errorf("Spec.MeshIP = %q, want %q", got.Spec.MeshIP, state.Spec.MeshIP)
	}
	if !got.LastUpdate.Equal(state.LastUpdate) {
		t.Errorf("LastUpdate = %v, want %v", got.LastUpdate, state.LastUpdate)
	}
	if got.Spec.Metadata["region"] != "us-east-1" {
		t.Errorf("Spec.Metadata[region] = %q, want %q", got.Spec.Metadata["region"], "us-east-1")
	}
	if len(got.Spec.Data) != 1 || got.Spec.Data[0].Key != "role" {
		t.Errorf("Spec.Data unexpected: %+v", got.Spec.Data)
	}
	if len(got.Spec.SecretRefs) != 1 || got.Spec.SecretRefs[0].Key != "tls-cert" {
		t.Errorf("Spec.SecretRefs unexpected: %+v", got.Spec.SecretRefs)
	}
	if len(got.Status.Report) != 1 || got.Status.Report[0].Key != "health" {
		t.Errorf("Status.Report unexpected: %+v", got.Status.Report)
	}
}

func TestPlexdNodeState_JSONFieldNames(t *testing.T) {
	state := PlexdNodeState{
		Name:      "n",
		Namespace: "ns",
		Spec: PlexdNodeStateSpec{
			NodeID: "id",
			MeshIP: "10.0.0.1",
		},
		LastUpdate: time.Now(),
	}

	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map error: %v", err)
	}

	expected := []string{"name", "namespace", "spec", "lastUpdate"}
	for _, key := range expected {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing JSON field %q", key)
		}
	}
}

func TestPlexdNodeState_JSONOmitsEmptyOptionals(t *testing.T) {
	state := PlexdNodeState{
		Name:      "node-1",
		Namespace: "default",
		Spec: PlexdNodeStateSpec{
			NodeID: "id-1",
		},
		LastUpdate: time.Now(),
	}

	data, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map error: %v", err)
	}

	for _, key := range []string{"uid", "resourceVersion", "labels"} {
		if _, ok := raw[key]; ok {
			t.Errorf("expected field %q to be omitted for zero value, but it was present", key)
		}
	}
}

func TestKubeSecret_JSONRoundTrip(t *testing.T) {
	secret := KubeSecret{
		Name:         "plexd-secret-node1-tls",
		Namespace:    "plexd-system",
		Labels:       map[string]string{"app": "plexd"},
		Data:         map[string][]byte{"ciphertext": []byte("encrypted-data")},
		OwnerRefName: "node-node1",
		OwnerRefUID:  "uid-123",
	}

	data, err := json.Marshal(secret)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	var got KubeSecret
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if got.Name != secret.Name {
		t.Errorf("Name = %q, want %q", got.Name, secret.Name)
	}
	if got.OwnerRefName != secret.OwnerRefName {
		t.Errorf("OwnerRefName = %q, want %q", got.OwnerRefName, secret.OwnerRefName)
	}
	if got.OwnerRefUID != secret.OwnerRefUID {
		t.Errorf("OwnerRefUID = %q, want %q", got.OwnerRefUID, secret.OwnerRefUID)
	}
}

func TestSentinelErrors_ErrorsIs(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		target error
	}{
		{"ErrNotFound direct", ErrNotFound, ErrNotFound},
		{"ErrAlreadyExists direct", ErrAlreadyExists, ErrAlreadyExists},
		{"ErrUnauthorized direct", ErrUnauthorized, ErrUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !errors.Is(tt.err, tt.target) {
				t.Errorf("errors.Is(%v, %v) = false, want true", tt.err, tt.target)
			}
		})
	}
}

func TestSentinelErrors_WrappedErrorsIs(t *testing.T) {
	wrapped := fmt.Errorf("operation failed: %w", ErrNotFound)
	if !errors.Is(wrapped, ErrNotFound) {
		t.Error("errors.Is(wrapped, ErrNotFound) = false, want true")
	}

	wrapped2 := fmt.Errorf("create failed: %w", ErrAlreadyExists)
	if !errors.Is(wrapped2, ErrAlreadyExists) {
		t.Error("errors.Is(wrapped2, ErrAlreadyExists) = false, want true")
	}

	wrapped3 := fmt.Errorf("auth failed: %w", ErrUnauthorized)
	if !errors.Is(wrapped3, ErrUnauthorized) {
		t.Error("errors.Is(wrapped3, ErrUnauthorized) = false, want true")
	}
}

func TestSentinelErrors_NotEqual(t *testing.T) {
	if errors.Is(ErrNotFound, ErrAlreadyExists) {
		t.Error("ErrNotFound should not match ErrAlreadyExists")
	}
	if errors.Is(ErrAlreadyExists, ErrUnauthorized) {
		t.Error("ErrAlreadyExists should not match ErrUnauthorized")
	}
	if errors.Is(ErrUnauthorized, ErrNotFound) {
		t.Error("ErrUnauthorized should not match ErrNotFound")
	}
}

func TestSentinelErrors_Messages(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{ErrNotFound, "kubernetes: resource not found"},
		{ErrAlreadyExists, "kubernetes: resource already exists"},
		{ErrUnauthorized, "kubernetes: unauthorized"},
	}

	for _, tt := range tests {
		if got := tt.err.Error(); got != tt.want {
			t.Errorf("Error() = %q, want %q", got, tt.want)
		}
	}
}
