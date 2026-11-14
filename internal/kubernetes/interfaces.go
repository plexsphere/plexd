// Package kubernetes provides Kubernetes environment detection and integration.
package kubernetes

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors for Kubernetes operations.
var (
	// ErrNotFound is returned when a requested resource does not exist.
	ErrNotFound = errors.New("kubernetes: resource not found")
	// ErrAlreadyExists is returned when creating a resource that already exists.
	ErrAlreadyExists = errors.New("kubernetes: resource already exists")
	// ErrUnauthorized is returned when the client lacks valid credentials.
	ErrUnauthorized = errors.New("kubernetes: unauthorized")
)

// PlexdNodeStateSpec holds the spec fields of a PlexdNodeState CRD resource.
type PlexdNodeStateSpec struct {
	NodeID     string            `json:"nodeId"`
	MeshIP     string            `json:"meshIp,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	Data       []DataEntry       `json:"data,omitempty"`
	SecretRefs []SecretRef       `json:"secretRefs,omitempty"`
}

// DataEntry represents a single data item in the PlexdNodeState spec or status report.
type DataEntry struct {
	Key         string `json:"key"`
	ContentType string `json:"contentType,omitempty"`
	Payload     any    `json:"payload,omitempty"`
	Version     int    `json:"version,omitempty"`
	UpdatedAt   string `json:"updatedAt,omitempty"`
}

// SecretRef represents a reference to a Kubernetes Secret holding encrypted data.
type SecretRef struct {
	Key        string `json:"key"`
	SecretName string `json:"secretName"`
	Version    int    `json:"version,omitempty"`
}

// PlexdNodeStateStatus holds the status fields of a PlexdNodeState CRD resource.
type PlexdNodeStateStatus struct {
	Report []DataEntry `json:"report,omitempty"`
}

// PlexdNodeState represents the CRD resource for a node's state.
type PlexdNodeState struct {
	Name            string               `json:"name"`
	Namespace       string               `json:"namespace"`
	UID             string               `json:"uid,omitempty"`
	ResourceVersion string               `json:"resourceVersion,omitempty"`
	Labels          map[string]string    `json:"labels,omitempty"`
	Spec            PlexdNodeStateSpec   `json:"spec"`
	Status          PlexdNodeStateStatus `json:"status,omitempty"`
	LastUpdate      time.Time            `json:"lastUpdate"`
}

// PlexdNodeStateEvent represents a watch event for a PlexdNodeState resource.
type PlexdNodeStateEvent struct {
	Type  string          `json:"type"` // ADDED, MODIFIED, DELETED
	State *PlexdNodeState `json:"state"`
}

// KubeSecret represents a Kubernetes Secret managed by plexd.
type KubeSecret struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	Labels          map[string]string `json:"labels,omitempty"`
	Data            map[string][]byte `json:"data,omitempty"`
	OwnerRefName    string            `json:"ownerRefName,omitempty"`
	OwnerRefUID     string            `json:"ownerRefUID,omitempty"`
}

// KubeClient abstracts Kubernetes API interactions for testability.
// All methods that modify state must be idempotent: repeating an operation
// that is already applied returns nil.
type KubeClient interface {
	// GetNodeState retrieves the PlexdNodeState CRD for the given name and namespace.
	// Returns ErrNotFound if the resource does not exist.
	GetNodeState(ctx context.Context, namespace, name string) (*PlexdNodeState, error)

	// CreateNodeState creates a new PlexdNodeState CRD resource.
	// Returns ErrAlreadyExists if the resource already exists.
	CreateNodeState(ctx context.Context, state *PlexdNodeState) error

	// UpdateNodeState updates an existing PlexdNodeState CRD resource spec.
	// Returns ErrNotFound if the resource does not exist.
	UpdateNodeState(ctx context.Context, state *PlexdNodeState) error

	// DeleteNodeState deletes a PlexdNodeState CRD resource.
	// Returns nil if the resource does not exist (idempotent).
	DeleteNodeState(ctx context.Context, namespace, name string) error

	// WatchNodeState starts a watch on a specific PlexdNodeState resource.
	// Returns a channel that receives events until the context is cancelled.
	WatchNodeState(ctx context.Context, namespace, name string) (<-chan PlexdNodeStateEvent, error)

	// CreateSecret creates a Kubernetes Secret.
	// Returns ErrAlreadyExists if the secret already exists.
	CreateSecret(ctx context.Context, secret *KubeSecret) error

	// UpdateSecret updates an existing Kubernetes Secret.
	// Returns ErrNotFound if the secret does not exist.
	UpdateSecret(ctx context.Context, secret *KubeSecret) error

	// DeleteSecret deletes a Kubernetes Secret.
	// Returns nil if the secret does not exist (idempotent).
	DeleteSecret(ctx context.Context, namespace, name string) error
}
