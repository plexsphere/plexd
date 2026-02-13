// Package kubernetes provides Kubernetes environment detection and integration.
package kubernetes

import (
	"log/slog"
	"os"
)

// ServiceAccountBasePath is the base path for Kubernetes service account secrets.
const ServiceAccountBasePath = "/var/run/secrets/kubernetes.io/serviceaccount"

// DefaultTokenPath is the default path to the service account token.
const DefaultTokenPath = ServiceAccountBasePath + "/token"

// DefaultNamespacePath is the default path to the service account namespace file.
const DefaultNamespacePath = ServiceAccountBasePath + "/namespace"

// KubernetesEnvironment holds information about the Kubernetes environment
// in which plexd is running. A nil value indicates that the process is not
// running inside a Kubernetes pod.
type KubernetesEnvironment struct {
	// InCluster is true when plexd is running inside a Kubernetes pod.
	InCluster bool

	// Namespace is the Kubernetes namespace of the pod.
	Namespace string

	// PodName is the name of the pod, typically sourced from the HOSTNAME env var.
	PodName string

	// NodeName is the Kubernetes node name, sourced from the MY_NODE_NAME env var
	// (set via the downward API).
	NodeName string

	// ServiceAccountToken is the filesystem path to the service account token.
	ServiceAccountToken string
}

// EnvironmentDetector detects whether the process is running inside a
// Kubernetes cluster and returns environment metadata.
type EnvironmentDetector interface {
	// Detect returns information about the Kubernetes environment.
	// Returns nil if the process is not running inside a Kubernetes pod.
	Detect() *KubernetesEnvironment
}

// DefaultDetector implements EnvironmentDetector using real environment
// variables and filesystem paths.
type DefaultDetector struct {
	Logger *slog.Logger
}

// Detect checks environment variables and filesystem paths to determine
// whether the process is running inside a Kubernetes pod. Returns a
// KubernetesEnvironment with InCluster=false if KUBERNETES_SERVICE_HOST
// is not set, or if the service account token file does not exist.
func (d *DefaultDetector) Detect() *KubernetesEnvironment {
	logger := d.Logger
	if logger == nil {
		logger = slog.Default()
	}

	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		return &KubernetesEnvironment{InCluster: false}
	}

	// Check that the SA token file exists (REQ-001: partial environment).
	if _, err := os.Stat(DefaultTokenPath); err != nil {
		logger.Warn("kubernetes: partial environment detected: KUBERNETES_SERVICE_HOST set but SA token missing",
			"component", "kubernetes", "token_path", DefaultTokenPath)
		return &KubernetesEnvironment{InCluster: false}
	}

	ns, _ := os.ReadFile(DefaultNamespacePath)

	env := &KubernetesEnvironment{
		InCluster:           true,
		Namespace:           string(ns),
		PodName:             os.Getenv("HOSTNAME"),
		NodeName:            os.Getenv("MY_NODE_NAME"),
		ServiceAccountToken: DefaultTokenPath,
	}

	logger.Debug("kubernetes: environment detected",
		"component", "kubernetes",
		"namespace", env.Namespace,
		"node_name", env.NodeName,
		"pod_name", env.PodName,
	)

	return env
}
