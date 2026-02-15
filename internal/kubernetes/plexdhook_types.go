// Package kubernetes provides Kubernetes environment detection and integration.
package kubernetes

import "time"

// PlexdHookSpec holds the spec fields of a PlexdHook CRD resource.
type PlexdHookSpec struct {
	HookName    string                 `json:"hookName"`
	JobTemplate *PlexdHookJobTemplate  `json:"jobTemplate,omitempty"`
	Parameters  []PlexdHookParam       `json:"parameters,omitempty"`
	Privileged  bool                   `json:"privileged,omitempty"`
}

// PlexdHookJobTemplate holds the job template for a PlexdHook.
type PlexdHookJobTemplate struct {
	Image   string   `json:"image"`
	Command []string `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
}

// PlexdHookParam represents a name/value parameter for a PlexdHook.
type PlexdHookParam struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// PlexdHookStatus holds the status fields of a PlexdHook CRD resource.
type PlexdHookStatus struct {
	JobName     string     `json:"jobName,omitempty"`
	Phase       string     `json:"phase,omitempty"`
	Message     string     `json:"message,omitempty"`
	StartedAt   *time.Time `json:"startedAt,omitempty"`
	CompletedAt *time.Time `json:"completedAt,omitempty"`
}

// PlexdHook represents the CRD resource for a hook execution request.
type PlexdHook struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	UID             string            `json:"uid,omitempty"`
	ResourceVersion string            `json:"resourceVersion,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Spec            PlexdHookSpec     `json:"spec"`
	Status          PlexdHookStatus   `json:"status,omitempty"`
}

// PlexdHookEvent represents a watch event for a PlexdHook resource.
type PlexdHookEvent struct {
	Type string     `json:"type"`
	Hook *PlexdHook `json:"hook"`
}
