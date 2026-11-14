// Package kubernetes provides Kubernetes environment detection and integration.
package kubernetes

import (
	"regexp"
	"strings"
	"time"
)

// defaultHookImage is the container image a PlexdHook without a jobTemplate
// names. It carries no digest, so such a hook is neither reported in the
// capability manifest nor run.
const defaultHookImage = "busybox:latest"

// imageDigestRe matches the one image digest form the contract accepts in a
// plexd_hooks entry, and the one a PlexdHook's image must carry to run.
var imageDigestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// PlexdHookSpec holds the spec fields of a PlexdHook CRD resource.
type PlexdHookSpec struct {
	HookName    string                 `json:"hookName"`
	JobTemplate *PlexdHookJobTemplate  `json:"jobTemplate,omitempty"`
	Parameters  []PlexdHookParam       `json:"parameters,omitempty"`
	Privileged  bool                   `json:"privileged,omitempty"`
}

// Image returns the container image a hook with this spec runs: the job
// template's image, or defaultHookImage when the template or its image is
// absent.
func (s PlexdHookSpec) Image() string {
	if s.JobTemplate != nil && s.JobTemplate.Image != "" {
		return s.JobTemplate.Image
	}
	return defaultHookImage
}

// ImageDigest returns the digest after the last `@` of Image, and whether it is
// a canonical sha256 digest. plexd has no registry access to resolve a tag, so
// only a hook whose image is pinned this way is reported in the capability
// manifest and run. Both ask this method, so the manifest cannot report a hook
// the runner refuses, or the other way round.
func (s PlexdHookSpec) ImageDigest() (string, bool) {
	image := s.Image()
	at := strings.LastIndex(image, "@")
	if at < 0 {
		return "", false
	}
	digest := image[at+1:]
	if !imageDigestRe.MatchString(digest) {
		return "", false
	}
	return digest, true
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
