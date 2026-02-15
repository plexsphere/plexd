package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"
)

// defaultHookImage is the container image used when a PlexdHook omits jobTemplate.
const defaultHookImage = "busybox:latest"

// PlexdHookController watches PlexdHook CRD resources and creates Kubernetes
// Jobs to execute hook workloads on the local node.
type PlexdHookController struct {
	client    KubeClient
	cfg       Config
	namespace string
	nodeName  string
	logger    *slog.Logger

	mu     sync.Mutex
	cancel context.CancelFunc
}

// NewPlexdHookController creates a new PlexdHookController.
func NewPlexdHookController(client KubeClient, cfg Config, namespace, nodeName string, logger *slog.Logger) *PlexdHookController {
	cfg.ApplyDefaults(nil)
	return &PlexdHookController{
		client:    client,
		cfg:       cfg,
		namespace: namespace,
		nodeName:  nodeName,
		logger:    logger.With("component", "plexdhook-controller"),
	}
}

// Start watches PlexdHook resources and creates Jobs for new hooks.
// It blocks until the context is cancelled or the watch channel is closed.
func (c *PlexdHookController) Start(ctx context.Context) error {
	c.mu.Lock()
	ctx, c.cancel = context.WithCancel(ctx)
	c.mu.Unlock()

	watchCh, err := c.client.WatchPlexdHooks(ctx, c.namespace)
	if err != nil {
		c.cancel()
		return fmt.Errorf("kubernetes: plexdhook: watch: %w", err)
	}

	c.logger.InfoContext(ctx, "plexdhook controller started",
		"namespace", c.namespace, "node", c.nodeName)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case evt, ok := <-watchCh:
			if !ok {
				return nil
			}
			if evt.Type == "ADDED" && evt.Hook != nil {
				c.handleAdded(ctx, evt.Hook)
			}
		}
	}
}

// Stop cancels the watch and returns.
func (c *PlexdHookController) Stop() {
	c.mu.Lock()
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// handleAdded processes a newly added PlexdHook by creating a Job for it.
func (c *PlexdHookController) handleAdded(ctx context.Context, hook *PlexdHook) {
	// Skip if already processed (status.jobName is set).
	if hook.Status.JobName != "" {
		return
	}

	job := c.buildJob(hook)

	if err := c.client.CreateJob(ctx, job); err != nil {
		if errors.Is(err, ErrAlreadyExists) {
			c.logger.InfoContext(ctx, "plexdhook job already exists",
				"hook", hook.Name, "job", job.Name)
			// Update status even if job already exists.
			c.updateStatus(ctx, hook, job.Name, "Pending", "")
			return
		}
		c.logger.ErrorContext(ctx, "plexdhook job creation failed",
			"hook", hook.Name, "error", err)
		c.updateStatus(ctx, hook, "", "Failed", err.Error())
		return
	}

	c.logger.InfoContext(ctx, "plexdhook job created",
		"hook", hook.Name, "job", job.Name, "node", c.nodeName)
	c.updateStatus(ctx, hook, job.Name, "Pending", "")
}

// updateStatus updates the status subresource of a PlexdHook.
func (c *PlexdHookController) updateStatus(ctx context.Context, hook *PlexdHook, jobName, phase, message string) {
	now := time.Now()
	hook.Status.JobName = jobName
	hook.Status.Phase = phase
	hook.Status.Message = message
	hook.Status.StartedAt = &now

	if err := c.client.UpdatePlexdHookStatus(ctx, hook); err != nil {
		c.logger.WarnContext(ctx, "plexdhook status update failed",
			"hook", hook.Name, "error", err)
	}
}

// hookParamSanitizer replaces non-alphanumeric/underscore characters.
var hookParamSanitizer = regexp.MustCompile(`[^A-Za-z0-9_]`)

// sanitizeHookParamName converts a parameter name to an environment variable suffix.
func sanitizeHookParamName(name string) string {
	return strings.ToUpper(hookParamSanitizer.ReplaceAllString(name, "_"))
}

// buildJob creates a PlexdJob from a PlexdHook resource.
func (c *PlexdHookController) buildJob(hook *PlexdHook) *PlexdJob {
	jobName := fmt.Sprintf("plexdhook-%s", hook.Name)

	// Default image and command.
	image := defaultHookImage
	var command []string
	var args []string
	if hook.Spec.JobTemplate != nil {
		if hook.Spec.JobTemplate.Image != "" {
			image = hook.Spec.JobTemplate.Image
		}
		command = hook.Spec.JobTemplate.Command
		args = hook.Spec.JobTemplate.Args
	}

	// Build environment variables.
	env := map[string]string{
		"PLEXD_NODE_ID":   c.nodeName,
		"PLEXD_HOOK_NAME": hook.Spec.HookName,
	}
	for _, p := range hook.Spec.Parameters {
		envName := "PLEXD_PARAM_" + sanitizeHookParamName(p.Name)
		env[envName] = p.Value
	}

	// Security context based on privileged flag.
	container := PlexdJobContainer{
		Name:    "hook",
		Image:   image,
		Command: command,
		Args:    args,
		Env:     env,
	}

	if hook.Spec.Privileged {
		container.Privileged = true
	} else {
		container.ReadOnlyRootFS = true
		container.DropCapabilities = []string{"ALL"}
	}

	return &PlexdJob{
		Name:      jobName,
		Namespace: hook.Namespace,
		Labels: map[string]string{
			"app.kubernetes.io/managed-by":   "plexd",
			"plexd.plexsphere.com/hook-name": hook.Spec.HookName,
		},
		OwnerReferences: []PlexdJobOwnerRef{
			{
				APIVersion:         "plexd.plexsphere.com/v1alpha1",
				Kind:               "PlexdHook",
				Name:               hook.Name,
				UID:                hook.UID,
				Controller:         true,
				BlockOwnerDeletion: true,
			},
		},
		NodeSelector: map[string]string{
			"kubernetes.io/hostname": c.nodeName,
		},
		ServiceAccountName: "plexd",
		Containers:         []PlexdJobContainer{container},
		RestartPolicy:      "Never",
	}
}
