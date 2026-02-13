package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ReportNotifier is called when the CRDController detects new or changed
// report entries in the status subresource.
type ReportNotifier interface {
	NotifyChange()
}

// CRDController manages the lifecycle of a PlexdNodeState CRD resource:
// creates on startup, updates spec on state changes, watches status for
// workload-written report entries, and manages associated Kubernetes Secrets.
type CRDController struct {
	client         KubeClient
	reportNotifier ReportNotifier
	cfg            Config
	namespace      string
	nodeID         string
	meshIP         string
	resourceName   string // node-{node_id}
	logger         *slog.Logger

	mu             sync.Mutex
	currentSecrets map[string]string // key -> secretName
	cancel         context.CancelFunc
	lastReport     []DataEntry
}

// NewCRDController creates a new CRDController.
func NewCRDController(client KubeClient, cfg Config, nodeID, meshIP, namespace string, reportNotifier ReportNotifier, logger *slog.Logger) *CRDController {
	cfg.ApplyDefaults(nil)
	return &CRDController{
		client:         client,
		reportNotifier: reportNotifier,
		cfg:            cfg,
		namespace:      namespace,
		nodeID:         nodeID,
		meshIP:         meshIP,
		resourceName:   "node-" + nodeID,
		logger:         logger.With("component", "nodeapi"),
		currentSecrets: make(map[string]string),
	}
}

// Start creates or updates the PlexdNodeState resource and starts the status
// watcher goroutine. It blocks until the context is cancelled.
func (c *CRDController) Start(ctx context.Context) error {
	if err := c.ensureResource(ctx); err != nil {
		return fmt.Errorf("kubernetes: crd: start: %w", err)
	}

	c.mu.Lock()
	ctx, c.cancel = context.WithCancel(ctx)
	c.mu.Unlock()

	watchCh, err := c.client.WatchNodeState(ctx, c.namespace, c.resourceName)
	if err != nil {
		c.cancel()
		return fmt.Errorf("kubernetes: crd: watch: %w", err)
	}

	c.logger.InfoContext(ctx, "crd controller started",
		"name", c.resourceName, "namespace", c.namespace)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case evt, ok := <-watchCh:
			if !ok {
				return nil
			}
			if evt.Type == "MODIFIED" && evt.State != nil {
				c.handleStatusChange(ctx, evt.State.Status.Report)
			}
		}
	}
}

// Stop cancels the status watch and returns.
func (c *CRDController) Stop() {
	c.mu.Lock()
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// UpdateMetadata updates the PlexdNodeState .spec.metadata via the KubeClient.
func (c *CRDController) UpdateMetadata(ctx context.Context, metadata map[string]string) error {
	existing, err := c.client.GetNodeState(ctx, c.namespace, c.resourceName)
	if err != nil {
		return fmt.Errorf("kubernetes: crd: update metadata: get: %w", err)
	}

	existing.Spec.Metadata = metadata
	existing.LastUpdate = time.Now()

	if err := c.client.UpdateNodeState(ctx, existing); err != nil {
		return fmt.Errorf("kubernetes: crd: update metadata: %w", err)
	}
	c.logger.InfoContext(ctx, "crd metadata updated", "name", c.resourceName)
	return nil
}

// UpdateData updates the PlexdNodeState .spec.data via the KubeClient.
func (c *CRDController) UpdateData(ctx context.Context, data []DataEntry) error {
	existing, err := c.client.GetNodeState(ctx, c.namespace, c.resourceName)
	if err != nil {
		return fmt.Errorf("kubernetes: crd: update data: get: %w", err)
	}

	existing.Spec.Data = data
	existing.LastUpdate = time.Now()

	if err := c.client.UpdateNodeState(ctx, existing); err != nil {
		return fmt.Errorf("kubernetes: crd: update data: %w", err)
	}
	c.logger.InfoContext(ctx, "crd data updated", "name", c.resourceName)
	return nil
}

// UpdateSecretIndex updates the PlexdNodeState .spec.secretRefs and manages
// associated Kubernetes Secrets with ownerReferences. New refs get Secrets
// created; removed refs get Secrets deleted.
func (c *CRDController) UpdateSecretIndex(ctx context.Context, refs []SecretRef, secretData map[string][]byte) error {
	existing, err := c.client.GetNodeState(ctx, c.namespace, c.resourceName)
	if err != nil {
		return fmt.Errorf("kubernetes: crd: update secret index: get: %w", err)
	}

	// Build new ref set.
	newRefSet := make(map[string]SecretRef, len(refs))
	for _, ref := range refs {
		newRefSet[ref.Key] = ref
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Delete Secrets for removed refs.
	for key, secretName := range c.currentSecrets {
		if _, ok := newRefSet[key]; !ok {
			if err := c.client.DeleteSecret(ctx, c.namespace, secretName); err != nil {
				c.logger.WarnContext(ctx, "crd: failed to delete secret",
					"secret", secretName, "error", err)
			}
			delete(c.currentSecrets, key)
		}
	}

	// Create or update Secrets for new/changed refs.
	for i, ref := range refs {
		secretName := fmt.Sprintf("plexd-secret-%s-%s", c.nodeID, ref.Key)
		refs[i].SecretName = secretName

		secret := &KubeSecret{
			Name:      secretName,
			Namespace: c.namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "plexd",
				"plexd.plexsphere.com/node-id": c.nodeID,
			},
			Data:         map[string][]byte{"ciphertext": secretData[ref.Key]},
			OwnerRefName: c.resourceName,
			OwnerRefUID:  existing.UID,
		}

		if _, exists := c.currentSecrets[ref.Key]; exists {
			if err := c.client.UpdateSecret(ctx, secret); err != nil {
				return fmt.Errorf("kubernetes: crd: update secret %s: %w", secretName, err)
			}
		} else if err := c.client.CreateSecret(ctx, secret); err != nil {
			if !errors.Is(err, ErrAlreadyExists) {
				return fmt.Errorf("kubernetes: crd: create secret %s: %w", secretName, err)
			}
			if err := c.client.UpdateSecret(ctx, secret); err != nil {
				return fmt.Errorf("kubernetes: crd: update existing secret %s: %w", secretName, err)
			}
		}
		c.currentSecrets[ref.Key] = secretName
	}

	existing.Spec.SecretRefs = refs
	existing.LastUpdate = time.Now()

	if err := c.client.UpdateNodeState(ctx, existing); err != nil {
		return fmt.Errorf("kubernetes: crd: update secret refs: %w", err)
	}
	c.logger.InfoContext(ctx, "crd secret index updated", "name", c.resourceName)
	return nil
}

// ensureResource creates or updates the PlexdNodeState on startup.
func (c *CRDController) ensureResource(ctx context.Context) error {
	state := &PlexdNodeState{
		Name:      c.resourceName,
		Namespace: c.namespace,
		Labels: map[string]string{
			"plexd.plexsphere.com/node-id": c.nodeID,
		},
		Spec: PlexdNodeStateSpec{
			NodeID: c.nodeID,
			MeshIP: c.meshIP,
		},
		LastUpdate: time.Now(),
	}

	existing, err := c.client.GetNodeState(ctx, c.namespace, c.resourceName)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("get state: %w", err)
	}

	// Resource not found — create it (with conflict recovery).
	if errors.Is(err, ErrNotFound) {
		createErr := c.client.CreateNodeState(ctx, state)
		if createErr == nil {
			c.logger.InfoContext(ctx, "crd state created", "name", c.resourceName)
			return nil
		}
		if !errors.Is(createErr, ErrAlreadyExists) {
			return fmt.Errorf("create state: %w", createErr)
		}
		if updateErr := c.client.UpdateNodeState(ctx, state); updateErr != nil {
			return fmt.Errorf("update after create conflict: %w", updateErr)
		}
		c.logger.InfoContext(ctx, "crd state updated after create conflict", "name", c.resourceName)
		return nil
	}

	// Resource exists — update spec.
	existing.Spec.NodeID = c.nodeID
	existing.Spec.MeshIP = c.meshIP
	existing.LastUpdate = time.Now()
	if err := c.client.UpdateNodeState(ctx, existing); err != nil {
		return fmt.Errorf("update state: %w", err)
	}
	c.logger.InfoContext(ctx, "crd state updated on startup", "name", c.resourceName)
	return nil
}

// handleStatusChange detects new or changed report entries in the status
// subresource and notifies the ReportNotifier.
func (c *CRDController) handleStatusChange(ctx context.Context, report []DataEntry) {
	if reportEqual(c.lastReport, report) {
		return
	}
	c.lastReport = report
	if c.reportNotifier != nil {
		c.reportNotifier.NotifyChange()
		c.logger.DebugContext(ctx, "crd status change detected, report syncer notified",
			"name", c.resourceName, "report_count", len(report))
	}
}

// reportEqual returns true if two report slices are identical by key+version.
func reportEqual(a, b []DataEntry) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]int, len(a))
	for _, e := range a {
		m[e.Key] = e.Version
	}
	for _, e := range b {
		if v, ok := m[e.Key]; !ok || v != e.Version {
			return false
		}
	}
	return true
}
