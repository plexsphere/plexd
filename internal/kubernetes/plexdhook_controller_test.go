package kubernetes

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type mockPlexdHookClient struct {
	// WatchPlexdHooks
	watchHooksCh  chan PlexdHookEvent
	watchHooksErr error

	// UpdatePlexdHookStatus
	updateStatusErr    error
	updateStatusCalled bool
	lastStatusUpdate   *PlexdHook

	// CreateJob
	createJobErr    error
	createJobCalled bool
	lastCreatedJob  *PlexdJob
}

// PlexdNodeState stubs.
func (m *mockPlexdHookClient) GetNodeState(_ context.Context, _, _ string) (*PlexdNodeState, error) {
	return nil, nil
}
func (m *mockPlexdHookClient) CreateNodeState(_ context.Context, _ *PlexdNodeState) error {
	return nil
}
func (m *mockPlexdHookClient) UpdateNodeState(_ context.Context, _ *PlexdNodeState) error {
	return nil
}
func (m *mockPlexdHookClient) DeleteNodeState(_ context.Context, _, _ string) error { return nil }
func (m *mockPlexdHookClient) WatchNodeState(_ context.Context, _, _ string) (<-chan PlexdNodeStateEvent, error) {
	return nil, nil
}

// Secret stubs.
func (m *mockPlexdHookClient) CreateSecret(_ context.Context, _ *KubeSecret) error { return nil }
func (m *mockPlexdHookClient) UpdateSecret(_ context.Context, _ *KubeSecret) error  { return nil }
func (m *mockPlexdHookClient) DeleteSecret(_ context.Context, _, _ string) error     { return nil }

// PlexdHook methods.
func (m *mockPlexdHookClient) WatchPlexdHooks(_ context.Context, _ string) (<-chan PlexdHookEvent, error) {
	if m.watchHooksErr != nil {
		return nil, m.watchHooksErr
	}
	if m.watchHooksCh == nil {
		m.watchHooksCh = make(chan PlexdHookEvent)
	}
	return m.watchHooksCh, nil
}

func (m *mockPlexdHookClient) UpdatePlexdHookStatus(_ context.Context, hook *PlexdHook) error {
	m.updateStatusCalled = true
	m.lastStatusUpdate = hook
	return m.updateStatusErr
}

func (m *mockPlexdHookClient) CreateJob(_ context.Context, job *PlexdJob) error {
	m.createJobCalled = true
	m.lastCreatedJob = job
	return m.createJobErr
}

// startAndSendHook creates a controller, sends the hook as an ADDED event, and
// blocks until the event is processed. The caller inspects client fields (e.g.
// lastCreatedJob, updateStatusCalled) after this returns.
func startAndSendHook(t *testing.T, client *mockPlexdHookClient, nodeName string, hook *PlexdHook) {
	t.Helper()
	if client.watchHooksCh == nil {
		client.watchHooksCh = make(chan PlexdHookEvent, 1)
	}
	ctrl := NewPlexdHookController(client, Config{Enabled: true}, "plexd-system", nodeName, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- ctrl.Start(ctx) }()

	time.Sleep(50 * time.Millisecond)
	client.watchHooksCh <- PlexdHookEvent{Type: "ADDED", Hook: hook}
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
}

func newTestHook() *PlexdHook {
	return &PlexdHook{
		Name:      "test-hook-1",
		Namespace: "plexd-system",
		UID:       "uid-hook-1",
		Spec: PlexdHookSpec{
			HookName: "dns-update",
			JobTemplate: &PlexdHookJobTemplate{
				Image:   "plexd/dns-hook:v1",
				Command: []string{"/usr/bin/dns-update"},
				Args:    []string{"--apply"},
			},
		},
	}
}

func TestPlexdHookController_Start_CreatesJobOnNewHook(t *testing.T) {
	watchCh := make(chan PlexdHookEvent, 1)
	client := &mockPlexdHookClient{watchHooksCh: watchCh}
	ctrl := NewPlexdHookController(client, Config{Enabled: true}, "plexd-system", "node-alpha", testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- ctrl.Start(ctx) }()

	time.Sleep(50 * time.Millisecond)

	hook := newTestHook()
	watchCh <- PlexdHookEvent{Type: "ADDED", Hook: hook}
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}

	if !client.createJobCalled {
		t.Fatal("expected CreateJob to be called")
	}

	job := client.lastCreatedJob
	if job.Name != "plexdhook-test-hook-1" {
		t.Fatalf("unexpected job name: %s", job.Name)
	}
	if job.NodeSelector["kubernetes.io/hostname"] != "node-alpha" {
		t.Fatalf("unexpected nodeSelector: %v", job.NodeSelector)
	}
	if len(job.OwnerReferences) != 1 {
		t.Fatalf("expected 1 ownerReference, got %d", len(job.OwnerReferences))
	}
	ref := job.OwnerReferences[0]
	if ref.Name != "test-hook-1" || ref.UID != "uid-hook-1" {
		t.Fatalf("unexpected ownerRef: %+v", ref)
	}
	if job.Labels["app.kubernetes.io/managed-by"] != "plexd" {
		t.Fatalf("unexpected labels: %v", job.Labels)
	}

	if !client.updateStatusCalled {
		t.Fatal("expected UpdatePlexdHookStatus to be called")
	}
	if client.lastStatusUpdate.Status.Phase != "Pending" {
		t.Fatalf("unexpected phase: %s", client.lastStatusUpdate.Status.Phase)
	}
	if client.lastStatusUpdate.Status.JobName != "plexdhook-test-hook-1" {
		t.Fatalf("unexpected jobName in status: %s", client.lastStatusUpdate.Status.JobName)
	}
}

func TestPlexdHookController_Start_SkipsAlreadyProcessedHook(t *testing.T) {
	watchCh := make(chan PlexdHookEvent, 1)
	client := &mockPlexdHookClient{watchHooksCh: watchCh}
	ctrl := NewPlexdHookController(client, Config{Enabled: true}, "plexd-system", "node-alpha", testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- ctrl.Start(ctx) }()

	time.Sleep(50 * time.Millisecond)

	hook := newTestHook()
	hook.Status.JobName = "plexdhook-test-hook-1" // Already processed.
	watchCh <- PlexdHookEvent{Type: "ADDED", Hook: hook}
	time.Sleep(50 * time.Millisecond)
	cancel()

	<-done

	if client.createJobCalled {
		t.Fatal("expected CreateJob NOT to be called for already-processed hook")
	}
}

func TestPlexdHookController_Start_HandlesCreateJobError(t *testing.T) {
	watchCh := make(chan PlexdHookEvent, 1)
	client := &mockPlexdHookClient{
		watchHooksCh: watchCh,
		createJobErr: errors.New("api error"),
	}
	ctrl := NewPlexdHookController(client, Config{Enabled: true}, "plexd-system", "node-alpha", testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- ctrl.Start(ctx) }()

	time.Sleep(50 * time.Millisecond)

	hook := newTestHook()
	watchCh <- PlexdHookEvent{Type: "ADDED", Hook: hook}
	time.Sleep(50 * time.Millisecond)
	cancel()

	<-done

	if !client.updateStatusCalled {
		t.Fatal("expected UpdatePlexdHookStatus to be called on error")
	}
	if client.lastStatusUpdate.Status.Phase != "Failed" {
		t.Fatalf("expected phase Failed, got %s", client.lastStatusUpdate.Status.Phase)
	}
	if !strings.Contains(client.lastStatusUpdate.Status.Message, "api error") {
		t.Fatalf("expected error message to contain 'api error', got %s", client.lastStatusUpdate.Status.Message)
	}
}

func TestPlexdHookController_Start_WatchError(t *testing.T) {
	client := &mockPlexdHookClient{
		watchHooksErr: errors.New("connection refused"),
	}
	ctrl := NewPlexdHookController(client, Config{Enabled: true}, "plexd-system", "node-alpha", testLogger())

	err := ctrl.Start(context.Background())
	if err == nil {
		t.Fatal("expected error on watch failure")
	}
	if !strings.Contains(err.Error(), "kubernetes: plexdhook: watch:") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestPlexdHookController_Stop_GracefulShutdown(t *testing.T) {
	client := &mockPlexdHookClient{}
	ctrl := NewPlexdHookController(client, Config{Enabled: true}, "plexd-system", "node-alpha", testLogger())

	ctx := context.Background()
	done := make(chan error, 1)
	go func() { done <- ctrl.Start(ctx) }()

	time.Sleep(50 * time.Millisecond)
	ctrl.Stop()

	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

func TestPlexdHookController_Start_ContextCancellation(t *testing.T) {
	client := &mockPlexdHookClient{}
	ctrl := NewPlexdHookController(client, Config{Enabled: true}, "plexd-system", "node-alpha", testLogger())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- ctrl.Start(ctx) }()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

func TestPlexdHookController_BuildJob_NodeSelector(t *testing.T) {
	client := &mockPlexdHookClient{}
	startAndSendHook(t, client, "worker-03", newTestHook())

	job := client.lastCreatedJob
	if job == nil {
		t.Fatal("expected job to be created")
	}
	if job.NodeSelector["kubernetes.io/hostname"] != "worker-03" {
		t.Fatalf("expected nodeSelector kubernetes.io/hostname=worker-03, got %v", job.NodeSelector)
	}
}

func TestPlexdHookController_BuildJob_OwnerReferences(t *testing.T) {
	client := &mockPlexdHookClient{}
	startAndSendHook(t, client, "node-alpha", newTestHook())

	job := client.lastCreatedJob
	if job == nil {
		t.Fatal("expected job to be created")
	}
	if len(job.OwnerReferences) != 1 {
		t.Fatalf("expected 1 ownerReference, got %d", len(job.OwnerReferences))
	}
	ref := job.OwnerReferences[0]
	if ref.APIVersion != "plexd.plexsphere.com/v1alpha1" {
		t.Fatalf("unexpected apiVersion: %s", ref.APIVersion)
	}
	if ref.Kind != "PlexdHook" {
		t.Fatalf("unexpected kind: %s", ref.Kind)
	}
	if ref.Name != "test-hook-1" {
		t.Fatalf("unexpected name: %s", ref.Name)
	}
	if ref.UID != "uid-hook-1" {
		t.Fatalf("unexpected uid: %s", ref.UID)
	}
	if !ref.Controller {
		t.Fatal("expected controller=true")
	}
	if !ref.BlockOwnerDeletion {
		t.Fatal("expected blockOwnerDeletion=true")
	}
}

func TestPlexdHookController_BuildJob_NonPrivileged(t *testing.T) {
	client := &mockPlexdHookClient{}
	hook := newTestHook()
	hook.Spec.Privileged = false
	startAndSendHook(t, client, "node-alpha", hook)

	job := client.lastCreatedJob
	if job == nil {
		t.Fatal("expected job to be created")
	}
	c := job.Containers[0]
	if c.Privileged {
		t.Fatal("expected Privileged=false for non-privileged hook")
	}
	if !c.ReadOnlyRootFS {
		t.Fatal("expected ReadOnlyRootFS=true for non-privileged hook")
	}
	if len(c.DropCapabilities) != 1 || c.DropCapabilities[0] != "ALL" {
		t.Fatalf("expected DropCapabilities=[ALL], got %v", c.DropCapabilities)
	}
}

func TestPlexdHookController_BuildJob_Privileged(t *testing.T) {
	client := &mockPlexdHookClient{}
	hook := newTestHook()
	hook.Spec.Privileged = true
	startAndSendHook(t, client, "node-alpha", hook)

	job := client.lastCreatedJob
	if job == nil {
		t.Fatal("expected job to be created")
	}
	c := job.Containers[0]
	if !c.Privileged {
		t.Fatal("expected Privileged=true for privileged hook")
	}
	if c.ReadOnlyRootFS {
		t.Fatal("expected ReadOnlyRootFS=false for privileged hook")
	}
	if len(c.DropCapabilities) != 0 {
		t.Fatalf("expected no DropCapabilities for privileged hook, got %v", c.DropCapabilities)
	}
}

func TestPlexdHookController_BuildJob_Parameters(t *testing.T) {
	client := &mockPlexdHookClient{}
	hook := newTestHook()
	hook.Spec.Parameters = []PlexdHookParam{
		{Name: "target", Value: "10.0.0.1"},
		{Name: "my-param", Value: "val"},
	}
	startAndSendHook(t, client, "node-alpha", hook)

	job := client.lastCreatedJob
	if job == nil {
		t.Fatal("expected job to be created")
	}
	env := job.Containers[0].Env
	if env["PLEXD_NODE_ID"] != "node-alpha" {
		t.Fatalf("expected PLEXD_NODE_ID=node-alpha, got %s", env["PLEXD_NODE_ID"])
	}
	if env["PLEXD_HOOK_NAME"] != "dns-update" {
		t.Fatalf("expected PLEXD_HOOK_NAME=dns-update, got %s", env["PLEXD_HOOK_NAME"])
	}
	if env["PLEXD_PARAM_TARGET"] != "10.0.0.1" {
		t.Fatalf("expected PLEXD_PARAM_TARGET=10.0.0.1, got %s", env["PLEXD_PARAM_TARGET"])
	}
	if env["PLEXD_PARAM_MY_PARAM"] != "val" {
		t.Fatalf("expected PLEXD_PARAM_MY_PARAM=val, got %s", env["PLEXD_PARAM_MY_PARAM"])
	}
}

func TestPlexdHookController_BuildJob_ServiceAccount(t *testing.T) {
	client := &mockPlexdHookClient{}
	startAndSendHook(t, client, "node-alpha", newTestHook())

	job := client.lastCreatedJob
	if job == nil {
		t.Fatal("expected job to be created")
	}
	if job.ServiceAccountName != "plexd" {
		t.Fatalf("expected serviceAccountName=plexd, got %s", job.ServiceAccountName)
	}
}

func TestPlexdHookController_BuildJob_RestartPolicyNever(t *testing.T) {
	client := &mockPlexdHookClient{}
	startAndSendHook(t, client, "node-alpha", newTestHook())

	job := client.lastCreatedJob
	if job == nil {
		t.Fatal("expected job to be created")
	}
	if job.RestartPolicy != "Never" {
		t.Fatalf("expected restartPolicy=Never, got %s", job.RestartPolicy)
	}
}

func TestPlexdHookController_BuildJob_DefaultJobTemplate(t *testing.T) {
	client := &mockPlexdHookClient{}
	hook := newTestHook()
	hook.Spec.JobTemplate = nil // No job template.
	startAndSendHook(t, client, "node-alpha", hook)

	job := client.lastCreatedJob
	if job == nil {
		t.Fatal("expected job to be created")
	}
	if job.Containers[0].Image != defaultHookImage {
		t.Fatalf("expected default image %s, got %s", defaultHookImage, job.Containers[0].Image)
	}
}

func TestPlexdHookController_HandleAlreadyExistsJob(t *testing.T) {
	client := &mockPlexdHookClient{createJobErr: ErrAlreadyExists}
	startAndSendHook(t, client, "node-alpha", newTestHook())

	if !client.updateStatusCalled {
		t.Fatal("expected UpdatePlexdHookStatus to be called")
	}
	if client.lastStatusUpdate.Status.Phase != "Pending" {
		t.Fatalf("expected phase Pending, got %s", client.lastStatusUpdate.Status.Phase)
	}
	if client.lastStatusUpdate.Status.JobName != "plexdhook-test-hook-1" {
		t.Fatalf("expected jobName plexdhook-test-hook-1, got %s", client.lastStatusUpdate.Status.JobName)
	}
}

func TestPlexdHookController_BuildJob_Labels(t *testing.T) {
	client := &mockPlexdHookClient{}
	startAndSendHook(t, client, "node-alpha", newTestHook())

	job := client.lastCreatedJob
	if job == nil {
		t.Fatal("expected job to be created")
	}
	if job.Labels["app.kubernetes.io/managed-by"] != "plexd" {
		t.Fatalf("unexpected managed-by label: %s", job.Labels["app.kubernetes.io/managed-by"])
	}
	if job.Labels["plexd.plexsphere.com/hook-name"] != "dns-update" {
		t.Fatalf("unexpected hook-name label: %s", job.Labels["plexd.plexsphere.com/hook-name"])
	}
}

func TestPlexdHookController_Start_WatchChannelClosed(t *testing.T) {
	watchCh := make(chan PlexdHookEvent)
	client := &mockPlexdHookClient{watchHooksCh: watchCh}
	ctrl := NewPlexdHookController(client, Config{Enabled: true}, "plexd-system", "node-alpha", testLogger())

	done := make(chan error, 1)
	go func() { done <- ctrl.Start(context.Background()) }()

	time.Sleep(50 * time.Millisecond)
	close(watchCh)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected nil error on closed channel, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after watch channel closed")
	}
}
