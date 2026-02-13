package kubernetes

import (
	"context"
	"errors"
	"testing"
	"time"
)

type mockKubeClient struct {
	getResult *PlexdNodeState
	getErr    error
	createErr error
	updateErr error
	deleteErr error

	watchCh  chan PlexdNodeStateEvent
	watchErr error

	createSecretErr error
	updateSecretErr error
	deleteSecretErr error

	createCalled       bool
	updateCalled       bool
	lastCreated        *PlexdNodeState
	lastUpdated        *PlexdNodeState
	createdSecrets     []*KubeSecret
	deletedSecrets     []string
}

func (m *mockKubeClient) GetNodeState(_ context.Context, _, _ string) (*PlexdNodeState, error) {
	return m.getResult, m.getErr
}

func (m *mockKubeClient) CreateNodeState(_ context.Context, state *PlexdNodeState) error {
	m.createCalled = true
	m.lastCreated = state
	return m.createErr
}

func (m *mockKubeClient) UpdateNodeState(_ context.Context, state *PlexdNodeState) error {
	m.updateCalled = true
	m.lastUpdated = state
	return m.updateErr
}

func (m *mockKubeClient) DeleteNodeState(_ context.Context, _, _ string) error {
	return m.deleteErr
}

func (m *mockKubeClient) WatchNodeState(_ context.Context, _, _ string) (<-chan PlexdNodeStateEvent, error) {
	if m.watchErr != nil {
		return nil, m.watchErr
	}
	if m.watchCh == nil {
		m.watchCh = make(chan PlexdNodeStateEvent)
	}
	return m.watchCh, nil
}

func (m *mockKubeClient) CreateSecret(_ context.Context, secret *KubeSecret) error {
	m.createdSecrets = append(m.createdSecrets, secret)
	return m.createSecretErr
}

func (m *mockKubeClient) UpdateSecret(_ context.Context, _ *KubeSecret) error {
	return m.updateSecretErr
}

func (m *mockKubeClient) DeleteSecret(_ context.Context, _, name string) error {
	m.deletedSecrets = append(m.deletedSecrets, name)
	return m.deleteSecretErr
}

type mockReportNotifier struct {
	called int
}

func (m *mockReportNotifier) NotifyChange() {
	m.called++
}


func TestCRDController_Start_CreatesResource(t *testing.T) {
	client := &mockKubeClient{
		getErr: ErrNotFound,
	}
	ctrl := NewCRDController(client, Config{Enabled: true}, "node1", "10.0.0.1", "plexd-system", nil, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- ctrl.Start(ctx) }()

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

	if !client.createCalled {
		t.Fatal("expected CreateNodeState to be called")
	}
	if client.lastCreated.Name != "node-node1" {
		t.Fatalf("unexpected resource name: %s", client.lastCreated.Name)
	}
	if client.lastCreated.Spec.NodeID != "node1" {
		t.Fatalf("unexpected nodeID: %s", client.lastCreated.Spec.NodeID)
	}
	if client.lastCreated.Spec.MeshIP != "10.0.0.1" {
		t.Fatalf("unexpected meshIP: %s", client.lastCreated.Spec.MeshIP)
	}
	if client.lastCreated.Labels["plexd.plexsphere.com/node-id"] != "node1" {
		t.Fatalf("unexpected label: %v", client.lastCreated.Labels)
	}
}

func TestCRDController_Start_UpdatesExistingResource(t *testing.T) {
	existing := &PlexdNodeState{
		Name:      "node-node1",
		Namespace: "plexd-system",
		UID:       "uid-existing",
		Spec: PlexdNodeStateSpec{
			NodeID: "old-node",
			MeshIP: "10.0.0.99",
		},
	}
	client := &mockKubeClient{
		getResult: existing,
	}
	ctrl := NewCRDController(client, Config{Enabled: true}, "node1", "10.0.0.1", "plexd-system", nil, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- ctrl.Start(ctx) }()

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

	if client.createCalled {
		t.Fatal("expected CreateNodeState not to be called")
	}
	if !client.updateCalled {
		t.Fatal("expected UpdateNodeState to be called")
	}
	if client.lastUpdated.Spec.NodeID != "node1" {
		t.Fatalf("unexpected nodeID in update: %s", client.lastUpdated.Spec.NodeID)
	}
	if client.lastUpdated.Spec.MeshIP != "10.0.0.1" {
		t.Fatalf("unexpected meshIP in update: %s", client.lastUpdated.Spec.MeshIP)
	}
}

func TestCRDController_UpdateMetadata(t *testing.T) {
	existing := &PlexdNodeState{
		Name:      "node-node1",
		Namespace: "plexd-system",
		Spec: PlexdNodeStateSpec{
			NodeID: "node1",
		},
	}
	client := &mockKubeClient{
		getResult: existing,
	}
	ctrl := NewCRDController(client, Config{Enabled: true}, "node1", "10.0.0.1", "plexd-system", nil, testLogger())

	meta := map[string]string{"region": "us-east-1", "zone": "a"}
	if err := ctrl.UpdateMetadata(context.Background(), meta); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !client.updateCalled {
		t.Fatal("expected UpdateNodeState to be called")
	}
	if client.lastUpdated.Spec.Metadata["region"] != "us-east-1" {
		t.Fatalf("unexpected metadata: %v", client.lastUpdated.Spec.Metadata)
	}
}

func TestCRDController_UpdateData(t *testing.T) {
	existing := &PlexdNodeState{
		Name:      "node-node1",
		Namespace: "plexd-system",
		Spec: PlexdNodeStateSpec{
			NodeID: "node1",
		},
	}
	client := &mockKubeClient{
		getResult: existing,
	}
	ctrl := NewCRDController(client, Config{Enabled: true}, "node1", "10.0.0.1", "plexd-system", nil, testLogger())

	data := []DataEntry{
		{Key: "config", ContentType: "application/json", Version: 1},
	}
	if err := ctrl.UpdateData(context.Background(), data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !client.updateCalled {
		t.Fatal("expected UpdateNodeState to be called")
	}
	if len(client.lastUpdated.Spec.Data) != 1 || client.lastUpdated.Spec.Data[0].Key != "config" {
		t.Fatalf("unexpected data: %+v", client.lastUpdated.Spec.Data)
	}
}

func TestCRDController_UpdateSecretIndex_CreatesSecrets(t *testing.T) {
	existing := &PlexdNodeState{
		Name:      "node-node1",
		Namespace: "plexd-system",
		UID:       "uid-123",
		Spec: PlexdNodeStateSpec{
			NodeID: "node1",
		},
	}
	client := &mockKubeClient{
		getResult: existing,
	}
	ctrl := NewCRDController(client, Config{Enabled: true}, "node1", "10.0.0.1", "plexd-system", nil, testLogger())

	refs := []SecretRef{
		{Key: "tls-cert", Version: 1},
		{Key: "api-key", Version: 1},
	}
	secretData := map[string][]byte{
		"tls-cert": []byte("encrypted-cert"),
		"api-key":  []byte("encrypted-key"),
	}

	if err := ctrl.UpdateSecretIndex(context.Background(), refs, secretData); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(client.createdSecrets) != 2 {
		t.Fatalf("expected 2 secrets created, got %d", len(client.createdSecrets))
	}

	// Verify ownerReferences.
	for _, s := range client.createdSecrets {
		if s.OwnerRefName != "node-node1" {
			t.Errorf("secret %s: ownerRefName = %q, want %q", s.Name, s.OwnerRefName, "node-node1")
		}
		if s.OwnerRefUID != "uid-123" {
			t.Errorf("secret %s: ownerRefUID = %q, want %q", s.Name, s.OwnerRefUID, "uid-123")
		}
	}

	// Verify CRD spec updated with secretRefs.
	if !client.updateCalled {
		t.Fatal("expected UpdateNodeState to be called")
	}
	if len(client.lastUpdated.Spec.SecretRefs) != 2 {
		t.Fatalf("expected 2 secretRefs, got %d", len(client.lastUpdated.Spec.SecretRefs))
	}
}

func TestCRDController_UpdateSecretIndex_DeletesRemovedSecrets(t *testing.T) {
	existing := &PlexdNodeState{
		Name:      "node-node1",
		Namespace: "plexd-system",
		UID:       "uid-123",
		Spec: PlexdNodeStateSpec{
			NodeID: "node1",
		},
	}
	client := &mockKubeClient{
		getResult: existing,
	}
	ctrl := NewCRDController(client, Config{Enabled: true}, "node1", "10.0.0.1", "plexd-system", nil, testLogger())

	// First, create two secrets.
	refs1 := []SecretRef{
		{Key: "tls-cert", Version: 1},
		{Key: "api-key", Version: 1},
	}
	secretData := map[string][]byte{
		"tls-cert": []byte("cert"),
		"api-key":  []byte("key"),
	}
	if err := ctrl.UpdateSecretIndex(context.Background(), refs1, secretData); err != nil {
		t.Fatalf("first update: %v", err)
	}

	// Now update with only one ref — the other should be deleted.
	refs2 := []SecretRef{
		{Key: "tls-cert", Version: 2},
	}
	secretData2 := map[string][]byte{
		"tls-cert": []byte("cert-v2"),
	}
	if err := ctrl.UpdateSecretIndex(context.Background(), refs2, secretData2); err != nil {
		t.Fatalf("second update: %v", err)
	}

	if len(client.deletedSecrets) != 1 {
		t.Fatalf("expected 1 secret deleted, got %d: %v", len(client.deletedSecrets), client.deletedSecrets)
	}
	if client.deletedSecrets[0] != "plexd-secret-node1-api-key" {
		t.Fatalf("expected deleted secret plexd-secret-node1-api-key, got %s", client.deletedSecrets[0])
	}
}

func TestCRDController_StatusWatch_DetectsReportChange(t *testing.T) {
	existing := &PlexdNodeState{
		Name:      "node-node1",
		Namespace: "plexd-system",
		Spec:      PlexdNodeStateSpec{NodeID: "node1"},
	}
	watchCh := make(chan PlexdNodeStateEvent, 1)
	client := &mockKubeClient{
		getResult: existing,
		watchCh:   watchCh,
	}
	notifier := &mockReportNotifier{}
	ctrl := NewCRDController(client, Config{Enabled: true}, "node1", "10.0.0.1", "plexd-system", notifier, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- ctrl.Start(ctx) }()

	// Wait for watcher to start.
	time.Sleep(50 * time.Millisecond)

	// Send a status change event.
	watchCh <- PlexdNodeStateEvent{
		Type: "MODIFIED",
		State: &PlexdNodeState{
			Name: "node-node1",
			Status: PlexdNodeStateStatus{
				Report: []DataEntry{
					{Key: "health", Version: 1},
				},
			},
		},
	}

	time.Sleep(50 * time.Millisecond)
	cancel()

	<-done

	if notifier.called != 1 {
		t.Fatalf("expected NotifyChange called once, got %d", notifier.called)
	}
}

func TestCRDController_Stop_GracefulShutdown(t *testing.T) {
	existing := &PlexdNodeState{
		Name:      "node-node1",
		Namespace: "plexd-system",
		Spec:      PlexdNodeStateSpec{NodeID: "node1"},
	}
	client := &mockKubeClient{
		getResult: existing,
	}
	ctrl := NewCRDController(client, Config{Enabled: true}, "node1", "10.0.0.1", "plexd-system", nil, testLogger())

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

func TestCRDController_Start_GetError(t *testing.T) {
	client := &mockKubeClient{
		getErr: errors.New("connection refused"),
	}
	ctrl := NewCRDController(client, Config{Enabled: true}, "node1", "10.0.0.1", "plexd-system", nil, testLogger())

	err := ctrl.Start(context.Background())
	if err == nil {
		t.Fatal("expected error on get failure")
	}
}

func TestCRDController_Start_UpdateError(t *testing.T) {
	existing := &PlexdNodeState{
		Name:      "node-node1",
		Namespace: "plexd-system",
		Spec:      PlexdNodeStateSpec{NodeID: "node1"},
	}
	client := &mockKubeClient{
		getResult: existing,
		updateErr: errors.New("update denied"),
	}
	ctrl := NewCRDController(client, Config{Enabled: true}, "node1", "10.0.0.1", "plexd-system", nil, testLogger())

	err := ctrl.Start(context.Background())
	if err == nil {
		t.Fatal("expected error on update failure")
	}
}

func TestCRDController_UpdateMetadata_GetError(t *testing.T) {
	client := &mockKubeClient{
		getErr: errors.New("api unavailable"),
	}
	ctrl := NewCRDController(client, Config{Enabled: true}, "node1", "10.0.0.1", "plexd-system", nil, testLogger())

	err := ctrl.UpdateMetadata(context.Background(), map[string]string{"k": "v"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCRDController_UpdateData_UpdateError(t *testing.T) {
	existing := &PlexdNodeState{
		Name:      "node-node1",
		Namespace: "plexd-system",
		Spec:      PlexdNodeStateSpec{NodeID: "node1"},
	}
	client := &mockKubeClient{
		getResult: existing,
		updateErr: errors.New("conflict"),
	}
	ctrl := NewCRDController(client, Config{Enabled: true}, "node1", "10.0.0.1", "plexd-system", nil, testLogger())

	err := ctrl.UpdateData(context.Background(), []DataEntry{{Key: "k"}})
	if err == nil {
		t.Fatal("expected error on update failure")
	}
}

func TestNewCRDController_ResourceName(t *testing.T) {
	client := &mockKubeClient{}
	ctrl := NewCRDController(client, Config{Enabled: true}, "abc123", "10.0.0.1", "plexd-system", nil, testLogger())

	if ctrl.resourceName != "node-abc123" {
		t.Fatalf("unexpected resourceName: %s", ctrl.resourceName)
	}
}

func TestCRDController_StatusWatch_IgnoresDuplicateReport(t *testing.T) {
	existing := &PlexdNodeState{
		Name:      "node-node1",
		Namespace: "plexd-system",
		Spec:      PlexdNodeStateSpec{NodeID: "node1"},
	}
	watchCh := make(chan PlexdNodeStateEvent, 2)
	client := &mockKubeClient{
		getResult: existing,
		watchCh:   watchCh,
	}
	notifier := &mockReportNotifier{}
	ctrl := NewCRDController(client, Config{Enabled: true}, "node1", "10.0.0.1", "plexd-system", notifier, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- ctrl.Start(ctx) }()

	time.Sleep(50 * time.Millisecond)

	report := []DataEntry{{Key: "health", Version: 1}}
	watchCh <- PlexdNodeStateEvent{
		Type:  "MODIFIED",
		State: &PlexdNodeState{Name: "node-node1", Status: PlexdNodeStateStatus{Report: report}},
	}
	time.Sleep(20 * time.Millisecond)

	// Same report again — should not trigger notifier.
	watchCh <- PlexdNodeStateEvent{
		Type:  "MODIFIED",
		State: &PlexdNodeState{Name: "node-node1", Status: PlexdNodeStateStatus{Report: report}},
	}
	time.Sleep(20 * time.Millisecond)

	cancel()
	<-done

	if notifier.called != 1 {
		t.Fatalf("expected NotifyChange called once (duplicate ignored), got %d", notifier.called)
	}
}
