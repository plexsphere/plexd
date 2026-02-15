package kubernetes

import (
	"encoding/json"
	"testing"
	"time"
)

func TestPlexdHook_JSONRoundTrip(t *testing.T) {
	started := time.Date(2025, 7, 1, 10, 0, 0, 0, time.UTC)
	completed := time.Date(2025, 7, 1, 10, 5, 0, 0, time.UTC)

	hook := PlexdHook{
		Name:            "hook-abc123",
		Namespace:       "plexd-system",
		UID:             "uid-1",
		ResourceVersion: "42",
		Labels:          map[string]string{"plexd.plexsphere.com/hook": "dns-check"},
		Spec: PlexdHookSpec{
			HookName: "dns-check",
			JobTemplate: &PlexdHookJobTemplate{
				Image:   "busybox:latest",
				Command: []string{"/bin/sh"},
				Args:    []string{"-c", "nslookup example.com"},
			},
			Parameters: []PlexdHookParam{
				{Name: "target", Value: "example.com"},
			},
			Privileged: true,
		},
		Status: PlexdHookStatus{
			JobName:     "hook-abc123-job",
			Phase:       "Succeeded",
			Message:     "completed successfully",
			StartedAt:   &started,
			CompletedAt: &completed,
		},
	}

	data, err := json.Marshal(hook)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	var got PlexdHook
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if got.Name != hook.Name {
		t.Errorf("Name = %q, want %q", got.Name, hook.Name)
	}
	if got.Namespace != hook.Namespace {
		t.Errorf("Namespace = %q, want %q", got.Namespace, hook.Namespace)
	}
	if got.UID != hook.UID {
		t.Errorf("UID = %q, want %q", got.UID, hook.UID)
	}
	if got.ResourceVersion != hook.ResourceVersion {
		t.Errorf("ResourceVersion = %q, want %q", got.ResourceVersion, hook.ResourceVersion)
	}
	if got.Labels["plexd.plexsphere.com/hook"] != "dns-check" {
		t.Errorf("Labels[plexd.plexsphere.com/hook] = %q, want %q", got.Labels["plexd.plexsphere.com/hook"], "dns-check")
	}
	if got.Spec.HookName != hook.Spec.HookName {
		t.Errorf("Spec.HookName = %q, want %q", got.Spec.HookName, hook.Spec.HookName)
	}
	if got.Spec.JobTemplate == nil {
		t.Fatalf("Spec.JobTemplate = nil, want non-nil")
	}
	if got.Spec.JobTemplate.Image != "busybox:latest" {
		t.Errorf("Spec.JobTemplate.Image = %q, want %q", got.Spec.JobTemplate.Image, "busybox:latest")
	}
	if len(got.Spec.JobTemplate.Command) != 1 || got.Spec.JobTemplate.Command[0] != "/bin/sh" {
		t.Errorf("Spec.JobTemplate.Command = %v, want [/bin/sh]", got.Spec.JobTemplate.Command)
	}
	if len(got.Spec.JobTemplate.Args) != 2 || got.Spec.JobTemplate.Args[1] != "nslookup example.com" {
		t.Errorf("Spec.JobTemplate.Args = %v, want [-c nslookup example.com]", got.Spec.JobTemplate.Args)
	}
	if len(got.Spec.Parameters) != 1 || got.Spec.Parameters[0].Name != "target" {
		t.Errorf("Spec.Parameters unexpected: %+v", got.Spec.Parameters)
	}
	if !got.Spec.Privileged {
		t.Errorf("Spec.Privileged = false, want true")
	}
	if got.Status.JobName != hook.Status.JobName {
		t.Errorf("Status.JobName = %q, want %q", got.Status.JobName, hook.Status.JobName)
	}
	if got.Status.Phase != hook.Status.Phase {
		t.Errorf("Status.Phase = %q, want %q", got.Status.Phase, hook.Status.Phase)
	}
	if got.Status.Message != hook.Status.Message {
		t.Errorf("Status.Message = %q, want %q", got.Status.Message, hook.Status.Message)
	}
	if got.Status.StartedAt == nil || !got.Status.StartedAt.Equal(started) {
		t.Errorf("Status.StartedAt = %v, want %v", got.Status.StartedAt, started)
	}
	if got.Status.CompletedAt == nil || !got.Status.CompletedAt.Equal(completed) {
		t.Errorf("Status.CompletedAt = %v, want %v", got.Status.CompletedAt, completed)
	}
}

func TestPlexdHook_JSONOmitsEmptyOptionals(t *testing.T) {
	hook := PlexdHook{
		Name:      "hook-minimal",
		Namespace: "default",
		Spec: PlexdHookSpec{
			HookName: "minimal-hook",
		},
	}

	data, err := json.Marshal(hook)
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

	// Check spec-level optional fields are omitted.
	var specRaw map[string]json.RawMessage
	if err := json.Unmarshal(raw["spec"], &specRaw); err != nil {
		t.Fatalf("Unmarshal spec to map error: %v", err)
	}

	for _, key := range []string{"jobTemplate", "parameters", "privileged"} {
		if _, ok := specRaw[key]; ok {
			t.Errorf("expected spec field %q to be omitted for zero value, but it was present", key)
		}
	}
}

func TestPlexdHook_StatusJSONRoundTrip(t *testing.T) {
	started := time.Date(2025, 7, 1, 9, 0, 0, 0, time.UTC)
	completed := time.Date(2025, 7, 1, 9, 30, 0, 0, time.UTC)

	status := PlexdHookStatus{
		JobName:     "hook-xyz-job",
		Phase:       "Failed",
		Message:     "container exited with code 1",
		StartedAt:   &started,
		CompletedAt: &completed,
	}

	data, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	var got PlexdHookStatus
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if got.JobName != status.JobName {
		t.Errorf("JobName = %q, want %q", got.JobName, status.JobName)
	}
	if got.Phase != status.Phase {
		t.Errorf("Phase = %q, want %q", got.Phase, status.Phase)
	}
	if got.Message != status.Message {
		t.Errorf("Message = %q, want %q", got.Message, status.Message)
	}
	if got.StartedAt == nil || !got.StartedAt.Equal(started) {
		t.Errorf("StartedAt = %v, want %v", got.StartedAt, started)
	}
	if got.CompletedAt == nil || !got.CompletedAt.Equal(completed) {
		t.Errorf("CompletedAt = %v, want %v", got.CompletedAt, completed)
	}
}

func TestPlexdHookJobSpec_JSONFieldNames(t *testing.T) {
	jt := PlexdHookJobTemplate{
		Image:   "alpine:3.18",
		Command: []string{"echo"},
		Args:    []string{"hello"},
	}

	data, err := json.Marshal(jt)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal to map error: %v", err)
	}

	for _, key := range []string{"image", "command", "args"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing JSON field %q", key)
		}
	}
}

func TestPlexdHookParam_JSONRoundTrip(t *testing.T) {
	param := PlexdHookParam{
		Name:  "timeout",
		Value: "30s",
	}

	data, err := json.Marshal(param)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	var got PlexdHookParam
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if got.Name != param.Name {
		t.Errorf("Name = %q, want %q", got.Name, param.Name)
	}
	if got.Value != param.Value {
		t.Errorf("Value = %q, want %q", got.Value, param.Value)
	}
}

func TestPlexdHookEvent_JSONRoundTrip(t *testing.T) {
	hook := &PlexdHook{
		Name:      "hook-evt",
		Namespace: "plexd-system",
		Spec: PlexdHookSpec{
			HookName: "network-check",
		},
	}

	event := PlexdHookEvent{
		Type: "ADDED",
		Hook: hook,
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	var got PlexdHookEvent
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	if got.Type != event.Type {
		t.Errorf("Type = %q, want %q", got.Type, event.Type)
	}
	if got.Hook == nil {
		t.Fatalf("Hook = nil, want non-nil")
	}
	if got.Hook.Name != hook.Name {
		t.Errorf("Hook.Name = %q, want %q", got.Hook.Name, hook.Name)
	}
	if got.Hook.Namespace != hook.Namespace {
		t.Errorf("Hook.Namespace = %q, want %q", got.Hook.Namespace, hook.Namespace)
	}
	if got.Hook.Spec.HookName != hook.Spec.HookName {
		t.Errorf("Hook.Spec.HookName = %q, want %q", got.Hook.Spec.HookName, hook.Spec.HookName)
	}
}
