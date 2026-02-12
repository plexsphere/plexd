package nodeapi

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/plexsphere/plexd/internal/api"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestStateCache_InitiallyEmpty(t *testing.T) {
	dir := t.TempDir()
	sc := NewStateCache(dir, discardLogger())

	m := sc.GetMetadata()
	if len(m) != 0 {
		t.Errorf("GetMetadata() = %v, want empty map", m)
	}
	d := sc.GetData()
	if len(d) != 0 {
		t.Errorf("GetData() = %v, want empty map", d)
	}
	s := sc.GetSecretIndex()
	if len(s) != 0 {
		t.Errorf("GetSecretIndex() = %v, want empty slice", s)
	}
	r := sc.GetReports()
	if len(r) != 0 {
		t.Errorf("GetReports() = %v, want empty map", r)
	}
}

func TestStateCache_UpdateMetadata(t *testing.T) {
	dir := t.TempDir()
	sc := NewStateCache(dir, discardLogger())
	if err := sc.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	meta := map[string]string{"role": "worker", "region": "us-east"}
	sc.UpdateMetadata(meta)

	got := sc.GetMetadata()
	if got["role"] != "worker" {
		t.Errorf("role = %q, want %q", got["role"], "worker")
	}
	if got["region"] != "us-east" {
		t.Errorf("region = %q, want %q", got["region"], "us-east")
	}

	// Verify mutation isolation: changing the input should not affect cached data.
	meta["role"] = "changed"
	got2 := sc.GetMetadata()
	if got2["role"] != "worker" {
		t.Errorf("after mutation, role = %q, want %q", got2["role"], "worker")
	}

	// Verify returned map is a copy.
	got["role"] = "mutated"
	got3 := sc.GetMetadata()
	if got3["role"] != "worker" {
		t.Errorf("after return mutation, role = %q, want %q", got3["role"], "worker")
	}

	// Verify GetMetadataKey.
	val, ok := sc.GetMetadataKey("role")
	if !ok || val != "worker" {
		t.Errorf("GetMetadataKey(role) = (%q, %v), want (%q, true)", val, ok, "worker")
	}
	_, ok = sc.GetMetadataKey("nonexistent")
	if ok {
		t.Error("GetMetadataKey(nonexistent) = true, want false")
	}

	// Verify file persistence.
	data, err := os.ReadFile(filepath.Join(dir, "state", "metadata.json"))
	if err != nil {
		t.Fatalf("read metadata.json: %v", err)
	}
	var fileMeta map[string]string
	if err := json.Unmarshal(data, &fileMeta); err != nil {
		t.Fatalf("unmarshal metadata.json: %v", err)
	}
	if fileMeta["role"] != "worker" {
		t.Errorf("file role = %q, want %q", fileMeta["role"], "worker")
	}
}

func TestStateCache_UpdateData(t *testing.T) {
	dir := t.TempDir()
	sc := NewStateCache(dir, discardLogger())
	if err := sc.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	now := time.Now().Truncate(time.Second)
	entries := []api.DataEntry{
		{Key: "config-a", ContentType: "application/json", Payload: json.RawMessage(`{"x":1}`), Version: 1, UpdatedAt: now},
		{Key: "config-b", ContentType: "text/plain", Payload: json.RawMessage(`"hello"`), Version: 2, UpdatedAt: now},
	}
	sc.UpdateData(entries)

	got := sc.GetData()
	if len(got) != 2 {
		t.Fatalf("GetData() len = %d, want 2", len(got))
	}
	if got["config-a"].Version != 1 {
		t.Errorf("config-a version = %d, want 1", got["config-a"].Version)
	}
	if got["config-b"].ContentType != "text/plain" {
		t.Errorf("config-b content_type = %q, want %q", got["config-b"].ContentType, "text/plain")
	}

	// Verify GetDataEntry.
	entry, ok := sc.GetDataEntry("config-a")
	if !ok {
		t.Fatal("GetDataEntry(config-a) not found")
	}
	if entry.Key != "config-a" {
		t.Errorf("entry.Key = %q, want %q", entry.Key, "config-a")
	}
	_, ok = sc.GetDataEntry("nonexistent")
	if ok {
		t.Error("GetDataEntry(nonexistent) = true, want false")
	}

	// Verify file persistence.
	dataDir := filepath.Join(dir, "state", "data")
	for _, key := range []string{"config-a", "config-b"} {
		fpath := filepath.Join(dataDir, key+".json")
		raw, err := os.ReadFile(fpath)
		if err != nil {
			t.Fatalf("read %s: %v", fpath, err)
		}
		var de api.DataEntry
		if err := json.Unmarshal(raw, &de); err != nil {
			t.Fatalf("unmarshal %s: %v", fpath, err)
		}
		if de.Key != key {
			t.Errorf("file entry key = %q, want %q", de.Key, key)
		}
	}

	// Update with fewer entries: old files should be removed.
	sc.UpdateData([]api.DataEntry{entries[0]})
	if _, err := os.Stat(filepath.Join(dataDir, "config-b.json")); !os.IsNotExist(err) {
		t.Error("config-b.json should have been removed")
	}
	got2 := sc.GetData()
	if len(got2) != 1 {
		t.Errorf("GetData() after update len = %d, want 1", len(got2))
	}
}

func TestStateCache_UpdateSecretIndex(t *testing.T) {
	dir := t.TempDir()
	sc := NewStateCache(dir, discardLogger())
	if err := sc.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	refs := []api.SecretRef{
		{Key: "db-password", Version: 1},
		{Key: "api-token", Version: 3},
	}
	sc.UpdateSecretIndex(refs)

	got := sc.GetSecretIndex()
	if len(got) != 2 {
		t.Fatalf("GetSecretIndex() len = %d, want 2", len(got))
	}
	if got[0].Key != "db-password" || got[0].Version != 1 {
		t.Errorf("got[0] = %+v, want {db-password 1}", got[0])
	}

	// Verify mutation isolation.
	got[0].Key = "mutated"
	got2 := sc.GetSecretIndex()
	if got2[0].Key != "db-password" {
		t.Errorf("after mutation, got[0].Key = %q, want %q", got2[0].Key, "db-password")
	}

	// Verify file persistence.
	data, err := os.ReadFile(filepath.Join(dir, "state", "secrets.json"))
	if err != nil {
		t.Fatalf("read secrets.json: %v", err)
	}
	var fileRefs []api.SecretRef
	if err := json.Unmarshal(data, &fileRefs); err != nil {
		t.Fatalf("unmarshal secrets.json: %v", err)
	}
	if len(fileRefs) != 2 {
		t.Errorf("file refs len = %d, want 2", len(fileRefs))
	}
}

func TestStateCache_LoadFromDisk(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")

	// Create directory tree.
	if err := os.MkdirAll(filepath.Join(stateDir, "data"), 0700); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(stateDir, "report"), 0700); err != nil {
		t.Fatalf("mkdir report: %v", err)
	}

	// Write metadata.json.
	metaJSON, _ := json.Marshal(map[string]string{"env": "prod"})
	if err := os.WriteFile(filepath.Join(stateDir, "metadata.json"), metaJSON, 0600); err != nil {
		t.Fatalf("write metadata.json: %v", err)
	}

	// Write secrets.json.
	secretsJSON, _ := json.Marshal([]api.SecretRef{{Key: "s1", Version: 2}})
	if err := os.WriteFile(filepath.Join(stateDir, "secrets.json"), secretsJSON, 0600); err != nil {
		t.Fatalf("write secrets.json: %v", err)
	}

	// Write a data entry.
	now := time.Now().Truncate(time.Second)
	de := api.DataEntry{Key: "mydata", ContentType: "text/plain", Payload: json.RawMessage(`"val"`), Version: 5, UpdatedAt: now}
	deJSON, _ := json.Marshal(de)
	if err := os.WriteFile(filepath.Join(stateDir, "data", "mydata.json"), deJSON, 0600); err != nil {
		t.Fatalf("write data entry: %v", err)
	}

	// Write a report entry.
	re := ReportEntry{Key: "health", ContentType: "application/json", Payload: json.RawMessage(`{"ok":true}`), Version: 3, UpdatedAt: now}
	reJSON, _ := json.Marshal(re)
	if err := os.WriteFile(filepath.Join(stateDir, "report", "health.json"), reJSON, 0600); err != nil {
		t.Fatalf("write report entry: %v", err)
	}

	// Load into a fresh cache.
	sc := NewStateCache(dir, discardLogger())
	if err := sc.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Verify metadata.
	meta := sc.GetMetadata()
	if meta["env"] != "prod" {
		t.Errorf("metadata env = %q, want %q", meta["env"], "prod")
	}

	// Verify secret index.
	secrets := sc.GetSecretIndex()
	if len(secrets) != 1 || secrets[0].Key != "s1" {
		t.Errorf("secrets = %+v, want [{s1 2}]", secrets)
	}

	// Verify data.
	data := sc.GetData()
	if len(data) != 1 {
		t.Fatalf("data len = %d, want 1", len(data))
	}
	if data["mydata"].Version != 5 {
		t.Errorf("data mydata version = %d, want 5", data["mydata"].Version)
	}

	// Verify report.
	reports := sc.GetReports()
	if len(reports) != 1 {
		t.Fatalf("reports len = %d, want 1", len(reports))
	}
	if reports["health"].Version != 3 {
		t.Errorf("report health version = %d, want 3", reports["health"].Version)
	}
}

func TestStateCache_ReportCRUD(t *testing.T) {
	dir := t.TempDir()
	sc := NewStateCache(dir, discardLogger())
	if err := sc.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Create a report.
	payload := json.RawMessage(`{"status":"ok"}`)
	r, err := sc.PutReport("health", "application/json", payload, nil)
	if err != nil {
		t.Fatalf("PutReport (create): %v", err)
	}
	if r.Version != 1 {
		t.Errorf("version = %d, want 1", r.Version)
	}
	if r.Key != "health" {
		t.Errorf("key = %q, want %q", r.Key, "health")
	}
	if r.ContentType != "application/json" {
		t.Errorf("content_type = %q, want %q", r.ContentType, "application/json")
	}

	// Read back.
	got, ok := sc.GetReport("health")
	if !ok {
		t.Fatal("GetReport(health) not found")
	}
	if got.Version != 1 {
		t.Errorf("got version = %d, want 1", got.Version)
	}

	// Update (version should increment).
	payload2 := json.RawMessage(`{"status":"degraded"}`)
	r2, err := sc.PutReport("health", "application/json", payload2, nil)
	if err != nil {
		t.Fatalf("PutReport (update): %v", err)
	}
	if r2.Version != 2 {
		t.Errorf("updated version = %d, want 2", r2.Version)
	}

	// Verify file on disk.
	data, err := os.ReadFile(filepath.Join(dir, "state", "report", "health.json"))
	if err != nil {
		t.Fatalf("read report file: %v", err)
	}
	var diskReport ReportEntry
	if err := json.Unmarshal(data, &diskReport); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if diskReport.Version != 2 {
		t.Errorf("disk version = %d, want 2", diskReport.Version)
	}

	// Delete.
	if err := sc.DeleteReport("health"); err != nil {
		t.Fatalf("DeleteReport: %v", err)
	}
	_, ok = sc.GetReport("health")
	if ok {
		t.Error("GetReport(health) after delete should return false")
	}

	// File should be removed.
	if _, err := os.Stat(filepath.Join(dir, "state", "report", "health.json")); !os.IsNotExist(err) {
		t.Error("report file should have been removed after delete")
	}
}

func TestStateCache_ReportOptimisticLocking(t *testing.T) {
	dir := t.TempDir()
	sc := NewStateCache(dir, discardLogger())
	if err := sc.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Create a report at version 1.
	payload := json.RawMessage(`{"v":1}`)
	_, err := sc.PutReport("lock-test", "application/json", payload, nil)
	if err != nil {
		t.Fatalf("PutReport (create): %v", err)
	}

	// Update with correct ifMatch (version 1).
	v1 := 1
	payload2 := json.RawMessage(`{"v":2}`)
	r, err := sc.PutReport("lock-test", "application/json", payload2, &v1)
	if err != nil {
		t.Fatalf("PutReport with correct ifMatch: %v", err)
	}
	if r.Version != 2 {
		t.Errorf("version = %d, want 2", r.Version)
	}

	// Update with wrong ifMatch (version 1, but current is 2).
	payload3 := json.RawMessage(`{"v":3}`)
	_, err = sc.PutReport("lock-test", "application/json", payload3, &v1)
	if !errors.Is(err, ErrVersionConflict) {
		t.Errorf("PutReport with wrong ifMatch: err = %v, want ErrVersionConflict", err)
	}

	// Verify the value was not changed.
	got, _ := sc.GetReport("lock-test")
	if got.Version != 2 {
		t.Errorf("version after conflict = %d, want 2", got.Version)
	}

	// ifMatch on a new key should work (no existing entry to conflict with).
	v0 := 0
	payload4 := json.RawMessage(`{"new":true}`)
	r2, err := sc.PutReport("new-key", "application/json", payload4, &v0)
	if err != nil {
		t.Fatalf("PutReport new with ifMatch=0: %v", err)
	}
	if r2.Version != 1 {
		t.Errorf("new key version = %d, want 1", r2.Version)
	}
}

func TestStateCache_DeleteReportNotFound(t *testing.T) {
	dir := t.TempDir()
	sc := NewStateCache(dir, discardLogger())
	if err := sc.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	err := sc.DeleteReport("nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteReport(nonexistent) = %v, want ErrNotFound", err)
	}
}

func TestStateCache_ConcurrentAccess(t *testing.T) {
	dir := t.TempDir()
	sc := NewStateCache(dir, discardLogger())
	if err := sc.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	var wg sync.WaitGroup
	const goroutines = 20

	// Concurrent metadata writes.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sc.UpdateMetadata(map[string]string{"key": "val"})
		}()
	}

	// Concurrent metadata reads.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sc.GetMetadata()
			_, _ = sc.GetMetadataKey("key")
		}()
	}

	// Concurrent report writes.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = sc.PutReport("concurrent", "text/plain", json.RawMessage(`"x"`), nil)
		}()
	}

	// Concurrent report reads.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sc.GetReports()
			_, _ = sc.GetReport("concurrent")
		}()
	}

	// Concurrent data and secret index reads/writes.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sc.UpdateData([]api.DataEntry{{Key: "k", ContentType: "text/plain", Payload: json.RawMessage(`"v"`), Version: 1, UpdatedAt: time.Now()}})
			_ = sc.GetData()
			_, _ = sc.GetDataEntry("k")
		}()
	}

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sc.UpdateSecretIndex([]api.SecretRef{{Key: "s", Version: 1}})
			_ = sc.GetSecretIndex()
		}()
	}

	wg.Wait()
}

func TestStateCache_LoadMissingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "deep", "nested", "path")
	sc := NewStateCache(dir, discardLogger())

	if err := sc.Load(); err != nil {
		t.Fatalf("Load on missing dir: %v", err)
	}

	// Verify directory was created.
	stateDir := filepath.Join(dir, "state")
	info, err := os.Stat(stateDir)
	if err != nil {
		t.Fatalf("Stat(%q): %v", stateDir, err)
	}
	if !info.IsDir() {
		t.Errorf("%q is not a directory", stateDir)
	}

	// Verify subdirs created.
	for _, sub := range []string{"data", "report"} {
		subDir := filepath.Join(stateDir, sub)
		info, err := os.Stat(subDir)
		if err != nil {
			t.Fatalf("Stat(%q): %v", subDir, err)
		}
		if !info.IsDir() {
			t.Errorf("%q is not a directory", subDir)
		}
	}

	// Cache should have empty state.
	if len(sc.GetMetadata()) != 0 {
		t.Error("metadata should be empty")
	}
	if len(sc.GetData()) != 0 {
		t.Error("data should be empty")
	}
	if len(sc.GetSecretIndex()) != 0 {
		t.Error("secret index should be empty")
	}
	if len(sc.GetReports()) != 0 {
		t.Error("reports should be empty")
	}
}
