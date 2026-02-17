---
title: File System Utilities
package: internal/fsutil
feature: PXD-0034
---

# File System Utilities

The `internal/fsutil` package provides file system primitives for crash-safe persistence. Its primary export, `WriteFileAtomic`, ensures that readers never observe a partially-written file by writing to a temporary file, calling `fsync`, and then performing an atomic rename.

## WriteFileAtomic

Writes data to `dir/name` atomically using a temp-file-and-rename strategy.

```go
func WriteFileAtomic(dir, name string, data []byte, perm os.FileMode) error
```

### Parameters

| Parameter | Type           | Description                                           |
|-----------|----------------|-------------------------------------------------------|
| `dir`     | `string`       | Directory where the target file resides               |
| `name`    | `string`       | Base name of the target file                          |
| `data`    | `[]byte`       | Content to write                                      |
| `perm`    | `os.FileMode`  | Permission bits for the created file (e.g. `0600`)    |

### Return Value

Returns `nil` on success. On failure, returns the underlying `os` error from whichever step failed (file creation, write, fsync, or rename). The original file, if any, is left untouched on error.

### Atomicity Guarantee

1. Creates a temporary file at `dir/.tmp-name` with the requested permissions
2. Writes `data` to the temporary file
3. Calls `f.Sync()` (`fsync`) to flush data to stable storage before renaming
4. Calls `os.Rename` to atomically replace the target file
5. On any error, the temporary file is removed via `defer os.Remove`

Because `os.Rename` is atomic on POSIX filesystems, concurrent readers will see either the old content or the new content — never a partial write.

## Usage Examples

### Persisting Identity Files (registration)

```go
jsonData, err := json.MarshalIndent(id, "", "  ")
if err != nil {
    return fmt.Errorf("registration: save identity: %w", err)
}

if err := fsutil.WriteFileAtomic(dataDir, "identity.json", jsonData, 0600); err != nil {
    return fmt.Errorf("registration: save identity: %w", err)
}
```

### Persisting Checksum Store (integrity)

```go
data, err := json.Marshal(s.checksums)
if err != nil {
    return fmt.Errorf("integrity: store: marshal: %w", err)
}
return fsutil.WriteFileAtomic(s.dataDir, checksumFileName, data, 0o600)
```

### Persisting Cache State (nodeapi)

```go
data, err := json.MarshalIndent(v, "", "  ")
if err != nil {
    sc.logger.Error("persist marshal failed", "path", path, "error", err)
    return
}
dir := filepath.Dir(path)
name := filepath.Base(path)
if err := fsutil.WriteFileAtomic(dir, name, data, 0600); err != nil {
    sc.logger.Error("persist write failed", "path", path, "error", err)
}
```

## Error Handling

### Failure Modes

| Scenario              | Cause                                          | Behavior                                                        |
|-----------------------|------------------------------------------------|-----------------------------------------------------------------|
| Permission denied     | `dir` is not writable                          | `os.OpenFile` fails; error returned, no files created           |
| Non-existent dir      | `dir` does not exist                           | `os.OpenFile` fails; error returned                             |
| Disk full             | No space for temp file or write                | Write or sync fails; error returned, temp file cleaned up       |
| Rename failure        | Cross-device rename or permission issue        | `os.Rename` fails; error returned, temp file cleaned up         |

### Temp File Cleanup

The function uses `defer os.Remove(tmpPath)` immediately after creating the temporary file. This ensures the `.tmp-` file is removed on any error path. On the success path, the rename has already moved the temp file to its target name, so the deferred remove is a no-op (removing a non-existent path).

### Concurrency Safety

`WriteFileAtomic` is safe to call concurrently from multiple goroutines writing to the **same directory with different file names**. For concurrent writes to the **same file name**, the last rename wins — callers that require serialized writes should protect calls with a `sync.Mutex` (as `integrity.Store` does).

## Callers

| Package                 | Import Path                                             | Use Case                                                                 |
|-------------------------|---------------------------------------------------------|--------------------------------------------------------------------------|
| `registration`          | `internal/registration`                                 | Persists node identity files (`identity.json`, `private_key`, `node_secret_key`, `signing_public_key`) |
| `integrity`             | `internal/integrity`                                    | Persists checksum store (`checksums.json`) for binary and hook verification |
| `nodeapi`               | `internal/nodeapi`                                      | Persists cached state (reports, metadata) to disk for crash recovery     |
| `tunnel`                | `internal/tunnel`                                       | Persists SSH host keys (`host_key`) for reverse tunnel authentication    |
