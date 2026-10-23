---
title: File System Utilities
package: internal/fsutil
feature: PXD-0034
---

# File System Utilities

The `internal/fsutil` package provides file system primitives for crash-safe persistence and for watching a directory. Its primary export, `WriteFileAtomic`, ensures that readers never observe a partially-written file by writing to a temporary file, calling `fsync`, and then performing an atomic rename. `WatchDir` sets up an `fsnotify` watch on a directory, and sets it up again when a file in the directory vanishes while that runs.

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

Returns `nil` on success. On failure, returns the underlying `os` error from whichever step failed (file creation, write, fsync, rename, or directory sync). The original file, if any, is left untouched on error.

### Atomicity Guarantee

1. Creates a temporary file at `dir/.tmp-name` with the requested permissions
2. Writes `data` to the temporary file
3. Calls `f.Sync()` (`fsync`) to flush data to stable storage before renaming
4. Calls `os.Rename` to atomically replace the target file. On Windows the replace is retried for up to two seconds (`rename_windows.go`): Go opens files without `FILE_SHARE_DELETE`, so any reader holding the target makes `MoveFileEx` fail with a sharing violation until it closes its handle. Unix has no such condition and does not retry.
5. Syncs the parent directory so the new entry survives a power cut, not just the file's contents (`sync_unix.go`). On Windows this step does nothing (`sync_windows.go`): Go opens a directory with `GENERIC_READ` alone and `FlushFileBuffers` requires `GENERIC_WRITE`, so the call could only fail there. NTFS journals directory metadata itself, and step 3 is unchanged, so the contents are as durable as on Unix.
6. On any error, the temporary file is removed via `defer os.Remove`

Because `os.Rename` is atomic on POSIX filesystems, concurrent readers will see either the old content or the new content — never a partial write.

## WatchDir

Returns an `fsnotify` watcher on `dir`, set up again when a file in `dir` vanishes while the watch is being set up.

```go
func WatchDir(ctx context.Context, dir string, onRetry func(err error)) (*fsnotify.Watcher, error)
```

On macOS and the BSDs, fsnotify's kqueue backend lists `dir` and then inspects and opens every file in it while it adds the directory. A file removed after the listing, before fsnotify opens it, fails the add with an error wrapping `fs.ErrNotExist`. The failed watcher keeps the directory registered, and a second add on it skips the files, so `WatchDir` closes it, calls `onRetry` with the error when `onRetry` is not nil, waits 100 ms, and sets the watch up again on a new watcher. It makes at most 10 attempts and then returns the last error, so a file that keeps failing the add as missing ends set-up instead of looping. A dangling symlink in `dir` is one: fsnotify v1.9.0 follows it when it opens the entry, so every attempt fails and set-up ends with the 10th attempt's error. On Linux (inotify) and Windows (`ReadDirectoryChangesW`), the add watches the directory alone, so a vanishing file cannot fail it; its errors, such as a missing or unreadable directory or the inotify watch limit (`no space left on device`), are returned without a retry.

| Case | Result |
|------|--------|
| A file in `dir` vanished during the add | The watcher is closed, `onRetry` is called, and the watch is set up again after 100 ms |
| The add still fails that way on the 10th attempt | That attempt's error is returned |
| `dir` itself is gone | The `fs.ErrNotExist` error is returned without a retry |
| Any other error from `fsnotify.NewWatcher` or the add | Returned as it is |
| `ctx` is done while waiting to retry | `ctx.Err()` is returned |

`WatchDir` closes a failed watcher before it retries or returns. With fsnotify v1.9.0 on kqueue, `Close` does not release the descriptors the watch opened, so each retried attempt there leaves one open for `dir` and one for each file fsnotify opened before the failure; the 10-attempt cap bounds that per set-up.

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
| Target held open      | A reader holds the target (Windows only)       | The replace is retried for two seconds, then the sharing-violation error is returned |
| Directory sync failure | Parent directory cannot be opened or flushed (Unix only) | `syncDir` fails after the rename; error returned, the renamed file stays in place |

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
