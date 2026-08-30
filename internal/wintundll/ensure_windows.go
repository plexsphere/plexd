//go:build windows

// Package wintundll carries the Wintun driver DLL that WireGuard needs on
// Windows and writes it out beside the running executable.
//
// Wintun is not part of Windows, and its loader searches only the executable's
// own directory and System32, so wintun.dll has to sit next to plexd.exe.
// plexd ships as a single .exe and service.upgrade replaces exactly that one
// file, so the DLL travels inside the binary: embedding leaves the release
// artifact set unchanged and lets an upgrade deliver a newer driver.
//
// The embedded files are the signed originals from wintun-0.14.1.zip
// (https://www.wintun.net, archive sha256
// 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51),
// byte for byte, and plexd calls into them only through the published API by
// way of golang.zx2c4.com/wintun. That is what the licence beside this file
// requires of a redistributor; read it before changing anything here.
// Updating the driver means replacing both .dll files with a newer signed
// archive's and nothing else.
package wintundll

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/plexsphere/plexd/internal/fsutil"
)

// dllName is the file name the wintun loader resolves.
const dllName = "wintun.dll"

// Ensure writes the embedded wintun.dll into dir unless an identical file is
// already there, and reports whether it wrote. It returns the DLL's path in
// both cases.
//
// Callers pass the directory of the running executable, which is where the
// loader looks. Ensure runs before the first adapter is created, while the DLL
// is not yet loaded into this process; a file that already matches is left
// alone, so a restart and a repeated create touch nothing.
func Ensure(dir string) (string, bool, error) {
	path := filepath.Join(dir, dllName)

	switch existing, err := os.ReadFile(path); {
	case err == nil:
		if sha256.Sum256(existing) == sha256.Sum256(dll) {
			return path, false, nil
		}
	case !errors.Is(err, fs.ErrNotExist):
		return "", false, fmt.Errorf("wintundll: read existing dll: %w", err)
	}

	// WriteFileAtomic fsyncs the contents before the rename, so a crash or a
	// power loss mid-write cannot leave a truncated DLL for the loader to find,
	// and its Windows rename retries while another process still holds the file
	// open.
	if err := fsutil.WriteFileAtomic(dir, dllName, dll, 0o644); err != nil {
		return "", false, fmt.Errorf("wintundll: write dll: %w", err)
	}

	return path, true, nil
}
