//go:build windows

package packaging

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// removeBinary deletes the installed binary. Windows refuses to delete a
// running image, which plexd uninstall is whenever it runs from the installed
// path, so the file is renamed aside and handed to the boot-time delete queue
// instead. A leftover .old from an earlier upgrade goes first.
func (ins *Installer) removeBinary() error {
	old := ins.cfg.BinaryPath + ".old"
	_ = os.Remove(old)

	err := os.Remove(ins.cfg.BinaryPath)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		ins.logger.Info("binary removed", "path", ins.cfg.BinaryPath)
		return nil
	}

	if renameErr := os.Rename(ins.cfg.BinaryPath, old); renameErr != nil {
		return fmt.Errorf("packaging: remove binary: %w", err)
	}
	oldPtr, ptrErr := windows.UTF16PtrFromString(old)
	if ptrErr != nil {
		return fmt.Errorf("packaging: remove binary: %w", err)
	}
	if moveErr := windows.MoveFileEx(oldPtr, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT); moveErr != nil {
		return fmt.Errorf("packaging: remove binary: %w", err)
	}
	ins.logger.Info("binary in use, removed at next reboot", "path", old)
	return nil
}
