//go:build unix

package packaging

import (
	"errors"
	"fmt"
	"os"
)

// removeBinary deletes the installed binary. Unix unlinks a running executable
// without complaint, so the file is simply removed and an absent one is done.
func (ins *Installer) removeBinary() error {
	if err := os.Remove(ins.cfg.BinaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("packaging: remove binary: %w", err)
	}
	ins.logger.Info("binary removed", "path", ins.cfg.BinaryPath)
	return nil
}
