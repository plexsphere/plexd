package packaging

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// realSystemdController implements SystemdController using os/exec to call systemctl.
type realSystemdController struct{}

// NewSystemdController returns a SystemdController that calls the real systemctl binary.
func NewSystemdController() SystemdController {
	return &realSystemdController{}
}

func (c *realSystemdController) IsAvailable() bool {
	_, err := exec.LookPath("systemctl")
	return err == nil
}

func (c *realSystemdController) DaemonReload() error {
	return c.run("daemon-reload")
}

func (c *realSystemdController) Enable(service string) error {
	return c.run("enable", service)
}

func (c *realSystemdController) Disable(service string) error {
	return c.run("disable", service)
}

func (c *realSystemdController) Stop(service string) error {
	return c.run("stop", service)
}

func (c *realSystemdController) IsActive(service string) bool {
	err := exec.Command("systemctl", "is-active", "--quiet", service).Run()
	return err == nil
}

func (c *realSystemdController) run(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("packaging: systemctl %s: %s: %w", args[0], strings.TrimSpace(string(output)), err)
	}
	return nil
}

// realRootChecker implements RootChecker using os.Getuid.
type realRootChecker struct{}

// NewRootChecker returns a RootChecker that checks the real process UID.
func NewRootChecker() RootChecker {
	return &realRootChecker{}
}

func (c *realRootChecker) IsRoot() bool {
	return os.Getuid() == 0
}
