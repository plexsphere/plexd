//go:build windows

package policy

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

const (
	// netNatName is the name plexd's NetNat object carries, so an operator
	// recognises it in Get-NetNat. Client editions of Windows hold one NetNat
	// object at a time, which is why plexd keeps exactly this one and rebuilds
	// it instead of adding a second. Every cmdlet below is built from it, so
	// the name plexd creates and the name plexd reports cannot drift apart.
	netNatName        = "plexd"
	powershellTimeout = 30 * time.Second // PowerShell takes seconds to start on a cold host

	// psAbsentOK and psAbsentOKEnd wrap a cmdlet so a name no object carries
	// is a success with no output while every other failure still terminates.
	// $ErrorActionPreference turns the cmdlet's non-terminating error into a
	// catchable one, and the catch recognises the miss by the error id every
	// CDXML query cmdlet raises for it. The message that goes with that id is
	// localized, so a match on its text would miss on every non-English
	// install and leave bridge mode unusable there. The explicit exit is what
	// makes the swallowed miss a success: -Command derives the process exit
	// code from $? after the last statement, and a caught error leaves $?
	// false, so without it the miss exits 1 with no output. A rethrow
	// terminates the script before the exit is reached and still exits 1.
	psAbsentOK    = "$ErrorActionPreference = 'Stop'; try { "
	psAbsentOKEnd = " } catch { if ($_.FullyQualifiedErrorId -notlike 'CmdletizationQuery_NotFound*') { throw } }; exit 0"

	// psGetNetNat prints the source prefix the current object translates,
	// which is the one value that decides whether it still fits the mesh, and
	// nothing at all when no such object exists.
	psGetNetNat = psAbsentOK + "(Get-NetNat -Name " + netNatName + ").InternalIPInterfaceAddressPrefix" + psAbsentOKEnd

	// psRemoveNetNat deletes the object. The cmdlet prompts for confirmation
	// by default, and a service has no console to answer with.
	psRemoveNetNat = psAbsentOK + "Remove-NetNat -Name " + netNatName + " -Confirm:$false" + psAbsentOKEnd

	// psNewNetNat is a format: the internal prefix is the argument. Out-Null
	// drops the created object from the output, so a failure's output carries
	// PowerShell's error text alone.
	psNewNetNat = "New-NetNat -Name " + netNatName + " -InternalIPInterfaceAddressPrefix %s | Out-Null"
)

// powershellPath is the Windows PowerShell the service can rely on. The
// service environment has no PATH worth trusting, and neither has %SystemRoot%:
// an elevated process inherits the environment block of whoever started it, so
// resolving the binary through that variable would run an unprivileged user's
// choice of powershell.exe as Administrator. GetSystemDirectory asks the kernel
// instead.
func powershellPath() string {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		dir = `C:\Windows\System32`
	}
	return filepath.Join(dir, "WindowsPowerShell", "v1.0", "powershell.exe")
}

// powershell runs one PowerShell command under a timeout and returns its
// combined output, which the caller reads even on failure: PowerShell exits 1
// whenever its last command failed, so the text is what an operator acts on.
// The error carries the script and that text, because "exit status 1" alone
// says nothing.
func (c *WFPController) powershell(op, script string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), powershellTimeout)
	defer cancel()

	out, err := c.run(ctx, nil, powershellPath(),
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	if err == nil {
		return out, nil
	}

	detail := strings.TrimSpace(string(out))
	if detail != "" {
		return out, fmt.Errorf("bridge: %s: powershell -Command %q: %w: %s", op, script, err, detail)
	}
	return out, fmt.Errorf("bridge: %s: powershell -Command %q: %w", op, script, err)
}

// AddNATMasquerade configures NAT for bridge egress. WFP cannot rewrite
// addresses without a callout driver of its own and Internet Connection
// Sharing reassigns the private adapter's address, so the translation is a
// WinNAT object instead. WinNAT is scoped by source prefix, not by interface:
// everything sourced from the mesh prefix is translated on its way out of
// whichever adapter carries the route, so iface is only logged and an empty
// one is accepted.
//
// Idempotent: an object that already translates the mesh prefix is left
// alone. One that translates another prefix is rebuilt, because the mesh
// moved and the host has no room for a second object.
func (c *WFPController) AddNATMasquerade(iface string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	op := fmt.Sprintf("add NAT masquerade on %q", iface)

	// The source prefix is the mesh adapter's, so only mesh traffic is
	// translated and the host's own networks are left alone.
	prefix, err := c.meshPrefix(c.meshIface)
	if err != nil {
		return fmt.Errorf("bridge: %s: resolve mesh prefix for %q: %w", op, c.meshIface, err)
	}

	out, err := c.powershell(op, psGetNetNat)
	if err != nil {
		return err
	}

	switch existing := strings.TrimSpace(string(out)); existing {
	case prefix.String():
		c.logger.Debug("NAT masquerade already configured",
			"component", "bridge",
			"interface", iface,
			"prefix", prefix,
		)
		return nil
	case "":
		// No object of that name, so there is nothing to remove first.
	default:
		if _, err := c.powershell(op, psRemoveNetNat); err != nil {
			return err
		}
	}

	if _, err := c.powershell(op, fmt.Sprintf(psNewNetNat, prefix)); err != nil {
		return err
	}

	c.logger.Debug("NAT masquerade configured",
		"component", "bridge",
		"interface", iface,
		"prefix", prefix,
		"nat", netNatName,
	)
	return nil
}

// RemoveNATMasquerade deletes the NetNat object. The interface is logged, not
// compared: the object is scoped by prefix and there is only ever one of it.
// The command runs whether or not this process configured it, as the Linux
// backend deletes its NAT table regardless of the name it is given.
// Idempotent: removing an object that is not there returns nil.
func (c *WFPController) RemoveNATMasquerade(iface string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, err := c.powershell(fmt.Sprintf("remove NAT masquerade on %q", iface), psRemoveNetNat); err != nil {
		return err
	}

	c.logger.Debug("NAT masquerade removed",
		"component", "bridge",
		"interface", iface,
	)
	return nil
}
