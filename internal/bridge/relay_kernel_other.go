package bridge

import "log/slog"

// platformRelayKernel returns nil: the relay forwards in the process on this
// platform, and useKernel leaves its newKernel seam nil.
func platformRelayKernel() func(port int, meshIface string, logger *slog.Logger) (relayKernel, error) {
	return nil
}
