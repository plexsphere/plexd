package bridge

import "testing"

func TestMockVPNController_ImplementsInterface(t *testing.T) {
	var _ VPNController = (*mockVPNController)(nil)
}
