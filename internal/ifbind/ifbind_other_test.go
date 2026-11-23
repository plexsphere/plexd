//go:build !linux && !darwin

package ifbind

import "testing"

func TestControl_OtherSystemsBindNothing(t *testing.T) {
	if Control("plexd0") != nil {
		t.Error(`Control("plexd0") returned a control, want nil`)
	}
}
