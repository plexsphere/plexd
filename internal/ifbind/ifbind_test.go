package ifbind

import "testing"

func TestControl_EmptyNameBindsNothing(t *testing.T) {
	if Control("") != nil {
		t.Error(`Control("") returned a control, want nil`)
	}
}
