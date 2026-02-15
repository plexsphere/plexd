package bridge

import "testing"

func TestValidateTunnelID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{name: "valid simple", id: "tun-001", wantErr: false},
		{name: "valid alphanumeric", id: "abc123", wantErr: false},
		{name: "valid with dashes", id: "my-tunnel-id", wantErr: false},
		{name: "valid single char", id: "a", wantErr: false},
		{name: "valid max length", id: "a234567890123456789012345678901234567890123456789012345678901ab", wantErr: false},
		{name: "empty", id: "", wantErr: true},
		{name: "starts with dash", id: "-bad", wantErr: true},
		{name: "path traversal", id: "../etc/passwd", wantErr: true},
		{name: "contains slash", id: "tun/bad", wantErr: true},
		{name: "contains dot", id: "tun.bad", wantErr: true},
		{name: "contains space", id: "tun bad", wantErr: true},
		{name: "contains newline", id: "tun\nbad", wantErr: true},
		{name: "too long", id: "a2345678901234567890123456789012345678901234567890123456789012abc", wantErr: true},
		{name: "null byte", id: "tun\x00bad", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTunnelID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTunnelID(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
			}
		})
	}
}

func TestValidateTunnelConfig(t *testing.T) {
	validCfg := TunnelConfig{
		TunnelID:       "tun-001",
		LocalSubnets:   []string{"10.0.0.0/24"},
		RemoteSubnets:  []string{"10.1.0.0/24"},
		RemoteEndpoint: "203.0.113.1:500",
		PSK:            "shared-secret-key",
	}

	t.Run("valid config", func(t *testing.T) {
		if err := ValidateTunnelConfig(validCfg); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("invalid tunnel ID", func(t *testing.T) {
		cfg := validCfg
		cfg.TunnelID = "../bad"
		if err := ValidateTunnelConfig(cfg); err == nil {
			t.Error("expected error for invalid tunnel ID")
		}
	})

	t.Run("newline in remote endpoint", func(t *testing.T) {
		cfg := validCfg
		cfg.RemoteEndpoint = "203.0.113.1\nmalicious"
		if err := ValidateTunnelConfig(cfg); err == nil {
			t.Error("expected error for newline in remote endpoint")
		}
	})

	t.Run("newline in PSK", func(t *testing.T) {
		cfg := validCfg
		cfg.PSK = "secret\nevil-config-line"
		if err := ValidateTunnelConfig(cfg); err == nil {
			t.Error("expected error for newline in PSK")
		}
	})

	t.Run("carriage return in PSK", func(t *testing.T) {
		cfg := validCfg
		cfg.PSK = "secret\revil"
		if err := ValidateTunnelConfig(cfg); err == nil {
			t.Error("expected error for carriage return in PSK")
		}
	})

	t.Run("newline in local subnet", func(t *testing.T) {
		cfg := validCfg
		cfg.LocalSubnets = []string{"10.0.0.0/24\nevil"}
		if err := ValidateTunnelConfig(cfg); err == nil {
			t.Error("expected error for newline in local subnet")
		}
	})

	t.Run("newline in remote subnet", func(t *testing.T) {
		cfg := validCfg
		cfg.RemoteSubnets = []string{"10.1.0.0/24\nevil"}
		if err := ValidateTunnelConfig(cfg); err == nil {
			t.Error("expected error for newline in remote subnet")
		}
	})
}
