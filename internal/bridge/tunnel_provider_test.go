package bridge

import (
	"strings"
	"testing"
)

// validTunnelConfig returns a TunnelConfig every check of
// ValidateTunnelConfig accepts: the ipsec tunnel of the contract's example.
func validTunnelConfig() TunnelConfig {
	return TunnelConfig{
		TunnelID:      "0190a8b8-a0c0-7a0a-8a0a-a0a0a0a0a0e2",
		InterfaceName: "xf-s2s-a0a0a0e2",
		InterfaceID:   2694881506,
		RemoteHost:    "203.0.113.10",
		RemotePort:    500,
		LocalSubnets:  []string{"10.99.0.0/24"},
		RemoteSubnets: []string{"10.30.0.0/16", "10.31.0.0/16"},
		Key:           "s3",
	}
}

func TestValidateTunnelConfig(t *testing.T) {
	for name, adjust := range map[string]func(*TunnelConfig){
		"the contract's example": func(*TunnelConfig) {},
		"a host name":            func(c *TunnelConfig) { c.RemoteHost = "vpn.dc-east.example.com" },
		"an IPv6 address":        func(c *TunnelConfig) { c.RemoteHost = "2001:db8::10" },
		"a host of 253":          func(c *TunnelConfig) { c.RemoteHost = strings.Repeat("a", 253) },
		"port 1":                 func(c *TunnelConfig) { c.RemotePort = 1 },
		"port 65535":             func(c *TunnelConfig) { c.RemotePort = 65535 },
		"no local subnet":        func(c *TunnelConfig) { c.LocalSubnets = nil },
		"a tun device":           func(c *TunnelConfig) { c.InterfaceName, c.InterfaceID = "ov-s2s-a0a0a0e3", 0 },
		"a key with a newline":   func(c *TunnelConfig) { c.Key = "line one\nline two" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validTunnelConfig()
			adjust(&cfg)
			if err := ValidateTunnelConfig(cfg); err != nil {
				t.Errorf("ValidateTunnelConfig() = %v, want nil", err)
			}
		})
	}

	for name, adjust := range map[string]func(*TunnelConfig){
		"no tunnel id":                func(c *TunnelConfig) { c.TunnelID = "" },
		"a tunnel id that is a path":  func(c *TunnelConfig) { c.TunnelID = "../../etc/swanctl" },
		"the zero UUID":               func(c *TunnelConfig) { c.TunnelID = "00000000-0000-0000-0000-000000000000" },
		"no remote host":              func(c *TunnelConfig) { c.RemoteHost = "" },
		"a remote host with a CR":     func(c *TunnelConfig) { c.RemoteHost = "203.0.113.10\r" },
		"a remote host with an LF":    func(c *TunnelConfig) { c.RemoteHost = "203.0.113.10\nsecret = 0x00" },
		"a remote host with a space":  func(c *TunnelConfig) { c.RemoteHost = "203.0.113.10 203.0.113.11" },
		"a remote host with a brace":  func(c *TunnelConfig) { c.RemoteHost = "vpn}" },
		"a remote host of 254":        func(c *TunnelConfig) { c.RemoteHost = strings.Repeat("a", 254) },
		"port 0":                      func(c *TunnelConfig) { c.RemotePort = 0 },
		"port 65536":                  func(c *TunnelConfig) { c.RemotePort = 65536 },
		"a local subnet with an LF":   func(c *TunnelConfig) { c.LocalSubnets = []string{"10.99.0.0/24\n"} },
		"a remote subnet not a CIDR":  func(c *TunnelConfig) { c.RemoteSubnets = []string{"10.30.0.0/16", "not-a-prefix"} },
		"no interface name":           func(c *TunnelConfig) { c.InterfaceName = "" },
		"an interface name of 16":     func(c *TunnelConfig) { c.InterfaceName = "xf-s2s-a0a0a0e2x" },
		"an interface name in upper":  func(c *TunnelConfig) { c.InterfaceName = "XF-S2S-A0A0A0E2" },
		"an interface name with a /":  func(c *TunnelConfig) { c.InterfaceName = "xf/s2s" },
		"an interface name with a LF": func(c *TunnelConfig) { c.InterfaceName = "xf-s2s\n" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validTunnelConfig()
			cfg.Key = "never-in-an-error"
			adjust(&cfg)
			err := ValidateTunnelConfig(cfg)
			if err == nil {
				t.Fatal("ValidateTunnelConfig() = nil, want an error")
			}
			if strings.Contains(err.Error(), cfg.Key) {
				t.Errorf("the error %q carries the key", err)
			}
		})
	}
}
