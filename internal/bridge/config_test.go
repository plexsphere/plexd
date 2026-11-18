package bridge

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestConfig_ApplyDefaults(t *testing.T) {
	var cfg Config
	cfg.ApplyDefaults()

	if cfg.Enabled {
		t.Error("Enabled should default to false")
	}
	if cfg.EnableNAT != nil {
		t.Error("EnableNAT should remain nil after ApplyDefaults")
	}
	if !cfg.natEnabled() {
		t.Error("natEnabled() should return true for nil EnableNAT")
	}
	if cfg.AccessInterface != "" {
		t.Error("AccessInterface should remain empty")
	}
	if len(cfg.AccessSubnets) != 0 {
		t.Error("AccessSubnets should remain empty")
	}
}

func TestConfig_NatEnabled(t *testing.T) {
	tests := []struct {
		name      string
		enableNAT *bool
		want      bool
	}{
		{"nil defaults to true", nil, true},
		{"explicit true", BoolPtr(true), true},
		{"explicit false", BoolPtr(false), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{EnableNAT: tt.enableNAT}
			if got := cfg.natEnabled(); got != tt.want {
				t.Errorf("natEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_Validate_Disabled(t *testing.T) {
	cfg := Config{Enabled: false}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate should return nil when disabled, got: %v", err)
	}
}

func TestConfig_Validate_MissingAccessInterface(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		AccessSubnets: []string{"10.0.0.0/24"},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate should return error for missing AccessInterface")
	}
	want := "bridge: config: AccessInterface is required when enabled"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestConfig_Validate_MissingAccessSubnets(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate should return error for missing AccessSubnets")
	}
	want := "bridge: config: at least one AccessSubnet is required when enabled"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestConfig_Validate_InvalidCIDR(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"not-a-cidr"},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate should return error for invalid CIDR")
	}
	if !strings.Contains(err.Error(), "invalid CIDR") {
		t.Errorf("error should mention invalid CIDR, got: %v", err)
	}
}

func TestConfig_Validate_ValidConfig(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24", "192.168.1.0/24"},
		EnableNAT:       BoolPtr(true),
		IngressEnabled:  BoolPtr(false),
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate should return nil for valid config, got: %v", err)
	}
}

func TestConfig_ApplyDefaults_RelayFields(t *testing.T) {
	var cfg Config
	cfg.ApplyDefaults()

	if cfg.RelayEnabled {
		t.Error("RelayEnabled should default to false")
	}
}

func TestConfig_Validate_RelayDisabled(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24"},
		RelayEnabled:    false,
		IngressEnabled:  BoolPtr(false),
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate should return nil when relay is disabled, got: %v", err)
	}
}

func TestConfig_Validate_RelayWithoutBridge(t *testing.T) {
	cfg := Config{
		Enabled:      false,
		RelayEnabled: true,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate should return error when relay enabled without bridge")
	}
	want := "bridge: config: relay requires bridge mode to be enabled"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

// The relay port comes from the state pull, so bridge mode with local consent
// validates without any relay port set.
func TestConfig_Validate_RelayValidConfig(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24"},
		RelayEnabled:    true,
		IngressEnabled:  BoolPtr(false),
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate should return nil for valid relay config, got: %v", err)
	}
}

// The control plane delivers every user access provider, so ApplyDefaults
// leaves the local switch unset and gives the ignored keys no value.
func TestConfig_ApplyDefaults_UserAccessFields(t *testing.T) {
	var cfg Config
	cfg.ApplyDefaults()

	if cfg.UserAccessEnabled != nil {
		t.Errorf("UserAccessEnabled = %v, want it to stay nil after ApplyDefaults", *cfg.UserAccessEnabled)
	}
	if keys := cfg.ReplacedUserAccessKeys(); keys != nil {
		t.Errorf("ReplacedUserAccessKeys() = %q after ApplyDefaults, want nil: the ignored keys have no default", keys)
	}
}

func TestConfig_UserAccessOptedOut(t *testing.T) {
	tests := []struct {
		name              string
		userAccessEnabled *bool
		want              bool
	}{
		{"nil serves", nil, false},
		{"explicit true", BoolPtr(true), false},
		{"explicit false opts out", BoolPtr(false), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{UserAccessEnabled: tt.userAccessEnabled}
			if got := cfg.UserAccessOptedOut(); got != tt.want {
				t.Errorf("UserAccessOptedOut() = %v, want %v", got, tt.want)
			}
		})
	}
}

// An unset switch is the default every node carries, so only an explicit true
// is refused outside bridge mode.
func TestConfig_Validate_UserAccessWithoutBridge(t *testing.T) {
	tests := []struct {
		name              string
		userAccessEnabled *bool
		wantErr           string
	}{
		{"explicit true", BoolPtr(true), "bridge: config: user access requires bridge mode to be enabled"},
		{"nil", nil, ""},
		{"explicit false", BoolPtr(false), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Enabled:           false,
				UserAccessEnabled: tt.userAccessEnabled,
			}
			err := cfg.Validate()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("Validate() = %v, want nil", err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("Validate() = nil, want %q", tt.wantErr)
			case tt.wantErr != "" && err.Error() != tt.wantErr:
				t.Errorf("got %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestConfig_Validate_UserAccessInBridgeMode(t *testing.T) {
	for name, enabled := range map[string]*bool{"nil": nil, "explicit true": BoolPtr(true), "explicit false": BoolPtr(false)} {
		t.Run(name, func(t *testing.T) {
			cfg := Config{
				Enabled:           true,
				AccessInterface:   "eth1",
				AccessSubnets:     []string{"10.0.0.0/24"},
				UserAccessEnabled: enabled,
				IngressEnabled:    BoolPtr(false),
			}
			if err := cfg.Validate(); err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestConfig_ReplacedUserAccessKeys(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want []string
	}{
		{"none set", Config{Enabled: true, UserAccessEnabled: BoolPtr(true)}, nil},
		{"interface name", Config{UserAccessInterfaceName: "wg-access"}, []string{"user_access_interface_name"}},
		{"listen port", Config{UserAccessListenPort: 51822}, []string{"user_access_listen_port"}},
		{"max peers", Config{MaxAccessPeers: 50}, []string{"max_access_peers"}},
		{"provider type", Config{UserAccessProviderType: "tailscale"}, []string{"user_access_provider_type"}},
		{"auth key env", Config{AuthKeyEnv: "PLEXD_TAILSCALE_AUTH_KEY"}, []string{"auth_key_env"}},
		{"setup key env", Config{SetupKeyEnv: "PLEXD_NETBIRD_SETUP_KEY"}, []string{"setup_key_env"}},
		{"two of them", Config{SetupKeyEnv: "PLEXD_NETBIRD_SETUP_KEY", UserAccessListenPort: 51822}, []string{"user_access_listen_port", "setup_key_env"}},
		{"all six", Config{
			UserAccessInterfaceName: "wg-access",
			UserAccessListenPort:    51822,
			MaxAccessPeers:          50,
			UserAccessProviderType:  "netbird",
			AuthKeyEnv:              "PLEXD_TAILSCALE_AUTH_KEY",
			SetupKeyEnv:             "PLEXD_NETBIRD_SETUP_KEY",
		}, []string{"user_access_interface_name", "user_access_listen_port", "max_access_peers", "user_access_provider_type", "auth_key_env", "setup_key_env"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.ReplacedUserAccessKeys()
			if tt.want == nil {
				if got != nil {
					t.Errorf("ReplacedUserAccessKeys() = %q, want nil", got)
				}
				return
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("ReplacedUserAccessKeys() = %q, want %q", got, tt.want)
			}
		})
	}
}

// The ignored keys are not validated: values the local model refused, such
// as an out-of-range port, a non-positive peer cap, an empty interface name
// with user access on and an unknown provider type, are accepted and ignored.
func TestConfig_Validate_ReplacedUserAccessKeysAccepted(t *testing.T) {
	tests := []struct {
		name string
		set  func(*Config)
	}{
		{"listen port zero", func(c *Config) { c.UserAccessListenPort = 0 }},
		{"listen port too high", func(c *Config) { c.UserAccessListenPort = 70000 }},
		{"negative peer cap", func(c *Config) { c.MaxAccessPeers = -1 }},
		{"no interface name", func(c *Config) { c.UserAccessInterfaceName = "" }},
		{"unknown provider type", func(c *Config) { c.UserAccessProviderType = "wireguard" }},
		{"key variables", func(c *Config) { c.AuthKeyEnv, c.SetupKeyEnv = "X", "Y" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Enabled:           true,
				AccessInterface:   "eth1",
				AccessSubnets:     []string{"10.0.0.0/24"},
				UserAccessEnabled: BoolPtr(true),
				IngressEnabled:    BoolPtr(false),
			}
			tt.set(&cfg)
			if err := cfg.Validate(); err != nil {
				t.Errorf("Validate() = %v, want nil: the key is ignored", err)
			}
		})
	}
}

func TestConfig_ApplyDefaults_IngressFields(t *testing.T) {
	var cfg Config
	cfg.ApplyDefaults()

	if cfg.IngressEnabled != nil {
		t.Errorf("IngressEnabled = %v, want it to stay nil after ApplyDefaults", *cfg.IngressEnabled)
	}
	if cfg.MaxIngressRules != DefaultMaxIngressRules {
		t.Errorf("MaxIngressRules = %d, want %d", cfg.MaxIngressRules, DefaultMaxIngressRules)
	}
	if cfg.IngressDialTimeout != DefaultIngressDialTimeout {
		t.Errorf("IngressDialTimeout = %v, want %v", cfg.IngressDialTimeout, DefaultIngressDialTimeout)
	}
}

func TestConfig_IngressOptedOut(t *testing.T) {
	tests := []struct {
		name           string
		ingressEnabled *bool
		want           bool
	}{
		{"nil serves", nil, false},
		{"explicit true", BoolPtr(true), false},
		{"explicit false opts out", BoolPtr(false), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{IngressEnabled: tt.ingressEnabled}
			if got := cfg.IngressOptedOut(); got != tt.want {
				t.Errorf("IngressOptedOut() = %v, want %v", got, tt.want)
			}
		})
	}
}

// An unset switch is the default every node carries, so only an explicit true
// is refused outside bridge mode.
func TestConfig_Validate_IngressWithoutBridge(t *testing.T) {
	tests := []struct {
		name           string
		ingressEnabled *bool
		wantErr        string
	}{
		{"explicit true", BoolPtr(true), "bridge: config: ingress requires bridge mode to be enabled"},
		{"nil", nil, ""},
		{"explicit false", BoolPtr(false), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Enabled:        false,
				IngressEnabled: tt.ingressEnabled,
			}
			err := cfg.Validate()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("Validate() = %v, want nil", err)
			case tt.wantErr != "" && err == nil:
				t.Fatalf("Validate() = nil, want %q", tt.wantErr)
			case tt.wantErr != "" && err.Error() != tt.wantErr:
				t.Errorf("got %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestConfig_Validate_IngressValidConfig(t *testing.T) {
	cfg := Config{
		Enabled:            true,
		AccessInterface:    "eth1",
		AccessSubnets:      []string{"10.0.0.0/24"},
		IngressEnabled:     BoolPtr(true),
		MaxIngressRules:    20,
		IngressDialTimeout: 10 * time.Second,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate should return nil for valid ingress config, got: %v", err)
	}
}

// A bridge serves public ingress unless it opts out, so the ingress values are
// checked with the switch unset.
func TestConfig_Validate_IngressInvalidMaxRules(t *testing.T) {
	tests := []struct {
		name     string
		maxRules int
	}{
		{"zero rules", 0},
		{"negative rules", -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Enabled:            true,
				AccessInterface:    "eth1",
				AccessSubnets:      []string{"10.0.0.0/24"},
				MaxIngressRules:    tt.maxRules,
				IngressDialTimeout: 10 * time.Second,
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate should return error for invalid MaxIngressRules")
			}
			want := "bridge: config: MaxIngressRules must be positive when ingress is enabled"
			if err.Error() != want {
				t.Errorf("got %q, want %q", err.Error(), want)
			}
		})
	}
}

func TestConfig_Validate_IngressInvalidDialTimeout(t *testing.T) {
	cfg := Config{
		Enabled:            true,
		AccessInterface:    "eth1",
		AccessSubnets:      []string{"10.0.0.0/24"},
		MaxIngressRules:    20,
		IngressDialTimeout: 500 * time.Millisecond,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate should return error for IngressDialTimeout below 1s")
	}
	want := "bridge: config: IngressDialTimeout must be at least 1s"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

// An opted-out bridge serves no ingress, so the values that bound it are not
// checked: the ones the two tests above refuse validate.
func TestConfig_Validate_IngressDisabled(t *testing.T) {
	tests := []struct {
		name        string
		maxRules    int
		dialTimeout time.Duration
	}{
		{"zero rules", 0, 10 * time.Second},
		{"negative rules", -1, 10 * time.Second},
		{"dial timeout below 1s", 20, 500 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Enabled:            true,
				AccessInterface:    "eth1",
				AccessSubnets:      []string{"10.0.0.0/24"},
				IngressEnabled:     BoolPtr(false),
				MaxIngressRules:    tt.maxRules,
				IngressDialTimeout: tt.dialTimeout,
			}
			if err := cfg.Validate(); err != nil {
				t.Errorf("Validate should return nil when ingress is opted out, got: %v", err)
			}
		})
	}
}

func TestConfig_ApplyDefaults_SiteToSiteFields(t *testing.T) {
	var cfg Config
	cfg.ApplyDefaults()

	if cfg.SiteToSiteEnabled {
		t.Error("SiteToSiteEnabled should default to false")
	}
	if cfg.SiteToSiteInterfacePrefix != DefaultSiteToSiteInterfacePrefix {
		t.Errorf("SiteToSiteInterfacePrefix = %q, want %q", cfg.SiteToSiteInterfacePrefix, DefaultSiteToSiteInterfacePrefix)
	}
	if cfg.SiteToSiteListenPort != DefaultSiteToSiteListenPort {
		t.Errorf("SiteToSiteListenPort = %d, want %d", cfg.SiteToSiteListenPort, DefaultSiteToSiteListenPort)
	}
	if cfg.MaxSiteToSiteTunnels != DefaultMaxSiteToSiteTunnels {
		t.Errorf("MaxSiteToSiteTunnels = %d, want %d", cfg.MaxSiteToSiteTunnels, DefaultMaxSiteToSiteTunnels)
	}
}

func TestConfig_Validate_SiteToSiteWithoutBridge(t *testing.T) {
	cfg := Config{
		Enabled:           false,
		SiteToSiteEnabled: true,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate should return error when site-to-site enabled without bridge")
	}
	want := "bridge: config: site-to-site requires bridge mode to be enabled"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestConfig_Validate_SiteToSiteValidConfig(t *testing.T) {
	cfg := Config{
		Enabled:                   true,
		AccessInterface:           "eth1",
		AccessSubnets:             []string{"10.0.0.0/24"},
		SiteToSiteEnabled:         true,
		SiteToSiteInterfacePrefix: "wg-s2s-",
		SiteToSiteListenPort:      51823,
		MaxSiteToSiteTunnels:      10,
		IngressEnabled:            BoolPtr(false),
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate should return nil for valid site-to-site config, got: %v", err)
	}
}

func TestConfig_Validate_SiteToSiteInvalidPort(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{"port zero", 0},
		{"port too high", 70000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Enabled:                   true,
				AccessInterface:           "eth1",
				AccessSubnets:             []string{"10.0.0.0/24"},
				SiteToSiteEnabled:         true,
				SiteToSiteInterfacePrefix: "wg-s2s-",
				SiteToSiteListenPort:      tt.port,
				MaxSiteToSiteTunnels:      10,
				IngressEnabled:            BoolPtr(false),
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate should return error for invalid port")
			}
			want := "bridge: config: SiteToSiteListenPort must be between 1 and 65535"
			if err.Error() != want {
				t.Errorf("got %q, want %q", err.Error(), want)
			}
		})
	}
}

func TestConfig_Validate_SiteToSiteBoundaryPorts(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{"port 1 (min valid)", 1, false},
		{"port 65535 (max valid)", 65535, false},
		{"port 65536 (just over max)", 65536, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Enabled:                   true,
				AccessInterface:           "eth1",
				AccessSubnets:             []string{"10.0.0.0/24"},
				SiteToSiteEnabled:         true,
				SiteToSiteInterfacePrefix: "wg-s2s-",
				SiteToSiteListenPort:      tt.port,
				MaxSiteToSiteTunnels:      10,
				IngressEnabled:            BoolPtr(false),
			}
			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("Validate should return error for out-of-range port")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Validate should return nil for valid port %d, got: %v", tt.port, err)
			}
		})
	}
}

func TestConfig_Validate_SiteToSiteInvalidMaxTunnels(t *testing.T) {
	tests := []struct {
		name       string
		maxTunnels int
	}{
		{"zero tunnels", 0},
		{"negative tunnels", -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Enabled:                   true,
				AccessInterface:           "eth1",
				AccessSubnets:             []string{"10.0.0.0/24"},
				SiteToSiteEnabled:         true,
				SiteToSiteInterfacePrefix: "wg-s2s-",
				SiteToSiteListenPort:      51823,
				MaxSiteToSiteTunnels:      tt.maxTunnels,
				IngressEnabled:            BoolPtr(false),
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate should return error for invalid MaxSiteToSiteTunnels")
			}
			want := "bridge: config: MaxSiteToSiteTunnels must be positive when site-to-site is enabled"
			if err.Error() != want {
				t.Errorf("got %q, want %q", err.Error(), want)
			}
		})
	}
}

func TestConfig_Validate_SiteToSiteDisabled(t *testing.T) {
	cfg := Config{
		Enabled:           true,
		AccessInterface:   "eth1",
		AccessSubnets:     []string{"10.0.0.0/24"},
		SiteToSiteEnabled: false,
		IngressEnabled:    BoolPtr(false),
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate should return nil when site-to-site is disabled, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TunnelProviders validation tests
// ---------------------------------------------------------------------------

func TestConfig_Validate_TunnelProviders_Valid(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24"},
		TunnelProviders: []string{"ipsec", "openvpn"},
		IngressEnabled:  BoolPtr(false),
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate should accept valid tunnel providers, got: %v", err)
	}
}

func TestConfig_Validate_TunnelProviders_Invalid(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		AccessInterface: "eth1",
		AccessSubnets:   []string{"10.0.0.0/24"},
		TunnelProviders: []string{"ipsec", "gre"},
		IngressEnabled:  BoolPtr(false),
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate should return error for unsupported tunnel provider")
	}
	want := `bridge: config: unsupported TunnelProvider "gre"`
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

// ---------------------------------------------------------------------------
// ACME directory validation tests
// ---------------------------------------------------------------------------

func TestConfig_Validate_ACMEDirectoryURLs_Valid(t *testing.T) {
	for name, urls := range map[string][]string{
		"empty":         nil,
		"one directory": {"https://ca.example/dir"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := Config{
				Enabled:            true,
				AccessInterface:    "eth1",
				AccessSubnets:      []string{"10.0.0.0/24"},
				IngressEnabled:     BoolPtr(true),
				MaxIngressRules:    20,
				IngressDialTimeout: 10 * time.Second,
				ACMEDirectoryURLs:  urls,
			}
			if err := cfg.Validate(); err != nil {
				t.Errorf("Validate should accept acme_directory_urls %q, got: %v", urls, err)
			}
		})
	}
}

func TestConfig_Validate_ACMEDirectoryURLs_Invalid(t *testing.T) {
	const want = `bridge: config: acme_directory_urls: "http://ca.example/dir" is not an absolute https URL`
	for name, cfg := range map[string]Config{
		"ingress enabled": {
			Enabled:            true,
			AccessInterface:    "eth1",
			AccessSubnets:      []string{"10.0.0.0/24"},
			IngressEnabled:     BoolPtr(true),
			MaxIngressRules:    20,
			IngressDialTimeout: 10 * time.Second,
		},
		"ingress disabled": {
			Enabled:         true,
			AccessInterface: "eth1",
			AccessSubnets:   []string{"10.0.0.0/24"},
			IngressEnabled:  BoolPtr(false),
		},
		"bridge disabled": {},
	} {
		t.Run(name, func(t *testing.T) {
			cfg.ACMEDirectoryURLs = []string{"https://ca.example/dir", "http://ca.example/dir"}
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate should refuse an http directory")
			}
			if err.Error() != want {
				t.Errorf("got %q, want %q", err.Error(), want)
			}
		})
	}
}
