package bridge

import (
	"fmt"
	"net"
	"path/filepath"
	"time"
)

const (
	DefaultMaxIngressRules    = 20
	DefaultIngressDialTimeout = 10 * time.Second
)

// Config holds the configuration for bridge mode.
// Config is passed as a constructor argument — no file I/O in this package.
type Config struct {
	// Enabled controls whether bridge mode is active.
	// Default: false
	Enabled bool `yaml:"enabled"`

	// AccessInterface is the name of the access-side network interface.
	AccessInterface string `yaml:"access_interface"`

	// AccessSubnets are the CIDR subnets reachable via the access-side interface.
	AccessSubnets []string `yaml:"access_subnets"`

	// EnableNAT controls whether NAT masquerading is applied on the access-side interface.
	// nil means use default (true); explicit false disables NAT.
	EnableNAT *bool `yaml:"enable_nat"`

	// RelayEnabled is the local consent to serve as a relay: the relay runs
	// only while this is true and the state pull's bridge.relay block is
	// enabled, on the port that block names.
	// Default: false. Requires Enabled=true.
	RelayEnabled bool `yaml:"relay_enabled"`

	// UserAccessEnabled is the local switch for user access. nil and true
	// serve the providers the state pull's bridge.user_access block enables;
	// false opts the node out: plexd builds no user access manager, creates
	// no interface and starts no vendor client whatever the pull says.
	// Default: nil, which serves. An explicit true requires Enabled=true.
	UserAccessEnabled *bool `yaml:"user_access_enabled"`

	// The six keys below are ignored: the control plane delivers each user
	// access provider with its interface, port, devices and join Secret. They
	// stay parseable so that a configuration written for an older plexd still
	// loads, have no default and no validation, and plexd up names those that
	// are set in one Warn (see ReplacedUserAccessKeys).

	// UserAccessInterfaceName is ignored.
	UserAccessInterfaceName string `yaml:"user_access_interface_name"`

	// UserAccessListenPort is ignored.
	UserAccessListenPort int `yaml:"user_access_listen_port"`

	// MaxAccessPeers is ignored.
	MaxAccessPeers int `yaml:"max_access_peers"`

	// UserAccessProviderType is ignored.
	UserAccessProviderType string `yaml:"user_access_provider_type"`

	// AuthKeyEnv is ignored.
	AuthKeyEnv string `yaml:"auth_key_env"`

	// SetupKeyEnv is ignored.
	SetupKeyEnv string `yaml:"setup_key_env"`

	// IngressEnabled is the local switch for public ingress. nil and true serve
	// the rules the state pull's bridge.ingress block enables; false opts the
	// node out: plexd builds no ingress manager, opens no public listener
	// whatever the pull says, and reports opted_out to the control plane.
	// Default: nil, which serves. An explicit true requires Enabled=true.
	IngressEnabled *bool `yaml:"ingress_enabled"`

	// MaxIngressRules is the maximum number of concurrent ingress rules.
	// Default: 20
	MaxIngressRules int `yaml:"max_ingress_rules"`

	// IngressDialTimeout is the timeout for dialing target mesh peers.
	// Default: 10s. Minimum: 1s.
	IngressDialTimeout time.Duration `yaml:"ingress_dial_timeout"`

	// SiteToSiteEnabled is the local switch for site-to-site tunnels. nil and
	// true serve the tunnels the state pull's bridge.site_to_site block
	// enables; false opts the node out: plexd builds no site-to-site manager,
	// creates no tunnel link and routes no network behind a tunnel into the
	// mesh whatever the pull says.
	// Default: nil, which serves. An explicit true requires Enabled=true.
	SiteToSiteEnabled *bool `yaml:"site_to_site_enabled"`

	// The four keys below are ignored: the control plane delivers each
	// site-to-site tunnel with its kind, port and subnets. They stay
	// parseable so that a configuration written for an older plexd still
	// loads, have no default and no validation, and plexd up names those that
	// are set in one Warn (see ReplacedSiteToSiteKeys).

	// SiteToSiteInterfacePrefix is ignored.
	SiteToSiteInterfacePrefix string `yaml:"site_to_site_interface_prefix"`

	// SiteToSiteListenPort is ignored.
	SiteToSiteListenPort int `yaml:"site_to_site_listen_port"`

	// MaxSiteToSiteTunnels is ignored.
	MaxSiteToSiteTunnels int `yaml:"max_site_to_site_tunnels"`

	// TunnelProviders is ignored.
	TunnelProviders []string `yaml:"tunnel_providers"`

	// SwanctlConfDir is the directory plexd writes the strongSwan connection
	// file of each ipsec tunnel into, which the host's
	// /etc/swanctl/swanctl.conf includes as <dir>/*.conf. Empty means
	// <run dir>/swanctl, which plexd up resolves. A value must be an
	// absolute path.
	SwanctlConfDir string `yaml:"swanctl_conf_dir"`

	// ACMECacheDir is the directory that holds the ACME account key and the
	// certificates of the acme rules. Empty means <data_dir>/acme.
	ACMECacheDir string `yaml:"acme_cache_dir"`

	// ACMEDirectoryURLs bounds the ACME directories the bridge accepts from the
	// state pull's bridge.ingress.acme member. Empty accepts any https directory.
	ACMEDirectoryURLs []string `yaml:"acme_directory_urls"`
}

// BoolPtr returns a pointer to the given bool value.
func BoolPtr(v bool) *bool { return &v }

// natEnabled returns the effective NAT setting: true unless explicitly set to false.
func (c *Config) natEnabled() bool {
	if c.EnableNAT == nil {
		return true
	}
	return *c.EnableNAT
}

// IngressOptedOut reports whether the node opts out of public ingress: true
// exactly when IngressEnabled is set to false. An unset IngressEnabled serves.
func (c *Config) IngressOptedOut() bool {
	return c.IngressEnabled != nil && !*c.IngressEnabled
}

// UserAccessOptedOut reports whether the node opts out of user access: true
// exactly when UserAccessEnabled is set to false. An unset UserAccessEnabled
// serves.
func (c *Config) UserAccessOptedOut() bool {
	return c.UserAccessEnabled != nil && !*c.UserAccessEnabled
}

// ReplacedUserAccessKeys returns the YAML names of the ignored user access
// keys that are set to a value other than the zero value, in the order
// user_access_interface_name, user_access_listen_port, max_access_peers,
// user_access_provider_type, auth_key_env, setup_key_env, and nil when none
// is set.
func (c *Config) ReplacedUserAccessKeys() []string {
	var keys []string
	for _, k := range []struct {
		name string
		set  bool
	}{
		{"user_access_interface_name", c.UserAccessInterfaceName != ""},
		{"user_access_listen_port", c.UserAccessListenPort != 0},
		{"max_access_peers", c.MaxAccessPeers != 0},
		{"user_access_provider_type", c.UserAccessProviderType != ""},
		{"auth_key_env", c.AuthKeyEnv != ""},
		{"setup_key_env", c.SetupKeyEnv != ""},
	} {
		if k.set {
			keys = append(keys, k.name)
		}
	}
	return keys
}

// SiteToSiteOptedOut reports whether the node opts out of site-to-site
// tunnels: true exactly when SiteToSiteEnabled is set to false. An unset
// SiteToSiteEnabled serves.
func (c *Config) SiteToSiteOptedOut() bool {
	return c.SiteToSiteEnabled != nil && !*c.SiteToSiteEnabled
}

// ReplacedSiteToSiteKeys returns the YAML names of the ignored site-to-site
// keys that are set to a value other than the zero value, in the order
// site_to_site_interface_prefix, site_to_site_listen_port,
// max_site_to_site_tunnels, tunnel_providers, and nil when none is set.
func (c *Config) ReplacedSiteToSiteKeys() []string {
	var keys []string
	for _, k := range []struct {
		name string
		set  bool
	}{
		{"site_to_site_interface_prefix", c.SiteToSiteInterfacePrefix != ""},
		{"site_to_site_listen_port", c.SiteToSiteListenPort != 0},
		{"max_site_to_site_tunnels", c.MaxSiteToSiteTunnels != 0},
		{"tunnel_providers", len(c.TunnelProviders) != 0},
	} {
		if k.set {
			keys = append(keys, k.name)
		}
	}
	return keys
}

// ApplyDefaults sets default values for zero-valued fields.
func (c *Config) ApplyDefaults() {
	// EnableNAT is handled via natEnabled(); nil means default true.
	if c.MaxIngressRules == 0 {
		c.MaxIngressRules = DefaultMaxIngressRules
	}
	if c.IngressDialTimeout == 0 {
		c.IngressDialTimeout = DefaultIngressDialTimeout
	}
}

// Validate checks that configuration values are acceptable. When bridge mode
// is disabled, validation is skipped, except for acme_directory_urls and
// swanctl_conf_dir, which are checked whatever the other settings say.
func (c *Config) Validate() error {
	for _, u := range c.ACMEDirectoryURLs {
		if !ValidACMEDirectoryURL(u) {
			return fmt.Errorf("bridge: config: acme_directory_urls: %q is not an absolute https URL", u)
		}
	}
	if c.SwanctlConfDir != "" && !filepath.IsAbs(c.SwanctlConfDir) {
		return fmt.Errorf("bridge: config: swanctl_conf_dir: %q is not an absolute path", c.SwanctlConfDir)
	}
	if c.RelayEnabled && !c.Enabled {
		return fmt.Errorf("bridge: config: relay requires bridge mode to be enabled")
	}
	// Only an explicit true is refused outside bridge mode: an unset switch is
	// the default every node carries, and an explicit false opts out of
	// user access, ingress or site-to-site tunnels that do not run there
	// either.
	if c.UserAccessEnabled != nil && *c.UserAccessEnabled && !c.Enabled {
		return fmt.Errorf("bridge: config: user access requires bridge mode to be enabled")
	}
	if c.IngressEnabled != nil && *c.IngressEnabled && !c.Enabled {
		return fmt.Errorf("bridge: config: ingress requires bridge mode to be enabled")
	}
	if c.SiteToSiteEnabled != nil && *c.SiteToSiteEnabled && !c.Enabled {
		return fmt.Errorf("bridge: config: site-to-site requires bridge mode to be enabled")
	}
	if !c.Enabled {
		return nil
	}
	if c.AccessInterface == "" {
		return fmt.Errorf("bridge: config: AccessInterface is required when enabled")
	}
	if len(c.AccessSubnets) == 0 {
		return fmt.Errorf("bridge: config: at least one AccessSubnet is required when enabled")
	}
	for _, subnet := range c.AccessSubnets {
		if _, _, err := net.ParseCIDR(subnet); err != nil {
			return fmt.Errorf("bridge: config: invalid CIDR %q: %w", subnet, err)
		}
	}
	if !c.IngressOptedOut() {
		if c.MaxIngressRules <= 0 {
			return fmt.Errorf("bridge: config: MaxIngressRules must be positive when ingress is enabled")
		}
		if c.IngressDialTimeout < 1*time.Second {
			return fmt.Errorf("bridge: config: IngressDialTimeout must be at least 1s")
		}
	}
	return nil
}
