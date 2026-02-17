import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'plexd',
  description: 'Plexsphere Node Agent Documentation',
  base: '/plexd/',

  themeConfig: {
    nav: [
      { text: 'Home', link: '/' },
      { text: 'Concepts', link: '/concepts' },
      { text: 'How-To', link: '/how-to/bare-metal-installation' },
      { text: 'Reference', link: '/reference/core/cli' },
    ],

    sidebar: [
      {
        text: 'Getting Started',
        items: [
          { text: 'Overview', link: '/' },
          { text: 'Architecture & Concepts', link: '/concepts' },
        ],
      },
      {
        text: 'How-To Guides',
        items: [
          { text: 'Bare-Metal Installation', link: '/how-to/bare-metal-installation' },
          { text: 'Cloud VM Deployment', link: '/how-to/cloud-vm-deployment' },
          { text: 'Kubernetes Deployment', link: '/how-to/kubernetes-deployment' },
          { text: 'Local Node API', link: '/how-to/local-node-api' },
          { text: 'Custom Hook Scripts', link: '/how-to/custom-hook-scripts' },
        ],
      },
      {
        text: 'Reference',
        items: [
          {
            text: 'Core',
            collapsed: false,
            items: [
              { text: 'CLI', link: '/reference/core/cli' },
              { text: 'Configuration', link: '/reference/core/configuration' },
              { text: 'Environment Variables', link: '/reference/core/environment-variables' },
              { text: 'Control Plane Client', link: '/reference/core/control-plane-client' },
              { text: 'API Types', link: '/reference/core/api-types' },
              { text: 'Event Verification', link: '/reference/core/event-verification' },
              { text: 'Registration', link: '/reference/core/registration' },
              { text: 'Reconciliation', link: '/reference/core/reconciliation' },
              { text: 'Heartbeat Service', link: '/reference/core/heartbeat-service' },
              { text: 'Local Node API', link: '/reference/core/nodeapi' },
            ],
          },
          {
            text: 'Networking',
            collapsed: true,
            items: [
              { text: 'WireGuard Tunnels', link: '/reference/networking/wireguard' },
              { text: 'NAT Traversal (STUN)', link: '/reference/networking/nat-traversal' },
              { text: 'Peer Endpoint Exchange', link: '/reference/networking/peer-endpoint-exchange' },
              { text: 'Network Policy', link: '/reference/networking/network-policy' },
              { text: 'nftables Firewall', link: '/reference/networking/nftables-firewall' },
              { text: 'Secure Access Tunneling', link: '/reference/networking/secure-access-tunneling' },
            ],
          },
          {
            text: 'Bridge',
            collapsed: true,
            items: [
              { text: 'Bridge Mode', link: '/reference/bridge/bridge-mode' },
              { text: 'NAT Relay', link: '/reference/bridge/nat-relay' },
              { text: 'User Access Integration', link: '/reference/bridge/user-access-integration' },
              { text: 'VPN Providers', link: '/reference/bridge/vpn-providers' },
              { text: 'Public Ingress', link: '/reference/bridge/public-ingress' },
              { text: 'ACME & SNI Routing', link: '/reference/bridge/acme-sni' },
              { text: 'Site-to-Site VPN', link: '/reference/bridge/site-to-site-vpn' },
              { text: 'Tunnel Providers', link: '/reference/bridge/tunnel-providers' },
              { text: 'Netlink Route Controller', link: '/reference/bridge/netlink-route-controller' },
            ],
          },
          {
            text: 'Observability',
            collapsed: true,
            items: [
              { text: 'Metrics Collection', link: '/reference/observability/metrics-collection' },
              { text: 'Log Forwarding', link: '/reference/observability/log-forwarding' },
              { text: 'Audit Forwarding', link: '/reference/observability/audit-forwarding' },
            ],
          },
          {
            text: 'Actions',
            collapsed: true,
            items: [
              { text: 'Remote Actions & Hooks', link: '/reference/actions/remote-actions-hooks' },
              { text: 'PlexdHook CRD', link: '/reference/actions/plexdhook-crd' },
              { text: 'Integrity Verification', link: '/reference/actions/integrity-verification' },
            ],
          },
          {
            text: 'Deployment',
            collapsed: true,
            items: [
              { text: 'Bare-Metal Packaging', link: '/reference/deployment/bare-metal-packaging' },
              { text: 'Cloud-Init VM', link: '/reference/deployment/cloud-init-vm-deployment' },
              { text: 'Kubernetes DaemonSet', link: '/reference/deployment/kubernetes-deployment' },
              { text: 'Dockerfile', link: '/reference/deployment/dockerfile' },
            ],
          },
          {
            text: 'Development',
            collapsed: true,
            items: [
              { text: 'CI Workflow', link: '/reference/development/ci-workflow' },
              { text: 'Container Workflow', link: '/reference/development/container-workflow' },
              { text: 'Release Workflow', link: '/reference/development/release-workflow' },
              { text: 'E2E Workflow', link: '/reference/development/e2e-workflow' },
              { text: 'Docker E2E Test', link: '/reference/development/docker-e2e-test' },
              { text: 'Kubernetes E2E Test', link: '/reference/development/kubernetes-e2e-test' },
              { text: 'Systemd E2E Test', link: '/reference/development/systemd-e2e-test' },
              { text: 'Mock API Server', link: '/reference/development/mock-api-server' },
              { text: 'File System Utilities', link: '/reference/development/fsutil' },
            ],
          },
        ],
      },
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/plexsphere/plexd' },
    ],

    search: {
      provider: 'local',
    },

    outline: {
      level: [2, 3],
    },
  },
})
