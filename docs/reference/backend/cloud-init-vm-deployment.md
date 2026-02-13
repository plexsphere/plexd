---
title: Cloud-Init VM Deployment Reference
quadrant: backend
package: internal/registration
feature: PXD-0021
---

# Cloud-Init VM Deployment Reference

Reference documentation for deploying plexd on virtual machines using Cloud-Init. Covers the IMDS provider, metadata-related configuration fields, cloud-init templates, and Terraform examples.

## IMDSProvider

`IMDSProvider` implements the `MetadataProvider` interface by reading a bootstrap token from a cloud instance metadata service (IMDS) over HTTP. It supports IMDSv2 (session-based) with automatic fallback to IMDSv1.

```go
type IMDSProvider struct {
    baseURL   string
    tokenPath string
    client    *http.Client
}
```

### Constructor

```go
func NewIMDSProvider(cfg *Config, baseURL string) *IMDSProvider
```

| Parameter | Type      | Description                                          |
|-----------|-----------|------------------------------------------------------|
| `cfg`     | `*Config` | Registration config (reads `MetadataTokenPath`, `MetadataTimeout`) |
| `baseURL` | `string`  | IMDS base URL (trailing slashes stripped)             |

### ReadToken

```go
func (p *IMDSProvider) ReadToken(ctx context.Context) (string, error)
```

Fetches `{baseURL}{tokenPath}` via HTTP GET. Before the GET, attempts IMDSv2 session token acquisition via PUT to `/latest/api/token`. If IMDSv2 is unavailable, falls back to unauthenticated IMDSv1 GET.

**Request behavior:**

- IMDSv2 session: `PUT {baseURL}/latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds: 21600`
- Method: `GET`
- URL: `baseURL + cfg.MetadataTokenPath`
- Auth: `X-aws-ec2-metadata-token: {sessionToken}` (omitted if IMDSv2 session acquisition failed)
- Timeout: `cfg.MetadataTimeout` (HTTP client timeout)
- Body limit: 513 bytes (`maxTokenLength + 1`) — reads one byte beyond the limit to detect oversized responses without silently truncating
- Context: request is context-aware and cancellable

**Error conditions:**

| Condition            | Error message                                |
|----------------------|----------------------------------------------|
| Request creation     | `registration: imds: create request: {err}`  |
| HTTP failure         | `registration: imds: request failed: {err}`  |
| Non-200 status       | `registration: imds: unexpected status {code}`|
| Body read failure    | `registration: imds: read body: {err}`       |
| Empty response       | `registration: imds: empty token`            |

## Config fields (metadata)

These fields were added to `registration.Config` for IMDS support:

| Field               | Type            | Default                  | Description                                      |
|---------------------|-----------------|--------------------------|--------------------------------------------------|
| `UseMetadata`       | `bool`          | `false`                  | Enable cloud metadata token source               |
| `MetadataTokenPath` | `string`        | `/plexd/bootstrap-token` | Metadata key path for the bootstrap token        |
| `MetadataTimeout`   | `time.Duration` | `2s`                     | Maximum time to wait for metadata service response|

`ApplyDefaults()` sets `MetadataTokenPath` and `MetadataTimeout` when zero-valued. `UseMetadata` defaults to `false` and must be explicitly enabled.

## Token resolution with IMDS

When `UseMetadata` is `true` and an `IMDSProvider` (or any `MetadataProvider`) is set, the metadata source is checked as the fourth priority:

1. Direct value (`Config.TokenValue`)
2. File (`Config.TokenFile`)
3. Environment variable (`Config.TokenEnv`)
4. **Metadata service** (`MetadataProvider.ReadToken`)

If the metadata service returns an error, the resolver falls through to the "no token found" error. Metadata errors are not propagated — they are treated as "source unavailable."

```go
cfg := &registration.Config{
    DataDir:           "/var/lib/plexd",
    UseMetadata:       true,
    MetadataTokenPath: "/plexd/bootstrap-token",
    MetadataTimeout:   2 * time.Second,
}
cfg.ApplyDefaults()

provider := registration.NewIMDSProvider(cfg, "http://169.254.169.254")
resolver := registration.NewTokenResolver(cfg, provider)
result, err := resolver.Resolve(ctx)
```

## Cloud-Init templates

### user-data.yaml (full)

Location: `deploy/cloud-init/user-data.yaml`

Full cloud-init template that writes configuration files and installs plexd.

**Template variables:**

| Variable                | Required | Default  | Description                    |
|-------------------------|----------|----------|--------------------------------|
| `PLEXD_API_URL`         | yes      | —        | Control plane API URL          |
| `PLEXD_BOOTSTRAP_TOKEN` | yes      | —        | Bootstrap token for enrollment |
| `PLEXD_VERSION`         | no       | `latest` | plexd version to install       |
| `PLEXD_HOSTNAME`        | no       | —        | Hostname override              |
| `PLEXD_LOG_LEVEL`       | no       | `info`   | Log level                      |

**Actions performed:**

1. `package_update: true` — updates package lists
2. Writes `/etc/plexd/config.yaml` (0600) — full configuration with `use_metadata: true`
3. Writes `/etc/plexd/bootstrap-token` (0600) — bootstrap token
4. Runs `install.sh` with `--token`, `--api-url`, `--version`

### user-data-minimal.yaml

Location: `deploy/cloud-init/user-data-minimal.yaml`

Minimal template that only writes the bootstrap token file. No runcmd — assumes plexd is pre-installed.

**Template variables:**

| Variable                | Required | Description                    |
|-------------------------|----------|--------------------------------|
| `PLEXD_BOOTSTRAP_TOKEN` | yes      | Bootstrap token for enrollment |

**Actions performed:**

1. Writes `/etc/plexd/bootstrap-token` (0600) — bootstrap token

## Terraform examples

### AWS EC2

Location: `deploy/cloud-init/examples/terraform-aws.tf`

Provisions an AWS EC2 instance with plexd enrollment via `cloudinit_config` data source.

| Variable                | Type     | Default     | Description                              |
|-------------------------|----------|-------------|------------------------------------------|
| `plexd_api_url`         | `string` | —           | Control plane API URL                    |
| `plexd_bootstrap_token` | `string` | —           | Bootstrap token (sensitive)              |
| `plexd_version`         | `string` | `latest`    | plexd version                            |
| `instance_type`         | `string` | `t3.micro`  | EC2 instance type                        |
| `ami_id`                | `string` | —           | AMI ID (must support cloud-init)         |
| `subnet_id`             | `string` | —           | Subnet ID                                |
| `key_name`              | `string` | `""`        | SSH key pair name (optional)             |

**Security:** Enforces IMDSv2 (`http_tokens = "required"`).

### OpenStack

Location: `deploy/cloud-init/examples/terraform-openstack.tf`

Provisions an OpenStack compute instance with plexd enrollment.

| Variable                | Type     | Default     | Description                              |
|-------------------------|----------|-------------|------------------------------------------|
| `plexd_api_url`         | `string` | —           | Control plane API URL                    |
| `plexd_bootstrap_token` | `string` | —           | Bootstrap token (sensitive)              |
| `plexd_version`         | `string` | `latest`    | plexd version                            |
| `flavor_name`           | `string` | `m1.small`  | OpenStack flavor                         |
| `image_name`            | `string` | —           | Image name (must support cloud-init)     |
| `network_name`          | `string` | —           | Network name                             |
| `key_pair`              | `string` | `""`        | SSH key pair name (optional)             |

## Cloud provider IMDS endpoints

Reference table for common cloud provider IMDS base URLs:

| Provider     | Base URL                                          | Auth mechanism          |
|--------------|---------------------------------------------------|-------------------------|
| AWS          | `http://169.254.169.254`                          | IMDSv2 session token (automatic) |
| GCP          | `http://metadata.google.internal/computeMetadata/v1` | `Metadata-Flavor: Google` header |
| Azure        | `http://169.254.169.254/metadata/instance`        | `Metadata: true` header |
| OpenStack    | `http://169.254.169.254/openstack/latest/meta_data.json` | None            |
| DigitalOcean | `http://169.254.169.254/metadata/v1`              | None                    |

## See also

- [Registration Reference](registration.md) — Full registration package documentation
- [Bare-Metal Installation Guide](../../how-to/backend/bare-metal-installation.md) — Bare-metal server installation
- [Cloud VM Deployment Guide](../../how-to/backend/cloud-vm-deployment.md) — Step-by-step VM deployment guide
