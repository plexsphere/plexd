---
title: Cloud VM Deployment Guide
quadrant: backend
---

# Cloud VM Deployment Guide

Step-by-step guide for deploying plexd on cloud virtual machines using Cloud-Init.

## Prerequisites

- **Cloud account** with VM provisioning access (AWS, GCP, Azure, OpenStack, or similar)
- **VM image** with cloud-init support (e.g., Ubuntu 22.04, Debian 12, Amazon Linux 2023)
- **Network connectivity** from the VM to the Plexsphere control plane API
- **Bootstrap token** from the control plane for node enrollment

## Quick start

Use the minimal cloud-init template to deploy a VM with plexd:

```yaml
#cloud-config
runcmd:
  - |
    set -eu
    curl -fsSL https://get.plexsphere.io/install.sh | sh -s -- \
      --token <YOUR_BOOTSTRAP_TOKEN> \
      --api-url https://api.your-plexsphere.io
```

Paste this as the user-data when launching a VM in your cloud provider.

## Using the cloud-init templates

### Full template

The full template writes a configuration file with metadata service support enabled, pre-provisions the bootstrap token, and runs the install script.

1. Copy `deploy/cloud-init/user-data.yaml`
2. Replace the template variables:

| Variable                | Description                    |
|-------------------------|--------------------------------|
| `PLEXD_API_URL`         | Control plane API URL          |
| `PLEXD_BOOTSTRAP_TOKEN` | Bootstrap token                |
| `PLEXD_VERSION`         | Version to install (`latest`)  |
| `PLEXD_HOSTNAME`        | Hostname override (optional)   |
| `PLEXD_LOG_LEVEL`       | Log level (`info`)             |

3. Pass the rendered template as VM user-data

### Minimal template

The minimal template only runs the install script with token and API URL. plexd uses defaults for all other settings.

1. Copy `deploy/cloud-init/user-data-minimal.yaml`
2. Replace `PLEXD_API_URL` and `PLEXD_BOOTSTRAP_TOKEN`
3. Pass as VM user-data

## Deploying with Terraform

### AWS EC2

1. Copy the example from `deploy/cloud-init/examples/terraform-aws.tf`
2. Provide the required variables:

```hcl
plexd_api_url         = "https://api.your-plexsphere.io"
plexd_bootstrap_token = "your-token-here"
ami_id                = "ami-0abcdef1234567890"  # Ubuntu 22.04
subnet_id             = "subnet-0123456789abcdef0"
```

3. Apply:

```sh
terraform init
terraform apply
```

The instance enforces IMDSv2 (`http_tokens = "required"`) for security.

### OpenStack

1. Copy the example from `deploy/cloud-init/examples/terraform-openstack.tf`
2. Provide the required variables:

```hcl
plexd_api_url         = "https://api.your-plexsphere.io"
plexd_bootstrap_token = "your-token-here"
image_name            = "Ubuntu 22.04"
network_name          = "internal-network"
```

3. Apply:

```sh
terraform init
terraform apply
```

## Using IMDS for token delivery

Instead of embedding the bootstrap token in user-data, you can deliver it through the cloud instance metadata service (IMDS). This avoids storing the token in cloud-init logs.

### 1. Set the metadata key

Set the key `/plexd/bootstrap-token` in your cloud provider's instance metadata with the bootstrap token value. The method varies by provider:

- **AWS**: Use instance tags or SSM Parameter Store with a startup script
- **OpenStack**: Set via `openstack server set --property plexd/bootstrap-token=<TOKEN>`
- **Custom**: Any HTTP endpoint that serves the token at the configured path

### 2. Configure plexd

In the cloud-init user-data, set `use_metadata: true` in the config:

```yaml
write_files:
  - path: /etc/plexd/config.yaml
    permissions: "0600"
    content: |
      api_url: "https://api.your-plexsphere.io"
      data_dir: /var/lib/plexd
      use_metadata: true
      metadata_token_path: /plexd/bootstrap-token
      metadata_timeout: 2s
```

plexd will query the IMDS at `{base_url}/plexd/bootstrap-token` during registration.

### Token resolution order

plexd checks these sources in priority order and uses the first non-empty result:

1. Direct value (`token_value` in config)
2. Token file (`/etc/plexd/bootstrap-token`)
3. Environment variable (`PLEXD_BOOTSTRAP_TOKEN`)
4. Metadata service (IMDS)

## Verification

### Check cloud-init status

```sh
cloud-init status --wait
```

Expected output: `status: done`

### Check plexd service

```sh
sudo systemctl status plexd
```

### View cloud-init logs

```sh
# Cloud-init output log
sudo cat /var/log/cloud-init-output.log

# Cloud-init detailed log
sudo cat /var/log/cloud-init.log | grep plexd
```

### View plexd logs

```sh
journalctl -u plexd -f
```

### Verify registration

```sh
plexd status
```

## Troubleshooting

### Cloud-init did not run

Check that your VM image has cloud-init installed and the datasource is configured:

```sh
cloud-init query datasource
```

### plexd install failed

Check the cloud-init output log for errors:

```sh
sudo cat /var/log/cloud-init-output.log | tail -50
```

Common issues:

- **Network unreachable**: The VM cannot reach the artifact server or control plane API. Check security groups and network ACLs.
- **Invalid token**: The bootstrap token is expired or malformed. Generate a new token from the control plane.
- **curl not found**: The minimal template assumes `curl` is installed. Use the full template (which installs `curl` via `packages`) or ensure `curl` is in the base image.

### IMDS token not found

If using metadata-based token delivery and plexd reports "no bootstrap token found":

1. Verify the metadata key is set: `curl -s http://169.254.169.254/plexd/bootstrap-token`
2. Check that `use_metadata: true` is in the config
3. Check that the metadata timeout hasn't been set too low for your provider

## See also

- [Cloud-Init VM Deployment Reference](../../reference/backend/cloud-init-vm-deployment.md) — Full reference for IMDSProvider, config fields, and templates
- [Bare-Metal Installation Guide](bare-metal-installation.md) — Bare-metal server installation
- [Registration Reference](../../reference/backend/registration.md) — Registration package documentation
