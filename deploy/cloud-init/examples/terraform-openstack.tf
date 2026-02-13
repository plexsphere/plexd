# Terraform example: OpenStack compute instance with plexd Cloud-Init enrollment
#
# This provisions an OpenStack instance that auto-enrolls into the Plexsphere
# mesh using cloud-init user-data and a bootstrap token.

variable "plexd_api_url" {
  description = "Plexsphere control plane API URL"
  type        = string
}

variable "plexd_bootstrap_token" {
  description = "Bootstrap token for plexd enrollment"
  type        = string
  sensitive   = true
}

variable "plexd_version" {
  description = "plexd version to install"
  type        = string
  default     = "latest"
}

variable "flavor_name" {
  description = "OpenStack flavor name"
  type        = string
  default     = "m1.small"
}

variable "image_name" {
  description = "OpenStack image name (must support cloud-init, e.g. Ubuntu 22.04)"
  type        = string
}

variable "network_name" {
  description = "OpenStack network name"
  type        = string
}

variable "key_pair" {
  description = "SSH key pair name"
  type        = string
  default     = ""
}

data "cloudinit_config" "plexd" {
  gzip          = false
  base64_encode = true

  part {
    content_type = "text/cloud-config"
    content = templatefile("${path.module}/../user-data.yaml", {
      PLEXD_API_URL         = var.plexd_api_url
      PLEXD_BOOTSTRAP_TOKEN = var.plexd_bootstrap_token
      PLEXD_VERSION         = var.plexd_version
      PLEXD_HOSTNAME        = ""
      PLEXD_LOG_LEVEL       = "info"
    })
  }
}

resource "openstack_compute_instance_v2" "plexd_node" {
  name            = "plexd-node"
  flavor_name     = var.flavor_name
  image_name      = var.image_name
  key_pair        = var.key_pair != "" ? var.key_pair : null
  user_data       = data.cloudinit_config.plexd.rendered

  network {
    name = var.network_name
  }

  metadata = {
    managed_by = "plexsphere"
  }
}

output "instance_id" {
  description = "OpenStack instance ID"
  value       = openstack_compute_instance_v2.plexd_node.id
}

output "access_ip" {
  description = "Access IP address"
  value       = openstack_compute_instance_v2.plexd_node.access_ip_v4
}
