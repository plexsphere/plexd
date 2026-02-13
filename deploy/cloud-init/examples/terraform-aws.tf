# Terraform example: AWS EC2 instance with plexd Cloud-Init enrollment
#
# This provisions an EC2 instance that auto-enrolls into the Plexsphere
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

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "ami_id" {
  description = "AMI ID (must support cloud-init, e.g. Ubuntu 22.04)"
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID for the instance"
  type        = string
}

variable "key_name" {
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

resource "aws_instance" "plexd_node" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  key_name               = var.key_name != "" ? var.key_name : null
  user_data_base64       = data.cloudinit_config.plexd.rendered
  user_data_replace_on_change = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = {
    Name      = "plexd-node"
    ManagedBy = "plexsphere"
  }
}

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.plexd_node.id
}

output "private_ip" {
  description = "Private IP address"
  value       = aws_instance.plexd_node.private_ip
}
