# iac/secure/main.tf

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "mock_access_key"
  secret_key                  = "mock_secret_key"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  endpoints {
    s3  = "http://localhost:4566"
    ec2 = "http://localhost:4566"
  }
}

# COMPLIANT RESOURCE 1: Private Encrypted S3 Bucket with Public Access Block Enabled
resource "aws_s3_bucket" "secure_vault" {
  bucket = "company-private-secure-vault"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  public_access_block {
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
}

# COMPLIANT RESOURCE 2: Restricted SSH Ingress (Restricted to Internal VPN Subnet Range)
resource "aws_security_group" "secure_ssh_sg" {
  name        = "restricted-ssh-rules"
  description = "Compliant security group restricting SSH access to internal VPN subnet"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]  # Private Corporate Network Range Only
  }
}