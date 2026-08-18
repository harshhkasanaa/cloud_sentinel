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

# Misconfiguration 1: Insecure S3 Bucket missing encryption and public block
resource "aws_s3_bucket" "vulnerable_data_bucket" {
  bucket = "company-sensitive-data-bucket"
}

# Misconfiguration 2: Security Group exposing SSH (Port 22) to 0.0.0.0/0
resource "aws_security_group" "vulnerable_ssh_sg" {
  name        = "open-ssh-sg"
  description = "Security group with unrestricted SSH ingress"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Misconfiguration 3: Security Group exposing RDP (Port 3389) to 0.0.0.0/0
resource "aws_security_group" "vulnerable_rdp_sg" {
  name        = "open-rdp-sg"
  description = "Security group with unrestricted RDP ingress"

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}