# Terraform configuration block
# Specifies which version of Terraform and which providers we need
# A provider is a plugin that knows how to talk to a specific cloud
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Provider configuration
# Tells the AWS provider which region to create resources in
# We use a variable so this can be changed without editing the code
provider "aws" {
  region = var.aws_region
}

# Variable declarations
# Variables make Terraform reusable — same code, different environments
variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "devsecops-project1"
}

# ECR Repository
# This is the same repo we created via CLI — here it's defined as code
# Checkov will scan this and verify security settings are correct
resource "aws_ecr_repository" "app" {
  name                 = var.project_name
  image_tag_mutability = "IMMUTABLE"
  # IMMUTABLE means once an image is pushed with a tag, that tag
  # cannot be overwritten. This prevents supply chain attacks where
  # an attacker replaces a known-good image with a malicious one.
  # We used MUTABLE when creating via CLI — Checkov will flag that.

  # Enable vulnerability scanning on every push
  image_scanning_configuration {
    scan_on_push = true
  }

  # Encrypt images at rest using AES256
  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    Project     = var.project_name
    ManagedBy   = "terraform"
    Environment = "dev"
  }
}

# ECR Lifecycle Policy
# Automatically deletes old untagged images to control storage costs
# Without this, every pipeline run adds a new image forever
resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 10 images, delete older untagged"
        selection = {
          tagStatus   = "untagged"
          countType   = "imageCountMoreThan"
          countNumber = 10
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

# S3 bucket for storing pipeline artifacts
# Checkov will scan this and flag any missing security controls
resource "aws_s3_bucket" "artifacts" {
  # INTENTIONAL MISCONFIGURATION — Checkov will catch this
  # bucket name without random suffix means it could conflict
  bucket = "${var.project_name}-artifacts"

  tags = {
    Project   = var.project_name
    ManagedBy = "terraform"
  }
}

# S3 bucket versioning — keeps history of every file version
# Required by CIS Benchmark and most compliance frameworks
resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 bucket encryption — encrypt all objects at rest
resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 public access block — prevent any public access to this bucket
# This is critical — S3 buckets exposed publicly caused many breaches
# Checkov check: CKV_AWS_53, CKV_AWS_54, CKV_AWS_55, CKV_AWS_56
resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Outputs — values Terraform prints after apply
# Useful for referencing resources in scripts or other configs
output "ecr_repository_uri" {
  description = "URI of the ECR repository"
  value       = aws_ecr_repository.app.repository_url
}

output "artifacts_bucket_name" {
  description = "Name of the S3 artifacts bucket"
  value       = aws_s3_bucket.artifacts.id
}