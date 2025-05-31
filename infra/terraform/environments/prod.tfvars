# Production Environment Configuration
# infra/terraform/environments/prod.tfvars

# General settings
aws_region    = "us-east-1"
environment   = "prod"
platform_name = "devsecops"

# High-availability configuration
availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]

# EKS cluster configuration
kubernetes_version     = "1.29"
enable_public_endpoint = false  # Private cluster for security
worker_instance_types  = ["m5.large"]  # Production-grade instances
min_worker_nodes       = 3  # Ensure high availability
max_worker_nodes       = 10 # Allow scaling for production loads
desired_worker_nodes   = 3
enable_eks_managed_upgrade = true  # Enable automatic upgrades

# Database configuration
create_audit_db    = true
db_instance_class  = "db.t3.medium"  # Production-grade instance

# Security configurations
enable_waf         = true
enable_config      = true
enable_guardduty   = true
enable_cloudtrail  = true

# ECR configuration
ecr_image_scan_on_push   = true
ecr_image_tag_mutability = "IMMUTABLE"  # Ensure image immutability for security

# Optional components
enable_istio  = true  # Enable service mesh for zero-trust networking
enable_argocd = true  # Enable GitOps
enable_falco  = true  # Enable runtime security monitoring

# Admin roles that can manage logs (replace with actual ARNs)
admin_role_arns = [
  "arn:aws:iam::ACCOUNT_ID:role/AdminRole"
]

# IP addresses to block (example - replace with actual IPs if needed)
ip_block_list = [
  # "192.0.2.1/32",  # Example malicious IP
]

# Domain configuration (replace with actual domain)
domain_name = "api.example.com"
