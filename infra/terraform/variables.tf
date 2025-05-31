# variables.tf - Secure DevSecOps Platform Variables

variable "aws_region" {
  description = "The AWS region to deploy resources into"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
  default     = "dev"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "platform_name" {
  description = "Name prefix for all platform resources"
  type        = string
  default     = "devsecops"
}

variable "availability_zones" {
  description = "List of availability zones to use for the subnets in the VPC"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "kubernetes_version" {
  description = "Kubernetes version to use for the EKS cluster"
  type        = string
  default     = "1.29"
}

variable "enable_public_endpoint" {
  description = "Whether to enable public access to the EKS cluster API endpoint"
  type        = bool
  default     = false
}

variable "worker_instance_types" {
  description = "List of instance types for the EKS worker nodes"
  type        = list(string)
  default     = ["t3.medium"]
}

variable "min_worker_nodes" {
  description = "Minimum number of worker nodes"
  type        = number
  default     = 2
}

variable "max_worker_nodes" {
  description = "Maximum number of worker nodes"
  type        = number
  default     = 5
}

variable "desired_worker_nodes" {
  description = "Desired number of worker nodes"
  type        = number
  default     = 2
}

variable "map_roles" {
  description = "Additional IAM roles to add to the aws-auth configmap"
  type = list(object({
    rolearn  = string
    username = string
    groups   = list(string)
  }))
  default = []
}

variable "admin_role_arns" {
  description = "List of IAM role ARNs that are allowed to delete objects from the logs bucket"
  type        = list(string)
  default     = []
}

variable "create_audit_db" {
  description = "Whether to create an RDS instance for audit logs"
  type        = bool
  default     = true
}

variable "db_instance_class" {
  description = "Instance class for the RDS database"
  type        = string
  default     = "db.t3.small"
}

variable "enable_waf" {
  description = "Whether to enable AWS WAF"
  type        = bool
  default     = true
}

variable "alb_arn" {
  description = "ARN of the ALB to associate with WAF (required if enable_waf is true)"
  type        = string
  default     = ""
}

variable "ip_block_list" {
  description = "List of IP addresses to block in WAF"
  type        = list(string)
  default     = []
}

variable "enable_config" {
  description = "Whether to enable AWS Config"
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "Whether to enable AWS GuardDuty"
  type        = bool
  default     = true
}

variable "enable_cloudtrail" {
  description = "Whether to enable AWS CloudTrail"
  type        = bool
  default     = true
}

# Optional variables with empty defaults
variable "domain_name" {
  description = "Domain name for the API Gateway and other services"
  type        = string
  default     = ""
}

variable "certificate_arn" {
  description = "ARN of the ACM certificate for HTTPS"
  type        = string
  default     = ""
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for security notifications"
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_eks_managed_upgrade" {
  description = "Whether to enable automatic EKS node upgrades"
  type        = bool
  default     = false
}

variable "enable_istio" {
  description = "Whether to install Istio service mesh via Terraform (alternative to manual installation)"
  type        = bool
  default     = false
}

variable "enable_argocd" {
  description = "Whether to install Argo CD via Terraform (alternative to manual installation)"
  type        = bool
  default     = false
}

variable "enable_falco" {
  description = "Whether to install Falco runtime security via Terraform"
  type        = bool
  default     = false
}

variable "ecr_image_scan_on_push" {
  description = "Whether to enable vulnerability scanning when images are pushed to ECR"
  type        = bool
  default     = true
}

variable "ecr_image_tag_mutability" {
  description = "Whether image tags are mutable (MUTABLE or IMMUTABLE)"
  type        = string
  default     = "IMMUTABLE"
  validation {
    condition     = contains(["MUTABLE", "IMMUTABLE"], var.ecr_image_tag_mutability)
    error_message = "ECR image tag mutability must be either MUTABLE or IMMUTABLE."
  }
}
