# main.tf - Secure DevSecOps Platform Infrastructure

terraform {
  required_version = ">= 1.6.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
  
  # Uncomment to use Terraform Cloud for state management
  # backend "remote" {
  #   organization = "your-org-name"
  #   workspaces {
  #     name = "secure-devsecops-platform"
  #   }
  # }
  
  # Default S3 backend for state management
  backend "s3" {
    bucket         = "terraform-state-secure-devsecops"
    key            = "global/s3/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
  }
}

# Provider configuration
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "SecureDevSecOps"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = "DevSecOps-Team"
    }
  }
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    args        = ["eks", "get-token", "--cluster-name", local.cluster_name]
    command     = "aws"
  }
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      args        = ["eks", "get-token", "--cluster-name", local.cluster_name]
      command     = "aws"
    }
  }
}

# Local variables
locals {
  cluster_name = "${var.platform_name}-eks-${var.environment}"
  vpc_name     = "${var.platform_name}-vpc-${var.environment}"
  
  # CIDR blocks for VPC and subnets
  vpc_cidr            = "10.0.0.0/16"
  public_subnet_cidrs = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  private_subnet_cidrs = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]
  
  # Security group rules
  cluster_sg_rules = {
    egress_all = {
      description      = "Allow all outbound traffic"
      from_port        = 0
      to_port          = 0
      protocol         = "-1"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = ["::/0"]
    }
    
    ingress_https_vpc = {
      description = "Allow HTTPS from within VPC"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = [local.vpc_cidr]
    }
  }
}

# VPC Module
module "vpc" {
  source = "./modules/vpc"
  
  name                 = local.vpc_name
  cidr                 = local.vpc_cidr
  azs                  = var.availability_zones
  private_subnets      = local.private_subnet_cidrs
  public_subnets       = local.public_subnet_cidrs
  
  # NAT Gateway for private subnet internet access
  enable_nat_gateway   = true
  single_nat_gateway   = var.environment != "prod" # Use multiple NAT gateways in prod
  
  # DNS settings
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  # VPC Flow Logs for network traffic auditing
  enable_flow_log                      = true
  flow_log_destination_type            = "s3"
  flow_log_destination_arn             = module.logs_bucket.s3_bucket_arn
  flow_log_traffic_type                = "ALL"
  flow_log_cloudwatch_log_group_kms_key_id = module.kms.key_arn
  
  # Tags for subnets to enable EKS auto-discovery
  public_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/elb"                      = "1"
  }
  
  private_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"             = "1"
  }
}

# KMS Module for encryption
module "kms" {
  source = "./modules/kms"
  
  alias_name              = "${var.platform_name}-key-${var.environment}"
  description             = "KMS key for encrypting resources in the Secure DevSecOps Platform"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  key_administrators = [
    "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/Admin"
  ]
  
  tags = {
    Purpose = "Encryption for DevSecOps platform resources"
  }
}

# S3 Bucket for logs with Object Lock for immutability
module "logs_bucket" {
  source = "./modules/s3"
  
  bucket_name          = "${var.platform_name}-logs-${var.environment}-${data.aws_caller_identity.current.account_id}"
  versioning_enabled   = true
  object_lock_enabled  = true
  
  # Server-side encryption using KMS
  sse_algorithm        = "aws:kms"
  kms_master_key_id    = module.kms.key_arn
  
  # Lifecycle rules for log rotation
  lifecycle_rules = [
    {
      id      = "log-rotation"
      enabled = true
      
      transition = [
        {
          days          = 30
          storage_class = "STANDARD_IA"
        },
        {
          days          = 90
          storage_class = "GLACIER"
        }
      ]
      
      expiration = {
        days = 365
      }
    }
  ]
  
  # Bucket policy to prevent deletion of logs
  bucket_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Deny"
        Principal = "*"
        Action = [
          "s3:DeleteObject",
          "s3:DeleteObjectVersion"
        ]
        Resource = "arn:aws:s3:::${var.platform_name}-logs-${var.environment}-${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringNotLike = {
            "aws:PrincipalARN": var.admin_role_arns
          }
        }
      }
    ]
  })
}

# ECR Repositories for container images
module "ecr_repositories" {
  source = "./modules/ecr"
  
  repositories = [
    {
      name                 = "vuln-scanner"
      image_tag_mutability = "IMMUTABLE"
      scan_on_push         = true
    },
    {
      name                 = "event-logger"
      image_tag_mutability = "IMMUTABLE"
      scan_on_push         = true
    },
    {
      name                 = "access-auditor"
      image_tag_mutability = "IMMUTABLE"
      scan_on_push         = true
    }
  ]
  
  # Enable encryption with KMS
  encryption_configuration = {
    encryption_type = "KMS"
    kms_key         = module.kms.key_arn
  }
}

# EKS Cluster
module "eks" {
  source = "./modules/eks"
  
  cluster_name                    = local.cluster_name
  cluster_version                 = var.kubernetes_version
  cluster_endpoint_private_access = true
  cluster_endpoint_public_access  = var.enable_public_endpoint
  
  # Use VPC from the VPC module
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets
  
  # Security groups
  cluster_security_group_additional_rules = local.cluster_sg_rules
  
  # Enable EKS managed node groups
  eks_managed_node_groups = {
    default = {
      name            = "default-node-group"
      instance_types  = var.worker_instance_types
      min_size        = var.min_worker_nodes
      max_size        = var.max_worker_nodes
      desired_size    = var.desired_worker_nodes
      
      # Use launch templates for additional customization
      create_launch_template = true
      launch_template_name   = "eks-node-group-lt"
      
      # Enable encryption for EBS volumes
      block_device_mappings = {
        xvda = {
          device_name = "/dev/xvda"
          ebs = {
            volume_size           = 50
            volume_type           = "gp3"
            encrypted             = true
            kms_key_id            = module.kms.key_arn
            delete_on_termination = true
          }
        }
      }
    }
  }
  
  # Enable IRSA (IAM Roles for Service Accounts)
  enable_irsa = true
  
  # Enable CloudWatch Container Insights for monitoring
  cloudwatch_log_group_kms_key_id = module.kms.key_arn
  cloudwatch_log_group_retention_in_days = 90
  
  # Add-ons
  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
    }
    aws-ebs-csi-driver = {
      most_recent = true
    }
  }
  
  # Enable EKS managed add-ons
  manage_aws_auth_configmap = true
  aws_auth_roles = var.map_roles
  
  # Enable encryption for Kubernetes secrets
  cluster_encryption_config = {
    provider_key_arn = module.kms.key_arn
    resources        = ["secrets"]
  }
}

# IAM roles for Kubernetes service accounts (IRSA)
module "iam_assumable_roles_for_services" {
  source = "./modules/iam/service-accounts"
  
  # Role for vulnerability scanner service
  vuln_scanner_role_name   = "vuln-scanner-role"
  vuln_scanner_namespace   = "vuln-scanner"
  vuln_scanner_sa_name     = "vuln-scanner-sa"
  vuln_scanner_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonECR-FullAccess",
    module.vuln_scanner_policy.policy_arn
  ]
  
  # Role for event logger service
  event_logger_role_name   = "event-logger-role"
  event_logger_namespace   = "event-logger"
  event_logger_sa_name     = "event-logger-sa"
  event_logger_policy_arns = [
    module.event_logger_policy.policy_arn
  ]
  
  # Role for access auditor service
  access_auditor_role_name   = "access-auditor-role"
  access_auditor_namespace   = "access-auditor"
  access_auditor_sa_name     = "access-auditor-sa"
  access_auditor_policy_arns = [
    module.access_auditor_policy.policy_arn
  ]
  
  # OIDC provider from EKS cluster
  oidc_provider_arn = module.eks.oidc_provider_arn
}

# Custom IAM policies for service-specific permissions
module "vuln_scanner_policy" {
  source = "./modules/iam/policy"
  
  name        = "vuln-scanner-policy"
  description = "Policy for vulnerability scanner service"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:DescribeImages",
          "ecr:GetAuthorizationToken"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${module.logs_bucket.s3_bucket_arn}/vulnerability-scans/*"
      }
    ]
  })
}

module "event_logger_policy" {
  source = "./modules/iam/policy"
  
  name        = "event-logger-policy"
  description = "Policy for security event logger service"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject"
        ]
        Resource = "${module.logs_bucket.s3_bucket_arn}/security-events/*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/eks/${local.cluster_name}/security-events:*"
      }
    ]
  })
}

module "access_auditor_policy" {
  source = "./modules/iam/policy"
  
  name        = "access-auditor-policy"
  description = "Policy for access auditor service"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "${module.logs_bucket.s3_bucket_arn}",
          "${module.logs_bucket.s3_bucket_arn}/access-logs/*"
        ]
      }
    ]
  })
}

# RDS PostgreSQL for audit database
module "rds" {
  source = "./modules/rds"
  
  create_db_instance = var.create_audit_db
  
  identifier           = "${var.platform_name}-audit-db-${var.environment}"
  engine               = "postgres"
  engine_version       = "14.7"
  family               = "postgres14"
  major_engine_version = "14"
  instance_class       = var.db_instance_class
  
  allocated_storage     = 20
  max_allocated_storage = 100
  
  db_name  = "auditdb"
  username = "auditadmin"
  port     = 5432
  
  # Use KMS for encryption
  storage_encrypted = true
  kms_key_id        = module.kms.key_arn
  
  # Network configuration
  subnet_ids             = module.vpc.private_subnets
  vpc_security_group_ids = [module.security_groups.db_security_group_id]
  
  # Backup and maintenance
  backup_retention_period = 35
  backup_window           = "03:00-06:00"
  maintenance_window      = "Mon:00:00-Mon:03:00"
  
  # Enhanced monitoring
  monitoring_interval    = 60
  monitoring_role_name   = "rds-monitoring-role"
  create_monitoring_role = true
  
  # Parameters
  parameters = [
    {
      name  = "log_connections"
      value = "1"
    },
    {
      name  = "log_disconnections"
      value = "1"
    },
    {
      name  = "log_statement"
      value = "all"
    },
    {
      name  = "log_min_duration_statement"
      value = "1000"
    }
  ]
  
  # Deletion protection
  deletion_protection = var.environment == "prod" ? true : false
}

# Security Groups
module "security_groups" {
  source = "./modules/security-groups"
  
  vpc_id = module.vpc.vpc_id
  
  # DB security group
  create_db_sg = var.create_audit_db
  db_sg_name   = "${var.platform_name}-db-sg-${var.environment}"
  db_sg_rules = {
    ingress_from_eks = {
      description     = "Allow PostgreSQL from EKS"
      from_port       = 5432
      to_port         = 5432
      protocol        = "tcp"
      security_groups = [module.eks.cluster_security_group_id]
    }
  }
  
  # ALB security group
  create_alb_sg = true
  alb_sg_name   = "${var.platform_name}-alb-sg-${var.environment}"
  alb_sg_rules = {
    ingress_https = {
      description = "HTTPS from internet"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
    egress_to_eks = {
      description     = "Traffic to EKS"
      from_port       = 0
      to_port         = 65535
      protocol        = "tcp"
      security_groups = [module.eks.cluster_security_group_id]
    }
  }
}

# AWS WAF for API Gateway/ALB
module "waf" {
  source = "./modules/waf"
  
  create_waf = var.enable_waf
  
  name        = "${var.platform_name}-waf-${var.environment}"
  description = "WAF for Secure DevSecOps Platform"
  
  # Associate with ALB
  alb_arn = var.alb_arn
  
  # Enable standard AWS managed rules
  enable_core_ruleset            = true
  enable_sql_injection_ruleset   = true
  enable_xss_ruleset             = true
  enable_admin_protection        = true
  enable_rate_limiting           = true
  rate_limit_threshold           = 2000
  
  # IP-based blocking
  ip_block_list = var.ip_block_list
}

# AWS Config for compliance monitoring
module "config" {
  source = "./modules/config"
  
  create_config = var.enable_config
  
  config_name         = "${var.platform_name}-config-${var.environment}"
  s3_bucket_name      = module.logs_bucket.s3_bucket_id
  sns_topic_name      = "${var.platform_name}-config-topic-${var.environment}"
  
  # Enable security best practice rules
  enable_iam_password_policy             = true
  enable_root_account_mfa                = true
  enable_s3_bucket_encryption            = true
  enable_s3_bucket_public_access_block   = true
  enable_encrypted_volumes               = true
  enable_vpc_flow_logs_enabled           = true
  enable_restricted_ssh                  = true
  enable_cloudtrail_enabled              = true
  enable_cloudwatch_log_group_encrypted  = true
  enable_ebs_snapshot_public_restorable  = true
}

# AWS GuardDuty for threat detection
module "guardduty" {
  source = "./modules/guardduty"
  
  create_guardduty = var.enable_guardduty
  
  guardduty_name                = "${var.platform_name}-guardduty-${var.environment}"
  findings_sns_topic_name       = "${var.platform_name}-guardduty-topic-${var.environment}"
  enable_s3_protection          = true
  enable_kubernetes_protection  = true
  enable_malware_protection     = true
  enable_findings_notification  = true
}

# AWS CloudTrail for API activity logging
module "cloudtrail" {
  source = "./modules/cloudtrail"
  
  create_cloudtrail = var.enable_cloudtrail
  
  cloudtrail_name            = "${var.platform_name}-cloudtrail-${var.environment}"
  s3_bucket_name             = module.logs_bucket.s3_bucket_id
  enable_log_file_validation = true
  is_multi_region_trail      = true
  include_global_service_events = true
  
  # Use KMS for encryption
  kms_key_id = module.kms.key_arn
  
  # Enable CloudWatch Logs integration
  enable_cloudwatch_logs      = true
  cloudwatch_logs_group_name  = "/aws/cloudtrail/${var.platform_name}-${var.environment}"
  cloudwatch_logs_retention   = 90
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
