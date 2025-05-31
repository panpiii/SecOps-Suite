# Secure DevSecOps Platform
# Master Makefile
#
# This Makefile provides centralized commands for managing the entire platform:
# - Infrastructure provisioning with Terraform
# - Kubernetes deployments
# - Service builds and deployments
# - Security scanning and compliance checks
# - Development utilities

# Load environment variables from .env file if it exists
-include .env

# Default environment
ENV ?= dev
AVAILABLE_ENVS := dev staging prod

# AWS settings
AWS_REGION ?= us-east-1
AWS_PROFILE ?= default

# Project settings
PROJECT_NAME ?= secure-devsecops-platform
PLATFORM_NAME ?= devsecops

# Infrastructure paths
TERRAFORM_DIR := infra/terraform
TERRAFORM_VARS := $(TERRAFORM_DIR)/environments/$(ENV).tfvars

# Kubernetes paths
K8S_DIR := k8s
K8S_BASE_DIR := $(K8S_DIR)/base
K8S_OVERLAY_DIR := $(K8S_DIR)/overlays/$(ENV)

# Service directories
SERVICES_DIR := services
SERVICE_NAMES := vuln-scanner event-logger access-auditor

# Tools versions
KUBECTL_VERSION ?= 1.29.0
TERRAFORM_VERSION ?= 1.6.0
HELM_VERSION ?= 3.13.0
ISTIO_VERSION ?= 1.20.0
ARGOCD_VERSION ?= 2.8.0
KUSTOMIZE_VERSION ?= 5.1.0

# Colors for terminal output
COLOR_RESET = \033[0m
COLOR_GREEN = \033[32m
COLOR_YELLOW = \033[33m
COLOR_CYAN = \033[36m
COLOR_RED = \033[31m

# Detect OS for proper commands
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	OPEN_CMD = xdg-open
endif
ifeq ($(UNAME_S),Darwin)
	OPEN_CMD = open
endif

#------------------------------------------------------------------------------
# Main targets
#------------------------------------------------------------------------------

.PHONY: all
all: init plan apply deploy ## Initialize, plan, apply infrastructure and deploy services

.PHONY: help
help: ## Show this help message
	@echo "$(COLOR_CYAN)Secure DevSecOps Platform$(COLOR_RESET)"
	@echo "$(COLOR_CYAN)Usage: make [target]$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_CYAN)Available targets:$(COLOR_RESET)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(COLOR_GREEN)%-30s$(COLOR_RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(COLOR_CYAN)Environment: $(COLOR_YELLOW)$(ENV)$(COLOR_RESET) (set with ENV=dev|staging|prod)"

#------------------------------------------------------------------------------
# Validation targets
#------------------------------------------------------------------------------

.PHONY: validate-env
validate-env:
	@if ! echo "$(AVAILABLE_ENVS)" | grep -w "$(ENV)" > /dev/null; then \
		echo "$(COLOR_RED)Error: Invalid environment '$(ENV)'. Available environments: $(AVAILABLE_ENVS)$(COLOR_RESET)"; \
		exit 1; \
	fi

.PHONY: validate-aws
validate-aws:
	@echo "$(COLOR_CYAN)Validating AWS credentials...$(COLOR_RESET)"
	@aws --profile $(AWS_PROFILE) sts get-caller-identity > /dev/null || \
		(echo "$(COLOR_RED)Error: AWS credentials not valid. Please run 'aws configure --profile $(AWS_PROFILE)'$(COLOR_RESET)" && exit 1)

.PHONY: validate-tools
validate-tools:
	@echo "$(COLOR_CYAN)Checking required tools...$(COLOR_RESET)"
	@command -v terraform >/dev/null 2>&1 || \
		(echo "$(COLOR_RED)Error: terraform is not installed. Visit https://developer.hashicorp.com/terraform/downloads$(COLOR_RESET)" && exit 1)
	@command -v kubectl >/dev/null 2>&1 || \
		(echo "$(COLOR_RED)Error: kubectl is not installed. Visit https://kubernetes.io/docs/tasks/tools$(COLOR_RESET)" && exit 1)
	@command -v helm >/dev/null 2>&1 || \
		(echo "$(COLOR_RED)Error: helm is not installed. Visit https://helm.sh/docs/intro/install$(COLOR_RESET)" && exit 1)
	@command -v docker >/dev/null 2>&1 || \
		(echo "$(COLOR_RED)Error: docker is not installed. Visit https://docs.docker.com/get-docker$(COLOR_RESET)" && exit 1)
	@command -v aws >/dev/null 2>&1 || \
		(echo "$(COLOR_RED)Error: aws cli is not installed. Visit https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html$(COLOR_RESET)" && exit 1)

#------------------------------------------------------------------------------
# Infrastructure targets
#------------------------------------------------------------------------------

.PHONY: init
init: validate-env validate-aws validate-tools ## Initialize Terraform
	@echo "$(COLOR_CYAN)Initializing Terraform for $(COLOR_YELLOW)$(ENV)$(COLOR_CYAN) environment...$(COLOR_RESET)"
	@cd $(TERRAFORM_DIR) && terraform init

.PHONY: plan
plan: validate-env validate-aws init ## Plan Terraform changes
	@echo "$(COLOR_CYAN)Planning Terraform changes for $(COLOR_YELLOW)$(ENV)$(COLOR_CYAN) environment...$(COLOR_RESET)"
	@cd $(TERRAFORM_DIR) && terraform plan -var-file=$(notdir $(TERRAFORM_VARS)) -out=tfplan

.PHONY: apply
apply: validate-env validate-aws ## Apply Terraform changes
	@echo "$(COLOR_CYAN)Applying Terraform changes for $(COLOR_YELLOW)$(ENV)$(COLOR_CYAN) environment...$(COLOR_RESET)"
	@cd $(TERRAFORM_DIR) && terraform apply tfplan

.PHONY: destroy
destroy: validate-env validate-aws ## Destroy Terraform-managed infrastructure
	@echo "$(COLOR_RED)WARNING: This will destroy all resources in the $(COLOR_YELLOW)$(ENV)$(COLOR_RED) environment!$(COLOR_RESET)"
	@echo "$(COLOR_RED)To continue, type the environment name '$(ENV)' and press Enter:$(COLOR_RESET)"
	@read -p "> " input && [ "$$input" = "$(ENV)" ] || (echo "$(COLOR_RED)Aborted.$(COLOR_RESET)" && exit 1)
	@cd $(TERRAFORM_DIR) && terraform destroy -var-file=$(notdir $(TERRAFORM_VARS))

.PHONY: output
output: validate-env ## Show Terraform outputs
	@cd $(TERRAFORM_DIR) && terraform output

.PHONY: state-list
state-list: validate-env ## List resources in Terraform state
	@cd $(TERRAFORM_DIR) && terraform state list

#------------------------------------------------------------------------------
# Kubernetes targets
#------------------------------------------------------------------------------

.PHONY: kubeconfig
kubeconfig: validate-env validate-aws ## Update kubeconfig for EKS cluster
	@echo "$(COLOR_CYAN)Updating kubeconfig for $(COLOR_YELLOW)$(ENV)$(COLOR_CYAN) environment...$(COLOR_RESET)"
	@aws --profile $(AWS_PROFILE) --region $(AWS_REGION) eks update-kubeconfig \
		--name $(PLATFORM_NAME)-eks-$(ENV)

.PHONY: k8s-apply
k8s-apply: validate-env kubeconfig ## Apply Kubernetes manifests using kustomize
	@echo "$(COLOR_CYAN)Applying Kubernetes manifests for $(COLOR_YELLOW)$(ENV)$(COLOR_CYAN) environment...$(COLOR_RESET)"
	@kubectl apply -k $(K8S_OVERLAY_DIR)

.PHONY: k8s-delete
k8s-delete: validate-env kubeconfig ## Delete Kubernetes resources
	@echo "$(COLOR_RED)WARNING: This will delete all Kubernetes resources in the $(COLOR_YELLOW)$(ENV)$(COLOR_RED) environment!$(COLOR_RESET)"
	@echo "$(COLOR_RED)To continue, type the environment name '$(ENV)' and press Enter:$(COLOR_RESET)"
	@read -p "> " input && [ "$$input" = "$(ENV)" ] || (echo "$(COLOR_RED)Aborted.$(COLOR_RESET)" && exit 1)
	@kubectl delete -k $(K8S_OVERLAY_DIR)

.PHONY: k8s-diff
k8s-diff: validate-env kubeconfig ## Show diff between current state and manifests
	@echo "$(COLOR_CYAN)Showing diff for Kubernetes manifests in $(COLOR_YELLOW)$(ENV)$(COLOR_CYAN) environment...$(COLOR_RESET)"
	@kubectl diff -k $(K8S_OVERLAY_DIR) || true

#------------------------------------------------------------------------------
# Add-on installation targets
#------------------------------------------------------------------------------

.PHONY: istio-install
istio-install: validate-env kubeconfig ## Install Istio service mesh
	@echo "$(COLOR_CYAN)Installing Istio in $(COLOR_YELLOW)$(ENV)$(COLOR_CYAN) environment...$(COLOR_RESET)"
	@helm repo add istio https://istio-release.storage.googleapis.com/charts
	@helm repo update
	@kubectl create namespace istio-system --dry-run=client -o yaml | kubectl apply -f -
	@helm upgrade --install istio-base istio/base -n istio-system --version $(ISTIO_VERSION)
	@helm upgrade --install istiod istio/istiod -n istio-system --version $(ISTIO_VERSION) --wait
	@helm upgrade --install istio-ingress istio/gateway -n istio-system --version $(ISTIO_VERSION)
	@kubectl label namespace default istio-injection=enabled --overwrite

.PHONY: argocd-install
argocd-install: validate-env kubeconfig ## Install Argo CD
	@echo "$(COLOR_CYAN)Installing Argo CD in $(COLOR_YELLOW)$(ENV)$(COLOR_CYAN) environment...$(COLOR_RESET)"
	@kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -
	@helm repo add argo https://argoproj.github.io/argo-helm
	@helm repo update
	@helm upgrade --install argocd argo/argo-cd -n argocd --version $(ARGOCD_VERSION)
	@echo "$(COLOR_GREEN)Argo CD installed. Run 'make argocd-password' to get the initial admin password.$(COLOR_RESET)"

.PHONY: falco-install
falco-install: validate-env kubeconfig ## Install Falco runtime security
	@echo "$(COLOR_CYAN)Installing Falco in $(COLOR_YELLOW)$(ENV)$(COLOR_CYAN) environment...$(COLOR_RESET)"
	@helm repo add falcosecurity https://falcosecurity.github.io/charts
	@helm repo update
	@kubectl create namespace falco --dry-run=client -o yaml | kubectl apply -f -
	@helm upgrade --install falco falcosecurity/falco -n falco

.PHONY: prometheus-install
prometheus-install: validate-env kubeconfig ## Install Prometheus monitoring stack
	@echo "$(COLOR_CYAN)Installing Prometheus in $(COLOR_YELLOW)$(ENV)$(COLOR_CYAN) environment...$(COLOR_RESET)"
	@helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
	@helm repo update
	@kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -
	@helm upgrade --install prometheus prometheus-community/kube-prometheus-stack -n monitoring

#------------------------------------------------------------------------------
# Service management targets
#------------------------------------------------------------------------------

.PHONY: build-all
build-all: $(addprefix build-,$(SERVICE_NAMES)) ## Build all services

.PHONY: push-all
push-all: $(addprefix push-,$(SERVICE_NAMES)) ## Push all service images to ECR

.PHONY: deploy-all
deploy-all: $(addprefix deploy-,$(SERVICE_NAMES)) ## Deploy all services

.PHONY: build-%
build-%: validate-aws ## Build a specific service
	@echo "$(COLOR_CYAN)Building service $(COLOR_YELLOW)$*$(COLOR_RESET)"
	@cd $(SERVICES_DIR)/$* && make docker-build

.PHONY: push-%
push-%: validate-aws ## Push a specific service image to ECR
	@echo "$(COLOR_CYAN)Pushing service $(COLOR_YELLOW)$*$(COLOR_RESET) to ECR"
	@cd $(SERVICES_DIR)/$* && make docker-push

.PHONY: deploy-%
deploy-%: validate-env kubeconfig ## Deploy a specific service
	@echo "$(COLOR_CYAN)Deploying service $(COLOR_YELLOW)$*$(COLOR_CYAN) to $(COLOR_YELLOW)$(ENV)$(COLOR_RESET)"
	@kubectl apply -k $(K8S_OVERLAY_DIR)/$*

.PHONY: logs-%
logs-%: validate-env kubeconfig ## View logs for a specific service
	@echo "$(COLOR_CYAN)Showing logs for service $(COLOR_YELLOW)$*$(COLOR_RESET)"
	@kubectl logs -n $* -l app=$* -f

.PHONY: test-%
test-%: ## Run tests for a specific service
	@echo "$(COLOR_CYAN)Running tests for service $(COLOR_YELLOW)$*$(COLOR_RESET)"
	@cd $(SERVICES_DIR)/$* && make test

#------------------------------------------------------------------------------
# Security and compliance targets
#------------------------------------------------------------------------------

.PHONY: security-scan
security-scan: ## Run security scans on all services
	@echo "$(COLOR_CYAN)Running security scans on all services...$(COLOR_RESET)"
	@for service in $(SERVICE_NAMES); do \
		echo "$(COLOR_YELLOW)Scanning $$service...$(COLOR_RESET)"; \
		(cd $(SERVICES_DIR)/$$service && make security-test && make docker-scan) || exit 1; \
	done

.PHONY: tf-security-scan
tf-security-scan: ## Run security scan on Terraform code
	@echo "$(COLOR_CYAN)Running security scan on Terraform code...$(COLOR_RESET)"
	@which tfsec > /dev/null || (echo "$(COLOR_RED)Error: tfsec not installed. Run 'go install github.com/aquasecurity/tfsec/cmd/tfsec@latest'$(COLOR_RESET)" && exit 1)
	@tfsec $(TERRAFORM_DIR)

.PHONY: k8s-security-scan
k8s-security-scan: ## Run security scan on Kubernetes manifests
	@echo "$(COLOR_CYAN)Running security scan on Kubernetes manifests...$(COLOR_RESET)"
	@which kubesec > /dev/null || (echo "$(COLOR_RED)Error: kubesec not installed. See https://kubesec.io/$(COLOR_RESET)" && exit 1)
	@find $(K8S_DIR) -name "*.yaml" -exec kubesec scan {} \;

.PHONY: compliance-check
compliance-check: ## Run compliance checks
	@echo "$(COLOR_CYAN)Running compliance checks...$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)Checking for secrets in git history...$(COLOR_RESET)"
	@which gitleaks > /dev/null || (echo "$(COLOR_RED)Error: gitleaks not installed. Run 'go install github.com/zricethezav/gitleaks/v8@latest'$(COLOR_RESET)" && exit 1)
	@gitleaks detect --verbose

#------------------------------------------------------------------------------
# Utility targets
#------------------------------------------------------------------------------

.PHONY: clean
clean: ## Clean build artifacts
	@echo "$(COLOR_CYAN)Cleaning build artifacts...$(COLOR_RESET)"
	@for service in $(SERVICE_NAMES); do \
		(cd $(SERVICES_DIR)/$$service && make clean); \
	done
	@rm -rf $(TERRAFORM_DIR)/.terraform/
	@rm -f $(TERRAFORM_DIR)/tfplan
	@rm -rf .terraform/

.PHONY: argocd-password
argocd-password: kubeconfig ## Get the Argo CD admin password
	@echo "$(COLOR_CYAN)Retrieving Argo CD admin password...$(COLOR_RESET)"
	@kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d
	@echo ""

.PHONY: argocd-port-forward
argocd-port-forward: kubeconfig ## Port forward Argo CD UI to localhost:8080
	@echo "$(COLOR_CYAN)Port forwarding Argo CD UI to localhost:8080...$(COLOR_RESET)"
	@echo "$(COLOR_CYAN)Access at: http://localhost:8080$(COLOR_RESET)"
	@kubectl port-forward svc/argocd-server -n argocd 8080:443

.PHONY: grafana-port-forward
grafana-port-forward: kubeconfig ## Port forward Grafana UI to localhost:3000
	@echo "$(COLOR_CYAN)Port forwarding Grafana UI to localhost:3000...$(COLOR_RESET)"
	@echo "$(COLOR_CYAN)Access at: http://localhost:3000$(COLOR_RESET)"
	@kubectl port-forward svc/prometheus-grafana -n monitoring 3000:80

.PHONY: list-services
list-services: kubeconfig ## List all services and their endpoints
	@echo "$(COLOR_CYAN)Services in $(COLOR_YELLOW)$(ENV)$(COLOR_CYAN) environment:$(COLOR_RESET)"
	@kubectl get svc --all-namespaces -o wide

.PHONY: list-pods
list-pods: kubeconfig ## List all pods and their status
	@echo "$(COLOR_CYAN)Pods in $(COLOR_YELLOW)$(ENV)$(COLOR_CYAN) environment:$(COLOR_RESET)"
	@kubectl get pods --all-namespaces -o wide

.PHONY: create-env-file
create-env-file: ## Create a template .env file
	@if [ -f .env ]; then \
		echo "$(COLOR_YELLOW)Warning: .env file already exists. Creating .env.example instead.$(COLOR_RESET)"; \
		output_file=".env.example"; \
	else \
		output_file=".env"; \
	fi; \
	echo "# Secure DevSecOps Platform Environment Variables" > $$output_file; \
	echo "# Created on $$(date)" >> $$output_file; \
	echo "" >> $$output_file; \
	echo "# AWS Configuration" >> $$output_file; \
	echo "AWS_PROFILE=default" >> $$output_file; \
	echo "AWS_REGION=us-east-1" >> $$output_file; \
	echo "" >> $$output_file; \
	echo "# Environment" >> $$output_file; \
	echo "ENV=dev" >> $$output_file; \
	echo "" >> $$output_file; \
	echo "# Platform Configuration" >> $$output_file; \
	echo "PLATFORM_NAME=devsecops" >> $$output_file; \
	echo "DOMAIN_NAME=example.com" >> $$output_file; \
	echo "" >> $$output_file; \
	echo "# Created $$output_file"

.PHONY: version
version: ## Show versions of installed tools
	@echo "$(COLOR_CYAN)Installed tool versions:$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)Terraform:$(COLOR_RESET) $$(terraform version | head -n1 | cut -d 'v' -f2)"
	@echo "$(COLOR_YELLOW)Kubectl:$(COLOR_RESET) $$(kubectl version --client --short | cut -d ' ' -f3)"
	@echo "$(COLOR_YELLOW)Helm:$(COLOR_RESET) $$(helm version --short | cut -d '+' -f1 | cut -d 'v' -f2)"
	@echo "$(COLOR_YELLOW)Docker:$(COLOR_RESET) $$(docker --version | cut -d ' ' -f3 | sed 's/,//')"
	@echo "$(COLOR_YELLOW)AWS CLI:$(COLOR_RESET) $$(aws --version | cut -d ' ' -f1 | cut -d '/' -f2)"
	@echo "$(COLOR_YELLOW)Go:$(COLOR_RESET) $$(go version | cut -d ' ' -f3 | sed 's/go//')"
