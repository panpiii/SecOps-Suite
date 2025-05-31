# Makefile for Vulnerability Scanner Service
# Part of the Secure DevSecOps Platform

# Variables
SERVICE_NAME := vuln-scanner
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
REGISTRY ?= $(shell aws ecr describe-repositories --repository-names $(SERVICE_NAME) --query 'repositories[0].repositoryUri' --output text 2>/dev/null || echo "localhost:5000")
IMAGE_NAME := $(REGISTRY)/$(SERVICE_NAME)
IMAGE_TAG ?= $(VERSION)
FULL_IMAGE_NAME := $(IMAGE_NAME):$(IMAGE_TAG)

# Go build variables
GOOS ?= linux
GOARCH ?= amd64
CGO_ENABLED ?= 0
GO_BUILD_FLAGS := -trimpath -ldflags="-s -w -X main.version=$(VERSION)"

# Docker build variables
DOCKER_BUILD_ARGS := --build-arg VERSION=$(VERSION) \
                    --build-arg BUILD_DATE=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ') \
                    --build-arg VCS_REF=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Local development variables
LOCAL_PORT ?= 8080
CONFIG_FILE ?= config/local.yaml

# AWS variables
AWS_REGION ?= us-east-1
AWS_PROFILE ?= default

# Colors for terminal output
COLOR_RESET = \033[0m
COLOR_GREEN = \033[32m
COLOR_YELLOW = \033[33m
COLOR_CYAN = \033[36m

# Default target
.PHONY: all
all: lint test build

# Build the Go binary
.PHONY: build
build:
	@echo "$(COLOR_CYAN)Building $(SERVICE_NAME) binary...$(COLOR_RESET)"
	@mkdir -p bin
	@GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) go build $(GO_BUILD_FLAGS) -o bin/$(SERVICE_NAME) ./cmd/server

# Run tests
.PHONY: test
test:
	@echo "$(COLOR_CYAN)Running tests...$(COLOR_RESET)"
	@go test -v -race -cover ./...

# Run security tests
.PHONY: security-test
security-test:
	@echo "$(COLOR_CYAN)Running security tests...$(COLOR_RESET)"
	@which gosec > /dev/null || go install github.com/securego/gosec/v2/cmd/gosec@latest
	@gosec -quiet ./...

# Run linting
.PHONY: lint
lint:
	@echo "$(COLOR_CYAN)Running linters...$(COLOR_RESET)"
	@which golangci-lint > /dev/null || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@golangci-lint run ./...

# Format code
.PHONY: fmt
fmt:
	@echo "$(COLOR_CYAN)Formatting code...$(COLOR_RESET)"
	@go fmt ./...
	@gofmt -s -w .

# Clean build artifacts
.PHONY: clean
clean:
	@echo "$(COLOR_CYAN)Cleaning build artifacts...$(COLOR_RESET)"
	@rm -rf bin/
	@rm -rf dist/
	@go clean -cache -testcache

# Run the service locally
.PHONY: run
run:
	@echo "$(COLOR_CYAN)Running service locally on port $(LOCAL_PORT)...$(COLOR_RESET)"
	@go run ./cmd/server

# Build Docker image
.PHONY: docker-build
docker-build:
	@echo "$(COLOR_CYAN)Building Docker image: $(FULL_IMAGE_NAME)$(COLOR_RESET)"
	@docker build $(DOCKER_BUILD_ARGS) -t $(FULL_IMAGE_NAME) -f Dockerfile .
	@echo "$(COLOR_GREEN)Successfully built $(FULL_IMAGE_NAME)$(COLOR_RESET)"

# Push Docker image to registry
.PHONY: docker-push
docker-push: docker-build
	@echo "$(COLOR_CYAN)Pushing Docker image: $(FULL_IMAGE_NAME)$(COLOR_RESET)"
	@docker push $(FULL_IMAGE_NAME)
	@echo "$(COLOR_GREEN)Successfully pushed $(FULL_IMAGE_NAME)$(COLOR_RESET)"

# Login to AWS ECR
.PHONY: ecr-login
ecr-login:
	@echo "$(COLOR_CYAN)Logging in to AWS ECR in $(AWS_REGION)...$(COLOR_RESET)"
	@aws ecr get-login-password --region $(AWS_REGION) --profile $(AWS_PROFILE) | docker login --username AWS --password-stdin $(shell echo $(REGISTRY) | cut -d/ -f1)
	@echo "$(COLOR_GREEN)Successfully logged in to ECR$(COLOR_RESET)"

# Run Docker image locally
.PHONY: docker-run
docker-run: docker-build
	@echo "$(COLOR_CYAN)Running Docker image locally on port $(LOCAL_PORT)...$(COLOR_RESET)"
	@docker run --rm -p $(LOCAL_PORT):8080 \
		-e LOG_LEVEL=debug \
		-e AWS_REGION=$(AWS_REGION) \
		$(FULL_IMAGE_NAME)

# Scan Docker image for vulnerabilities
.PHONY: docker-scan
docker-scan: docker-build
	@echo "$(COLOR_CYAN)Scanning Docker image for vulnerabilities...$(COLOR_RESET)"
	@which trivy > /dev/null || echo "$(COLOR_YELLOW)Trivy not found. Please install it: https://aquasecurity.github.io/trivy/$(COLOR_RESET)"
	@trivy image --severity HIGH,CRITICAL $(FULL_IMAGE_NAME)

# Generate SBOM
.PHONY: sbom
sbom:
	@echo "$(COLOR_CYAN)Generating Software Bill of Materials (SBOM)...$(COLOR_RESET)"
	@which syft > /dev/null || echo "$(COLOR_YELLOW)Syft not found. Please install it: https://github.com/anchore/syft$(COLOR_RESET)"
	@syft $(FULL_IMAGE_NAME) -o cyclonedx-json > sbom.json
	@echo "$(COLOR_GREEN)Generated SBOM at sbom.json$(COLOR_RESET)"

# Sign the Docker image
.PHONY: sign-image
sign-image:
	@echo "$(COLOR_CYAN)Signing Docker image with cosign...$(COLOR_RESET)"
	@which cosign > /dev/null || echo "$(COLOR_YELLOW)Cosign not found. Please install it: https://github.com/sigstore/cosign$(COLOR_RESET)"
	@cosign sign --key cosign.key $(FULL_IMAGE_NAME)

# Generate Go module documentation
.PHONY: docs
docs:
	@echo "$(COLOR_CYAN)Generating documentation...$(COLOR_RESET)"
	@which godoc > /dev/null || go install golang.org/x/tools/cmd/godoc@latest
	@echo "$(COLOR_GREEN)Run 'godoc -http=:6060' and visit http://localhost:6060/pkg/$(shell go list -m)$(COLOR_RESET)"

# Show help
.PHONY: help
help:
	@echo "$(COLOR_CYAN)Available targets:$(COLOR_RESET)"
	@echo "  $(COLOR_GREEN)all$(COLOR_RESET)          - Run lint, test, and build"
	@echo "  $(COLOR_GREEN)build$(COLOR_RESET)        - Build the Go binary"
	@echo "  $(COLOR_GREEN)test$(COLOR_RESET)         - Run tests"
	@echo "  $(COLOR_GREEN)security-test$(COLOR_RESET) - Run security tests with gosec"
	@echo "  $(COLOR_GREEN)lint$(COLOR_RESET)         - Run linters"
	@echo "  $(COLOR_GREEN)fmt$(COLOR_RESET)          - Format code"
	@echo "  $(COLOR_GREEN)clean$(COLOR_RESET)        - Clean build artifacts"
	@echo "  $(COLOR_GREEN)run$(COLOR_RESET)          - Run service locally"
	@echo "  $(COLOR_GREEN)docker-build$(COLOR_RESET) - Build Docker image"
	@echo "  $(COLOR_GREEN)docker-push$(COLOR_RESET)  - Push Docker image to registry"
	@echo "  $(COLOR_GREEN)ecr-login$(COLOR_RESET)    - Login to AWS ECR"
	@echo "  $(COLOR_GREEN)docker-run$(COLOR_RESET)   - Run Docker image locally"
	@echo "  $(COLOR_GREEN)docker-scan$(COLOR_RESET)  - Scan Docker image for vulnerabilities"
	@echo "  $(COLOR_GREEN)sbom$(COLOR_RESET)         - Generate Software Bill of Materials"
	@echo "  $(COLOR_GREEN)sign-image$(COLOR_RESET)   - Sign the Docker image with cosign"
	@echo "  $(COLOR_GREEN)docs$(COLOR_RESET)         - Generate Go module documentation"
	@echo "  $(COLOR_GREEN)help$(COLOR_RESET)         - Show this help message"
	@echo ""
	@echo "$(COLOR_CYAN)Variables:$(COLOR_RESET)"
	@echo "  $(COLOR_GREEN)VERSION$(COLOR_RESET)      - Version tag (default: git tag or 'dev')"
	@echo "  $(COLOR_GREEN)REGISTRY$(COLOR_RESET)     - Docker registry (default: ECR repository or localhost:5000)"
	@echo "  $(COLOR_GREEN)IMAGE_TAG$(COLOR_RESET)    - Docker image tag (default: VERSION)"
	@echo "  $(COLOR_GREEN)LOCAL_PORT$(COLOR_RESET)   - Port for local service (default: 8080)"
	@echo "  $(COLOR_GREEN)AWS_REGION$(COLOR_RESET)   - AWS region (default: us-east-1)"
	@echo "  $(COLOR_GREEN)AWS_PROFILE$(COLOR_RESET)  - AWS profile (default: default)"
