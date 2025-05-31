# Repository Structure

This project follows an *Infrastructure-as-Code + GitOps* philosophy: every artefact that defines **how the platform works**—from cloud resources to Kubernetes policies and CI pipelines—lives in version control and is delivered through automated workflows.

```
secure-devsecops-platform
├── .github/                 # GitHub-native CI/CD and community files
│   ├── workflows/           #  └─ Action definitions for build, scan, deploy
│   └── ISSUE_TEMPLATE/      #     Issue & PR templates
├── charts/                  # Helm charts (Istio, Argo CD, Falco, …)
├── ci/                      # Re-usable pipeline logic (scripts, templates)
│   └── github/              #   └─ Composite actions, shared steps
├── docs/                    # Project documentation (THIS file lives here)
│   ├── setup/               # 1-click bootstrap and local-dev guides
│   ├── auth/                # Cognito / JWT flow, OIDC details
│   ├── architecture/        # Diagrams, ADRs, threat models
│   └── runbooks/            # Ops & incident-response manuals (symlinked)
├── infra/                   # Infrastructure-as-Code
│   └── terraform/           #   └─ Modular Terraform for AWS & EKS
│       ├── modules/         #       Opinionated, reusable TF modules
│       ├── environments/    #       prod/, staging/, sandbox/ var sets
│       └── policies/        #       OPA/Checkov policy bundles
├── k8s/                     # Kubernetes deployment manifests
│   ├── base/                # Kustomize bases (namespace, PSP, HPA)
│   ├── overlays/            # Environment-specific overlays (prod, stage)
│   └── policies/            # Gatekeeper & Kyverno security policies
├── services/                # Source code for micro-services
│   ├── vuln-scanner/        # CVE scanning API (Go)
│   ├── event-logger/        # Security event ingestion (Python/FastAPI)
│   └── access-auditor/      # API access audit exporter (Rust)
├── scripts/                 # Helper CLI & bootstrap scripts (Bash/Python)
├── tests/                   # Unit, integration, and security tests
│   ├── integration/         # End-to-end tests run in CI
│   └── security/            # Semgrep rules, container benchmarks
├── runbooks/                # Markdown runbooks (symlinked into docs/)
├── Makefile                 # One-liner developer UX (make deploy, make scan)
├── .env.example             # Sample environment variables for local dev
└── LICENSE
```

## Directory Details

| Directory | Purpose | Key Tools & Conventions |
|-----------|---------|-------------------------|
| `.github/workflows` | GitHub Actions YAML files that compose the CI/CD pipeline (test → scan → build → sign → push → deploy). | *GitHub Actions*, *Cosign*, *Trivy*, *Argo CD CLI* |
| `charts/` | Helm charts vendored or authored for cluster add-ons (Istio, Prometheus, Falco). Version-pinned to avoid upstream drift. | *Helm*, *Helmfile* |
| `ci/` | Shared scripts & composite actions so workflow logic stays DRY and testable. | *Bash*, *Python*, *Reusable Actions* |
| `docs/` | Living documentation—setup guides, ADRs, diagrams, runbooks. Published via GitHub Pages. | *MkDocs* |
| `infra/terraform/` | Declarative cloud resources. Each environment folder has its own `tfvars`. Modules encapsulate VPC, EKS, RDS, etc. | *Terraform*, *tflint*, *tfsec*, *Checkov* |
| `k8s/` | GitOps source of truth for Kubernetes. `kustomize build` output is what Argo CD applies. Policies enforce zero-trust and Pod Security Standards. | *Kustomize*, *Argo CD*, *OPA Gatekeeper* |
| `services/` | Application source. Each service contains its own `Dockerfile`, `helm/` chart, and Make targets for local build/test. | *Go*, *Python*, *Rust*, *OpenAPI* |
| `scripts/` | Automation helpers (e.g., `rotate-keys.sh`, `ecr-login.py`). Not used in production runtime. | *Bash*, *Python* |
| `tests/` | All test code. Security tests run with every PR to enforce “break builds, not prod.” | *pytest*, *Ginkgo*, *k6* |
| `runbooks/` | Operational procedures for on-call engineers. Markdown keeps them version-controlled. | *PagerDuty integration* |

## Why This Layout?

* **Separation of concerns** — infrastructure, application code, and pipeline logic evolve independently.  
* **Reusability** — Terraform modules and composite GitHub actions reduce duplication.  
* **GitOps** — `k8s/` is the single source of truth for runtime state; Argo CD reconciles divergences.  
* **Security by design** — policies, scans, and runbooks live alongside the code they protect.

Use this document as your “map” while navigating or contributing to the project. Questions? Open an issue or discussion thread!
