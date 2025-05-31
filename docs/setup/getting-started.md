# Getting Started

Welcome!  
This guide walks you from an empty AWS account to a fully-running **SecOps-Suite** deployment in **≈ 60 minutes**.  
It assumes **basic familiarity with AWS CLI and Docker**—nothing more.

---

## 1  Prerequisites

| Tool | Tested Version | Install Link |
|------|---------------|--------------|
| Terraform | ≥ 1.6 | https://developer.hashicorp.com/terraform/downloads |
| AWS CLI  | ≥ 2.15 | https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html |
| kubectl  | Match EKS version (1.29) | https://kubernetes.io/docs/tasks/tools |
| Docker   | ≥ 24 | https://docs.docker.com/get-docker/ |
| Helm     | ≥ 3.13 | https://helm.sh/docs/intro/install/ |
| Git      | ≥ 2.34 | https://git-scm.com/downloads |
| (Optional) cosign | ≥ 2.2 | https://docs.sigstore.dev/cosign/installation |

### AWS Account Prep

1. Create an IAM user **devsecops-admin**  
   – Programmatic access, **AdministratorAccess**, MFA enabled.  
2. Save Access Key + Secret.  
3. Configure CLI profile:

```bash
aws configure --profile devsecops-admin
# Access Key, Secret, default region (e.g. us-east-1), json
```

---

## 2  Clone the Repository

```bash
git clone https://github.com/panpiii/SecOps-Suite.git
cd SecOps-Suite
```

---

## 3  Bootstrap Environment File

```bash
cp .env.example .env
vim .env            # adjust AWS_PROFILE, AWS_REGION, DOMAIN_NAME …
```

`.env` is **git-ignored**—safe for local secrets.

---

## 4  Provision Cloud Infrastructure

All infra lives in `infra/terraform`.

```bash
cd infra/terraform
terraform init
terraform apply -var-file=environments/prod.tfvars   # ~20 min
```

Creates VPC, EKS (private API), IRSA, RDS audit DB, S3 logs (ObjectLock), KMS, GuardDuty, WAF, CloudTrail …

---

## 5  Configure kubectl

```bash
aws eks update-kubeconfig \
  --profile devsecops-admin \
  --region $AWS_REGION \
  --name devsecops-eks-prod

kubectl get nodes
```

---

## 6  Install Cluster Add-ons

Run from project root:

```bash
make istio-install        # service mesh + mTLS
make argocd-install       # GitOps control plane
make prometheus-install   # monitoring stack
```

Get Argo CD credentials:

```bash
make argocd-password
make argocd-port-forward      # UI → https://localhost:8080
```

---

## 7  Build & Push the Vulnerability Scanner

```bash
cd services/vuln-scanner
make ecr-login          # one-time ECR auth
make docker-build
make docker-push
```

The image is automatically scanned by ECR.

---

## 8  Configure GitHub Actions Secrets

Repository → Settings → Secrets & variables → Actions

| Secret | Value |
|--------|-------|
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | from IAM user |
| `AWS_REGION` | same as `.env` |
| `AWS_ROLE_TO_ASSUME` | (recommended) CI federated role |
| `COSIGN_PRIVATE_KEY` & `COSIGN_PASSWORD` | if signing images |
| `SLACK_WEBHOOK` | for deployment alerts |
| `ARGOCD_TOKEN` | Argo CD API token (optional) |

---

## 9  Commit → CI/CD Pipeline

Push any commit to `main`:

1. **Lint & Tests** – `golangci-lint`, `go test -race -cover`.  
2. **SAST / IaC Scan** – `gosec`, `gitleaks`, `tfsec`.  
3. **Build & Scan Image** – Buildx multi-arch, Trivy scan.  
4. **Supply-chain** – SBOM generation, cosign signature.  
5. **GitOps** – kustomize patch with new tag, commit to `k8s/overlays/staging`.  
6. **Argo CD Sync** – cluster state reconciled automatically.

---

## 10  Validate Deployment

```bash
kubectl -n vuln-scanner get pods
kubectl -n vuln-scanner logs -f deploy/vuln-scanner
```

Retrieve gateway DNS & call health endpoint:

```bash
GW=$(kubectl -n istio-system get svc istio-ingressgateway \
       -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
curl -H "Host: api.${DOMAIN_NAME}" https://$GW/v1/scan/healthz -k
# → {"status":"ok"}
```

---

## 11  Troubleshooting

| Symptom | Likely Cause | Resolution |
|---------|-------------|------------|
| `terraform lock` error | stale lock | `terraform force-unlock <ID>` |
| `kubectl timeout` | kubeconfig outdated | re-run update-kubeconfig |
| `ImagePullBackOff` | nodes lack ECR access | add `ECRReadOnly` to node role |
| TLS error curling service | used IP not hostname | add `Host:` header or Route53 record |

---

## 12  Next Milestones

| Objective | Starting Point |
|-----------|----------------|
| Add **Security Event Logger** | `services/event-logger/` |
| Add **Access Auditor** | `services/access-auditor/` |
| Enforce **OPA Gatekeeper** | `make gatekeeper-install` |
| Enable **Falco** runtime IDS | `make falco-install` |
| Integrate **Slack/PagerDuty** alerts | `charts/prometheus/alertmanager.yaml` |
| Experiment with **Blue/Green** rollouts | kustomize overlays |

---

## 13  Cleanup

```bash
make destroy ENV=prod
```

⚠️ Destroys all AWS resources created by Terraform.

---

### 🎉 Congratulations!

You now have a fully operational, security-hardened **SecOps-Suite** showcasing:

* **Infrastructure-as-Code** with Terraform  
* **GitOps** continuous delivery via Argo CD  
* **Zero-Trust** networking with Istio mTLS  
* **Shift-Left Security** baked into CI/CD  
* A working **RESTful micro-service** (Vulnerability Scanner)

Use this repository as a portfolio centerpiece in DevOps / Cloud / Cyber-Security interviews.  
Happy hacking — and stay secure!  
