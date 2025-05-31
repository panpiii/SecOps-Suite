# Step-by-Step Implementation Guide  
Secure DevSecOps Platform – Cyber-Security Edition
=================================================

> Target duration: **≈ 60–90 minutes**  
> Goal: provision AWS infrastructure with Terraform, deploy the **Vulnerability Scanner** micro-service to EKS via GitOps, and validate secure end-to-end operation.

---

## 0  Prerequisites

| Tool | Min Version | Check |
|------|------------|-------|
| Terraform | 1.6 | `terraform -version` |
| AWS CLI   | 2.15 | `aws --version` |
| kubectl   | = EKS v1.29 | `kubectl version --client` |
| Docker    | 24 | `docker version` |
| Helm      | 3.13 | `helm version --short` |
| Git       | 2.34 | `git --version` |
| (opt) cosign | 2.2 | `cosign version` |
| (opt) trivy | latest | `trivy -v` |

AWS account: create IAM user **devsecops-admin** → programmatic + `AdministratorAccess` + MFA.

```bash
aws configure --profile devsecops-admin
# Access Key, Secret, default region (e.g. us-east-1), json
```

---

## 1  Fork & Clone the Repository

```bash
git fork https://github.com/your-username/secure-devsecops-platform.git
git clone https://github.com/your-username/secure-devsecops-platform.git
cd secure-devsecops-platform
```

📚 *Learning checkpoint:* Git forking workflow & README-driven development.

---

## 2  Bootstrap Environment File

```bash
cp .env.example .env
vim .env   # adjust AWS_PROFILE, AWS_REGION, DOMAIN_NAME, etc.
```

`.env` is **git-ignored**—safe for local secrets.

---

## 3  Provision Cloud Infrastructure (Terraform)

```bash
cd infra/terraform
terraform init
terraform apply -var-file=environments/prod.tfvars     # ≈20 min
```

Creates VPC, EKS (private API), IRSA, RDS audit DB, S3 logs (ObjectLock), KMS, GuardDuty, WAF, CloudTrail…

📚 *Checkpoint:* Infrastructure-as-Code & AWS shared-responsibility.

---

## 4  Configure `kubectl`

```bash
aws eks update-kubeconfig \
  --profile devsecops-admin \
  --region $AWS_REGION \
  --name devsecops-eks-prod

kubectl get nodes
```

---

## 5  Install Cluster Add-ons

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

📚 *Checkpoint:* Service mesh basics & continuous reconciliation with Argo CD.

---

## 6  Build & Push the Vulnerability Scanner

```bash
cd services/vuln-scanner
make ecr-login          # one-time ECR auth
make docker-build
make docker-push
```

The image is automatically scanned by ECR.

---

## 7  Configure GitHub Actions Secrets

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

## 8  Commit → CI/CD Pipeline

Push any commit to `main`:

1. **Lint & Tests** – `golangci-lint`, `go test -race -cover`.  
2. **SAST / IaC Scan** – `gosec`, `gitleaks`, `tfsec`.  
3. **Build & Scan Image** – Buildx multi-arch, Trivy scan.  
4. **Supply-chain** – SBOM generation, cosign signature.  
5. **GitOps** – kustomize patch with new tag, commit to `k8s/overlays/staging`.  
6. **Argo CD Sync** – cluster state reconciled automatically.

📚 *Checkpoint:* Supply-chain security (SLSA, SBOM) & OIDC → STS federation.

---

## 9  Validate Deployment

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

## 10  Troubleshooting Table

| Symptom | Likely Cause | Resolution |
|---------|-------------|------------|
| `terraform lock` error | stale lock | `terraform force-unlock <ID>` |
| `kubectl timeout` | kubeconfig outdated | re-run update-kubeconfig |
| `ImagePullBackOff` | nodes lack ECR access | add `ECRReadOnly` to node role |
| TLS error curling service | used IP not hostname | add `Host:` header or Route53 record |

---

## 11  Next Milestones

| Objective | Starting Point |
|-----------|----------------|
| Add **Security Event Logger** | `services/event-logger/` |
| Add **Access Auditor** | `services/access-auditor/` |
| Enforce **OPA Gatekeeper** | `make gatekeeper-install` |
| Enable **Falco** runtime IDS | `make falco-install` |
| Integrate **Slack/PagerDuty** alerts | `charts/prometheus/alertmanager.yaml` |
| Experiment with **Blue/Green** rollouts | kustomize overlays |

---

## 12  Cleanup

```bash
make destroy ENV=prod
```

⚠️ Destroys all AWS resources created by Terraform.

---

## 13  Keep Learning

* Terraform modules & remote back-ends  
* Kubernetes security: PodSecurityStandards, NetworkPolicies  
* Container hardening: distroless images, rootless runtime  
* Cloud security: IRSA, GuardDuty, WAF rules  

---

### 🎉 Congratulations!

You now have a fully-operational, security-hardened DevSecOps platform showcasing:

* **Infrastructure-as-Code** with Terraform  
* **GitOps** continuous delivery via Argo CD  
* **Zero-Trust** networking with Istio mTLS  
* **Shift-Left Security** baked into CI/CD  
* A working **RESTful micro-service** (Vulnerability Scanner)

Use this repository as a portfolio centerpiece in DevOps / Cloud / Cyber-Security interviews.  
Happy hacking — and stay secure!  
