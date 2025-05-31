# Step-by-Step Implementation Guide  
SecOps-Suite – Cyber-Security Edition
====================================

> Hands-on time: **≈ 60-90 minutes**  
> Goal: provision AWS infrastructure with Terraform, deploy the **Vulnerability Scanner** micro-service to EKS via GitOps, and validate secure end-to-end operation.

---

## 0  Prerequisites

| Tool | Min Version | Quick Check |
|------|-------------|-------------|
| Terraform | 1.6 | `terraform -version` |
| AWS CLI   | 2.15 | `aws --version` |
| kubectl   | = EKS v1.29 | `kubectl version --client` |
| Docker    | 24 | `docker version` |
| Helm      | 3.13 | `helm version --short` |
| Git       | 2.34 | `git --version` |
| (opt) cosign | 2.2 | `cosign version` |
| (opt) trivy | latest | `trivy -v` |

**AWS account**  
Create IAM user **devsecops-admin** → Programmatic access, `AdministratorAccess`, MFA enabled.

```bash
aws configure --profile devsecops-admin
# Access Key, Secret, default region (e.g. us-east-1), json
```

---

## 1  Fork & Clone

```bash
git clone https://github.com/panpiii/SecOps-Suite.git
cd SecOps-Suite
```

*Learning checkpoint → README-driven development & Git workflow.*

---

## 2  Bootstrap `.env`

```bash
cp .env.example .env
vim .env         # adjust AWS_PROFILE, AWS_REGION, DOMAIN_NAME …
```

`.env` is **git-ignored**—safe for local secrets.

---

## 3  Provision Cloud Infrastructure (Terraform)

```bash
cd infra/terraform
terraform init
terraform apply -var-file=environments/prod.tfvars     # ≈20 min
```

Creates VPC, EKS (private API), IRSA, RDS audit DB, S3 logs (ObjectLock), KMS, GuardDuty, WAF, CloudTrail …

*Checkpoint → Infrastructure-as-Code, state management, AWS shared responsibility.*

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

From project root:

```bash
make istio-install        # service mesh + mTLS
make argocd-install       # GitOps control plane
make prometheus-install   # monitoring stack
```

Get Argo CD credentials & UI:

```bash
make argocd-password
make argocd-port-forward   # https://localhost:8080
```

*Checkpoint → Service mesh concepts & continuous reconciliation.*

---

## 6  Build & Push the Vulnerability Scanner

```bash
cd services/vuln-scanner
make ecr-login            # one-time ECR auth
make docker-build
make docker-push
```

Image is automatically scanned by ECR.

---

## 7  Configure GitHub Actions Secrets

Repo → Settings → Secrets & variables → Actions

| Secret | Value |
|--------|-------|
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | from IAM user |
| `AWS_REGION` | same as `.env` |
| `AWS_ROLE_TO_ASSUME` | (recommended) CI federated role |
| `COSIGN_PRIVATE_KEY` / `COSIGN_PASSWORD` | if signing images |
| `SLACK_WEBHOOK` | for deployment alerts |
| `ARGOCD_TOKEN` | Argo CD API token (optional) |

---

## 8  Commit → CI/CD Pipeline

Push any commit to **main** and watch the *Actions* tab:

1. Lint & unit tests  
2. SAST / IaC scanning (`gosec`, `gitleaks`, `tfsec`)  
3. Build & Trivy-scan image  
4. Generate SBOM, cosign signature → ECR  
5. Patch kustomize with new tag → commit to `k8s/overlays/staging`  
6. Argo CD sync → EKS

*Checkpoint → Supply-chain security (SBOM, signatures) & GitHub OIDC → AWS STS.*

---

## 9  Validate Deployment

```bash
kubectl -n vuln-scanner get pods
kubectl -n vuln-scanner logs -f deploy/vuln-scanner
```

Health check:

```bash
GW=$(kubectl -n istio-system get svc istio-ingressgateway \
       -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
curl -H "Host: api.${DOMAIN_NAME}" https://$GW/v1/scan/healthz -k
# {"status":"ok"}
```

---

## 10  Troubleshooting

| Symptom | Likely Cause | Resolution |
|---------|-------------|------------|
| `terraform lock` error | stale lock | `terraform force-unlock <ID>` |
| `kubectl timeout` | kubeconfig outdated | re-run update-kubeconfig |
| `ImagePullBackOff` | nodes lack ECR access | add `ECRReadOnly` to node role |
| TLS error when curling | using IP not hostname | add `Host:` header or Route53 record |

---

## 11  Next Milestones

| Objective | Where to Start |
|-----------|----------------|
| Add **Security Event Logger** | `services/event-logger/` |
| Add **Access Auditor** | `services/access-auditor/` |
| Enforce **OPA Gatekeeper** | `make gatekeeper-install` |
| Enable **Falco** runtime IDS | `make falco-install` |
| Integrate Slack/PagerDuty alerts | `charts/prometheus/alertmanager.yaml` |
| Experiment with Blue/Green roll-outs | kustomize overlays |

---

## 12  Cleanup

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
