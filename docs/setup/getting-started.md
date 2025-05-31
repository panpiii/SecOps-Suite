# Getting Started

Welcome!  
This guide walks you from an empty AWS account to a fully-running Secure DevSecOps Platform in **≈ 60 minutes**.  
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
# Access key, secret, default region (e.g. us-east-1), output json
```

---

## 2  Clone Repository

```bash
git clone https://github.com/your-username/secure-devsecops-platform.git
cd secure-devsecops-platform
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

Creates VPC, EKS, IRSA, RDS audit DB, GuardDuty, WAF, CloudTrail, etc.

---

## 5  Configure kubectl

```bash
aws eks update-kubeconfig \
  --profile devsecops-admin \
  --region $AWS_REGION \
  --name devsecops-eks-prod

kubectl get nodes          # should list 3 Ready nodes
```

---

## 6  Install Cluster Add-ons

Run from project root:

```bash
make istio-install     # service mesh + mTLS
make argocd-install    # GitOps control plane
make prometheus-install
```

Get Argo CD password & UI:

```bash
make argocd-password
make argocd-port-forward      # UI → https://localhost:8080
```

---

## 7  Build & Push First Microservice

```bash
cd services/vuln-scanner
make ecr-login          # one-time ECR auth
make docker-build
make docker-push
```

Image is scanned by AWS ECR automatically.

---

## 8  Wire GitHub Secrets

Repo → Settings → Secrets & variables → Actions

| Secret | Value |
|--------|-------|
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | from step 1 |
| `AWS_REGION` | same as `.env` |
| `AWS_ROLE_TO_ASSUME` | (recommended) federated CI role |
| `COSIGN_PRIVATE_KEY` / `COSIGN_PASSWORD` | if signing images |
| `SLACK_WEBHOOK` | for deployment alerts |
| `ARGOCD_TOKEN` | Argo CD API token (optional) |

---

## 9  Commit → CI Pipeline

Push any commit; GitHub Actions pipeline will:

1. Lint & unit tests  
2. SAST / IaC scan (gosec, tfsec)  
3. Build & scan image (Trivy)  
4. SBOM + cosign sign → ECR  
5. Update kustomization → Argo CD sync

---

## 10  Validate Deployment

```bash
kubectl -n vuln-scanner get pods
kubectl -n vuln-scanner logs -f deploy/vuln-scanner
```

Health check:

```bash
GW=$(kubectl -n istio-system get svc istio-ingressgateway \
      -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
curl -H "Host: api.${DOMAIN_NAME}" https://$GW/v1/scan/healthz -k
# → {"status":"ok"}
```

---

## 11  Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| `terraform lock` error | Stale state lock | `terraform force-unlock <id>` |
| `kubectl timeout` | kubeconfig outdated | Re-run update-kubeconfig |
| `ImagePullBackOff` | Node can’t pull from ECR | Ensure node IAM has `ECRReadOnly` |
| TLS cert error curling service | Using IP not hostname | Add `Host:` header or Route53 record |

---

## 12  Next Steps

* Add **Event Logger** & **Access Auditor** services.  
* Install **OPA Gatekeeper**: `make gatekeeper-install`.  
* Enable **Falco** runtime IDS: `make falco-install`.  
* Hook Slack/PagerDuty for alerts in `charts/prometheus/alertmanager.yaml`.  
* Experiment with **Blue/Green** roll-outs in kustomize overlays.

---

## 13  Cleanup

```bash
make destroy ENV=prod
```

---

### 🎓 Keep Learning

* Terraform modules, remote back-ends  
* Kubernetes security: PodSecurityStandards, NetworkPolicies  
* Container hardening: distroless, rootless runtime  
* Cloud security: IRSA, WAF, GuardDuty

Happy hacking & stay secure!  
