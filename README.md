# SecOps-Suite

![Build](https://img.shields.io/github/actions/workflow/status/panpiii/SecOps-Suite/ci.yml?label=CI%20Status)
![License](https://img.shields.io/github/license/panpiii/SecOps-Suite)

A hands-on, end-to-end reference implementation that shows how to **design, build, and operate secure micro-services on AWS using modern DevOps & DevSecOps practices**.  
It is intentionally opinionated toward security-first choices, making it an ideal portfolio project for roles in cybersecurity, FinTech, or cloud-infrastructure engineering.

---

## Table of Contents
1. Project Overview  
2. Architecture  
3. Core Components  
4. Security Highlights  
5. Prerequisites  
6. Setup & Deployment  
7. Usage & API Reference  
8. Observability & Incident Response  
9. Contributing  
10. Roadmap  
11. License  

---

## 1. Project Overview
**SecOps-Suite** provisions a production-ready AWS EKS cluster, deploys three security micro-services, and wires a fully automated CI/CD pipeline that embeds security checks in every phase.

Key goals  
* Demonstrate **Infrastructure-as-Code**, **GitOps**, and **Immutable Infrastructure** patterns.  
* Provide concrete examples of **shift-left security**—static analysis, container scanning, policy enforcement.  
* Offer a RESTful control plane to trigger deployments, collect security events, and audit access.  
* Showcase least-privilege IAM, network segmentation, and runtime hardening on Kubernetes.  

---

## 2. Architecture
```
┌─────────────────────────GitHub─────────────────────────┐
│  PR → CI Pipeline → Image Build + Tests + Sec Scans    │
└──────────────┬─────────────────┬───────────────────────┘
               │ GitOps (tags)   │
               ▼                 │
   ┌─────────────────────────────▼──────────────────────────────┐
   │                     AWS Account (Prod)                     │
   │                                                            │
   │  ┌───────────────┐  ┌─────────────────┐   ┌──────────────┐ │
   │  │  EKS Cluster  │  │   RDS (Audit)   │   │  S3 (Logs)   │ │
   │  │   (K8s)       │  └─────────────────┘   └──────────────┘ │
   │  │  ┌──────────┐ │                                         │
   │  │  │ Istio SM │ │                                         │
   │  │  └────┬─────┘ │                                         │
   │  │       │ mTLS  │                                         │
   │  │  ┌────▼────┐  │  ┌───────────────┐   ┌────────────────┐ │
   │  │  │ VulnSvc │  │  │  EventLogger  │   │  AccessAuditor │ │
   │  │  └─────────┘  │  └───────────────┘   └────────────────┘ │
   │  └────────────────┘                                         │
   └─────────────────────────────────────────────────────────────┘
```
* All infrastructure is **codified with Terraform**.  
* GitHub Actions pushes signed container images to **AWS ECR** after passing security gates (Trivy, Checkov, OPA).  
* **Argo CD** reconciles Kubernetes manifests, enforcing GitOps.  
* **Istio** provides service-to-service encryption (mTLS) and zero-trust policies.  

---

## 3. Core Components

| Layer                | Technology | Description |
|----------------------|------------|-------------|
| Infrastructure       | Terraform, AWS VPC, EKS | Reproducible Kubernetes cluster with private subnets, NAT, bastion-less SSM access |
| Containerization     | Docker, ECR | Multi-stage, minimal-base images |
| Orchestration        | Kubernetes, Helm/Argo CD | Declarative deployment, HPA, PodSecurityStandards |
| CI/CD                | GitHub Actions | test → scan → build → sign → push → deploy |
| Service Mesh         | Istio | mTLS, policy enforcement, observability |
| Security Services    | Go / Python | 1) Vulnerability Scanner, 2) Security Event Logger, 3) Access Auditor |
| Observability        | Prometheus, Loki, Grafana | Metrics, logs, dashboards with alerting to Slack |

---

## 4. Security Highlights
* **Infrastructure Security** – private subnets, IRSA, VPC flow logs.  
* **Pipeline Security** – SBOM generation, container signing (*cosign*), IaC scanning (*Checkov*).  
* **Runtime Security** – Pod Security Standards, NetworkPolicies, Istio AuthorizationPolicy, optional Falco.  
* **Audit & Compliance** – CloudTrail, RDS audit DB, log immutability via S3 ObjectLock, Security Hub & GuardDuty.  

---

## 5. Prerequisites
* AWS account with administrative access for bootstrapping.  
* `terraform >= 1.6`, `awscli`, `kubectl`, `helm`, Docker.  
* GitHub account with Actions enabled.  
* (Optional) GPG or Sigstore key pair for image signing.

---

## 6. Setup & Deployment (TL;DR)
```bash
# Clone
git clone https://github.com/panpiii/SecOps-Suite.git
cd SecOps-Suite

# Provision AWS infra (≈20 min)
cd infra/terraform
terraform init
terraform apply -var-file=prod.tfvars

# Configure kubeconfig
aws eks update-kubeconfig --name devsecops-eks --region us-east-1

# Install add-ons
make istio-install
make argocd-install

# Push first micro-service image
cd services/vuln-scanner
make ecr-login docker-build docker-push
```
Detailed, step-by-step instructions live in [`/docs/setup`](docs/setup).

---

## 7. Usage & API Reference

| Service | Endpoint | Example |
|---------|----------|---------|
| **Vulnerability Scanner** | `POST /v1/scan` | `{ "image_name":"nginx","image_tag":"latest","registry":"ecr" }` |
|  | `GET /v1/scan/{id}` | Retrieve scan result & CVE list |
| **Security Event Logger** | `POST /v1/events` | Ingest custom security event |
| **Access Auditor** | `GET /v1/audit` | Download CSV of API access logs |

All endpoints require a **JWT issued by Cognito** (see [`/docs/auth`](docs/auth)).

---

## 8. Observability & Incident Response
* Grafana dashboards for cluster health and security KPIs.  
* Alertmanager routes high-severity alerts to Slack/PagerDuty.  
* Runbooks stored in `/runbooks` guide on-call responders.  

---

## 9. Contributing
Pull requests are welcome! Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) and open an issue before major changes.

---

## 10. Roadmap
- [ ] Integrate **OPA Gatekeeper** for policy as code  
- [ ] Chaos engineering experiments (Litmus)  
- [ ] SOAR-style automated remediation workflows  
- [ ] Terraform Cloud backend example  

---

## 11. License
Distributed under the MIT License. See [`LICENSE`](LICENSE) for more information.
