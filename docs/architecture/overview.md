# Architecture Overview  
Secure DevSecOps Platform — Cyber-Security Edition
==================================================

This document offers a **security-centric** walk-through of the platform’s architecture—how cloud infrastructure, Kubernetes, CI/CD, and micro-services are assembled to deliver a production-ready, continuously-monitored environment.

---

## 1  High-Level Topology

```
┌──────────────────────┐
│   GitHub (Source)    │
│  CI → SBOM → Image   │
└─────────┬────────────┘
          │ signed OCI
          ▼
┌───────────────────────────────┐
│         AWS Account           │
│                               │
│  ┌──────────────┐             │
│  │    VPC       │             │
│  │ public | pri │             │
│  │  IGW   | NAT │             │
│  └────┬───┴─────┘             │
│       │Private Subnets        │
│       ▼                       │
│  ┌──────────────┐             │
│  │   EKS        │◀──ArgoCD──┐ │
│  │ (Kubernetes) │            │
│  └─┬────────────┘            │
│    │ mTLS / Istio            │
│    ▼                         │
│ ┌────────────┐  ┌──────────┐ │
│ │VulnScanner │  │EventLog  │ │
│ └────────────┘  └──────────┘ │
│            ▲ JWT / OIDC ▲    │
│            │            │    │
│      ┌──────────┐  ┌────────┐│
│      │ API GW   │  │Cognito ││
│      └──────────┘  └────────┘│
│                               │
│  Logs → S3 (ObjectLock)       │
│  Alerts → SNS → Slack         │
└───────────────────────────────┘
```

---

## 2  Infrastructure Design

### 2.1  Cloud Foundation (Terraform)

| Resource | Hardening Notes |
|----------|-----------------|
| **VPC** | Public/Private split; only ALB is internet-facing; worker nodes in private subnets |
| **EKS** | Control-plane private; IRSA enabled; managed node groups auto-patched |
| **IAM** | Granular roles; no wildcard `*`; access keys rotated automatically |
| **S3 Logs** | SSE-KMS + ObjectLock (compliance mode) to prevent tampering |
| **RDS Audit DB** | Encrypted, backup-retained 35 d; network-restricted to cluster CIDR |

### 2.2  Network Controls

* **Security Groups** act as micro-firewalls; only 443 exposed on ALB.  
* **Istio** enforces **mTLS** between pods; unauthenticated traffic rejected.  
* **AWS Network Firewall** (optional) egress-filters to CVE feeds only.

---

## 3  Security Principles Applied

| Principle | Implementation |
|-----------|----------------|
| Least Privilege | IRSA scopes pods; Kubernetes RBAC mirrors AWS scope |
| Zero Trust | Istio AuthorizationPolicies + NetworkPolicies |
| Shift-Left | CI pipeline runs SAST, IaC scanning **before** image build |
| Immutable Infrastructure | All changes via Terraform PRs; no console edits |
| Supply-Chain Integrity | Images signed with **cosign**; verified by admission control |
| Audit & Traceability | CloudTrail + Falco + app logs shipped to immutable S3 |
| Defense in Depth | Controls layered at cloud, cluster, mesh, container, code |

---

## 4  Component Interaction Flow

1. **Developer Pushes Code**  
   a. Unit tests → lint → Semgrep  
   b. Terraform & K8s manifests scanned (tflint, kube-score)  
   c. OCI image built; scanned by **Trivy**  
   d. SBOM generated, signed (cosign), pushed to **ECR**

2. **GitOps Deployment**  
   Tag updates manifests in `k8s/overlays/prod/`; Argo CD verifies signature and applies.

3. **Runtime Operations**  
   * Istio sidecars encrypt traffic.  
   * **Vulnerability Scanner** pulls image manifests, runs Trivy, stores CVEs in RDS.  
   * **Security Event Logger** ingests events → Loki + S3.  
   * **Access Auditor** tails Istio logs, enriches with identity, exposes CSV.

4. **Observability & Response**  
   Prometheus scrapes metrics → Alertmanager → Slack/PagerDuty.  
   Falco detects abnormal syscalls → SNS.  
   Runbooks in `/runbooks` guide responders.

---

## 5  Data Flow & Trust Boundaries

| Boundary | Control Mechanism |
|----------|------------------|
| Internet → ALB | AWS WAF (OWASP rules), TLS 1.2+, ACM certs |
| ALB → API GW | ALB logs enabled, private subnets |
| API GW → Services | JWT (Cognito), Istio mTLS, RBAC |
| Pods → AWS APIs | IRSA, scoped IAM, egress-only gateway |
| Cluster → Logs | VPC Endpoint, S3 policy denies `s3:DeleteObject` |

---

## 6  Threat Modeling Highlights

* **Supply-chain poisoning** mitigated by SBOM + signature verification.  
* **Lateral movement** reduced by strict NetworkPolicies & namespace isolation.  
* **Credential theft** limited by IRSA and short-lived Cognito tokens.  
* **Data exfiltration** hampered via egress firewall & ObjectLock logs.

---

## 7  Extensibility

* Plug new scanners (e.g., **grype**) via sidecar pattern.  
* Swap Cognito for any OIDC provider—policies unchanged.  
* Add **OPA Gatekeeper** for mandatory CIS policy packs.

---

## 8  Conclusion

The Secure DevSecOps Platform layers **IaC, GitOps, service mesh, hardened Kubernetes, and automated security tests** to deliver a defense-in-depth runtime suited for modern cybersecurity workloads. All controls are **code-defined** and **continuously validated**, making the platform both auditable and reproducible—a key requirement for security-critical industries such as fintech and cyber defense.
