# Kahu — Project A to Z

**Prepared by:** ComplyHI
**Date:** August 2026
**Status:** Working product, deployed and running on test infrastructure

---

## What Kahu Is

Kahu is an on-premises AI security operations appliance. It combines an open-source SIEM/XDR platform (Wazuh), a locally hosted large language model (Ollama), and a proprietary orchestration layer (Kahu Core) to deliver automated alert triage, natural-language log investigation, vulnerability scanning, and continuous compliance evidence generation — with zero security telemetry ever leaving the customer's premises.

The name is Hawaiian for "shield, as for battle" (*Mamaka Kaiao*). Traditional Hawaiian warfare had no shields; the word was coined when the need arose. Kahu exists for the same reason: small organizations facing modern threats need a defense that did not previously exist at their scale or price point.

---

## The Problem

Organizations with 10 to 150 endpoints that handle regulated or sensitive data (CUI, PHI, privileged legal material, financial records) face an impossible choice:

- **Cloud MDR contracts** cost $10K+/month and require shipping all security telemetry off-premises — a compliance disqualifier for many.
- **Hiring a SOC analyst** costs $80K-$120K/year and still leaves gaps in 24/7 coverage.
- **Doing nothing** is increasingly untenable as compliance frameworks (CMMC, HIPAA, PCI DSS, FTC Safeguards) add teeth and enforcement.

These organizations have no dedicated security staff. Their IT is one person, or outsourced. They know they need monitoring, but every available option either costs too much, violates their data-handling requirements, or both.

---

## The Solution

Kahu functions as their tier-1 SOC analyst in a box. It watches everything, surfaces the few things that matter, explains them in plain English, and produces the compliance paperwork as a byproduct of operating.

**What it does, concretely:**

1. **Collects** — Wazuh agents on every endpoint, plus syslog/NetFlow/API ingestion from firewalls, cloud services, and network gear. A wizard-driven connector framework makes attaching a new source something an office manager can do.

2. **Triages** — A 5-stage pipeline processes every alert: deterministic filtering strips noise, enrichment adds context, the local AI assesses severity and explains what happened, auto-disposition handles the obvious cases, and the result lands in a mobile-first swipe interface where the analyst acknowledges, escalates, or confirms each alert in seconds. A deterministic floor guarantees that critical alerts can never be silently dismissed, regardless of what the model recommends.

3. **Investigates** — A chat interface where anyone can ask "show me failed logins from outside the US this week" and get a plain-English answer backed by the raw data one click below.

4. **Scans** — Integrated vulnerability scanning (Greenbone/OpenVAS) with on-demand and scheduled scans, findings correlated with alert data.

5. **Complies** — Every detection, disposition, and response action is automatically mapped to compliance framework controls and retained in a tamper-evident, hash-chained evidence store. Assessment evidence packages generate on demand.

6. **Scores** — The Pono Score is a 100-point posture metric across six domains (detection, tuning, vulnerability, identity, response, human) that gives executives a single number and gives the operator a clear improvement path.

7. **Tunes** — Bayesian alert rate modeling with Gamma conjugate priors, shrinkage, seasonality detection, and KL-divergence drift alerting. Ed25519-signed tuning proposals ensure integrity. A nightly batch service produces tuning recommendations that are cryptographically verifiable.

8. **Reports** — Monthly executive reports (AI-drafted, human-reviewed), incident reports, and evidence packages — all generated on the appliance as PDFs.

9. **Attests** — Signed posture export bundles for third-party verification. An external party can independently verify that a Kahu appliance reported a given posture score at a given time, without access to the appliance.

---

## Design Principles (Priority Order)

| # | Principle | What It Means |
|---|-----------|---------------|
| 1 | **Data sovereignty** | All telemetry, logs, model inference, and analysis remain on the appliance. No cloud dependency for core function. The appliance operates fully when the WAN is down. |
| 2 | **Fail closed** | If any component that enforces a data-handling boundary degrades, the system defaults to the restrictive behavior. There is no silent fallback that routes data somewhere it should not go. |
| 3 | **The model advises, the ruleset governs** | The LLM cannot override deterministic severity bounds. A critical alert stays critical regardless of what the model says. Auto-dismissal of high/critical alerts is architecturally forbidden — enforced at two independent points in the pipeline, not by prompting. |
| 4 | **Human in the loop** | The AI recommends, summarizes, and drafts. It does not autonomously remediate. Every recommended action requires human approval. This is a marketed feature, not a limitation. |
| 5 | **Evidence as byproduct** | Every operational action automatically generates compliance evidence. The customer's continuous monitoring evidence writes itself. |

---

## Architecture

```
Layer 5 — Interfaces     React 19 PWA (desktop + mobile), Cloudflare Zero Trust portal,
                          operator plane (fleet management)

Layer 4 — Kahu Core      Python 3.12 / FastAPI orchestration: triage pipeline, investigation,
                          reporting, compliance engine, Pono scoring, attestation
                          Postgres (state) + Redis (queues)

Layer 3 — Inference       Ollama serving quantized LLMs locally
                          Model-agnostic: swappable per tier, updated via subscription

Layer 2 — SIEM/XDR       Wazuh 4.14.1 manager + indexer (OpenSearch) + dashboard
                          Agents on endpoints, syslog/NetFlow collectors

Layer 1 — Platform        Hardened Linux, Docker Compose, full-disk encryption

Layer 0 — Hardware        Tiered appliance chassis (S / M / V)
```

### Software Packages (5 packages under `src/`)

| Package | Purpose |
|---------|---------|
| **`kahu`** | Core FastAPI app — the main deliverable |
| **`kahu_tuning`** | Bayesian alert rate modeling (Gamma priors, shrinkage, seasonality, KL-divergence drift). Ed25519-signed proposals. |
| **`kahu_tuner`** | Nightly batch service that runs tuning against historical alert data |
| **`kahu_pono`** | 100-point posture score across six security domains |
| **`kahu_attest`** | Signed posture export bundles for third-party verification |

Dependency direction is one-way: `kahu` imports the satellite packages; they never import `kahu`.

---

## Hardware Tiers

| | Kahu S | Kahu M | Kahu V |
|---|---|---|---|
| **Target** | up to 25 endpoints | 25-150 endpoints | 150+ or existing virtualization |
| **Form factor** | UGREEN NAS chassis | 1U server with GPU | Virtual appliance (OVA/Hyper-V) |
| **Inference** | CPU-only, 7-8B model | GPU (RTX 4500/5000), 12-30B model | Sized to allocated resources |
| **Retention** | 90 days hot, 1 year cold | 180 days hot, 1-3 years cold | Per contract |
| **Margin** | Hardware + service | Hardware + service | Software + service only |

---

## What's Built (August 2026)

The product is not a slide deck. Working code is deployed and running against live infrastructure in a test environment.

### Kahu Core — 15,700+ lines of Python (5 packages)

| Component | Status | What It Does |
|-----------|--------|-------------|
| Triage Pipeline | **Live** | 5-stage: filter, enrich, LLM triage, auto-disposition, disposition. Processes Wazuh alerts end-to-end. |
| Auto-Disposition Floor | **Live** | AI handles obvious alerts automatically; critical/high deterministic alerts are architecturally forbidden from auto-dismiss, routed to a human regardless of model confidence. |
| Severity Bounding | **Live** | LLM cannot lower severity more than one band below deterministic assessment. Enforced independently of auto-disposition. |
| Re-evaluation Loop | **Live** | Periodic re-check of acknowledged alerts. If new evidence changes the picture, the alert resurfaces. |
| Swipe Feed API | **Live** | Mobile-first triage: left=acknowledge, right=confirm, up=escalate. 3 seconds per alert. |
| Gamification (XP/Ranks) | **Live** | Points, streaks, badges, leaderboard. Turns alert triage from a chore into a game. |
| Ticket System | **Live** | Auto-creates incident/investigation tickets on confirm/escalate with full lifecycle. |
| Investigation Chat | **Live** | Natural-language queries translated to Wazuh indexer searches, results summarized by AI. Session history preserved. |
| Connector Framework | **Live** | Wizard-driven source onboarding. Catalog: syslog (multi-vendor), SNMP, Wazuh agents, M365/Entra, Defender, Sentinel. |
| Compliance Engine | **Live** | Framework profiles (CMMC, HIPAA, PCI DSS, CIS, SOC 2, NIST 800-171), gap analysis, evidence collection. |
| Evidence Store | **Live** | Append-only, SHA-256 hash-chained, control-tagged. Assessor-ready export. Verifiable via `verify_chain()`. |
| Pono Score | **Live** | 100-point composite posture score across 6 domains with configurable weights. |
| Bayesian Tuning | **Live** | Gamma conjugate prior alert rate modeling with shrinkage, seasonality, and KL-divergence drift detection. Ed25519-signed tuning proposals. |
| Attestation Bundles | **Live** | Signed posture exports for third-party verification. External parties can verify scores without appliance access. |
| Vulnerability Scanning | **Live** | Greenbone/OpenVAS integration — create scans, view findings, generate reports. |
| Reporting | **Live** | Executive briefings, incident reports, evidence packages — generated as PDFs on the appliance. |
| Redaction | **Live** | Pattern-based secret stripping (passwords, API keys, AWS keys, private keys, emails) before any data reaches the LLM. |
| Auth & RBAC | **Live** | JWT authentication, role-based access control, admin user management. |
| Arsenal | **Live** | Curated response action catalog with unlock/audit controls. |

### Frontend — React 19 + TypeScript + Tailwind PWA

| Page | Status |
|------|--------|
| Glance (alert orb + AI briefing) | **Live** |
| Feed (swipe card triage) | **Live** |
| Investigate (NL chat) | **Live** |
| Score (Pono posture + tickets + badges) | **Live** |
| Reports (executive, incident, evidence) | **Live** |
| Compliance (frameworks, coverage, gaps) | **Live** |
| Connectors (catalog + wizard) | **Live** |
| Recon (vulnerability scanner) | **Live** |
| Arsenal (response actions) | **Live** |
| Settings (tolerance, auto-triage, services) | **Live** |
| More (profile, themes, about) | **Live** |
| Login / first-user setup | **Live** |
| Desktop layout (sidebar nav) | **Live** |
| Mobile PWA (installable, service worker) | **Live** |

### Infrastructure & Deployment

| Component | Status |
|-----------|--------|
| Docker Compose (10 services) | **Live** |
| Ubuntu installer (single-node + distributed 3+ node) | **Live** |
| Remote-site probe installer | **Live** |
| Distributed role split (core / siem / ai / scanner) | **Live** |
| Join bundle for multi-node deployment | **Live** |
| TLS certificate generation | **Live** |
| Wazuh 4.14.1 (manager + indexer + dashboard) | **Live** |
| Ollama (GPU or CPU) | **Live** |
| Greenbone/OpenVAS | **Live** |
| PostgreSQL 16 + Alembic migrations | **Live** |
| Redis 7 | **Live** |
| Cloudflare Tunnel (Zero Trust) | **Ready** — config built, `cloud` profile in compose |
| Alert generator (demo/testing) | **Live** |
| Wazuh agent installer (Windows PowerShell) | **Live** |
| 320 automated tests | **Live** |

---

## Data Flows — The Load-Bearing Rule

**Security telemetry and derived analysis never leave the customer premises.** Three flows cross the appliance boundary, and only three:

1. **Inbound updates** (WAN to appliance) — Signed update bundles pulled over TLS. No update credential grants access to appliance data.

2. **Outbound health** (appliance to operator plane) — Heartbeat and counts only: service status, disk/memory/GPU utilization, agent count, alert counts by severity. Explicitly excluded: log content, alert content, hostnames, usernames, IPs, model inputs/outputs. Schema is documented in the customer contract and enforced by an allowlist serializer.

3. **Escalation** (human-initiated, bidirectional) — Cloudflare Access-mediated support sessions. Time-boxed, logged on the appliance, no standing backdoor.

---

## Compliance Frameworks (Launch Set)

| Framework | Target Buyer |
|-----------|-------------|
| CMMC Level 1 | Defense subcontractors (basic) |
| CMMC Level 2 / NIST 800-171 | Defense subcontractors handling CUI |
| HIPAA Security Rule | Healthcare, dental, behavioral health |
| PCI DSS 4.0 | Retail, hospitality, any card processing |
| SOC 2 (Trust Services Criteria) | SaaS, professional services |
| CIS Controls v8 | General best practice baseline |
| FTC Safeguards Rule | CPAs, dealerships, financial-adjacent SMBs |

**The compliance loop** — the product's core value cycle:

1. Customer selects applicable frameworks
2. Gap analysis runs instantly against attached sources
3. Dashboard shows exactly which controls are covered, partial, or missing
4. Each gap links to a connector wizard that closes it ("attach firewall syslog to cover Requirement 10")
5. Attaching the source visibly improves the compliance score
6. Evidence generates automatically as the system operates
7. Pono Score gives executives a single number; attestation bundles let them prove it to third parties

This loop — select framework, see gaps, close them, watch coverage climb, prove it externally — is the product's core dopamine cycle and the thing no bare SIEM offers.

---

## Market

### Target Customer Profile

- 10-150 endpoints
- Handles regulated or sensitive data
- Cannot justify $10K+/month cloud MDR
- Cannot ship telemetry off-premises (compliance or trust)
- No dedicated security staff
- Needs compliance evidence (audit is coming, contract requires it, or insurance demands it)

### Beachhead Markets (Hawaii + Pacific)

| Vertical | Compliance Driver | Size |
|----------|------------------|------|
| Defense subcontractors | CMMC L2 (mandatory for CUI contracts) | ~200 firms in Hawaii |
| Healthcare / dental | HIPAA Security Rule | ~1,500 practices in Hawaii |
| Law firms | Ethical duty of competence, client data protection | ~800 firms in Hawaii |
| Architecture/Engineering/Construction | CUI handling (federal projects), insurance | ~300 firms in Hawaii |
| CPA firms | FTC Safeguards Rule (mandatory 2024+) | ~400 firms in Hawaii |
| Auto dealerships | FTC Safeguards Rule | ~100 dealerships in Hawaii |

### Expansion Path

1. **Hawaii pilot** — ISE (internal) + 1-2 external pilots at cost
2. **Hawaii market** — Direct sales leveraging existing ComplyHI relationships
3. **Pacific Islands** — Guam, CNMI, American Samoa (same compliance requirements, zero local options)
4. **Japan (USFJ ecosystem)** — Defense contractors supporting US Forces Japan
5. **National channel** — MSP/MSSP partnerships for mainland SMBs

---

## Revenue Model

### Recurring Revenue (Monthly Subscription)

| Tier | Monthly | Includes |
|------|---------|----------|
| Kahu S | $500-800 | Appliance lease, updates, monthly report, quarterly tuning, email support |
| Kahu M | $1,200-2,000 | Above + GPU inference, priority support, incident escalation |
| Kahu V | $800-1,500 | Software + service (no hardware), scales with endpoint count |

### Unit Economics

The AI layer is what makes the unit economics work. One operator can carry a fleet because the appliances pre-digest their own noise.

**Key metric:** ComplyHI human minutes per customer per month. Target: <60 minutes for routine customers (monthly report review, quarterly tuning check). The AI handles the 99% of alerts that are noise; the human handles the 1% that matters and the relationship.

### Hardware Margin

- **Kahu S:** Hardware BOM ~$800-1,200. Sold/leased at $2,000-3,000. Margin exists.
- **Kahu M:** Hardware BOM ~$3,000-5,000. Sold/leased at $6,000-10,000. Margin exists.
- **Kahu V:** No hardware. Pure software + service margin.

---

## Competitive Landscape

| Competitor | Why Kahu Wins |
|------------|---------------|
| **Cloud MDR** (Arctic Wolf, Huntress, etc.) | Data leaves premises. $10K+/month. No compliance evidence engine. |
| **Bare SIEM** (Wazuh, Elastic, Splunk) | Requires a security engineer to operate. No AI triage. No compliance automation. No monthly report. |
| **Cloud SIEM** (Sentinel, Chronicle) | Data leaves premises. Per-GB pricing scales painfully. |
| **GRC platforms** (Vanta, Drata, Sprinto) | Checkbox compliance, not real detection. No SIEM. No AI triage. |
| **Managed Wazuh** (SOCFortress, etc.) | Cloud-managed = data leaves. No compliance evidence engine. No local inference. |

**Kahu's moat:**
1. **On-prem AI inference** — No one else does local LLM triage on a commodity appliance
2. **Compliance evidence as byproduct** — Detection and compliance in one box, not two vendors
3. **Wizard-driven simplicity** — An office manager can attach sources; competitors require a security engineer
4. **Data sovereignty as architecture** — Not a policy promise, an engineering constraint. There is no cloud fallback to accidentally enable.
5. **Cryptographic verifiability** — Ed25519-signed tuning proposals and attestation bundles. Posture claims are independently verifiable, not just asserted.

---

## Security of the Appliance Itself

A compromised security appliance is worse than no appliance, and the irony would be fatal to the brand.

- **Physical theft:** Full-disk encryption. No data recoverable from a powered-off stolen unit without keys.
- **Prompt injection via log content:** Architectural containment — the model advises, the ruleset governs. Two independent enforcement points (severity bounding and auto-dismiss floor) prevent a poisoned model output from silencing critical alerts. Treated as a permanent condition, not a solvable bug.
- **Supply chain:** Signed update artifacts, SBOM per release, base images built from upstream by ComplyHI CI.
- **ComplyHI as threat:** No standing remote access. Update signing keys offline. Health payload allowlist means a compromised operator plane cannot exfiltrate customer data.
- **Self-monitoring:** The appliance runs its own Wazuh agent and monitors itself. The shield watches itself.
- **Tuning integrity:** All tuning proposals are Ed25519-signed. A tampered proposal is rejected before it can affect alert thresholds.

---

## Technology Stack

| Layer | Technology | License |
|-------|-----------|---------|
| Core orchestration | Python 3.12 / FastAPI | Proprietary (ComplyHI) |
| Tuning engine | SciPy + custom Bayesian modeling | Proprietary (ComplyHI) |
| Database | PostgreSQL 16 | PostgreSQL License (permissive) |
| Cache/queues | Redis 7 | BSD |
| SIEM/XDR | Wazuh 4.14.1 | GPL v2 |
| Search/indexing | OpenSearch (via Wazuh Indexer) | Apache 2.0 |
| Local AI | Ollama | MIT |
| Vulnerability scanning | Greenbone/OpenVAS | GPL v2 |
| Containerization | Docker Compose | Apache 2.0 |
| Remote access | Cloudflare Tunnel + Access | Cloudflare (SaaS) |
| Frontend | React 19 + TypeScript + Vite + Tailwind | Proprietary (ComplyHI) |
| Cryptography | Ed25519 (signing), SHA-256 (evidence chain) | Standard |

---

## Team

| Role | Person | Background |
|------|--------|-----------|
| Founder / Architect | Tim Ames | ComplyHI founder, ISE operations, infrastructure engineering, compliance consulting |

*Kahu is currently a solo build. The architecture is designed for a small team to operate at scale — one operator managing a fleet of appliances, with the AI handling the per-appliance workload.*

---

## Roadmap

### v1 — Pilot (Current)

Everything described above. Detection and advise-only. ISE as customer zero, plus one external pilot at cost.

### v1.x — Market Entry

- Additional framework packs (FTC Safeguards, state-specific requirements)
- Expanded cloud source connectors (Google Workspace, AWS CloudTrail)
- Kahu V tier packaging and pricing
- MSP/MSSP partner program design
- Multi-site aggregation for customers with branches

### v2 — Autonomy (Gated)

- **Active response** — Pre-approved playbooks the customer authorizes in advance (e.g., isolate host on confirmed ransomware). Still not free-form model-driven action.
- **Fine-tuned triage model** — Trained on accumulated, customer-consented, anonymized disposition data. Consent architecture designed before v1 ships.
- **Connector SDK** — Open the manifest format for third-party or customer-authored connectors

---

## What We're Looking For

1. **Pilot funding** — Hardware for 5-10 pilot deployments across target verticals, plus 6 months of runway for full-time product development
2. **Channel introductions** — Defense subcontractor networks (CMMC compliance is mandatory and the deadline is real), healthcare associations, bar associations
3. **Advisory** — Security product go-to-market experience, compliance framework expertise, MSP/MSSP channel development

---

## Key Numbers

| Metric | Value |
|--------|-------|
| Lines of proprietary code | ~19,400 (Python backend + React frontend) |
| Backend Python (5 packages) | 15,700+ lines |
| Frontend (React 19 + TypeScript) | 2,200+ lines |
| Test suite | 320 tests, 4,000+ lines |
| Demo traffic generator | 1,500+ lines |
| API endpoints | 90+ |
| Docker services | 10 |
| Compliance frameworks supported | 7 |
| Connector types in catalog | 10+ |
| UI pages | 12 |
| Installer modes | 3 (single-node, distributed, remote probe) |
| Time from zero to working product | Solo build, ~7 months |

---

## The One-Liner

**Kahu is an AI security analyst in a box — it watches your network, triages your alerts, and writes your compliance evidence, without your data ever leaving your building.**

---

*Kahu is a product of ComplyHI. For pilot inquiries: Tim Ames, ComplyHI.*
