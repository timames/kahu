# Kahu

On-premises AI security operations appliance. Detects, triages, and proves — all data stays local.

Kahu combines Wazuh (SIEM/XDR), Ollama (local LLM inference), and a FastAPI orchestration layer into a single deployable stack. It's built for small and mid-sized organizations that are genuinely defended but can't produce compliance evidence on demand.

## What it does

**Triage pipeline** — Wazuh alerts flow through four stages: deterministic filtering, asset enrichment, LLM-assisted triage, and disposition. The LLM advises but the ruleset governs — it cannot lower severity more than one band below the deterministic score.

**Pono Score** — 100-point security posture score across six components. Evidence decays exponentially (δ=0.992 per day), so the score falls unless you keep doing the work. A validation sampler randomly spot-checks endpoints to verify the score isn't lying.

| Component | Weight | What it measures |
|---|---|---|
| Detection posture | 25 | Sensor health, log source coverage, rule freshness, canary pass rate |
| Vulnerability posture | 20 | CVSS-weighted findings, remediation velocity vs SLA |
| Tuning hygiene | 15 | Suppression quality, proposal review rate, drift flags |
| Identity & access | 15 | MFA coverage, stale accounts, privilege creep, secret rotation |
| Response readiness | 15 | Acknowledgement time, SLA adherence, playbook success rate |
| Human layer | 10 | Training completion, training recency |

**Compliance evidence engine** — Append-only, hash-chained evidence records generated as a byproduct of operations. Coverage mapping across NIST 800-171, CMMC L2, HIPAA, SOC 2 Type II, and CIS Controls v8 with gap analysis.

**Bayesian alert tuning** — Conjugate prior modeling (Gamma distributions) over rolling time windows to generate suppression proposals. Signed with Ed25519. Drift detection via KL divergence against golden baselines.

**Investigation & reporting** — Natural language queries against Wazuh data, executive reports, incident packages, evidence export bundles with portable attestation.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Kahu Core                         │
│  FastAPI · Postgres · Redis · Alembic                │
│                                                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐            │
│  │  Triage   │ │  Pono    │ │Compliance│            │
│  │ Pipeline  │ │  Score   │ │  Engine  │            │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘            │
│       │            │            │                    │
│  ┌────┴────────────┴────────────┴─────┐             │
│  │         Evidence Store              │             │
│  │   (append-only, hash-chained)       │             │
│  └─────────────────────────────────────┘             │
└──────────┬──────────────┬──────────────┬─────────────┘
           │              │              │
     ┌─────┴─────┐ ┌─────┴─────┐ ┌─────┴──────┐
     │   Wazuh    │ │  Ollama   │ │ Greenbone  │
     │ SIEM/XDR   │ │ Local LLM │ │  OpenVAS   │
     └───────────┘ └───────────┘ └────────────┘
```

### Packages

| Package | Purpose |
|---|---|
| `kahu` | Core FastAPI app — triage, investigation, compliance, API |
| `kahu_pono` | Pono Score engine — component scoring, freshness decay |
| `kahu_tuning` | Bayesian alert rate modeling — suppression proposals |
| `kahu_tuner` | Nightly batch service that runs tuning against historical data |
| `kahu_attest` | Signed security posture export bundles for third-party verification |

## Quick start

### Docker (full stack)

```bash
cp .env.example .env
# Edit .env with your secrets

docker compose up -d --build
```

This starts: Kahu Core (port 8000), Postgres, Redis, Ollama (port 11434), Wazuh manager/indexer/dashboard (ports 1514-1515, 9200, 443), Greenbone (port 9392), and the demo event generator (port 8080).

### Minimal (API dev)

```bash
docker compose up -d core postgres redis
```

### Local development

```bash
pip install -e ".[dev]"
uvicorn kahu.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

React 19 + TypeScript + Vite + Tailwind CSS. Builds to `frontend/dist`, served as static files by FastAPI.

## API

All routes under `/api`. Health and auth are public; everything else requires JWT.

| Route | Description |
|---|---|
| `POST /api/auth/login` | Get JWT token |
| `GET /api/triage/queue` | Alert triage queue |
| `POST /api/triage/alerts/{id}/disposition` | Record analyst verdict |
| `GET /api/pono/current` | Current Pono Score with component breakdown |
| `GET /api/pono/history` | Score time series |
| `POST /api/pono/recalculate` | Trigger immediate recalculation |
| `POST /api/validation/rounds` | Run validation spot-check |
| `GET /api/validation/drift` | Check if score diverges from ground truth |
| `GET /api/compliance/frameworks/{id}/coverage` | Control coverage matrix |
| `GET /api/compliance/frameworks/{id}/gaps` | Gap analysis with recommendations |

Full OpenAPI docs at `/api/docs` when `DEBUG=true`.

## Testing

```bash
pytest                              # all tests
pytest tests/test_pono/             # pono score suite
pytest tests/test_validation.py     # validation sampler
pytest tests/test_pipeline.py       # triage pipeline
```

## Configuration

All settings via environment variables or `.env` file. See `.env.example`.

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | — | Postgres connection string (asyncpg) |
| `REDIS_URL` | — | Redis connection string |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama API endpoint |
| `OLLAMA_MODEL` | `mistral:7b-instruct-v0.3-q4_K_M` | Model for triage |
| `WAZUH_API_URL` | `https://localhost:55000` | Wazuh management API |
| `SECRET_KEY` | — | JWT signing key |

## Hardware tiers

| Tier | Endpoints | Inference | Form factor |
|---|---|---|---|
| S | ≤ 25 | CPU | UGREEN NAS |
| M | 25–150 | GPU (RTX 4500/5000) | 1U rackmount |
| V | 150+ | GPU | Virtual appliance (OVA/Hyper-V) |

## Design principles

1. **Data sovereignty** — nothing leaves premises
2. **Fail closed** — restrictive defaults on any failure
3. **Human in the loop** — no autonomous remediation in v1
4. **Evidence as byproduct** — compliance artifacts generated from operations, not a separate workflow

## License

Proprietary. Copyright ComplyHI.
