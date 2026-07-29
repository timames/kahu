# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Kahu is an on-premises AI security operations appliance. It combines Wazuh (SIEM/XDR) + Ollama (local LLM) + a FastAPI orchestration layer. All data stays on-premises. The project was renamed from "Kuahene" to "Kahu" but the repo directory still uses the old name.

## Commands

### Backend (Python)
```bash
# Install (editable, with dev deps)
pip install -e ".[dev]"

# Run API server
uvicorn kahu.main:app --reload --port 8000

# Run all tests
pytest

# Run a single test file / specific test
pytest tests/test_pipeline.py
pytest tests/test_filters.py::test_something -v

# Lint
ruff check src/ tests/
ruff format --check src/ tests/

# Type check
mypy src/

# Database migrations
alembic upgrade head
alembic revision --autogenerate -m "description"
```

### Frontend (React)
```bash
cd frontend
npm install
npm run dev       # Vite dev server
npm run build     # Build to frontend/dist (then copy to src/kahu/static/)
```

### Docker (full stack)
```bash
docker compose up -d --build          # core + postgres + redis + ollama + wazuh + greenbone + generator
docker compose up -d core postgres redis  # minimal for API dev
```

## Architecture

### Packages (all under `src/`)

- **`kahu`** -- Core FastAPI app. The main deliverable.
- **`kahu_tuning`** -- Bayesian alert rate modeling engine (suppression proposals via conjugate priors).
- **`kahu_tuner`** -- Nightly batch service that runs `kahu_tuning` against historical alert data.
- **`kahu_pono`** -- "Pono Score" -- 100-point security posture scoring across detection, tuning, vulnerability, identity, response, and human components.
- **`kahu_attest`** -- Signed security posture export bundles for third-party attestation.

### Kahu Core Layers

**API routes** (`src/kahu/api/`): All routes mount under `/api`. Health and auth are public; everything else requires JWT via `get_current_user` dependency. Use `require_role()` for role-based access.

**Triage pipeline** (`src/kahu/services/triage/pipeline.py`): The central subsystem. Four stages:
1. **Filters** -- deterministic rule-based suppression, dedup, correlation
2. **Enrichment** -- asset context, related events, vuln state
3. **LLM triage** -- structured prompt to Ollama, returns severity + explanation
4. **Disposition** -- DB persistence + evidence recording + auto-disposition for obvious cases

Key invariant: the LLM advises but the ruleset governs. LLM cannot lower severity more than one band below the deterministic severity (`_bound_severity`).

**Clients** (`src/kahu/clients/`): Infrastructure integration -- `ollama.py`, `wazuh.py`, `greenbone.py`, `redaction.py` (PII scrubbing).

**Background tasks**: `poller.py` polls Wazuh for new alerts every 15s; `reeval.py` re-evaluates alerts on a loop. Both start in `main.py` lifespan.

### Database

Async Postgres via SQLAlchemy 2.0 + asyncpg. Session factory in `db.py`. Models in `src/kahu/models/`. Migrations via Alembic (async-aware `env.py`).

### Frontend

React 19 + TypeScript + Vite + Tailwind CSS PWA. Pages: Glance (dashboard), Feed (alert stream), Investigate, Reports, Compliance, Connectors, Arsenal, Settings. Built output is served as static files by FastAPI with SPA catch-all routing.

### Generator

Separate Docker service (`generator/`) that produces synthetic security events for demos. Not part of the core product. Has its own REST API on port 8080.

## Configuration

All settings via env vars or `.env` file (see `.env.example`). Loaded by pydantic-settings in `src/kahu/config.py`. Key vars: `DATABASE_URL`, `REDIS_URL`, `OLLAMA_BASE_URL`, `OLLAMA_MODEL`, `WAZUH_API_URL`, `SECRET_KEY`.

## Conventions

- Python 3.12+. Ruff for linting/formatting (line length 100). Mypy strict mode.
- `pytest-asyncio` with `asyncio_mode = "auto"` -- async test functions work without decorators.
- Security rule `S101` is ignored (asserts allowed in tests).
- The project uses hatchling as build backend.
