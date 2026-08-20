# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Kahu is an on-premises AI security operations appliance. It combines Wazuh (SIEM/XDR) + Ollama (local LLM) + a FastAPI orchestration layer. All data stays on-premises — there is no cloud-inference fallback anywhere, not as a config option, not at all. The project was renamed from "Kuahene" to "Kahu"; a few older artifacts under `docs/` still use the old name.

## Commands

### Backend (Python)
```bash
# Install (editable, with dev deps)
pip install -e ".[dev]"

# Run API server
uvicorn kahu.main:app --reload --port 8000

# Run all tests
pytest

# Run a single test file / class / test
pytest tests/test_pipeline.py
pytest tests/test_auto_disposition_floor.py::TestAutoDismissForbidden -v
pytest tests/test_filters.py::test_something -v

# Lint / format / type check
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/

# Database migrations (Postgres only — see SQLite dev mode below)
alembic upgrade head
alembic revision --autogenerate -m "description"

# Verify an attestation bundle
python -m kahu_attest <bundle.json>
```

### Frontend (React)
```bash
cd frontend
npm install
npm run dev       # Vite dev server on :5173, proxies /api -> localhost:8000
npm run build     # tsc -b && vite build
```

`vite.config.ts` sets `outDir: ../src/kahu/static` with `emptyOutDir: true`. A build writes **directly into the Python package** and wipes that directory first — there is no `frontend/dist` and no copy step. `src/kahu/static/` is committed build output; rebuild and commit it when frontend changes need to ship.

### Docker (full stack)
```bash
docker compose up -d --build              # core, postgres, redis, ollama, wazuh-{manager,indexer,dashboard}, greenbone, generator
docker compose up -d core postgres redis  # minimal for API dev
docker compose --profile cloud up -d cloudflared   # Cloudflare tunnel (opt-in profile)
```

The Wazuh API (55000) is deliberately not published to the host — Windows reserves that port range. Reach it from inside the network at `wazuh-manager:55000`. `kahu_tuner` has no compose service; it is a standalone container/service driven by `KAHU_CONFIG_DIR` and `KAHU_SIGNING_KEY`.

## Architecture

### Packages (all under `src/`)

- **`kahu`** — Core FastAPI app. The main deliverable.
- **`kahu_tuning`** — Bayesian alert rate modeling (Gamma conjugate priors, shrinkage, seasonality, KL-divergence drift). Ed25519-signed proposals.
- **`kahu_tuner`** — Nightly batch service that runs `kahu_tuning` against historical alert data. Exposes `/healthz`, `/metrics`, `POST /run`.
- **`kahu_pono`** — "Pono Score" — 100-point posture score across detection, tuning, vulnerability, identity, response, and human components.
- **`kahu_attest`** — Signed posture export bundles for third-party verification. Reuses `kahu_tuning.signing` / `canonical_json`.

Dependency direction is one-way: `kahu` imports the satellite packages; they never import `kahu`. `kahu_pono` and `kahu_attest` both depend on `kahu_tuning` for canonical JSON and signing.

### Kahu Core layers

**API routes** (`src/kahu/api/`): every router is mounted in `api/__init__.py` under `/api`. Health and auth are public; every other router is mounted with `dependencies=[Depends(get_current_user)]`, so auth is enforced at mount time, not per-endpoint. Use `require_role()` from `api/deps.py` for role gating. An endpoint that needs the caller's identity (for evidence attribution) must still declare `user: User = Depends(get_current_user)` itself.

**Triage pipeline** (`src/kahu/services/triage/pipeline.py`): the central subsystem. Stages:
1. **Filters** (`filters.py`) — deterministic suppression, dedup, correlation. Assigns `FilterResult.severity` and `critical_rule`.
2. **Enrichment** (`enrichment.py`) — asset context, related events, vuln state, rule/agent disposition history.
3. **LLM triage** (`llm_triage.py`) — structured prompt to Ollama, returns severity + explanation + confidence.
4. **Disposition** (`disposition.py`) — DB persistence + evidence recording.
5. **Auto-disposition** (`auto_disposition.py`) — closes obvious cases without a human.

### The governing invariant: the model advises, the ruleset governs

This is the most important rule in the codebase and the easiest to accidentally break. LLM output is derived from attacker-controllable log content (Wazuh alert bodies, delimited in the prompt by `<ALERT_DATA>`). Prompt injection is *assumed*, not defended against by prompting. The real defense is architectural, and it has **two independent enforcement points**:

- `pipeline._bound_severity()` bounds the **displayed** severity — the LLM may raise freely but cannot lower more than one band below the deterministic severity.
- `auto_disposition.auto_dismiss_forbidden()` bounds the **auto-dismiss action**, which is separate and silent. A high/critical *deterministic* severity, or any `CRITICAL_RULE_IDS` hit, can never be auto-acknowledged — regardless of tolerance level, model confidence, or rule false-positive history. It routes to a human and stamps `auto_dismiss_blocked_by_floor` into provenance.

The second check reads `FilterResult.severity` (the raw deterministic value), **not** the bounded severity, specifically to bypass any one-band laundering the model did. Auto-confirm and escalate are deliberately unbounded: erring toward visibility is safe, erring toward silence is the failure this pipeline exists to prevent.

When touching triage, preserve both. `tests/test_auto_disposition_floor.py` is the regression suite for the second one.

**Verdict vocabulary:** the canonical spelling is `DispositionVerdict`'s — `"acknowledged"`, not `"acknowledge"`. `canonical_verdict()` in `llm_triage.py` folds the legacy `"acknowledge"`/`"false_positive"` variants to it at the parse boundary, and `maybe_auto_dispose` re-normalizes defensively so hand-built `llm_output` can't silently disable the comparison. Explicit model recommendations DO flow into auto-dismissal now (still floor-bounded); keep any new verdict comparison keyed on the canonical value via `canonical_verdict()`.

**Evidence store** (`services/compliance/evidence.py`): append-only, SHA-256 hash-chained. Any subsystem calls `record_evidence(session, event_type=..., control_tags=[...], payload=..., actor=...)`; **the caller owns the commit**. `verify_chain()` walks it. Security-relevant configuration changes belong here too, not just operational events — see `set_tolerance_audited()` for the pattern (mutate, record with attribution, commit).

**Clients** (`src/kahu/clients/`): `ollama.py`, `wazuh.py` (`WazuhAPIClient` + `WazuhIndexerClient`), `greenbone.py`, `redaction.py` (PII/secret scrubbing, applied to prompt text before it reaches the model).

**Degraded mode**: when Ollama is unhealthy or returns unparseable output, `llm_triage` returns a `degraded: true` result and the pipeline continues deterministic-only. Downstream code must treat `degraded` as "no model signal" — `maybe_auto_dispose` refuses to act on it entirely. Preserve that; never substitute a remote model.

**Background loops**, all started in `main.py` lifespan: `triage/poller.py` (Wazuh poll, 15s), `services/pono.py::run_pono_loop` (score recalc, 300s), `triage/reeval.py` (alert re-evaluation). Each swallows exceptions and logs, so a broken loop degrades silently — check logs, not just liveness.

### Process-global mutable state

Several subsystems keep state in module-level globals rather than the DB: `auto_disposition._current_tolerance`, `arsenal/mode.py._unlocked`, `filters.DeduplicationWindow._instance`. These reset on restart and are **not shared across uvicorn workers** — the appliance is intended to run single-process. Don't add `--workers` without moving this state to Redis/Postgres first.

### Database

Async Postgres via SQLAlchemy 2.0 + asyncpg. Engine and `async_session` in `db.py`; models in `src/kahu/models/` on the `Base`/`TimestampMixin`/`UUIDPrimaryKey` bases. Migrations via an async-aware Alembic `env.py` that pulls the URL from `settings.database_url`.

Models are written for **Postgres and SQLite compatibility** — note `from sqlalchemy import JSON as JSONB` in `models/evidence.py`. Keep new models portable; the test suite runs on SQLite.

**SQLite dev mode**: if `DATABASE_URL` starts with `sqlite`, `main.py` lifespan calls `create_tables()` (`Base.metadata.create_all`) at startup and Alembic is bypassed entirely. Good for a fast loop; it means schema drift won't surface as a migration failure, so still generate migrations for Postgres.

### Configuration

Env vars or `.env`, loaded by pydantic-settings in `src/kahu/config.py` (see `.env.example`). Key vars: `DATABASE_URL`, `REDIS_URL`, `OLLAMA_BASE_URL`, `OLLAMA_MODEL`, `WAZUH_API_URL`, `SECRET_KEY`, `APPLIANCE_HOST`.

JSON config lives in `config/` at the repo root: `weights_schema.json` (Pono weights) and `tuning_config.json` / `risk_config.json` / `canary_config.json` (consumed by `kahu_tuner` via `KAHU_CONFIG_DIR`).

**Config-dir resolution:** all consumers honor `KAHU_CONFIG_DIR` (`settings.kahu_config_dir` in `config.py` for the core; the env var directly in `kahu_pono/main.py` and `kahu_tuner`), falling back to the repo-root `config/` walk which only works from a source checkout. The `Dockerfile` copies `config/` to `/app/config` and sets `KAHU_CONFIG_DIR=/app/config`. If you add a new JSON config consumer, resolve it through `KAHU_CONFIG_DIR` — never a `parents[N]` walk from `__file__` alone, which breaks in an installed wheel.

### Frontend

React 19 + TypeScript + Vite + Tailwind PWA. Pages: Glance, Feed, Investigate, Score, Reports, Compliance, Connectors, Recon, Arsenal, Settings, More. All API calls go through `frontend/src/api/client.ts`, which reads the JWT from `localStorage["kahu_auth"]` and hard-redirects to `/login` on any 401. FastAPI serves the built output with an SPA catch-all, plus explicit routes for `sw.js`, `registerSW.js`, and `manifest.webmanifest` at the root so the service worker gets full scope.

### Generator

Separate Docker service (`generator/`) producing synthetic security events for demos, syslog → `wazuh-manager`. Not part of the core product; own REST API on 8080.

## Testing

- `pytest-asyncio` with `asyncio_mode = "auto"` — async test functions need no decorator.
- **There is no `conftest.py`.** Tests that need a DB construct their own in-memory engine fixture (`create_async_engine("sqlite+aiosqlite:///:memory:")` + `Base.metadata.create_all`). Copy the fixture from `tests/test_pono/test_integration.py` when adding one.
- `aiosqlite` is declared in the dev extras and required by those tests.
- The suite exercises async DB paths on aiosqlite, not asyncpg. Postgres-specific behaviour (notably JSON operators such as the `Alert.pipeline_provenance["auto_disposed"].as_string()` query in `services/pono.py`) is not covered — verify those against a real Postgres.
- `tests/synthetic/generators.py` holds shared fixture builders for alert payloads.

## Conventions

- Python 3.12+. Ruff (line length 100, `E,F,I,N,W,UP,S,B,A,SIM`, `S101` ignored). Mypy strict with the pydantic plugin.
- Hatchling build backend; the five `src/*` packages are listed explicitly in `[tool.hatch.build.targets.wheel]` — a new top-level package must be added there.
- Security-relevant invariants are documented in long module-level docstrings and inline comments explaining *why* (see `auto_disposition.py`). Keep that density when modifying those files; the rationale is the point.
