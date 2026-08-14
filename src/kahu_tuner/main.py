"""Kahu tuner service entrypoint.

Scheduled container that runs the nightly batch job.
Provides /healthz and /metrics endpoints.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC
from pathlib import Path

from fastapi import FastAPI
from prometheus_client import Counter, Gauge, generate_latest
from starlette.responses import PlainTextResponse

app = FastAPI(title="kahu-tuner", version="0.1.0")
log = logging.getLogger("kahu_tuner")

# ── Prometheus metrics ────────────────────────────────────

proposals_emitted = Counter("kahu_tuner_proposals_emitted_total", "Total proposals emitted")
drift_flags = Counter("kahu_tuner_drift_flags_total", "Total drift flags raised")
tuples_processed = Gauge("kahu_tuner_tuples_processed", "Tuples processed in last batch")
batch_errors = Counter("kahu_tuner_batch_errors_total", "Total batch processing errors")
last_batch_ts = Gauge("kahu_tuner_last_batch_timestamp", "Timestamp of last batch run")


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "kahu-tuner"}


@app.get("/metrics")
async def metrics():
    return PlainTextResponse(generate_latest(), media_type="text/plain")


@app.post("/run")
async def trigger_batch():
    """Manually trigger a batch run (for testing/ops)."""
    from datetime import datetime

    from kahu_tuner.batch import run_batch
    from kahu_tuning.config import (
        CanaryConfig,
        RiskConfig,
        TuningConfig,
        load_json,
    )
    from kahu_tuning.signing import load_private

    config_dir = Path(os.environ.get("KAHU_CONFIG_DIR", "/app/config"))
    key_path = os.environ.get("KAHU_SIGNING_KEY", "/app/keys/tuner.key")

    tuning_raw = load_json(config_dir / "tuning_config.json")
    risk_raw = load_json(config_dir / "risk_config.json")
    canary_raw = load_json(config_dir / "canary_config.json")

    tc = TuningConfig.from_dict(tuning_raw)
    rc = RiskConfig.from_dict(risk_raw)
    cc = CanaryConfig.from_dict(canary_raw)
    pk = load_private(key_path)

    # In production, tuple_observations come from OpenSearch aggregations.
    # For the /run endpoint, we process an empty batch (placeholder).
    result = await run_batch(
        tuple_observations=[],
        states={},
        tuning_config=tc,
        risk_config=rc,
        canary_config=cc,
        tuning_config_raw=tuning_raw,
        risk_config_raw=risk_raw,
        private_key=pk,
    )

    proposals_emitted.inc(len(result.proposals))
    drift_flags.inc(len(result.drift_reviews))
    tuples_processed.set(result.tuples_processed)
    batch_errors.inc(len(result.errors))
    last_batch_ts.set(datetime.now(UTC).timestamp())

    return {
        "tuples_processed": result.tuples_processed,
        "proposals": len(result.proposals),
        "drift_reviews": len(result.drift_reviews),
        "errors": len(result.errors),
    }
