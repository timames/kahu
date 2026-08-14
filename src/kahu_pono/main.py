"""Pono Score service -- FastAPI endpoints."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from pydantic import BaseModel

from kahu_pono.config import WeightsSchema
from kahu_pono.engine import (
    COMPONENT_REGISTRY,
    check_pono_drop,
    compute_pono_score,
)

app = FastAPI(title="Kahu Pono Score", version="0.1.0")

# Load weights schema at startup
_schema: WeightsSchema | None = None


def get_schema() -> WeightsSchema:
    global _schema
    if _schema is None:
        schema_path = Path(__file__).resolve().parents[2] / "config" / "weights_schema.json"
        _schema = WeightsSchema.from_file(schema_path)
    return _schema


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "kahu_pono"}


class ScoreRequest(BaseModel):
    inputs: dict = {}
    evidence_ages: dict[str, float] = {}
    previous_score: float | None = None


class ScoreResponse(BaseModel):
    pono_score: float
    components: list[dict]
    schema_version: str
    biggest_gain: dict | None = None
    pono_drop: dict | None = None


@app.post("/score", response_model=ScoreResponse)
async def score(req: ScoreRequest):
    schema = get_schema()

    # Build typed inputs from request dicts
    typed_inputs = {}
    for comp_name, raw in req.inputs.items():
        if comp_name in COMPONENT_REGISTRY:
            _, input_cls = COMPONENT_REGISTRY[comp_name]
            typed_inputs[comp_name] = input_cls(**raw)

    result = compute_pono_score(schema, typed_inputs, req.evidence_ages)

    drop = None
    if req.previous_score is not None:
        drop = check_pono_drop(
            result.pono_score,
            req.previous_score,
            schema.pono_drop_threshold,
        )

    return ScoreResponse(
        pono_score=round(result.pono_score, 2),
        components=[
            {
                "name": c.name,
                "raw_score": round(c.raw_score, 4),
                "weighted_score": round(c.weighted_score, 2),
                "max_points": c.max_points,
                "assessed": c.assessed,
                "label": c.label,
                "evidence_age_days": round(c.evidence_age_days, 1),
            }
            for c in result.components
        ],
        schema_version=result.schema_version,
        biggest_gain=result.biggest_gain,
        pono_drop=drop,
    )


@app.get("/schema")
async def schema_info():
    schema = get_schema()
    return {
        "schema_version": schema.schema_version,
        "total_weight": schema.total_weight(),
        "components": {
            name: {
                "weight": c.weight,
                "subweights": c.subweights,
            }
            for name, c in schema.components.items()
        },
        "freshness_decay_delta": schema.freshness_decay_delta,
        "not_assessed_ceiling_pct": schema.not_assessed_ceiling_pct,
        "pono_drop_threshold": schema.pono_drop_threshold,
    }
