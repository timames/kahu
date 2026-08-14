"""Pono Score engine -- orchestrates component scoring."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from kahu_pono.components import ComponentResult
from kahu_pono.components.detection import DetectionInput, score_detection
from kahu_pono.components.human import HumanInput, score_human
from kahu_pono.components.identity import IdentityInput, score_identity
from kahu_pono.components.response import ResponseInput, score_response
from kahu_pono.components.tuning import TuningInput, score_tuning
from kahu_pono.components.vulnerability import VulnerabilityInput, score_vulnerability
from kahu_pono.config import WeightsSchema
from kahu_pono.freshness import apply_freshness

# Maps component config names to (scorer_func, input_class)
COMPONENT_REGISTRY: dict[str, tuple] = {
    "detection_posture": (score_detection, DetectionInput),
    "tuning_hygiene": (score_tuning, TuningInput),
    "vulnerability_posture": (score_vulnerability, VulnerabilityInput),
    "identity_access": (score_identity, IdentityInput),
    "response_readiness": (score_response, ResponseInput),
    "human_layer": (score_human, HumanInput),
}


@dataclass
class PonoResult:
    """Full Pono Score result."""

    pono_score: float  # 0-100
    components: list[ComponentResult]
    schema_version: str
    biggest_gain: dict | None = None
    metadata: dict = field(default_factory=dict)


def score_component(
    name: str,
    inp: Any,
    max_points: int,
    subweights: dict[str, float],
    evidence_age_days: float = 0.0,
    freshness_delta: float = 0.992,
    not_assessed_ceiling_pct: float = 0.40,
) -> ComponentResult:
    """Score a single component and return ComponentResult."""
    if name not in COMPONENT_REGISTRY:
        raise ValueError(f"Unknown component: {name}")

    scorer_fn, _ = COMPONENT_REGISTRY[name]
    raw_score, details = scorer_fn(inp, subweights)

    assessed = details.get("status") != "not assessed"

    if assessed:
        # Apply freshness decay
        decayed = apply_freshness(raw_score, evidence_age_days, freshness_delta)
        weighted = decayed * max_points
    else:
        # Not assessed: cap at ceiling percentage of max points
        weighted = not_assessed_ceiling_pct * max_points
        raw_score = not_assessed_ceiling_pct

    return ComponentResult(
        name=name,
        raw_score=raw_score,
        weighted_score=weighted,
        max_points=max_points,
        assessed=assessed,
        label="assessed" if assessed else "not assessed",
        evidence_age_days=evidence_age_days,
        details=details,
    )


def compute_pono_score(
    schema: WeightsSchema,
    inputs: dict[str, Any],
    evidence_ages: dict[str, float] | None = None,
) -> PonoResult:
    """Compute the full 100-point Pono Score.

    Args:
        schema: Weights configuration.
        inputs: Map of component name -> input dataclass instance.
        evidence_ages: Map of component name -> evidence age in days.

    Returns:
        PonoResult with score, components, and biggest-gain recommendation.
    """
    if evidence_ages is None:
        evidence_ages = {}

    components: list[ComponentResult] = []

    for comp_name, comp_cfg in schema.components.items():
        inp = inputs.get(comp_name)
        if inp is None:
            # Component not provided: create default input with data_available=False
            if comp_name in COMPONENT_REGISTRY:
                _, input_cls = COMPONENT_REGISTRY[comp_name]
                inp = input_cls(data_available=False)
            else:
                continue

        result = score_component(
            name=comp_name,
            inp=inp,
            max_points=comp_cfg.weight,
            subweights=comp_cfg.subweights,
            evidence_age_days=evidence_ages.get(comp_name, 0.0),
            freshness_delta=schema.freshness_decay_delta,
            not_assessed_ceiling_pct=schema.not_assessed_ceiling_pct,
        )
        components.append(result)

    pono_score = sum(c.weighted_score for c in components)
    biggest_gain = find_biggest_gain(components)

    return PonoResult(
        pono_score=pono_score,
        components=components,
        schema_version=schema.schema_version,
        biggest_gain=biggest_gain,
    )


def find_biggest_gain(components: list[ComponentResult]) -> dict | None:
    """Find the component with the biggest available point gain.

    For each component, the gap = max_points - weighted_score.
    Returns the component with the largest gap.
    """
    if not components:
        return None

    best = None
    best_gap = -1.0

    for c in components:
        gap = c.max_points - c.weighted_score
        if gap > best_gap:
            best_gap = gap
            best = c

    if best is None or best_gap <= 0:
        return None

    return {
        "component": best.name,
        "current_score": round(best.weighted_score, 2),
        "max_points": best.max_points,
        "available_gain": round(best_gap, 2),
        "assessed": best.assessed,
    }


def check_pono_drop(
    current: float,
    previous: float,
    threshold: int = 5,
) -> dict | None:
    """Check if Pono Score dropped by more than threshold points.

    Returns drop event dict if triggered, None otherwise.
    """
    drop = previous - current
    if drop >= threshold:
        return {
            "event": "pono_drop",
            "current_score": round(current, 2),
            "previous_score": round(previous, 2),
            "drop": round(drop, 2),
            "threshold": threshold,
        }
    return None
