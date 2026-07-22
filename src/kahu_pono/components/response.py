"""Component 5: Response readiness (15 points).

Subweights (from weights_schema.json):
- median_ack_time: acknowledgement time vs SLA
- cases_past_sla: fraction of cases within SLA
- playbook_success_rate: fraction of playbook executions successful
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ResponseInput:
    median_ack_minutes: float = 0.0
    ack_sla_minutes: float = 15.0
    cases_in_sla: int = 0
    cases_total: int = 0
    playbook_successes: int = 0
    playbook_executions: int = 0
    data_available: bool = True


def score_response(inp: ResponseInput, subweights: dict[str, float]) -> tuple[float, dict]:
    """Score response readiness. Returns (raw_score 0-1, details)."""
    if not inp.data_available:
        return 0.0, {"status": "not assessed"}

    scores = {}

    # Median ack time: 1.0 if within SLA, linear decay to 0 at 3x SLA
    if inp.median_ack_minutes <= inp.ack_sla_minutes:
        scores["median_ack_time"] = 1.0
    else:
        overage = inp.median_ack_minutes - inp.ack_sla_minutes
        max_overage = inp.ack_sla_minutes * 2
        scores["median_ack_time"] = max(0.0, 1.0 - overage / max_overage)

    # Cases past SLA: fraction within SLA
    if inp.cases_total > 0:
        scores["cases_past_sla"] = inp.cases_in_sla / inp.cases_total
    else:
        scores["cases_past_sla"] = 1.0

    # Playbook success rate
    if inp.playbook_executions > 0:
        scores["playbook_success_rate"] = inp.playbook_successes / inp.playbook_executions
    else:
        scores["playbook_success_rate"] = 0.0

    raw = sum(scores.get(k, 0.0) * w for k, w in subweights.items())
    return raw, scores
