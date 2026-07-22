"""Exponential forgetting for rolling posteriors."""

from __future__ import annotations

from datetime import date, datetime, timezone

from kahu_tuning.config import TuningConfig
from kahu_tuning.models import TupleState


def apply_decay(
    state: TupleState,
    today: date | None = None,
    config: TuningConfig | None = None,
) -> TupleState:
    """Apply nightly exponential decay to rolling posteriors.

    alpha *= delta, beta *= delta, where delta = 0.992 (about 90-day effective memory).
    Applied to rolling posteriors only, never to golden snapshots.
    Idempotent: will not re-apply if already decayed today.

    Properties preserved:
    - Posterior mean (alpha/beta) stays the same after decay
    - Posterior variance (alpha/beta^2) increases (wider uncertainty)
    """
    cfg = config or TuningConfig()
    if today is None:
        today = datetime.now(timezone.utc).date()

    # Idempotent: skip if already decayed today
    if state.last_decay_ts is not None:
        last_date = state.last_decay_ts.date() if isinstance(state.last_decay_ts, datetime) else state.last_decay_ts
        if last_date >= today:
            return state

    delta = cfg.decay_delta

    # Decay all rolling windows
    w_1h = _decay_window(state.w_1h, delta)
    w_24h = _decay_window(state.w_24h, delta)
    w_7d = _decay_window(state.w_7d, delta)
    w_90d = _decay_window(state.w_90d, delta)

    return TupleState(
        rule_id=state.rule_id,
        source_key=state.source_key,
        asset_id=state.asset_id,
        w_1h=w_1h,
        w_24h=w_24h,
        w_7d=w_7d,
        w_90d=w_90d,
        golden_alpha=state.golden_alpha,  # Never decayed
        golden_beta=state.golden_beta,
        last_decay_ts=datetime(today.year, today.month, today.day, tzinfo=timezone.utc),
        last_update_ts=state.last_update_ts,
    )


def _decay_window(window, delta: float):
    from kahu_tuning.models import WindowState

    return WindowState(
        alpha=window.alpha * delta,
        beta=window.beta * delta,
        n_events=window.n_events,
        t_hours=window.t_hours,
    )
