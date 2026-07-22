"""End-to-end batch tests with synthetic data."""

from datetime import date

import pytest

from kahu_tuning.config import CanaryConfig, RiskConfig, TuningConfig
from kahu_tuning.models import FleetPrior, TupleState, WindowState
from kahu_tuning.proposal import verify_proposal_signature
from kahu_tuning.signing import generate_keypair
from kahu_tuner.batch import run_batch


@pytest.fixture
def keypair():
    return generate_keypair()


@pytest.fixture
def configs():
    tuning_raw = {"theta_base": 20, "gamma_elevated": 3.0, "decay_delta": 0.992}
    risk_raw = {"geo_asn_risk": {"low": 1, "medium": 5, "high": 25}}
    return {
        "tuning": TuningConfig.from_dict(tuning_raw),
        "risk": RiskConfig.from_dict(risk_raw),
        "canary": CanaryConfig(canary_rule_ids=("canary-001",)),
        "tuning_raw": tuning_raw,
        "risk_raw": risk_raw,
    }


def _make_observation(rule_id, source_key, asset_id, n_events, hours=2160):
    """Build a synthetic tuple observation."""
    # Distribute events evenly across hours of week
    hour_indices = list(range(168)) * (hours // 168 + 1)
    hour_indices = hour_indices[:hours]
    return {
        "rule_id": rule_id,
        "source_key": source_key,
        "asset_id": asset_id,
        "total_events": n_events,
        "hourly_counts": [n_events // max(hours, 1)] * hours,
        "hour_of_week_indices": hour_indices,
    }


class TestBatchEndToEnd:
    @pytest.mark.asyncio
    async def test_synthetic_90d_produces_proposals(self, keypair, configs):
        """Acceptance test 1: seed 90 days of events, run batch, assert proposals."""
        priv, pub = keypair
        c = configs

        # Well-established baseline state
        state = TupleState(
            rule_id="100001", source_key="fw-01", asset_id="srv-01",
            w_1h=WindowState(1.0, 1.0),
            w_24h=WindowState(24.0, 24.0),
            w_7d=WindowState(168.0, 168.0),
            w_90d=WindowState(2160.0, 2160.0),
            golden_alpha=2160.0, golden_beta=2160.0,
        )
        states = {("100001", "fw-01", "srv-01"): state}

        # 90 days of consistent low-rate events (1/hr = 2160 total)
        obs = [_make_observation("100001", "fw-01", "srv-01", 2160, hours=2160)]

        result = await run_batch(
            tuple_observations=obs,
            states=states,
            tuning_config=c["tuning"],
            risk_config=c["risk"],
            canary_config=c["canary"],
            tuning_config_raw=c["tuning_raw"],
            risk_config_raw=c["risk_raw"],
            private_key=priv,
            today=date(2026, 7, 21),
        )

        assert result.tuples_processed == 1
        assert len(result.proposals) >= 1

        # Verify proposal structure and signature
        p = result.proposals[0]
        assert p["tuple"]["rule_id"] == "100001"
        assert p["action"] == "demote"
        assert "signature" in p
        assert verify_proposal_signature(p, pub) is True

        # Evidence values should be populated
        ev = p["evidence"]
        assert ev["n_90d"] == 2160
        assert ev["posterior_mean"] > 0
        assert ev["log_bf01"] != 0
        assert ev["risk_multiplier"] == 1.0

    @pytest.mark.asyncio
    async def test_canary_excluded(self, keypair, configs):
        """Canary rules are excluded from tuning."""
        priv, pub = keypair
        c = configs

        obs = [_make_observation("canary-001", "fw-01", "srv-01", 1000)]

        result = await run_batch(
            tuple_observations=obs,
            states={},
            tuning_config=c["tuning"],
            risk_config=c["risk"],
            canary_config=c["canary"],
            tuning_config_raw=c["tuning_raw"],
            risk_config_raw=c["risk_raw"],
            private_key=priv,
            today=date(2026, 7, 21),
        )

        assert result.tuples_processed == 0
        assert len(result.proposals) == 0
        assert len(result.canary_results) == 1

    @pytest.mark.asyncio
    async def test_drift_produces_review_no_proposal(self, keypair, configs):
        """Drifting tuples produce review items, not proposals."""
        priv, pub = keypair
        c = configs

        # State with golden at rate=1.0 but current 90d at rate=5.0
        state = TupleState(
            rule_id="200001", source_key="fw-01", asset_id="srv-01",
            w_1h=WindowState(5.0, 1.0),
            w_24h=WindowState(120.0, 24.0),
            w_7d=WindowState(840.0, 168.0),
            w_90d=WindowState(2160.0, 2160.0),  # will get updated
            golden_alpha=2160.0, golden_beta=2160.0,  # mean=1.0
        )
        states = {("200001", "fw-01", "srv-01"): state}

        # 90d data with elevated rate (5.0 * 2160 = 10800 events)
        obs = [_make_observation("200001", "fw-01", "srv-01", 10800, hours=2160)]

        result = await run_batch(
            tuple_observations=obs,
            states=states,
            tuning_config=c["tuning"],
            risk_config=c["risk"],
            canary_config=c["canary"],
            tuning_config_raw=c["tuning_raw"],
            risk_config_raw=c["risk_raw"],
            private_key=priv,
            today=date(2026, 7, 21),
        )

        assert result.tuples_processed == 1
        # Drift detected: should produce review, not proposal
        assert len(result.drift_reviews) >= 1
        assert len(result.proposals) == 0

    @pytest.mark.asyncio
    async def test_signature_valid_on_all_proposals(self, keypair, configs):
        """Every emitted proposal has a valid signature."""
        priv, pub = keypair
        c = configs

        states = {}
        obs = []
        for i in range(5):
            rid = f"rule-{i}"
            state = TupleState(
                rule_id=rid, source_key="fw-01", asset_id="srv-01",
                w_1h=WindowState(1.0, 1.0),
                w_24h=WindowState(24.0, 24.0),
                w_7d=WindowState(168.0, 168.0),
                w_90d=WindowState(2160.0, 2160.0),
                golden_alpha=2160.0, golden_beta=2160.0,
            )
            states[(rid, "fw-01", "srv-01")] = state
            obs.append(_make_observation(rid, "fw-01", "srv-01", 2160))

        result = await run_batch(
            tuple_observations=obs,
            states=states,
            tuning_config=c["tuning"],
            risk_config=c["risk"],
            canary_config=c["canary"],
            tuning_config_raw=c["tuning_raw"],
            risk_config_raw=c["risk_raw"],
            private_key=priv,
            today=date(2026, 7, 21),
        )

        for p in result.proposals:
            assert verify_proposal_signature(p, pub) is True, (
                f"Proposal {p['proposal_id']} failed signature verification"
            )
