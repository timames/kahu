"""Suppression proposal schema, generation, and signing."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kahu_tuning import __version__
from kahu_tuning.config import canonical_json, config_hash
from kahu_tuning.signing import sign_payload


def build_evidence_block(
    n_90d: int,
    t_star_hours: float,
    posterior_mean: float,
    posterior_cv: float,
    log_bf01: float,
    posterior_odds: float,
    risk_multiplier: float,
    threshold_applied: float,
    kl_vs_golden: float,
    windows_consistent: bool,
) -> dict:
    """Build the evidence sub-object for a proposal."""
    return {
        "n_90d": n_90d,
        "t_star_hours": round(t_star_hours, 4),
        "posterior_mean": round(posterior_mean, 6),
        "posterior_cv": round(posterior_cv, 6),
        "log_bf01": round(log_bf01, 6),
        "posterior_odds": round(posterior_odds, 6),
        "risk_multiplier": round(risk_multiplier, 4),
        "threshold_applied": round(threshold_applied, 4),
        "kl_vs_golden": round(kl_vs_golden, 6),
        "windows_consistent": windows_consistent,
    }


def build_proposal(
    rule_id: str,
    source_key: str,
    asset_id: str,
    action: str,
    action_params: dict,
    evidence: dict,
    tuning_config_raw: dict,
    risk_config_raw: dict,
    expiry_days: int = 90,
) -> dict:
    """Build an unsigned proposal document.

    The proposal is constructed with all fields except signature.
    Call sign_proposal() to add the Ed25519 signature.
    """
    now = datetime.now(timezone.utc)
    return {
        "proposal_id": str(uuid.uuid4()),
        "created": now.isoformat(),
        "tuple": {
            "rule_id": rule_id,
            "source_key": source_key,
            "asset_id": asset_id,
        },
        "action": action,
        "action_params": action_params,
        "evidence": evidence,
        "expiry": (now + timedelta(days=expiry_days)).isoformat(),
        "engine_version": __version__,
        "config_hashes": {
            "tuning_config": config_hash(tuning_config_raw),
            "risk_config": config_hash(risk_config_raw),
        },
    }


def sign_proposal(proposal: dict, private_key: Ed25519PrivateKey) -> dict:
    """Sign a proposal and return the complete document with signature.

    The signature covers ALL fields in the proposal (everything except
    the signature field itself). The signed portion is constructed
    BEFORE any narration is added.
    """
    # Create a copy without any existing signature or narration
    signable = {k: v for k, v in proposal.items() if k not in ("signature", "narration")}
    sig = sign_payload(signable, private_key)
    return {**proposal, "signature": sig}


def extract_signable(proposal: dict) -> dict:
    """Extract the signable portion of a proposal (excludes signature and narration)."""
    return {k: v for k, v in proposal.items() if k not in ("signature", "narration")}


def add_narration(proposal: dict, narration: str) -> dict:
    """Add narration to a signed proposal.

    Narration is added AFTER signing and is NOT covered by the signature.
    This enforces that narration cannot alter the signed payload.
    """
    return {**proposal, "narration": narration}


def verify_proposal_signature(
    proposal: dict,
    public_key: Any,
) -> bool:
    """Verify the Ed25519 signature on a proposal.

    Returns True if the signature is valid over the signable fields.
    """
    from kahu_tuning.signing import verify_signature

    sig = proposal.get("signature", "")
    if not sig:
        return False
    signable = extract_signable(proposal)
    return verify_signature(signable, sig, public_key)
