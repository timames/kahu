"""Tests for mind narration isolation enforcement."""

import copy

from kahu_tuning.proposal import (
    add_narration,
    build_evidence_block,
    build_proposal,
    extract_signable,
    sign_proposal,
    verify_proposal_signature,
)
from kahu_tuning.signing import generate_keypair


class TestNarrationIsolation:
    """Acceptance test 5: narration step provably cannot mutate signed payload."""

    def _make_signed_proposal(self):
        priv, pub = generate_keypair()
        evidence = build_evidence_block(
            n_90d=500, t_star_hours=2160.0, posterior_mean=0.23,
            posterior_cv=0.04, log_bf01=5.5, posterior_odds=244.7,
            risk_multiplier=1.0, threshold_applied=20.0,
            kl_vs_golden=0.12, windows_consistent=True,
        )
        proposal = build_proposal(
            rule_id="100001", source_key="fw-01", asset_id="srv-01",
            action="demote", action_params={"target_level": 3},
            evidence=evidence,
            tuning_config_raw={"theta_base": 20},
            risk_config_raw={"geo_asn_risk": {"low": 1}},
        )
        signed = sign_proposal(proposal, priv)
        return signed, priv, pub

    def test_narration_added_after_signing(self):
        """Narration is added AFTER the proposal is signed."""
        signed, priv, pub = self._make_signed_proposal()

        # Add narration
        with_narration = add_narration(signed, "The alert rate is consistent with baseline.")

        # Narration field exists
        assert with_narration["narration"] == "The alert rate is consistent with baseline."

        # Signature is still valid
        assert verify_proposal_signature(with_narration, pub) is True

    def test_narration_not_in_signable_payload(self):
        """Narration is excluded from the signable portion."""
        signed, priv, pub = self._make_signed_proposal()
        with_narration = add_narration(signed, "Any text here.")

        signable = extract_signable(with_narration)
        assert "narration" not in signable

    def test_modifying_narration_does_not_break_signature(self):
        """Changing narration text does not invalidate the signature."""
        signed, priv, pub = self._make_signed_proposal()

        v1 = add_narration(signed, "Version 1 narration.")
        v2 = add_narration(signed, "Completely different narration.")

        assert verify_proposal_signature(v1, pub) is True
        assert verify_proposal_signature(v2, pub) is True

    def test_narration_cannot_alter_action(self):
        """Attempting to alter action via narration injection fails verification."""
        signed, priv, pub = self._make_signed_proposal()

        # Even if narration somehow gets into action field, sig fails
        tampered = copy.deepcopy(signed)
        tampered["action"] = "destroy"  # malicious override attempt
        assert verify_proposal_signature(tampered, pub) is False

    def test_narration_cannot_alter_thresholds(self):
        """Attempting to alter thresholds fails verification."""
        signed, priv, pub = self._make_signed_proposal()

        tampered = copy.deepcopy(signed)
        tampered["evidence"]["threshold_applied"] = 0.001
        assert verify_proposal_signature(tampered, pub) is False

    def test_narration_cannot_alter_approval_state(self):
        """Injecting approval state into proposal fails verification."""
        signed, priv, pub = self._make_signed_proposal()

        # Try adding an "approved" field to the signed portion
        tampered = copy.deepcopy(signed)
        tampered["approved"] = True
        # This changes the signable payload (new key), so verification fails
        assert verify_proposal_signature(tampered, pub) is False
