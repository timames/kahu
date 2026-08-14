"""Tests for proposal schema, signing, and narration isolation."""

import copy

from kahu_tuning.proposal import (
    add_narration,
    build_evidence_block,
    build_proposal,
    extract_signable,
    sign_proposal,
    verify_proposal_signature,
)
from kahu_tuning.signing import generate_keypair, sign_payload, verify_signature


class TestSigning:
    def test_sign_and_verify(self):
        """Round-trip sign and verify."""
        priv, pub = generate_keypair()
        payload = {"foo": "bar", "n": 42}
        sig = sign_payload(payload, priv)
        assert verify_signature(payload, sig, pub)

    def test_verify_fails_on_tamper(self):
        """Verification fails when any field is altered post-signing."""
        priv, pub = generate_keypair()
        payload = {"foo": "bar", "n": 42}
        sig = sign_payload(payload, priv)

        tampered = {"foo": "baz", "n": 42}
        assert verify_signature(tampered, sig, pub) is False

    def test_verify_fails_on_bad_sig(self):
        """Bad signature hex fails."""
        priv, pub = generate_keypair()
        payload = {"foo": "bar"}
        assert verify_signature(payload, "deadbeef" * 16, pub) is False

    def test_different_keys_fail(self):
        """Signature from one key does not verify with another."""
        priv1, pub1 = generate_keypair()
        priv2, pub2 = generate_keypair()
        payload = {"x": 1}
        sig = sign_payload(payload, priv1)
        assert verify_signature(payload, sig, pub2) is False


class TestProposal:
    def _make_proposal(self):
        evidence = build_evidence_block(
            n_90d=500, t_star_hours=2160.0, posterior_mean=0.23,
            posterior_cv=0.04, log_bf01=5.5, posterior_odds=244.7,
            risk_multiplier=1.0, threshold_applied=20.0,
            kl_vs_golden=0.12, windows_consistent=True,
        )
        return build_proposal(
            rule_id="100001", source_key="fw-01", asset_id="srv-01",
            action="demote", action_params={"target_level": 3},
            evidence=evidence,
            tuning_config_raw={"theta_base": 20},
            risk_config_raw={"geo_asn_risk": {"low": 1}},
        )

    def test_proposal_schema_complete(self):
        """Proposal has all required fields."""
        p = self._make_proposal()
        assert "proposal_id" in p
        assert "created" in p
        assert "tuple" in p
        assert "action" in p
        assert "evidence" in p
        assert "expiry" in p
        assert "engine_version" in p
        assert "config_hashes" in p
        assert "tuning_config" in p["config_hashes"]
        assert "risk_config" in p["config_hashes"]

    def test_sign_proposal(self):
        """Signed proposal has signature field."""
        priv, pub = generate_keypair()
        p = self._make_proposal()
        signed = sign_proposal(p, priv)
        assert "signature" in signed
        assert len(signed["signature"]) == 128  # Ed25519 sig = 64 bytes = 128 hex

    def test_verify_signed_proposal(self):
        """Acceptance test 4 (Phase 2): Signature verification succeeds."""
        priv, pub = generate_keypair()
        p = self._make_proposal()
        signed = sign_proposal(p, priv)
        assert verify_proposal_signature(signed, pub) is True

    def test_verify_fails_on_evidence_tamper(self):
        """Acceptance test 4: verification fails when evidence field altered."""
        priv, pub = generate_keypair()
        p = self._make_proposal()
        signed = sign_proposal(p, priv)

        # Tamper with evidence
        tampered = copy.deepcopy(signed)
        tampered["evidence"]["n_90d"] = 999999
        assert verify_proposal_signature(tampered, pub) is False

    def test_verify_fails_on_action_tamper(self):
        """Tampering action field breaks signature."""
        priv, pub = generate_keypair()
        p = self._make_proposal()
        signed = sign_proposal(p, priv)

        tampered = copy.deepcopy(signed)
        tampered["action"] = "threshold"
        assert verify_proposal_signature(tampered, pub) is False

    def test_narration_not_in_signable(self):
        """Acceptance test 5: narration cannot mutate the signed payload."""
        priv, pub = generate_keypair()
        p = self._make_proposal()
        signed = sign_proposal(p, priv)

        # Add narration
        with_narration = add_narration(signed, "This is a test narration.")
        assert "narration" in with_narration

        # Narration is not in signable portion
        signable = extract_signable(with_narration)
        assert "narration" not in signable

        # Signature still valid (narration does not break it)
        assert verify_proposal_signature(with_narration, pub) is True

    def test_narration_attempt_inject_into_signed(self):
        """Acceptance test 5: attempting to inject narration into signed fields fails verify."""
        priv, pub = generate_keypair()
        p = self._make_proposal()
        signed = sign_proposal(p, priv)

        # Try injecting narration content into a signed field
        tampered = copy.deepcopy(signed)
        tampered["action_params"]["injected"] = "malicious narration override"
        assert verify_proposal_signature(tampered, pub) is False
