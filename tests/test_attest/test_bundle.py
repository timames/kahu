"""Tests for attestation v2 bundle building, signing, and verification."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from kahu_attest.bundle import (
    build_attestation,
    build_evidence_chain,
    build_pono_snapshot,
    export_bundle,
    extract_signable,
    is_attestation_expired,
    sign_attestation,
    verify_attestation_signature,
    verify_evidence_chain,
)
from kahu_tuning.signing import generate_keypair

# --- Helpers ---

class _FakeComponent:
    def __init__(
        self, name, raw_score, weighted_score, max_points,
        assessed, label, evidence_age_days,
    ):
        self.name = name
        self.raw_score = raw_score
        self.weighted_score = weighted_score
        self.max_points = max_points
        self.assessed = assessed
        self.label = label
        self.evidence_age_days = evidence_age_days


class _FakePonoResult:
    def __init__(self):
        self.pono_score = 85.5
        self.schema_version = "1.0"
        self.components = [
            _FakeComponent("detection_posture", 0.95, 23.75, 25, True, "assessed", 1.0),
            _FakeComponent("vulnerability_posture", 0.80, 16.0, 20, True, "assessed", 2.0),
        ]
        self.biggest_gain = {"component": "vulnerability_posture", "available_gain": 4.0,
                             "current_score": 16.0, "max_points": 20}


def _make_attestation(**kwargs):
    snapshot = build_pono_snapshot(_FakePonoResult())
    defaults = dict(
        pono_snapshot=snapshot,
        appliance_id="kahu-001",
        org_name="TestOrg",
        evidence_ids=["ev-1", "ev-2", "ev-3"],
    )
    defaults.update(kwargs)
    return build_attestation(**defaults)


# --- Tests ---

class TestBuildAttestation:
    def test_has_required_fields(self):
        att = _make_attestation()
        assert "attestation_id" in att
        assert att["version"] == "2.0"
        assert "created" in att
        assert "expires" in att
        assert att["appliance"]["org_name"] == "TestOrg"
        assert att["pono_snapshot"]["pono_score"] == 85.5

    def test_evidence_chain_present(self):
        att = _make_attestation()
        chain = att["evidence_chain"]
        assert len(chain["chain"]) == 3
        assert chain["root"]

    def test_empty_evidence_chain(self):
        att = _make_attestation(evidence_ids=[])
        chain = att["evidence_chain"]
        assert chain["chain"] == []
        assert chain["root"]  # genesis hash

    def test_validity_period(self):
        att = _make_attestation(validity_days=7)
        created = datetime.fromisoformat(att["created"])
        expires = datetime.fromisoformat(att["expires"])
        delta = expires - created
        assert abs(delta.days - 7) <= 1


class TestSignVerify:
    def test_sign_verify_roundtrip(self):
        priv, pub = generate_keypair()
        att = _make_attestation()
        signed = sign_attestation(att, priv)
        assert "signature" in signed
        assert verify_attestation_signature(signed, pub)

    def test_tamper_detection(self):
        priv, pub = generate_keypair()
        att = _make_attestation()
        signed = sign_attestation(att, priv)
        # Tamper with score
        signed["pono_snapshot"]["pono_score"] = 100.0
        assert not verify_attestation_signature(signed, pub)

    def test_wrong_key_fails(self):
        priv1, _ = generate_keypair()
        _, pub2 = generate_keypair()
        att = _make_attestation()
        signed = sign_attestation(att, priv1)
        assert not verify_attestation_signature(signed, pub2)

    def test_missing_signature_fails(self):
        _, pub = generate_keypair()
        att = _make_attestation()
        assert not verify_attestation_signature(att, pub)

    def test_extract_signable_excludes_signature(self):
        priv, _ = generate_keypair()
        att = _make_attestation()
        signed = sign_attestation(att, priv)
        signable = extract_signable(signed)
        assert "signature" not in signable
        # All other fields present
        assert "attestation_id" in signable
        assert "pono_snapshot" in signable


class TestEvidenceChain:
    def test_chain_verifies(self):
        att = _make_attestation()
        assert verify_evidence_chain(att)

    def test_tampered_chain_fails(self):
        att = _make_attestation()
        att["evidence_chain"]["chain"][1]["hash"] = "deadbeef"
        assert not verify_evidence_chain(att)

    def test_tampered_root_fails(self):
        att = _make_attestation()
        att["evidence_chain"]["root"] = "deadbeef"
        assert not verify_evidence_chain(att)

    def test_empty_chain_verifies(self):
        att = _make_attestation(evidence_ids=[])
        assert verify_evidence_chain(att)

    def test_chain_is_deterministic(self):
        c1 = build_evidence_chain(["a", "b", "c"])
        c2 = build_evidence_chain(["a", "b", "c"])
        assert c1 == c2

    def test_chain_order_matters(self):
        c1 = build_evidence_chain(["a", "b"])
        c2 = build_evidence_chain(["b", "a"])
        assert c1["root"] != c2["root"]


class TestExpiry:
    def test_not_expired(self):
        att = _make_attestation(validity_days=30)
        assert not is_attestation_expired(att)

    def test_expired(self):
        att = _make_attestation(validity_days=30)
        future = datetime.now(UTC) + timedelta(days=31)
        assert is_attestation_expired(att, now=future)

    def test_exact_expiry(self):
        att = _make_attestation(validity_days=0)
        # expires ≈ now, so checking even 1 second later should be expired
        future = datetime.now(UTC) + timedelta(seconds=1)
        assert is_attestation_expired(att, now=future)


class TestExport:
    def test_export_is_valid_json(self):
        import json
        att = _make_attestation()
        exported = export_bundle(att)
        parsed = json.loads(exported)
        assert parsed["version"] == "2.0"

    def test_export_is_canonical(self):
        att = _make_attestation()
        e1 = export_bundle(att)
        e2 = export_bundle(att)
        assert e1 == e2  # Deterministic


class TestPonoSnapshot:
    def test_snapshot_structure(self):
        snapshot = build_pono_snapshot(_FakePonoResult())
        assert snapshot["pono_score"] == 85.5
        assert len(snapshot["components"]) == 2
        assert snapshot["components"][0]["name"] == "detection_posture"
        assert snapshot["biggest_gain"]["component"] == "vulnerability_posture"
