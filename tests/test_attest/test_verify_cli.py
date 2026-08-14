"""Tests for the verify CLI tool."""

from __future__ import annotations

import json
from pathlib import Path

from kahu_attest.bundle import build_attestation, build_pono_snapshot, sign_attestation
from kahu_attest.verify import main, verify_bundle
from kahu_tuning.signing import generate_keypair, save_public_key

# --- Helpers ---

class _FakeComponent:
    def __init__(self, name):
        self.name = name
        self.raw_score = 0.9
        self.weighted_score = 22.5
        self.max_points = 25
        self.assessed = True
        self.label = "assessed"
        self.evidence_age_days = 1.0


class _FakePonoResult:
    def __init__(self):
        self.pono_score = 90.0
        self.schema_version = "1.0"
        self.components = [_FakeComponent("detection_posture")]
        self.biggest_gain = None


def _write_signed_bundle(tmp_path: Path) -> tuple[Path, Path]:
    """Create a signed bundle and public key, return (bundle_path, pubkey_path)."""
    priv, pub = generate_keypair()
    snapshot = build_pono_snapshot(_FakePonoResult())
    att = build_attestation(
        pono_snapshot=snapshot,
        appliance_id="test-001",
        org_name="TestCo",
        validity_days=30,
    )
    signed = sign_attestation(att, priv)

    bundle_path = tmp_path / "attestation.json"
    bundle_path.write_text(json.dumps(signed), encoding="utf-8")

    pubkey_path = tmp_path / "pubkey.pem"
    save_public_key(pub, pubkey_path)

    return bundle_path, pubkey_path


class TestVerifyBundle:
    def test_valid_bundle(self, tmp_path):
        bundle_path, pubkey_path = _write_signed_bundle(tmp_path)
        result = verify_bundle(bundle_path, pubkey_path)
        assert result["valid"] is True
        assert result["signature_valid"] is True
        assert result["chain_valid"] is True

    def test_tampered_bundle(self, tmp_path):
        bundle_path, pubkey_path = _write_signed_bundle(tmp_path)
        # Tamper
        data = json.loads(bundle_path.read_text())
        data["pono_snapshot"]["pono_score"] = 100.0
        bundle_path.write_text(json.dumps(data))
        result = verify_bundle(bundle_path, pubkey_path)
        assert result["valid"] is False
        assert result["signature_valid"] is False

    def test_missing_bundle(self, tmp_path):
        _, pubkey_path = _write_signed_bundle(tmp_path)
        result = verify_bundle(tmp_path / "nonexistent.json", pubkey_path)
        assert result["valid"] is False
        assert len(result["errors"]) > 0

    def test_missing_pubkey(self, tmp_path):
        bundle_path, _ = _write_signed_bundle(tmp_path)
        result = verify_bundle(bundle_path, tmp_path / "nonexistent.pem")
        assert result["valid"] is False

    def test_skip_expiry_check(self, tmp_path):
        bundle_path, pubkey_path = _write_signed_bundle(tmp_path)
        result = verify_bundle(bundle_path, pubkey_path, check_expiry=False)
        assert result["valid"] is True
        assert result["expired"] is None


class TestVerifyCLI:
    def test_cli_valid_bundle(self, tmp_path):
        bundle_path, pubkey_path = _write_signed_bundle(tmp_path)
        exit_code = main([str(bundle_path), str(pubkey_path), "--no-expiry-check"])
        assert exit_code == 0

    def test_cli_invalid_bundle(self, tmp_path):
        bundle_path, pubkey_path = _write_signed_bundle(tmp_path)
        data = json.loads(bundle_path.read_text())
        data["pono_snapshot"]["pono_score"] = 100.0
        bundle_path.write_text(json.dumps(data))
        exit_code = main([str(bundle_path), str(pubkey_path), "--no-expiry-check"])
        assert exit_code == 1

    def test_cli_json_output(self, tmp_path, capsys):
        bundle_path, pubkey_path = _write_signed_bundle(tmp_path)
        main([str(bundle_path), str(pubkey_path), "--no-expiry-check", "--json"])
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["valid"] is True

    def test_cli_expired_bundle_fails(self, tmp_path):
        # Create a bundle with 0-day validity (already expired)
        priv, pub = generate_keypair()
        snapshot = build_pono_snapshot(_FakePonoResult())
        att = build_attestation(
            pono_snapshot=snapshot,
            appliance_id="test-001",
            org_name="TestCo",
            validity_days=0,
        )
        signed = sign_attestation(att, priv)
        bundle_path = tmp_path / "expired.json"
        bundle_path.write_text(json.dumps(signed))
        pubkey_path = tmp_path / "pubkey.pem"
        save_public_key(pub, pubkey_path)

        # With expiry check (default), should fail
        exit_code = main([str(bundle_path), str(pubkey_path)])
        assert exit_code == 1

        # Without expiry check, should pass
        exit_code = main([str(bundle_path), str(pubkey_path), "--no-expiry-check"])
        assert exit_code == 0
