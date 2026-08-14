"""Tests for PDF renderer (conditional on fpdf2 availability)."""

from __future__ import annotations

import pytest

from kahu_attest.bundle import build_attestation, build_pono_snapshot, sign_attestation
from kahu_tuning.signing import generate_keypair

try:
    from fpdf import FPDF  # noqa: F401
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False


class _FakeComponent:
    def __init__(self, name, score, max_pts):
        self.name = name
        self.raw_score = score / max_pts
        self.weighted_score = score
        self.max_points = max_pts
        self.assessed = True
        self.label = "assessed"
        self.evidence_age_days = 1.0


class _FakePonoResult:
    def __init__(self):
        self.pono_score = 82.3
        self.schema_version = "1.0"
        self.components = [
            _FakeComponent("detection_posture", 23.0, 25),
            _FakeComponent("tuning_hygiene", 13.0, 15),
            _FakeComponent("vulnerability_posture", 16.0, 20),
            _FakeComponent("identity_access", 12.0, 15),
            _FakeComponent("response_readiness", 11.0, 15),
            _FakeComponent("human_layer", 7.3, 10),
        ]
        self.biggest_gain = {
            "component": "vulnerability_posture",
            "available_gain": 4.0,
            "current_score": 16.0,
            "max_points": 20,
        }


def _signed_attestation():
    priv, _ = generate_keypair()
    snapshot = build_pono_snapshot(_FakePonoResult())
    att = build_attestation(
        pono_snapshot=snapshot,
        appliance_id="kahu-test-001",
        org_name="Acme Security Corp",
        evidence_ids=["ev-001", "ev-002", "ev-003"],
    )
    return sign_attestation(att, priv)


@pytest.mark.skipif(not HAS_FPDF, reason="fpdf2 not installed")
class TestPDFRenderer:
    def test_render_produces_bytes(self):
        from kahu_attest.renderer import AttestationPDF
        att = _signed_attestation()
        pdf_bytes = AttestationPDF(att).render()
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 100

    def test_pdf_starts_with_header(self):
        from kahu_attest.renderer import AttestationPDF
        att = _signed_attestation()
        pdf_bytes = AttestationPDF(att).render()
        assert pdf_bytes[:5] == b"%PDF-"

    def test_save_to_file(self, tmp_path):
        from kahu_attest.renderer import AttestationPDF
        att = _signed_attestation()
        out_path = tmp_path / "attestation.pdf"
        AttestationPDF(att).save(out_path)
        assert out_path.exists()
        assert out_path.stat().st_size > 100

    def test_render_without_evidence_chain(self):
        from kahu_attest.renderer import AttestationPDF
        priv, _ = generate_keypair()
        snapshot = build_pono_snapshot(_FakePonoResult())
        att = build_attestation(
            pono_snapshot=snapshot,
            appliance_id="kahu-001",
            org_name="TestOrg",
            evidence_ids=[],
        )
        signed = sign_attestation(att, priv)
        pdf_bytes = AttestationPDF(signed).render()
        assert pdf_bytes[:5] == b"%PDF-"


@pytest.mark.skipif(HAS_FPDF, reason="Test only when fpdf2 is NOT installed")
class TestPDFRendererMissing:
    def test_import_error_raised(self):
        from kahu_attest.renderer import AttestationPDF
        att = _signed_attestation()
        with pytest.raises(ImportError, match="fpdf2"):
            AttestationPDF(att).render()
