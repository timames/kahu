"""Tests for level-gated approval logic."""

import pytest

from kahu_tuner.approval import (
    OperatorLevel,
    build_approval_record,
    can_approve,
    can_auto_apply,
    parse_level,
)


class TestParseLevel:
    def test_string_format(self):
        assert parse_level({"kahu_level": "L0"}) == OperatorLevel.L0
        assert parse_level({"kahu_level": "L1"}) == OperatorLevel.L1
        assert parse_level({"kahu_level": "L2"}) == OperatorLevel.L2
        assert parse_level({"kahu_level": "L3"}) == OperatorLevel.L3

    def test_int_format(self):
        assert parse_level({"kahu_level": 2}) == OperatorLevel.L2

    def test_missing_defaults_l0(self):
        assert parse_level({}) == OperatorLevel.L0

    def test_invalid_defaults_l0(self):
        assert parse_level({"kahu_level": "admin"}) == OperatorLevel.L0
        assert parse_level({"kahu_level": "L9"}) == OperatorLevel.L0


class TestCanApprove:
    def test_l0_cannot_approve(self):
        """Acceptance: L0 token cannot approve."""
        ok, reason = can_approve(OperatorLevel.L0)
        assert ok is False
        assert "L0/L1" in reason

    def test_l1_cannot_approve(self):
        """Acceptance: L1 token cannot approve."""
        ok, reason = can_approve(OperatorLevel.L1)
        assert ok is False

    def test_l2_can_approve(self):
        """Acceptance: L2 can approve."""
        ok, reason = can_approve(OperatorLevel.L2)
        assert ok is True

    def test_l3_can_approve(self):
        """L3 can always approve."""
        ok, _ = can_approve(OperatorLevel.L3)
        assert ok is True


class TestAutoApply:
    def test_l3_with_flag(self):
        """Acceptance: L3 auto-apply only with config flag."""
        assert can_auto_apply(OperatorLevel.L3, auto_apply_enabled=True) is True

    def test_l3_without_flag(self):
        """L3 cannot auto-apply without config flag."""
        assert can_auto_apply(OperatorLevel.L3, auto_apply_enabled=False) is False

    def test_l2_never_auto_apply(self):
        """L2 can never auto-apply regardless of flag."""
        assert can_auto_apply(OperatorLevel.L2, auto_apply_enabled=True) is False

    def test_l1_never_auto_apply(self):
        assert can_auto_apply(OperatorLevel.L1, auto_apply_enabled=True) is False

    def test_l0_never_auto_apply(self):
        assert can_auto_apply(OperatorLevel.L0, auto_apply_enabled=True) is False


class TestApprovalRecord:
    def test_record_structure(self):
        rec = build_approval_record(
            proposal_id="abc-123",
            approver_identity="partner@example.com",
            level=OperatorLevel.L2,
        )
        assert rec["proposal_id"] == "abc-123"
        assert rec["approver"] == "partner@example.com"
        assert rec["level"] == "L2"
        assert rec["auto_applied"] is False
        assert "approved_at" in rec

    def test_auto_apply_record(self):
        rec = build_approval_record(
            proposal_id="def-456",
            approver_identity="system",
            level=OperatorLevel.L3,
            auto_applied=True,
            applied_artifact="abc123def456",
        )
        assert rec["auto_applied"] is True
        assert rec["applied_artifact"] == "abc123def456"
