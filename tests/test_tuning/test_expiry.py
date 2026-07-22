"""Tests for proposal expiry enforcement."""

from datetime import datetime, timedelta, timezone

import pytest

from kahu_tuner.expiry import (
    build_rejustification_context,
    find_expired_proposals,
    is_expired,
)


class TestIsExpired:
    def test_not_expired(self):
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        assert is_expired({"expiry": future}) is False

    def test_expired(self):
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        assert is_expired({"expiry": past}) is True

    def test_missing_expiry(self):
        assert is_expired({}) is True

    def test_explicit_now(self):
        """Time-travel: proposal created 100 days ago, expired at 90 days."""
        created = datetime(2026, 1, 1, tzinfo=timezone.utc)
        expiry = (created + timedelta(days=90)).isoformat()
        now = created + timedelta(days=100)
        assert is_expired({"expiry": expiry}, now=now) is True

    def test_not_yet_expired_with_now(self):
        created = datetime(2026, 1, 1, tzinfo=timezone.utc)
        expiry = (created + timedelta(days=90)).isoformat()
        now = created + timedelta(days=50)
        assert is_expired({"expiry": expiry}, now=now) is False


class TestFindExpired:
    def test_filters_applied_expired(self):
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        proposals = [
            {"proposal_id": "1", "status": "applied", "expiry": past},
            {"proposal_id": "2", "status": "applied", "expiry": future},
            {"proposal_id": "3", "status": "pending", "expiry": past},
        ]
        expired = find_expired_proposals(proposals)
        assert len(expired) == 1
        assert expired[0]["proposal_id"] == "1"

    def test_time_travel(self):
        """Acceptance: time-travel test finds expired proposals."""
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        proposals = [
            {
                "proposal_id": "x",
                "status": "applied",
                "expiry": (base + timedelta(days=90)).isoformat(),
                "approval": {"applied_artifact": "abc123"},
            },
        ]

        # At day 80: not expired
        assert len(find_expired_proposals(proposals, now=base + timedelta(days=80))) == 0

        # At day 91: expired
        assert len(find_expired_proposals(proposals, now=base + timedelta(days=91))) == 1


class TestRejustification:
    def test_extracts_context(self):
        proposal = {
            "proposal_id": "abc-123",
            "tuple": {"rule_id": "100001", "source_key": "fw-01", "asset_id": "srv-01"},
            "action": "demote",
            "evidence": {"n_90d": 500},
        }
        ctx = build_rejustification_context(proposal)
        assert ctx["rule_id"] == "100001"
        assert ctx["previous_action"] == "demote"
        assert ctx["expired_proposal_id"] == "abc-123"
