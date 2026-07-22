"""Level-gated approval logic for tuning proposals."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import IntEnum


class OperatorLevel(IntEnum):
    L0 = 0
    L1 = 1
    L2 = 2
    L3 = 3


def parse_level(token_claims: dict) -> OperatorLevel:
    """Extract kahu_level from Keycloak token claims.

    Returns L0 if claim is missing or invalid.
    """
    raw = token_claims.get("kahu_level", "L0")
    if isinstance(raw, int):
        try:
            return OperatorLevel(raw)
        except ValueError:
            return OperatorLevel.L0
    if isinstance(raw, str) and raw.startswith("L") and raw[1:].isdigit():
        try:
            return OperatorLevel(int(raw[1:]))
        except ValueError:
            return OperatorLevel.L0
    return OperatorLevel.L0


def can_approve(level: OperatorLevel, auto_apply_enabled: bool = False) -> tuple[bool, str]:
    """Check if an operator level can approve proposals.

    Approval flow:
    - L0/L1: Cannot approve directly. Proposals create DFIR-IRIS tasks
      assigned to the ComplyHI queue. Apply only on human approval in IRIS.
    - L2: Partner identities can approve via the IRIS flow.
    - L3: Auto-apply permitted only if tuning_config.auto_apply=true.

    Returns:
        (can_approve, reason)
    """
    if level <= OperatorLevel.L1:
        return False, "L0/L1 operators cannot approve proposals. Requires IRIS task approval."

    if level == OperatorLevel.L2:
        return True, "L2 partner approval via IRIS flow."

    if level == OperatorLevel.L3:
        if auto_apply_enabled:
            return True, "L3 auto-apply enabled."
        return True, "L3 manual approval."

    return False, "Unknown level."


def can_auto_apply(level: OperatorLevel, auto_apply_enabled: bool) -> bool:
    """Check if auto-apply is permitted for this level and config."""
    return level >= OperatorLevel.L3 and auto_apply_enabled


def build_approval_record(
    proposal_id: str,
    approver_identity: str,
    level: OperatorLevel,
    auto_applied: bool = False,
    applied_artifact: str = "",
) -> dict:
    """Build an approval record for a proposal."""
    return {
        "proposal_id": proposal_id,
        "approver": approver_identity,
        "level": f"L{level.value}",
        "auto_applied": auto_applied,
        "approved_at": datetime.now(timezone.utc).isoformat(),
        "applied_artifact": applied_artifact,
    }
