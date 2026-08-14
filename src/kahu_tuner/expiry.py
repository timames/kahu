"""Expiry enforcement for applied tuning proposals.

Daily job: any applied tune past expiry is reverted and a
re-justification proposal is generated against current posteriors.
Never silently extend.
"""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from pathlib import Path


def is_expired(proposal: dict, now: datetime | None = None) -> bool:
    """Check if a proposal has passed its expiry date."""
    if now is None:
        now = datetime.now(UTC)
    expiry_str = proposal.get("expiry", "")
    if not expiry_str:
        return True
    try:
        expiry = datetime.fromisoformat(expiry_str)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        return now >= expiry
    except (ValueError, TypeError):
        return True


def find_expired_proposals(
    proposals: list[dict],
    now: datetime | None = None,
) -> list[dict]:
    """Filter to only expired, applied proposals."""
    return [p for p in proposals if p.get("status") == "applied" and is_expired(p, now)]


def revert_applied_tune(
    proposal: dict,
    detection_content_dir: str | Path,
) -> tuple[bool, str]:
    """Revert an applied tune by git-reverting its commit.

    Each applied proposal records its commit SHA in the approval record.
    This function performs `git revert <sha>` in the detection-content repo.

    Returns:
        (success, message)
    """
    commit_sha = proposal.get("approval", {}).get("applied_artifact", "") or proposal.get(
        "applied_commit", ""
    )
    if not commit_sha:
        return False, "No commit SHA recorded for this proposal"

    content_dir = Path(detection_content_dir)
    if not content_dir.exists():
        return False, f"Detection content directory not found: {content_dir}"

    try:
        result = subprocess.run(  # noqa: S603, S607
            ["git", "revert", "--no-edit", commit_sha],  # noqa: S607
            cwd=str(content_dir),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return True, f"Reverted commit {commit_sha}"
        return False, f"Git revert failed: {result.stderr.strip()}"
    except subprocess.TimeoutExpired:
        return False, "Git revert timed out"
    except FileNotFoundError:
        return False, "Git not found"


def build_rejustification_context(proposal: dict) -> dict:
    """Extract context needed to generate a re-justification proposal.

    When an applied tune expires, the system must re-evaluate the tuple
    against current posteriors and generate a new proposal if still warranted.
    """
    return {
        "rule_id": proposal.get("tuple", {}).get("rule_id", ""),
        "source_key": proposal.get("tuple", {}).get("source_key", ""),
        "asset_id": proposal.get("tuple", {}).get("asset_id", ""),
        "previous_action": proposal.get("action", ""),
        "previous_evidence": proposal.get("evidence", {}),
        "expired_proposal_id": proposal.get("proposal_id", ""),
    }
