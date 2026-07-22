"""Component 4: Identity and access (15 points).

Subweights (from weights_schema.json):
- mfa_coverage: fraction of accounts with MFA enabled
- stale_accounts: fraction of accounts not stale
- admin_count: ratio of admins to expected (inverse penalty)
- secret_age: fraction of secrets rotated within policy
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class IdentityInput:
    accounts_with_mfa: int = 0
    accounts_total: int = 0
    stale_accounts: int = 0
    privileged_accounts: int = 0
    expected_privileged: int = 0
    secrets_rotated: int = 0
    secrets_total: int = 0
    data_available: bool = True


def score_identity(inp: IdentityInput, subweights: dict[str, float]) -> tuple[float, dict]:
    """Score identity and access. Returns (raw_score 0-1, details)."""
    if not inp.data_available:
        return 0.0, {"status": "not assessed"}

    scores = {}

    # MFA coverage
    if inp.accounts_total > 0:
        scores["mfa_coverage"] = inp.accounts_with_mfa / inp.accounts_total
    else:
        scores["mfa_coverage"] = 0.0

    # Stale accounts: 1.0 if none stale
    if inp.accounts_total > 0:
        scores["stale_accounts"] = 1.0 - (inp.stale_accounts / inp.accounts_total)
    else:
        scores["stale_accounts"] = 1.0

    # Admin count: 1.0 if at or below expected, decays if over
    if inp.expected_privileged > 0:
        ratio = inp.privileged_accounts / inp.expected_privileged
        scores["admin_count"] = min(1.0, 1.0 / max(ratio, 0.01))
    else:
        scores["admin_count"] = 1.0 if inp.privileged_accounts == 0 else 0.0

    # Secret age: fraction rotated within policy
    if inp.secrets_total > 0:
        scores["secret_age"] = inp.secrets_rotated / inp.secrets_total
    else:
        scores["secret_age"] = 1.0

    raw = sum(scores.get(k, 0.0) * w for k, w in subweights.items())
    return raw, scores
