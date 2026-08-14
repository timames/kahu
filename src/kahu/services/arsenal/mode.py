"""Unlocked mode gate — controls access to offensive tooling.

Guardian mode (default): blue team only — detect, triage, comply.
Unlocked mode: red team capability — recon, exploit, simulate.

Toggle requires explicit analyst confirmation. All mode changes are logged.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

log = logging.getLogger(__name__)

_unlocked: bool = False
_unlocked_by: str = ""
_unlocked_at: datetime | None = None


def is_unlocked() -> bool:
    return _unlocked


def unlock(analyst: str) -> dict:
    global _unlocked, _unlocked_by, _unlocked_at
    _unlocked = True
    _unlocked_by = analyst
    _unlocked_at = datetime.now(UTC)
    log.warning("Arsenal UNLOCKED by %s at %s", analyst, _unlocked_at.isoformat())
    return status()


def lock(analyst: str) -> dict:
    global _unlocked, _unlocked_by, _unlocked_at
    log.warning("Arsenal LOCKED by %s (was unlocked by %s)", analyst, _unlocked_by)
    _unlocked = False
    _unlocked_by = ""
    _unlocked_at = None
    return status()


def status() -> dict:
    return {
        "mode": "unlocked" if _unlocked else "guardian",
        "unlocked_by": _unlocked_by,
        "unlocked_at": _unlocked_at.isoformat() if _unlocked_at else None,
    }
