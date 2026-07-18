"""Stage 1 — Deterministic filtering, deduplication, and correlation.

No LLM involvement. The goal is that the model only ever sees the interesting
residue — this controls inference cost, keeps S-tier CPU inference viable, and
keeps the deterministic layer auditable.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import ClassVar


@dataclass
class FilterResult:
    passed: bool
    alert: dict = field(default_factory=dict)
    severity: str = "medium"
    rules_fired: list[str] = field(default_factory=list)
    correlation_key: str | None = None


# Rule IDs known to be high-noise in SMB/AEC environments (from ISE deployment tuning).
# Loaded from config in production; hardcoded baseline here.
SUPPRESSED_RULE_IDS: set[str] = {
    "86001",  # Wazuh agent started
    "86002",  # Wazuh agent disconnected (transient on laptops)
    "86003",  # Wazuh agent reconnected
    "5104",   # Interface entered promiscuous mode (Docker/Hyper-V noise)
    "5302",   # User login session closed (excessive volume)
}

# Rules that must never be suppressed regardless of level or dedup.
CRITICAL_RULE_IDS: set[str] = {
    "554",    # Attempt to exploit known vulnerability
    "100100", # File integrity change on critical path
    "100200", # Rootkit detection
    "87700",  # Vulnerability detected — critical CVSS
    "87900",  # Active response triggered
}


class DeduplicationWindow:
    """Sliding window dedup — suppress duplicate (rule_id, agent) pairs within window."""

    _instance: ClassVar[DeduplicationWindow | None] = None

    def __init__(self, window_seconds: int = 300) -> None:
        self.window_seconds = window_seconds
        self._seen: dict[str, float] = {}

    @classmethod
    def get(cls) -> DeduplicationWindow:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        cls._instance = None

    def _evict_expired(self) -> None:
        cutoff = time.monotonic() - self.window_seconds
        self._seen = {k: v for k, v in self._seen.items() if v > cutoff}

    def is_duplicate(self, rule_id: str, agent_name: str) -> bool:
        self._evict_expired()
        key = f"{rule_id}:{agent_name}"
        if key in self._seen:
            return True
        self._seen[key] = time.monotonic()
        return False


def apply_deterministic_filters(
    raw_alert: dict,
    suppressed_rules: set[str] | None = None,
) -> FilterResult:
    """Apply rule-based suppression, dedup, and severity mapping.

    Returns a FilterResult indicating whether the alert should proceed to
    enrichment and LLM triage.
    """
    rules_fired: list[str] = []
    suppress_set = suppressed_rules if suppressed_rules is not None else SUPPRESSED_RULE_IDS

    rule = raw_alert.get("rule", {})
    rule_id = str(rule.get("id", ""))
    rule_level = rule.get("level", 0)
    agent_name = raw_alert.get("agent", {}).get("name", "unknown")

    # --- Critical rules always pass, never suppressed ---
    if rule_id in CRITICAL_RULE_IDS:
        rules_fired.append("critical_rule_pass")
        severity = _level_to_severity(max(rule_level, 12))
        return FilterResult(
            passed=True,
            alert=raw_alert,
            severity=severity,
            rules_fired=rules_fired,
            correlation_key=_correlation_key(rule_id, agent_name),
        )

    # --- Suppress known noisy rules ---
    if rule_id in suppress_set:
        rules_fired.append(f"suppressed:{rule_id}")
        return FilterResult(passed=False, rules_fired=rules_fired)

    # --- Level-based suppression ---
    if rule_level < 3:
        rules_fired.append("level_suppression")
        return FilterResult(passed=False, rules_fired=rules_fired)

    rules_fired.append("level_pass")

    # --- Deduplication within time window ---
    dedup = DeduplicationWindow.get()
    if rule_level < 10 and dedup.is_duplicate(rule_id, agent_name):
        rules_fired.append("dedup_suppressed")
        return FilterResult(passed=False, rules_fired=rules_fired)

    rules_fired.append("dedup_pass")

    # --- Group matching for correlation ---
    groups = rule.get("groups", [])
    if _is_authentication_event(groups):
        rules_fired.append("auth_correlation")
    if _is_fim_event(groups):
        rules_fired.append("fim_correlation")

    severity = _level_to_severity(rule_level)

    return FilterResult(
        passed=True,
        alert=raw_alert,
        severity=severity,
        rules_fired=rules_fired,
        correlation_key=_correlation_key(rule_id, agent_name),
    )


def _level_to_severity(level: int) -> str:
    if level >= 12:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    if level >= 3:
        return "low"
    return "info"


def _correlation_key(rule_id: str, agent_name: str) -> str:
    """Key for grouping related alerts within the enrichment window."""
    raw = f"{rule_id}:{agent_name}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def _is_authentication_event(groups: list[str]) -> bool:
    auth_groups = {"authentication_failed", "authentication_success", "sshd", "win_authentication"}
    return bool(set(groups) & auth_groups)


def _is_fim_event(groups: list[str]) -> bool:
    return "syscheck" in groups or "fim" in groups
