"""Stage 1 — Deterministic filtering, deduplication, and correlation."""

from dataclasses import dataclass, field


@dataclass
class FilterResult:
    passed: bool
    alert: dict = field(default_factory=dict)
    severity: str = "medium"
    rules_fired: list[str] = field(default_factory=list)


def apply_deterministic_filters(raw_alert: dict) -> FilterResult:
    """Apply rule-based suppression and dedup. No LLM involvement."""
    rules_fired: list[str] = []

    rule_level = raw_alert.get("rule", {}).get("level", 0)

    # Suppress low-noise rules below threshold
    if rule_level < 3:
        return FilterResult(passed=False, rules_fired=["level_suppression"])

    rules_fired.append("level_pass")

    severity = _level_to_severity(rule_level)

    return FilterResult(
        passed=True,
        alert=raw_alert,
        severity=severity,
        rules_fired=rules_fired,
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
