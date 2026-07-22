"""Load and hash tuning configuration files."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def canonical_json(obj: Any) -> str:
    """Canonical JSON: sorted keys, no insignificant whitespace, default str."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def config_hash(obj: Any) -> str:
    """SHA-256 of the canonical JSON representation."""
    return hashlib.sha256(canonical_json(obj).encode()).hexdigest()


def load_json(path: str | Path) -> dict:
    with open(path) as f:
        return json.load(f)


@dataclass(frozen=True)
class TuningConfig:
    kappa_1h: float = 24.0
    kappa_24h: float = 168.0
    kappa_7d: float = 720.0
    kappa_90d: float = 2160.0
    fleet_alpha: float = 0.5
    fleet_beta: float = 0.5
    gamma_elevated: float = 3.0
    prior_odds: float = 1.0
    theta_base: float = 20.0
    decay_delta: float = 0.992
    kl_epsilon_default: float = 0.5
    seasonality_min_events: int = 500
    seasonality_business_hours: tuple[int, int] = (7, 18)
    seasonality_business_days: tuple[int, ...] = (0, 1, 2, 3, 4)
    auto_apply: bool = False
    engine_version: str = "0.1.0"

    @classmethod
    def from_dict(cls, d: dict) -> TuningConfig:
        bh = d.get("seasonality_business_hours", [7, 18])
        bd = d.get("seasonality_business_days", [0, 1, 2, 3, 4])
        return cls(
            kappa_1h=d.get("kappa_1h", 24.0),
            kappa_24h=d.get("kappa_24h", 168.0),
            kappa_7d=d.get("kappa_7d", 720.0),
            kappa_90d=d.get("kappa_90d", 2160.0),
            fleet_alpha=d.get("fleet_alpha", 0.5),
            fleet_beta=d.get("fleet_beta", 0.5),
            gamma_elevated=d.get("gamma_elevated", 3.0),
            prior_odds=d.get("prior_odds", 1.0),
            theta_base=d.get("theta_base", 20.0),
            decay_delta=d.get("decay_delta", 0.992),
            kl_epsilon_default=d.get("kl_epsilon_default", 0.5),
            seasonality_min_events=d.get("seasonality_min_events", 500),
            seasonality_business_hours=tuple(bh),
            seasonality_business_days=tuple(bd),
            auto_apply=d.get("auto_apply", False),
            engine_version=d.get("engine_version", "0.1.0"),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> TuningConfig:
        return cls.from_dict(load_json(path))

    def kappa_for_window(self, window: str) -> float:
        return {
            "1h": self.kappa_1h,
            "24h": self.kappa_24h,
            "7d": self.kappa_7d,
            "90d": self.kappa_90d,
        }[window]


@dataclass(frozen=True)
class RiskConfig:
    geo_asn_risk: dict[str, float] = field(
        default_factory=lambda: {"low": 1.0, "medium": 5.0, "high": 25.0}
    )
    asset_criticality: dict[str, float] = field(
        default_factory=lambda: {"standard": 1.0, "elevated": 3.0, "critical": 10.0}
    )
    misp_indicator_overlap: float = 50.0
    protocol_class: dict[str, float] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> RiskConfig:
        return cls(
            geo_asn_risk=d.get("geo_asn_risk", {"low": 1.0, "medium": 5.0, "high": 25.0}),
            asset_criticality=d.get("asset_criticality", {"standard": 1.0, "elevated": 3.0, "critical": 10.0}),
            misp_indicator_overlap=d.get("misp_indicator_overlap", 50.0),
            protocol_class=d.get("protocol_class", {}),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> RiskConfig:
        return cls.from_dict(load_json(path))


@dataclass(frozen=True)
class CanaryConfig:
    canary_rule_ids: tuple[str, ...] = ()
    inject_timeout_seconds: int = 120
    test_index: str = "kahu-canary-events"

    @classmethod
    def from_dict(cls, d: dict) -> CanaryConfig:
        return cls(
            canary_rule_ids=tuple(d.get("canary_rule_ids", [])),
            inject_timeout_seconds=d.get("inject_timeout_seconds", 120),
            test_index=d.get("test_index", "kahu-canary-events"),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> CanaryConfig:
        return cls.from_dict(load_json(path))
