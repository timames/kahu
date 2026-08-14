"""Pono Score weights schema and configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from kahu_tuning.config import load_json


@dataclass(frozen=True)
class ComponentWeight:
    name: str
    weight: int
    subweights: dict[str, float]
    staleness_threshold_days: int = 7


@dataclass(frozen=True)
class WeightsSchema:
    schema_version: str = "1.0"
    components: dict[str, ComponentWeight] = field(default_factory=dict)
    freshness_decay_delta: float = 0.992
    not_assessed_ceiling_pct: float = 0.40
    pono_drop_threshold: int = 5

    @classmethod
    def from_dict(cls, d: dict) -> WeightsSchema:
        components = {}
        for name, cfg in d.get("components", {}).items():
            components[name] = ComponentWeight(
                name=name,
                weight=cfg["weight"],
                subweights=cfg.get("subweights", {}),
                staleness_threshold_days=cfg.get("staleness_threshold_days", 7),
            )
        return cls(
            schema_version=d.get("schema_version", "1.0"),
            components=components,
            freshness_decay_delta=d.get("freshness_decay_delta", 0.992),
            not_assessed_ceiling_pct=d.get("not_assessed_ceiling_pct", 0.40),
            pono_drop_threshold=d.get("pono_drop_threshold", 5),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> WeightsSchema:
        return cls.from_dict(load_json(path))

    def total_weight(self) -> int:
        return sum(c.weight for c in self.components.values())
