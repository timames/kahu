"""Stage 2 — Alert enrichment with asset context, related events, vuln state."""

import hashlib
import json
from dataclasses import dataclass, field


@dataclass
class EnrichedAlert:
    data: dict = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    prompt_hash: str = ""


async def enrich_alert_group(alert: dict) -> EnrichedAlert:
    """Enrich a filtered alert with context for LLM triage."""
    enriched_data = {
        "alert": alert,
        "asset_context": {},      # TODO: pull from asset inventory
        "related_events": [],     # TODO: query recent related events
        "vuln_state": {},         # TODO: host vulnerability state
        "historical_dispositions": [],  # TODO: similar past alerts
    }

    sources = ["alert_data"]
    prompt_content = json.dumps(enriched_data, sort_keys=True, default=str)
    prompt_hash = hashlib.sha256(prompt_content.encode()).hexdigest()[:16]

    return EnrichedAlert(
        data=enriched_data,
        sources=sources,
        prompt_hash=prompt_hash,
    )
