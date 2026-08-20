"""Devices API — Wazuh agents, SCA posture, and guarded indexer search.

Wazuh agents used to be rendered as synthetic "connector sources" on the
Connectors page. They now live here as first-class devices, with per-device
CIS/SCA configuration-assessment results (Wazuh API) and a guarded raw
OpenSearch query endpoint for the Search tab.

Security notes:
- ``agent_id`` / ``policy_id`` are validated against strict patterns before
  being interpolated into Wazuh API paths (no path traversal / query smuggling).
- The OpenSearch endpoint never accepts raw DSL from the client. The client
  supplies a Lucene ``query_string`` (parsed leniently server-side) and an
  index pattern that must match ``^wazuh-...`` — internal indices such as
  ``.opensearch-security`` are unreachable by construction.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Path, Query
from pydantic import BaseModel, Field

from kahu.clients.ollama import OllamaClient
from kahu.clients.wazuh import WazuhAPIClient, WazuhIndexerClient

logger = logging.getLogger(__name__)

router = APIRouter()

_INDEX_PATTERN_RE = re.compile(r"^wazuh-[a-zA-Z0-9.*_-]+$")


# ── Schemas ────────────────────────────────────────────────


class Device(BaseModel):
    agent_id: str
    name: str
    ip: str | None
    status: str
    os_name: str
    os_platform: str
    date_add: str | None
    last_keepalive: str | None
    events_today: int
    events_total: int
    is_manager: bool


class DevicesResponse(BaseModel):
    devices: list[Device]
    error: str | None = None


class ScaPolicy(BaseModel):
    policy_id: str
    name: str
    description: str
    pass_count: int
    fail_count: int
    invalid_count: int
    total_checks: int
    score: int
    end_scan: str | None


class ScaCheck(BaseModel):
    check_id: str
    title: str
    result: str
    rationale: str | None
    remediation: str | None
    description: str | None


class ScaChecksResponse(BaseModel):
    checks: list[ScaCheck]
    total: int
    offset: int
    limit: int


class OpenSearchRequest(BaseModel):
    index_pattern: str = "wazuh-alerts-*"
    query: str = "*"
    time_from: str | None = None
    time_to: str | None = None
    size: int = Field(50, ge=1, le=100)
    offset: int = Field(0, ge=0, le=9000)


class OpenSearchHit(BaseModel):
    id: str
    index: str
    source: dict


class OpenSearchResponse(BaseModel):
    total: int
    took_ms: int
    hits: list[OpenSearchHit]


class LuceneSuggestRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=500)


class LuceneSuggestResponse(BaseModel):
    query: str


# ── Shared fetch (also used by connectors overview) ────────


async def fetch_wazuh_devices() -> tuple[list[Device], str | None]:
    """Fetch Wazuh agents + per-agent event counts from the indexer.

    Returns ``(devices, error)`` — on Wazuh API failure devices is empty and
    error carries a short message; indexer failures only zero the counts.
    """
    try:
        wazuh = WazuhAPIClient()
        await wazuh.authenticate()
        resp = await wazuh.api_get(
            "/agents",
            params={
                "limit": 500,
                "select": "id,name,ip,status,os.platform,os.name,dateAdd,lastKeepAlive",
            },
        )
        agents = resp.get("data", {}).get("affected_items", [])
    except Exception:
        logger.debug("Could not fetch Wazuh agents", exc_info=True)
        return [], "Wazuh API unavailable"

    events_today: dict[str, int] = {}
    events_total: dict[str, int] = {}
    try:
        indexer = WazuhIndexerClient()
        count_resp = await indexer.search(
            "wazuh-alerts-*",
            {"size": 0, "aggs": {"by_agent": {"terms": {"field": "agent.name", "size": 500}}}},
        )
        for bucket in count_resp.get("aggregations", {}).get("by_agent", {}).get("buckets", []):
            events_total[bucket["key"]] = bucket["doc_count"]

        today = datetime.now(UTC).strftime("%Y.%m.%d")
        today_resp = await indexer.search(
            f"wazuh-alerts-4.x-{today}",
            {"size": 0, "aggs": {"by_agent": {"terms": {"field": "agent.name", "size": 500}}}},
        )
        for bucket in today_resp.get("aggregations", {}).get("by_agent", {}).get("buckets", []):
            events_today[bucket["key"]] = bucket["doc_count"]
    except Exception:
        logger.debug("Could not fetch indexer event counts", exc_info=True)

    devices: list[Device] = []
    for agent in agents:
        agent_id = agent.get("id", "000")
        name = agent.get("name", "unknown")
        status = agent.get("status", "disconnected")
        mapped_status = (
            "active"
            if status in ("active", "Active")
            else "disconnected"
            if status == "disconnected"
            else "pending"
        )
        devices.append(
            Device(
                agent_id=agent_id,
                name=name,
                ip=agent.get("ip"),
                status=mapped_status,
                os_name=agent.get("os", {}).get("name", ""),
                os_platform=agent.get("os", {}).get("platform", ""),
                date_add=agent.get("dateAdd"),
                last_keepalive=agent.get("lastKeepAlive"),
                events_today=events_today.get(name, 0),
                events_total=events_total.get(name, 0),
                is_manager=agent_id == "000",
            )
        )
    return devices, None


# ── Routes ─────────────────────────────────────────────────


@router.get("", response_model=DevicesResponse)
async def list_devices() -> DevicesResponse:
    """All Wazuh agents (manager included) with indexer event counts."""
    devices, error = await fetch_wazuh_devices()
    return DevicesResponse(devices=devices, error=error)


@router.get("/{agent_id}/sca", response_model=list[ScaPolicy])
async def device_sca(
    agent_id: str = Path(pattern=r"^\d{3,}$"),  # noqa: B008
) -> list[ScaPolicy]:
    """SCA (configuration assessment) policy summaries for one agent.

    Agents with no SCA results (the manager, never-scanned agents) return an
    empty list rather than an error.
    """
    try:
        wazuh = WazuhAPIClient()
        resp = await wazuh.api_get(f"/sca/{agent_id}", params={"limit": 100})
        items = resp.get("data", {}).get("affected_items", [])
    except Exception:
        logger.debug("Could not fetch SCA for agent %s", agent_id, exc_info=True)
        return []

    policies: list[ScaPolicy] = []
    for item in items:
        policies.append(
            ScaPolicy(
                policy_id=str(item.get("policy_id", "")),
                name=item.get("name", "") or "",
                description=item.get("description", "") or "",
                pass_count=int(item.get("pass", 0) or 0),
                fail_count=int(item.get("fail", 0) or 0),
                invalid_count=int(item.get("invalid", 0) or 0),
                total_checks=int(item.get("total_checks", 0) or 0),
                score=int(item.get("score", 0) or 0),
                end_scan=item.get("end_scan"),
            )
        )
    return policies


@router.get("/{agent_id}/sca/{policy_id}/checks", response_model=ScaChecksResponse)
async def device_sca_checks(
    agent_id: str = Path(pattern=r"^\d{3,}$"),  # noqa: B008
    policy_id: str = Path(pattern=r"^[a-zA-Z0-9._-]{1,100}$"),  # noqa: B008
    result: str | None = Query(None, pattern="^(failed|passed|not applicable)$"),  # noqa: B008
    offset: int = Query(0, ge=0),  # noqa: B008
    limit: int = Query(50, ge=1, le=100),  # noqa: B008
) -> ScaChecksResponse:
    """Individual SCA check results for one policy on one agent."""
    params: dict = {"limit": limit, "offset": offset}
    if result:
        params["result"] = result
    try:
        wazuh = WazuhAPIClient()
        resp = await wazuh.api_get(f"/sca/{agent_id}/checks/{policy_id}", params=params)
        data = resp.get("data", {})
        items = data.get("affected_items", [])
        total = int(data.get("total_affected_items", len(items)) or 0)
    except Exception as exc:
        logger.debug(
            "Could not fetch SCA checks for agent %s policy %s", agent_id, policy_id, exc_info=True
        )
        raise HTTPException(status_code=503, detail="Wazuh API unavailable") from exc

    checks = [
        ScaCheck(
            check_id=str(item.get("id", "")),
            title=item.get("title", "") or "",
            result=item.get("result", "") or "not run",
            rationale=item.get("rationale"),
            remediation=item.get("remediation"),
            description=item.get("description"),
        )
        for item in items
    ]
    return ScaChecksResponse(checks=checks, total=total, offset=offset, limit=limit)


# Grammar-constrained response shape for the Lucene helper — the model can only
# emit a single-field JSON object, never prose or extra keys.
_LUCENE_SCHEMA = {
    "type": "object",
    "properties": {"query": {"type": "string"}},
    "required": ["query"],
}

_LUCENE_SYSTEM_PROMPT = """You translate an analyst's natural-language request into a single \
Lucene query string for the OpenSearch query_string parser, run against Wazuh alert indices \
(wazuh-alerts-*).

Common fields:
- rule.level (integer 0-16; >=7 medium, >=10 high, >=13 critical), rule.id, rule.description, \
rule.groups
- agent.name, agent.id, agent.ip
- timestamp (do NOT emit time filters — the UI applies the time range separately)
- data.srcip, data.dstip, data.srcport, data.dstport, data.srcuser, data.dstuser
- data.win.eventdata.* (Windows events: targetUserName, image, commandLine, ipAddress), \
data.win.system.eventID
- location, predecoder.hostname, decoder.name, full_log

Syntax rules:
- field:value ; quote multi-word values: rule.description:"logon failure"
- Ranges: rule.level:>=10 or rule.level:[7 TO 12]
- Boolean: AND OR NOT with parentheses; wildcards: data.srcip:192.168.1.*
- Free text with no obvious field: search full_log or rule.description
- Output ONLY the query string in the JSON "query" field — no explanation, no time ranges."""


@router.post("/opensearch/suggest", response_model=LuceneSuggestResponse)
async def suggest_lucene(body: LuceneSuggestRequest) -> LuceneSuggestResponse:
    """Translate a natural-language request into a Lucene query via the local LLM.

    The result is only a suggestion placed into the query box for the analyst
    to review and run — it is executed through the same guarded query_string
    endpoint as hand-typed queries, so a bad or malicious suggestion can at
    worst match the wrong documents, never touch a non-wazuh index.
    """
    ollama = OllamaClient()
    try:
        raw = await ollama.generate(
            prompt=body.prompt,
            system=_LUCENE_SYSTEM_PROMPT,
            num_predict=256,
            options={"temperature": 0.1},
            response_format=_LUCENE_SCHEMA,
        )
        query = str(json.loads(raw).get("query", "")).strip()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail="AI model unavailable") from exc
    if not query:
        raise HTTPException(status_code=502, detail="Model returned an empty query")
    return LuceneSuggestResponse(query=query)


@router.post("/opensearch", response_model=OpenSearchResponse)
async def opensearch_query(body: OpenSearchRequest) -> OpenSearchResponse:
    """Guarded raw search against the Wazuh indexer.

    The index pattern is restricted to ``wazuh-*`` names so internal indices
    (security config, credentials) can never be read. The query is a Lucene
    query_string, not raw DSL — the request body shape is fixed server-side.
    """
    if not _INDEX_PATTERN_RE.match(body.index_pattern):
        raise HTTPException(
            status_code=400,
            detail="Invalid index pattern — must match wazuh-* (letters, digits, . * _ -)",
        )

    filters: list[dict] = []
    if body.time_from or body.time_to:
        rng: dict = {}
        if body.time_from:
            rng["gte"] = body.time_from
        if body.time_to:
            rng["lte"] = body.time_to
        filters.append({"range": {"timestamp": rng}})

    search_body = {
        "from": body.offset,
        "size": body.size,
        "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": body.query or "*",
                            "lenient": True,
                            "default_field": "*",
                        }
                    }
                ],
                "filter": filters,
            }
        },
    }

    indexer = WazuhIndexerClient()
    try:
        result = await indexer.search(index=body.index_pattern, query=search_body)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail="Wazuh indexer unavailable") from exc

    hits_obj = result.get("hits", {})
    total_raw = hits_obj.get("total", 0)
    total = total_raw.get("value", 0) if isinstance(total_raw, dict) else total_raw

    hits = [
        OpenSearchHit(
            id=str(h.get("_id", "")),
            index=str(h.get("_index", "")),
            source=h.get("_source", {}) or {},
        )
        for h in hits_obj.get("hits", [])
    ]
    return OpenSearchResponse(total=total, took_ms=int(result.get("took", 0) or 0), hits=hits)
