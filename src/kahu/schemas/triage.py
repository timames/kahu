"""Pydantic schemas for triage API request/response models."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class AlertSummary(BaseModel):
    id: uuid.UUID
    wazuh_alert_id: str
    rule_id: str
    rule_description: str
    severity: str
    agent_name: str | None
    created_at: datetime
    has_disposition: bool
    llm_explanation: str | None = None
    degraded: bool = False


class AlertDetail(BaseModel):
    id: uuid.UUID
    wazuh_alert_id: str
    rule_id: str
    rule_description: str
    severity: str
    agent_name: str | None
    created_at: datetime
    raw_event: dict
    enrichment: dict | None
    llm_triage: dict | None
    pipeline_provenance: dict | None
    control_tags: list[str] | None
    disposition: DispositionOut | None = None


class DispositionIn(BaseModel):
    verdict: str = Field(
        ...,
        pattern="^(true_positive|acknowledged|false_positive|benign_true_positive|undetermined)$",
        description="Analyst verdict for this alert",
    )
    analyst: str = Field(..., min_length=1, max_length=255)
    notes: str | None = Field(None, max_length=4000)


class DispositionOut(BaseModel):
    id: uuid.UUID
    alert_id: uuid.UUID
    verdict: str
    analyst: str
    notes: str | None
    created_at: datetime


class HistoryAlertSummary(BaseModel):
    id: uuid.UUID
    wazuh_alert_id: str
    rule_id: str
    rule_description: str
    severity: str
    agent_name: str | None
    created_at: datetime
    verdict: str | None = None
    analyst: str | None = None
    disposition_at: datetime | None = None
    llm_explanation: str | None = None
    muted: bool = False


class TriageQueueResponse(BaseModel):
    alerts: list[AlertSummary]
    total: int
    offset: int
    limit: int
    degraded: bool = False


class HistoryResponse(BaseModel):
    alerts: list[HistoryAlertSummary]
    total: int
    offset: int
    limit: int


class WazuhLog(BaseModel):
    id: str
    timestamp: datetime | None
    rule_id: str
    rule_level: int
    severity: str
    rule_description: str
    agent_name: str | None
    src_ip: str | None
    location: str | None
    full_log: str | None


class WazuhLogsResponse(BaseModel):
    logs: list[WazuhLog]
    total: int
    offset: int
    limit: int


class LogStorageResponse(BaseModel):
    disk_total_bytes: int
    disk_used_bytes: int
    disk_available_bytes: int
    logs_size_bytes: int
    logs_doc_count: int
    oldest_log: datetime | None
    newest_log: datetime | None
    span_days: float
    bytes_per_day: float
    docs_per_day: float
    retention_days_current: float
    days_until_full: float
    total_capacity_days: float


class MuteCreate(BaseModel):
    rule_id: str = Field(..., min_length=1, max_length=50)
    reason: str | None = Field(None, max_length=2000)
    # "24h" | "7d" | None (forever)
    duration: str | None = Field(None, pattern="^(24h|7d)$")


class MutedRuleOut(BaseModel):
    id: uuid.UUID
    rule_id: str
    reason: str | None
    created_by: str
    expires_at: datetime | None
    created_at: datetime
    # Most recent alert description for this rule — helps the user recognise
    # what they muted.
    rule_description: str | None = None


class MutesResponse(BaseModel):
    mutes: list[MutedRuleOut]


class PipelineBatchRequest(BaseModel):
    alerts: list[dict] = Field(..., min_length=1, max_length=100)


class PipelineBatchResponse(BaseModel):
    processed: int
    filtered: int
    triaged: int
    persisted: int
    errors: int


class PipelineStatusResponse(BaseModel):
    pipeline_running: bool
    ollama_healthy: bool
    ollama_model_loaded: bool
    wazuh_api_healthy: bool
    wazuh_indexer_healthy: bool
    pipeline_degraded: bool


# Forward ref resolution
AlertDetail.model_rebuild()
