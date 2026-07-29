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
    wazuh_api_healthy: bool
    wazuh_indexer_healthy: bool
    pipeline_degraded: bool


# Forward ref resolution
AlertDetail.model_rebuild()
