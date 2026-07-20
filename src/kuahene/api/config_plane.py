"""Config-plane API — two-plane model, token management, conversational reconfig, factory reset."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from kuahene.db import get_session
from kuahene.models.config_plane import (
    AssessmentScope,
    ConfigChangeLog,
    ConfigPlaneSession,
    FactoryResetLog,
    PractitionerLicense,
    TokenEnrollment,
    TokenType,
    TokenStatus,
    SessionStatus,
    ScopeStatus,
    LicenseTier,
    LicenseStatus,
    ResetType,
)
from kuahene.services.config_plane import config_plane

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class TokenEnrollIn(BaseModel):
    token_serial: str = Field(..., min_length=1)
    token_type: str = Field(default="software_dev", pattern="^(yubikey|encrypted_usb|software_dev)$")
    operator: str = Field(..., min_length=1)
    public_key_fingerprint: str = Field(default="")


class ActivateIn(BaseModel):
    token_serial: str = Field(..., min_length=1)
    operator: str = Field(..., min_length=1)
    pin: str = Field(..., min_length=4, description="Operator PIN/passphrase")
    api_key: str = Field(..., min_length=1, description="Anthropic API key (held in memory only, never persisted)")


class DeactivateIn(BaseModel):
    reason: str = Field(default="operator_initiated")


class ConfigPromptIn(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=5000)
    artifact_type: str = Field(default="dashboard", pattern="^(dashboard|connector|ruleset|panel|setting)$")


class ApproveChangeIn(BaseModel):
    change_id: str = Field(..., min_length=1)
    approved: bool


class ScopeCreateIn(BaseModel):
    name: str = Field(..., min_length=1)
    cidrs: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    exclusions: list[str] = Field(default_factory=list)


class LicenseActivateIn(BaseModel):
    license_key: str = Field(..., min_length=1)
    operator_name: str = Field(..., min_length=1)
    organization: str = Field(..., min_length=1)


class FactoryResetIn(BaseModel):
    reset_type: str = Field(default="full", pattern="^(full|data_only)$")
    confirmation: str = Field(..., description="Must be 'CONFIRM FACTORY RESET'")


# ---------------------------------------------------------------------------
# Two-plane status
# ---------------------------------------------------------------------------

@router.get("/status")
async def plane_status(session: AsyncSession = Depends(get_session)) -> dict:
    """Get current two-plane status."""
    # Count enrolled tokens
    token_count = await session.scalar(
        select(func.count()).select_from(TokenEnrollment).where(
            TokenEnrollment.status == TokenStatus.ACTIVE
        )
    ) or 0

    # Get active license info
    license_result = await session.execute(
        select(PractitionerLicense).where(
            PractitionerLicense.status == LicenseStatus.ACTIVE
        )
    )
    active_license = license_result.scalar_one_or_none()

    return {
        "data_plane": {
            "status": "active",
            "air_gapped": True,
            "description": "Data plane is always active and air-gapped. No external egress.",
        },
        "config_plane": {
            "status": "active" if config_plane.is_config_plane_active else "inactive",
            "air_gapped": not config_plane.is_config_plane_active,
            "operator": config_plane.current_operator,
            "description": "Config plane is air-gapped by default. Requires hardware token to activate.",
        },
        "enrolled_tokens": token_count,
        "license": {
            "tier": active_license.tier.value if active_license else "self_assessment",
            "organization": active_license.organization if active_license else None,
            "operator": active_license.operator_name if active_license else None,
        } if active_license else {"tier": "self_assessment"},
    }


# ---------------------------------------------------------------------------
# Token management
# ---------------------------------------------------------------------------

@router.post("/tokens/enroll")
async def enroll_token(
    body: TokenEnrollIn,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Enroll a hardware token for config-plane access."""
    # Check for duplicate
    existing = await session.scalar(
        select(TokenEnrollment).where(
            TokenEnrollment.token_serial == body.token_serial,
            TokenEnrollment.status == TokenStatus.ACTIVE,
        )
    )
    if existing:
        raise HTTPException(status_code=409, detail="Token already enrolled")

    token = TokenEnrollment(
        token_serial=body.token_serial,
        token_type=TokenType(body.token_type),
        enrolled_by=body.operator,
        public_key_fingerprint=body.public_key_fingerprint or "",
        status=TokenStatus.ACTIVE,
    )
    session.add(token)
    await session.commit()
    await session.refresh(token)

    return {
        "id": str(token.id),
        "token_serial": token.token_serial,
        "token_type": token.token_type.value,
        "enrolled_by": token.enrolled_by,
        "status": token.status.value,
    }


@router.get("/tokens")
async def list_tokens(session: AsyncSession = Depends(get_session)) -> dict:
    """List enrolled tokens."""
    result = await session.execute(
        select(TokenEnrollment).order_by(TokenEnrollment.created_at.desc())
    )
    tokens = result.scalars().all()
    return {
        "tokens": [
            {
                "id": str(t.id),
                "token_serial": t.token_serial,
                "token_type": t.token_type.value,
                "enrolled_by": t.enrolled_by,
                "status": t.status.value,
                "enrolled_at": t.created_at.isoformat(),
            }
            for t in tokens
        ]
    }


@router.delete("/tokens/{token_serial}")
async def revoke_token(
    token_serial: str,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Revoke an enrolled token."""
    result = await session.execute(
        select(TokenEnrollment).where(
            TokenEnrollment.token_serial == token_serial,
            TokenEnrollment.status == TokenStatus.ACTIVE,
        )
    )
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(status_code=404, detail="Active token not found")

    token.status = TokenStatus.REVOKED
    await session.commit()

    # If this token is currently activating the config plane, kill it
    if config_plane.is_config_plane_active and config_plane._token_serial == token_serial:
        config_plane.deactivate()

    return {"revoked": True, "token_serial": token_serial}


# ---------------------------------------------------------------------------
# Config plane activation
# ---------------------------------------------------------------------------

@router.post("/activate")
async def activate_config_plane(
    body: ActivateIn,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Activate the config plane with a seated token + operator PIN + API key.

    The API key is held in memory ONLY — never written to disk, DB, or logs.
    """
    if config_plane.is_config_plane_active:
        raise HTTPException(status_code=409, detail="Config plane already active")

    # Verify token is enrolled
    result = await session.execute(
        select(TokenEnrollment).where(
            TokenEnrollment.token_serial == body.token_serial,
            TokenEnrollment.status == TokenStatus.ACTIVE,
        )
    )
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(status_code=403, detail="Token not enrolled or revoked")

    # In production: validate PIN against token's secure element
    # For dev/software_dev tokens, accept any PIN >= 4 chars
    if token.token_type == TokenType.SOFTWARE_DEV:
        if len(body.pin) < 4:
            raise HTTPException(status_code=403, detail="Invalid PIN")
    # TODO: YubiKey PIV validation, encrypted USB unlock

    # Create session record
    cp_session = ConfigPlaneSession(
        token_id=token.id,
        operator=body.operator,
        status=SessionStatus.ACTIVE,
    )
    session.add(cp_session)
    await session.commit()
    await session.refresh(cp_session)

    # Activate — credential held in memory only
    config_plane.activate(
        session_id=cp_session.id,
        operator=body.operator,
        token_serial=body.token_serial,
        api_credential=body.api_key,
    )

    return {
        "status": "active",
        "session_id": str(cp_session.id),
        "operator": body.operator,
        "message": "Config plane active. API credential held in memory only. Remove token or call /deactivate to close.",
    }


@router.post("/deactivate")
async def deactivate_config_plane(
    body: DeactivateIn,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Deactivate the config plane and zeroize all credentials from memory."""
    if not config_plane.is_config_plane_active:
        return {"status": "already_inactive", "message": "Config plane was not active"}

    session_id = config_plane._current_session_id

    # Close the DB session record
    if session_id:
        cp_session = await session.get(ConfigPlaneSession, session_id)
        if cp_session:
            cp_session.status = SessionStatus.CLOSED
            cp_session.ended_at = datetime.now(timezone.utc)
            await session.commit()

    # Zeroize and deactivate
    config_plane.deactivate()

    return {
        "status": "inactive",
        "message": "Config plane deactivated. All credentials zeroized from memory.",
        "air_gapped": True,
    }


# ---------------------------------------------------------------------------
# Conversational reconfiguration
# ---------------------------------------------------------------------------

@router.post("/reconfig")
async def conversational_reconfig(
    body: ConfigPromptIn,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Generate a config change via the Anthropic API (config plane must be active)."""
    if not config_plane.is_config_plane_active:
        raise HTTPException(
            status_code=403,
            detail="Config plane is not active. Seat a token and activate first.",
        )

    api_key = config_plane.get_api_credential()
    if not api_key:
        raise HTTPException(status_code=403, detail="No API credential available")

    # Build the config-only prompt (R3.1 — config artifacts only, never data)
    system_prompt = """You are Kuahene's config-plane assistant. You generate ONLY configuration artifacts:
- Dashboard panel definitions (JSON)
- Connector configurations (JSON)
- Ruleset adjustments (JSON diffs)
- Appliance settings changes (JSON)

CRITICAL RULES:
- NEVER include, reference, or request actual telemetry data, log content, alert bodies, or CUI/PHI.
- Output ONLY valid JSON configuration artifacts.
- Every artifact must include a "description" field explaining what it does.
- Include a "rollback" field with the reverse change.
"""

    # Call Anthropic API
    import httpx
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-sonnet-4-20250514",
                    "max_tokens": 2048,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": body.prompt}],
                },
            )
            resp.raise_for_status()
            result = resp.json()
            generated = result["content"][0]["text"]
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"Anthropic API error: {e.response.status_code}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to reach Anthropic API: {e}")

    # Create pending change log entry (not yet approved)
    change = ConfigChangeLog(
        session_id=config_plane._current_session_id,
        operator=config_plane.current_operator,
        prompt_text=body.prompt,
        diff_json={"generated": generated, "artifact_type": body.artifact_type},
        artifact_type=body.artifact_type,
        approved=False,
    )
    session.add(change)
    await session.commit()
    await session.refresh(change)

    return {
        "change_id": str(change.id),
        "artifact_type": body.artifact_type,
        "generated": generated,
        "status": "pending_approval",
        "message": "Review the generated config. POST /approve to apply or reject.",
    }


@router.post("/approve")
async def approve_change(
    body: ApproveChangeIn,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Approve or reject a pending config change (R3.2 — diff-and-approve, always)."""
    if not config_plane.is_config_plane_active:
        raise HTTPException(status_code=403, detail="Config plane is not active")

    change = await session.get(ConfigChangeLog, uuid.UUID(body.change_id))
    if not change:
        raise HTTPException(status_code=404, detail="Change not found")

    if change.applied_at:
        raise HTTPException(status_code=409, detail="Change already processed")

    change.approved = body.approved
    change.applied_at = datetime.now(timezone.utc)
    await session.commit()

    status = "applied" if body.approved else "rejected"
    return {
        "change_id": body.change_id,
        "status": status,
        "operator": change.operator,
        "artifact_type": change.artifact_type,
    }


@router.get("/changelog")
async def get_changelog(session: AsyncSession = Depends(get_session)) -> dict:
    """Get the config change audit log (R3.3 — every change logged)."""
    result = await session.execute(
        select(ConfigChangeLog).order_by(ConfigChangeLog.created_at.desc()).limit(100)
    )
    changes = result.scalars().all()
    return {
        "changes": [
            {
                "id": str(c.id),
                "operator": c.operator,
                "prompt": c.prompt_text[:200] if c.prompt_text else "",
                "artifact_type": c.artifact_type,
                "approved": c.approved,
                "applied_at": c.applied_at.isoformat() if c.applied_at else None,
                "created_at": c.created_at.isoformat(),
            }
            for c in changes
        ]
    }


# ---------------------------------------------------------------------------
# Assessment scope management
# ---------------------------------------------------------------------------

@router.post("/scopes")
async def create_scope(
    body: ScopeCreateIn,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Create a declared assessment scope (R4.1 — scan targets pinned to declared inventory)."""
    scope = AssessmentScope(
        name=body.name,
        cidrs=body.cidrs,
        hosts=body.hosts,
        exclusions=body.exclusions,
        created_by=config_plane.current_operator or "system",
        status=ScopeStatus.ACTIVE,
    )
    session.add(scope)
    await session.commit()
    await session.refresh(scope)

    return {
        "id": str(scope.id),
        "name": scope.name,
        "cidrs": scope.cidrs,
        "hosts": scope.hosts,
        "exclusions": scope.exclusions,
        "status": scope.status.value,
    }


@router.get("/scopes")
async def list_scopes(session: AsyncSession = Depends(get_session)) -> dict:
    """List declared assessment scopes."""
    result = await session.execute(
        select(AssessmentScope).where(
            AssessmentScope.status == ScopeStatus.ACTIVE
        ).order_by(AssessmentScope.created_at.desc())
    )
    scopes = result.scalars().all()
    return {
        "scopes": [
            {
                "id": str(s.id),
                "name": s.name,
                "cidrs": s.cidrs,
                "hosts": s.hosts,
                "exclusions": s.exclusions,
                "created_by": s.created_by,
                "status": s.status.value,
            }
            for s in scopes
        ]
    }


# ---------------------------------------------------------------------------
# Practitioner license
# ---------------------------------------------------------------------------

@router.post("/license/activate")
async def activate_license(
    body: LicenseActivateIn,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Activate a practitioner license."""
    # For v1: accept any key format, validate structure
    # Production: cryptographic license validation
    tier = LicenseTier.PRACTITIONER if body.license_key.startswith("PRAC-") else LicenseTier.SELF_ASSESSMENT

    license_record = PractitionerLicense(
        license_key=body.license_key,
        operator_name=body.operator_name,
        organization=body.organization,
        tier=tier,
        status=LicenseStatus.ACTIVE,
    )
    session.add(license_record)
    await session.commit()
    await session.refresh(license_record)

    return {
        "id": str(license_record.id),
        "tier": license_record.tier.value,
        "operator": license_record.operator_name,
        "organization": license_record.organization,
        "status": license_record.status.value,
    }


@router.get("/license")
async def get_license(session: AsyncSession = Depends(get_session)) -> dict:
    """Get current license status."""
    result = await session.execute(
        select(PractitionerLicense).where(
            PractitionerLicense.status == LicenseStatus.ACTIVE
        ).order_by(PractitionerLicense.created_at.desc()).limit(1)
    )
    lic = result.scalar_one_or_none()
    if not lic:
        return {"tier": "self_assessment", "licensed": False}
    return {
        "licensed": True,
        "tier": lic.tier.value,
        "operator": lic.operator_name,
        "organization": lic.organization,
        "activated_at": lic.created_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# Factory reset
# ---------------------------------------------------------------------------

@router.post("/factory-reset")
async def factory_reset(
    body: FactoryResetIn,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Initiate factory reset with attestation (R7.1-R7.3).

    This does NOT require the config plane / token (R7.3 — token independence).
    It IS a local, physical-operator function.
    """
    if body.confirmation != "CONFIRM FACTORY RESET":
        raise HTTPException(status_code=400, detail="Confirmation text must be exactly: CONFIRM FACTORY RESET")

    # Generate attestation
    attestation_data = {
        "reset_type": body.reset_type,
        "initiated_at": datetime.now(timezone.utc).isoformat(),
        "tables_to_wipe": ["alerts", "alert_dispositions", "evidence", "vuln_findings", "vuln_scans"],
    }
    if body.reset_type == "full":
        attestation_data["tables_to_wipe"].extend([
            "connector_instances", "compliance_profiles",
            "config_plane_sessions", "config_change_log",
            "assessment_scopes", "practitioner_licenses",
        ])

    attestation_hash = hashlib.sha256(
        str(attestation_data).encode()
    ).hexdigest()

    # Log the reset BEFORE wiping (attestation survives the wipe)
    reset_log = FactoryResetLog(
        initiated_by="local_operator",
        reset_type=ResetType(body.reset_type),
        attestation_hash=attestation_hash,
        completed_at=datetime.now(timezone.utc),
    )
    session.add(reset_log)
    await session.flush()

    # Perform the wipe
    from sqlalchemy import text
    data_tables = ["alert_dispositions", "alerts", "evidence", "vuln_findings", "vuln_scans"]
    for table in data_tables:
        await session.execute(text(f"TRUNCATE TABLE {table} CASCADE"))

    if body.reset_type == "full":
        config_tables = [
            "connector_instances", "compliance_profiles",
            "config_plane_sessions", "config_change_log",
            "assessment_scopes", "practitioner_licenses",
            "token_enrollments",
        ]
        for table in config_tables:
            try:
                await session.execute(text(f"TRUNCATE TABLE {table} CASCADE"))
            except Exception:
                pass  # Table may not exist yet

        # Kill config plane if active
        config_plane.deactivate()

    await session.commit()

    return {
        "status": "reset_complete",
        "reset_type": body.reset_type,
        "attestation_hash": attestation_hash,
        "attestation": attestation_data,
        "message": "Factory reset complete. Attestation record preserved in factory_reset_log.",
    }
