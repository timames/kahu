"""Connector framework API — source catalog, wizard, and lifecycle."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from kuahene.db import get_session
from kuahene.models.connectors import ConnectorInstance, ConnectorStatus

router = APIRouter()

# ---------------------------------------------------------------------------
# Connector catalog — what source types are available
# ---------------------------------------------------------------------------

CONNECTOR_CATALOG = {
    "wazuh_syslog": {
        "name": "Wazuh Syslog",
        "description": "Collect events via syslog forwarding to the Wazuh manager",
        "category": "SIEM",
        "config_schema": {
            "port": {"type": "integer", "default": 514, "label": "Syslog Port"},
            "protocol": {"type": "string", "default": "tcp", "label": "Protocol", "options": ["tcp", "udp"]},
            "format": {"type": "string", "default": "rfc3164", "label": "Format", "options": ["rfc3164", "rfc5424"]},
        },
    },
    "wazuh_agent": {
        "name": "Wazuh Agent",
        "description": "Endpoint agent reporting to Wazuh manager (encrypted)",
        "category": "Endpoint",
        "config_schema": {
            "agent_group": {"type": "string", "default": "default", "label": "Agent Group"},
        },
    },
    "windows_event_log": {
        "name": "Windows Event Log",
        "description": "Collect Windows Security, System, and Application event logs",
        "category": "Endpoint",
        "config_schema": {
            "channels": {"type": "string", "default": "Security,System", "label": "Log Channels"},
            "collect_interval": {"type": "integer", "default": 60, "label": "Poll Interval (s)"},
        },
    },
    "linux_auditd": {
        "name": "Linux Auditd",
        "description": "Collect Linux audit daemon logs for file integrity and process monitoring",
        "category": "Endpoint",
        "config_schema": {
            "log_path": {"type": "string", "default": "/var/log/audit/audit.log", "label": "Log Path"},
        },
    },
    "fortigate_firewall": {
        "name": "FortiGate Firewall",
        "description": "Syslog from FortiGate next-gen firewall (traffic, UTM, event logs)",
        "category": "Network",
        "config_schema": {
            "source_ip": {"type": "string", "default": "", "label": "Firewall IP"},
            "log_types": {"type": "string", "default": "traffic,utm,event", "label": "Log Types"},
        },
    },
    "palo_alto": {
        "name": "Palo Alto Networks",
        "description": "Syslog from PAN-OS firewalls (threat, traffic, system)",
        "category": "Network",
        "config_schema": {
            "source_ip": {"type": "string", "default": "", "label": "Firewall IP"},
            "log_types": {"type": "string", "default": "threat,traffic,system", "label": "Log Types"},
        },
    },
    "m365_graph": {
        "name": "Microsoft 365 / Entra ID",
        "description": "Azure AD sign-in logs, audit logs, and security alerts via Graph API",
        "category": "Cloud",
        "config_schema": {
            "tenant_id": {"type": "string", "default": "", "label": "Tenant ID"},
            "client_id": {"type": "string", "default": "", "label": "Client ID"},
            "client_secret": {"type": "string", "default": "", "label": "Client Secret", "sensitive": True},
        },
    },
    "aws_cloudtrail": {
        "name": "AWS CloudTrail",
        "description": "AWS API activity logs from CloudTrail (management and data events)",
        "category": "Cloud",
        "config_schema": {
            "region": {"type": "string", "default": "us-east-1", "label": "Region"},
            "s3_bucket": {"type": "string", "default": "", "label": "S3 Bucket"},
            "access_key_id": {"type": "string", "default": "", "label": "Access Key ID", "sensitive": True},
            "secret_access_key": {"type": "string", "default": "", "label": "Secret Access Key", "sensitive": True},
        },
    },
    "snmp_trap": {
        "name": "SNMP Trap Receiver",
        "description": "Receive SNMP v2c/v3 traps from network devices (switches, UPS, printers)",
        "category": "Network",
        "config_schema": {
            "community": {"type": "string", "default": "public", "label": "Community String"},
            "port": {"type": "integer", "default": 162, "label": "Trap Port"},
        },
    },
    "netflow": {
        "name": "NetFlow / sFlow",
        "description": "Network flow data (NetFlow v5/v9, IPFIX, sFlow) for traffic analysis",
        "category": "Network",
        "config_schema": {
            "port": {"type": "integer", "default": 2055, "label": "Collector Port"},
            "version": {"type": "string", "default": "v5", "label": "Version", "options": ["v5", "v9", "ipfix", "sflow"]},
        },
    },
}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ConnectorCreateIn(BaseModel):
    connector_type: str
    name: str = Field(..., min_length=1, max_length=255)
    config: dict = Field(default_factory=dict)
    control_tags: list[str] = Field(default_factory=list)


class ConnectorUpdateIn(BaseModel):
    name: str | None = None
    config: dict | None = None
    control_tags: list[str] | None = None
    status: str | None = Field(None, pattern="^(active|disabled)$")


class ConnectorOut(BaseModel):
    id: str
    connector_type: str
    name: str
    status: str
    config: dict
    control_tags: list[str]
    last_event_at: str | None
    created_at: str
    catalog_info: dict | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/catalog")
async def list_catalog() -> dict:
    """List all available connector types."""
    return {"connectors": CONNECTOR_CATALOG}


@router.get("/instances")
async def list_instances(session: AsyncSession = Depends(get_session)) -> dict:
    """List all configured connector instances."""
    result = await session.execute(
        select(ConnectorInstance).order_by(ConnectorInstance.created_at.desc())
    )
    instances = result.scalars().all()
    return {
        "instances": [_to_out(i) for i in instances],
        "total": len(instances),
    }


@router.post("/instances", status_code=201)
async def create_instance(
    body: ConnectorCreateIn,
    session: AsyncSession = Depends(get_session),
) -> ConnectorOut:
    """Create a new connector instance."""
    if body.connector_type not in CONNECTOR_CATALOG:
        raise HTTPException(status_code=400, detail=f"Unknown connector type: {body.connector_type}")

    instance = ConnectorInstance(
        connector_type=body.connector_type,
        name=body.name,
        status=ConnectorStatus.PENDING,
        config=body.config,
        control_tags=body.control_tags,
        last_event_at=None,
    )
    session.add(instance)
    await session.commit()
    await session.refresh(instance)
    return _to_out(instance)


@router.get("/instances/{instance_id}")
async def get_instance(
    instance_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> ConnectorOut:
    """Get a connector instance by ID."""
    instance = await session.get(ConnectorInstance, instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Connector not found")
    return _to_out(instance)


@router.patch("/instances/{instance_id}")
async def update_instance(
    instance_id: uuid.UUID,
    body: ConnectorUpdateIn,
    session: AsyncSession = Depends(get_session),
) -> ConnectorOut:
    """Update a connector instance."""
    instance = await session.get(ConnectorInstance, instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Connector not found")

    if body.name is not None:
        instance.name = body.name
    if body.config is not None:
        instance.config = body.config
    if body.control_tags is not None:
        instance.control_tags = body.control_tags
    if body.status is not None:
        instance.status = ConnectorStatus(body.status)

    await session.commit()
    await session.refresh(instance)
    return _to_out(instance)


@router.delete("/instances/{instance_id}", status_code=204)
async def delete_instance(
    instance_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> None:
    """Delete a connector instance."""
    instance = await session.get(ConnectorInstance, instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Connector not found")
    await session.delete(instance)
    await session.commit()


@router.post("/instances/{instance_id}/activate")
async def activate_instance(
    instance_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> ConnectorOut:
    """Activate a connector (moves from pending/disabled to active)."""
    instance = await session.get(ConnectorInstance, instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Connector not found")
    instance.status = ConnectorStatus.ACTIVE
    await session.commit()
    await session.refresh(instance)
    return _to_out(instance)


@router.post("/instances/{instance_id}/test")
async def test_connection(
    instance_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Test connectivity for a connector instance."""
    import httpx

    instance = await session.get(ConnectorInstance, instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Connector not found")

    config = instance.config or {}
    ctype = instance.connector_type
    result = {"connector_id": str(instance.id), "type": ctype, "success": False, "detail": ""}

    try:
        if ctype == "wazuh_syslog":
            import socket
            port = config.get("port", 514)
            proto = config.get("protocol", "tcp")
            sock_type = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
            s = socket.socket(socket.AF_INET, sock_type)
            s.settimeout(5)
            s.connect(("wazuh-manager", port))
            s.close()
            result["success"] = True
            result["detail"] = f"Syslog {proto.upper()}:{port} reachable"

        elif ctype == "wazuh_agent":
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                from kuahene.config import settings
                resp = await client.post(
                    f"{settings.wazuh_api_url}/security/user/authenticate",
                    auth=(settings.wazuh_api_user, settings.wazuh_api_password),
                )
                if resp.status_code == 200:
                    result["success"] = True
                    result["detail"] = "Wazuh API authenticated"
                else:
                    result["detail"] = f"Wazuh API returned {resp.status_code}"

        elif ctype in ("fortigate_firewall", "palo_alto"):
            source_ip = config.get("source_ip", "")
            if not source_ip:
                result["detail"] = "No source IP configured"
            else:
                import socket
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                try:
                    s.connect((source_ip, 443))
                    s.close()
                    result["success"] = True
                    result["detail"] = f"HTTPS port reachable on {source_ip}"
                except (socket.timeout, ConnectionRefusedError, OSError) as e:
                    result["detail"] = f"Cannot reach {source_ip}:443 — {e}"

        elif ctype == "m365_graph":
            tenant_id = config.get("tenant_id", "")
            client_id = config.get("client_id", "")
            client_secret = config.get("client_secret", "")
            if not all([tenant_id, client_id, client_secret]):
                result["detail"] = "Missing tenant_id, client_id, or client_secret"
            else:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.post(
                        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                        data={
                            "grant_type": "client_credentials",
                            "client_id": client_id,
                            "client_secret": client_secret,
                            "scope": "https://graph.microsoft.com/.default",
                        },
                    )
                    if resp.status_code == 200:
                        result["success"] = True
                        result["detail"] = "Microsoft Graph token obtained"
                    else:
                        result["detail"] = f"Auth failed: {resp.status_code}"

        elif ctype == "aws_cloudtrail":
            region = config.get("region", "us-east-1")
            bucket = config.get("s3_bucket", "")
            if not bucket:
                result["detail"] = "No S3 bucket configured"
            else:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.head(f"https://{bucket}.s3.{region}.amazonaws.com/")
                    result["success"] = resp.status_code in (200, 403)
                    result["detail"] = f"S3 bucket exists (HTTP {resp.status_code})"

        elif ctype in ("snmp_trap", "netflow"):
            port = config.get("port", 162 if ctype == "snmp_trap" else 2055)
            result["success"] = True
            result["detail"] = f"Passive listener on UDP:{port} — ready to receive"

        elif ctype in ("windows_event_log", "linux_auditd"):
            result["success"] = True
            result["detail"] = "Agent-based collection — connectivity managed by Wazuh agent"

        else:
            result["detail"] = f"No test implemented for type {ctype}"

    except Exception as e:
        result["detail"] = f"Connection test failed: {e}"

    # Update connector status based on test
    if result["success"]:
        instance.status = ConnectorStatus.ACTIVE
    else:
        instance.status = ConnectorStatus.ERROR
    await session.commit()

    return result


def _to_out(instance: ConnectorInstance) -> ConnectorOut:
    catalog_info = CONNECTOR_CATALOG.get(instance.connector_type)
    return ConnectorOut(
        id=str(instance.id),
        connector_type=instance.connector_type,
        name=instance.name,
        status=instance.status.value if isinstance(instance.status, ConnectorStatus) else instance.status,
        config=instance.config,
        control_tags=instance.control_tags or [],
        last_event_at=instance.last_event_at,
        created_at=instance.created_at.isoformat() if instance.created_at else "",
        catalog_info=catalog_info,
    )
