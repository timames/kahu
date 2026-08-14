"""Attestation v2 bundle builder.

An attestation bundle is a signed JSON document containing:
- Pono Score snapshot (score, components, schema version)
- Appliance identity (appliance_id, org_name)
- Evidence chain references (hash-chained evidence IDs)
- Timestamp and expiry
- Ed25519 signature over canonical JSON of signable fields
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kahu_attest import __version__
from kahu_tuning.config import canonical_json
from kahu_tuning.signing import sign_payload, verify_signature


def build_pono_snapshot(pono_result: Any) -> dict:
    """Extract a serializable snapshot from a PonoResult."""
    return {
        "pono_score": round(pono_result.pono_score, 2),
        "schema_version": pono_result.schema_version,
        "components": [
            {
                "name": c.name,
                "raw_score": round(c.raw_score, 4),
                "weighted_score": round(c.weighted_score, 2),
                "max_points": c.max_points,
                "assessed": c.assessed,
                "label": c.label,
                "evidence_age_days": round(c.evidence_age_days, 1),
            }
            for c in pono_result.components
        ],
        "biggest_gain": pono_result.biggest_gain,
    }


def build_evidence_chain(evidence_ids: list[str]) -> dict:
    """Build a hash chain over evidence IDs.

    Each link is SHA-256(previous_hash || evidence_id).
    The chain root is SHA-256("genesis").
    """
    if not evidence_ids:
        return {"chain": [], "root": hashlib.sha256(b"genesis").hexdigest()}

    chain = []
    prev_hash = hashlib.sha256(b"genesis").hexdigest()
    for eid in evidence_ids:
        link_data = f"{prev_hash}:{eid}".encode()
        current_hash = hashlib.sha256(link_data).hexdigest()
        chain.append({"evidence_id": eid, "hash": current_hash})
        prev_hash = current_hash

    return {"chain": chain, "root": prev_hash}


def build_attestation(
    pono_snapshot: dict,
    appliance_id: str,
    org_name: str,
    evidence_ids: list[str] | None = None,
    validity_days: int = 30,
    metadata: dict | None = None,
) -> dict:
    """Build an unsigned attestation v2 document."""
    now = datetime.now(UTC)
    evidence_chain = build_evidence_chain(evidence_ids or [])

    return {
        "attestation_id": str(uuid.uuid4()),
        "version": "2.0",
        "created": now.isoformat(),
        "expires": (now + timedelta(days=validity_days)).isoformat(),
        "appliance": {
            "appliance_id": appliance_id,
            "org_name": org_name,
        },
        "pono_snapshot": pono_snapshot,
        "evidence_chain": evidence_chain,
        "engine_version": __version__,
        "metadata": metadata or {},
    }


def sign_attestation(attestation: dict, private_key: Ed25519PrivateKey) -> dict:
    """Sign an attestation and return the complete document with signature.

    The signature covers all fields except 'signature' itself.
    """
    signable = extract_signable(attestation)
    sig = sign_payload(signable, private_key)
    return {**attestation, "signature": sig}


def extract_signable(attestation: dict) -> dict:
    """Extract the signable portion (excludes signature)."""
    return {k: v for k, v in attestation.items() if k != "signature"}


def verify_attestation_signature(
    attestation: dict,
    public_key: Any,
) -> bool:
    """Verify the Ed25519 signature on an attestation."""
    sig = attestation.get("signature", "")
    if not sig:
        return False
    signable = extract_signable(attestation)
    return verify_signature(signable, sig, public_key)


def verify_evidence_chain(attestation: dict) -> bool:
    """Verify the integrity of the evidence hash chain."""
    chain_data = attestation.get("evidence_chain", {})
    chain = chain_data.get("chain", [])
    root = chain_data.get("root", "")

    if not chain:
        expected_root = hashlib.sha256(b"genesis").hexdigest()
        return root == expected_root

    prev_hash = hashlib.sha256(b"genesis").hexdigest()
    for link in chain:
        link_data = f"{prev_hash}:{link['evidence_id']}".encode()
        current_hash = hashlib.sha256(link_data).hexdigest()
        if current_hash != link["hash"]:
            return False
        prev_hash = current_hash

    return prev_hash == root


def is_attestation_expired(
    attestation: dict,
    now: datetime | None = None,
) -> bool:
    """Check if an attestation has expired."""
    if now is None:
        now = datetime.now(UTC)
    expires = datetime.fromisoformat(attestation["expires"])
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    return now >= expires


def export_bundle(attestation: dict) -> str:
    """Export attestation as canonical JSON string for storage/transmission."""
    return canonical_json(attestation)
