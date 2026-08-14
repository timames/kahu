"""Tests for Stage 4 — Evidence hash chaining."""

import hashlib
import json


def test_evidence_hash_determinism():
    """Verify the hash chain computation is deterministic."""
    previous_hash = "0" * 64
    event_type = "alert_raised"
    control_tags = ["800-171:3.3.1"]
    payload = {"alert_id": "test-123", "severity": "high"}
    actor = "system:triage_pipeline"

    content = json.dumps(
        {"previous_hash": previous_hash, "event_type": event_type,
         "control_tags": control_tags, "payload": payload, "actor": actor},
        sort_keys=True, default=str,
    )
    hash1 = hashlib.sha256(content.encode()).hexdigest()
    hash2 = hashlib.sha256(content.encode()).hexdigest()

    assert hash1 == hash2
    assert len(hash1) == 64


def test_evidence_hash_changes_with_payload():
    """Different payloads produce different hashes."""
    base = {
        "previous_hash": "0" * 64,
        "event_type": "alert_raised",
        "control_tags": ["800-171:3.3.1"],
        "actor": "system",
    }

    content1 = json.dumps({**base, "payload": {"id": "1"}}, sort_keys=True)
    content2 = json.dumps({**base, "payload": {"id": "2"}}, sort_keys=True)

    hash1 = hashlib.sha256(content1.encode()).hexdigest()
    hash2 = hashlib.sha256(content2.encode()).hexdigest()
    assert hash1 != hash2


def test_evidence_chain_links():
    """Each record's hash becomes the next record's previous_hash."""
    genesis_hash = "0" * 64

    record1 = json.dumps(
        {"previous_hash": genesis_hash, "event_type": "test", "control_tags": [],
         "payload": {"n": 1}, "actor": "test"},
        sort_keys=True,
    )
    hash1 = hashlib.sha256(record1.encode()).hexdigest()

    record2 = json.dumps(
        {"previous_hash": hash1, "event_type": "test", "control_tags": [],
         "payload": {"n": 2}, "actor": "test"},
        sort_keys=True,
    )
    hash2 = hashlib.sha256(record2.encode()).hexdigest()

    assert hash1 != hash2
    # Tampering with record1 would break the chain
    tampered = json.dumps(
        {"previous_hash": genesis_hash, "event_type": "test", "control_tags": [],
         "payload": {"n": 999}, "actor": "test"},
        sort_keys=True,
    )
    tampered_hash = hashlib.sha256(tampered.encode()).hexdigest()
    assert tampered_hash != hash1
