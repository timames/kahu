"""Webhook emitter — posts alert payloads to Kahu's triage ingest API.

This runs alongside the syslog emitter so the demo dashboard updates in
real-time without requiring Wazuh decoder configuration.
"""
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Optional

import httpx

from .config import cfg

log = logging.getLogger("webhook")

KAHU_INGEST_URL = cfg.KAHU_INGEST_URL or \
    f"http://{cfg.KAHU_HOST}/api/triage/ingest"

_lock = threading.Lock()
_buffer: list[dict] = []
_counter = {"sent": 0, "errors": 0}
_flush_thread: Optional[threading.Thread] = None
_stop = threading.Event()


# Severity mapping from syslog severity to Wazuh-style rule levels
SEVERITY_MAP = {
    "emerg": 15, "alert": 14, "crit": 12, "err": 10,
    "warning": 7, "notice": 5, "info": 3, "debug": 1,
}


def queue_alert(host: str, tag: str, message: str,
                facility: str = "local0", severity: str = "info",
                rule_id: str | None = None, rule_desc: str | None = None) -> None:
    """Queue an alert for batch delivery to Kahu."""
    level = SEVERITY_MAP.get(severity, 3)
    alert = {
        "id": f"{int(time.time())}.{_counter['sent'] + len(_buffer)}",
        "rule": {
            "id": rule_id or _infer_rule_id(tag, message),
            "level": level,
            "description": rule_desc or message[:120],
        },
        "agent": {
            "id": "gen-001",
            "name": host,
            "ip": "10.20.10.1",
        },
        "data": {
            "srcip": _extract_ip(message),
            "program": tag,
            "message": message,
        },
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "location": f"/var/log/{tag.lower()}",
    }

    with _lock:
        _buffer.append(alert)


def _infer_rule_id(tag: str, message: str) -> str:
    """Map common event patterns to plausible Wazuh rule IDs."""
    msg_lower = message.lower()
    if "logonfail" in msg_lower or "4625" in message or "failed" in msg_lower:
        return "5710"
    if "4624" in message or "logon" in msg_lower:
        return "5501"
    if "scan" in msg_lower or "port" in msg_lower:
        return "5701"
    if "ransomware" in msg_lower or ".locked" in msg_lower or "rename" in msg_lower:
        return "100002"
    if "beacon" in msg_lower or "callback" in msg_lower:
        return "100010"
    if "exfil" in msg_lower or "transfer" in msg_lower:
        return "100020"
    if "privilege" in msg_lower or "4728" in message or "admin" in msg_lower:
        return "5502"
    if "psexec" in msg_lower or "lateral" in msg_lower or "7045" in message:
        return "92000"
    if "cleared" in msg_lower or "1102" in message:
        return "5503"
    if "deny" in msg_lower or "drop" in msg_lower:
        return "5710"
    if "fortigate" in tag.lower():
        return "81600"
    return "5000"


def _extract_ip(message: str) -> str:
    """Try to extract an IP from the message."""
    import re
    m = re.search(r'(?:srcip=|Source=|from[ =])(\d+\.\d+\.\d+\.\d+)', message)
    if m:
        return m.group(1)
    m = re.search(r'(\d+\.\d+\.\d+\.\d+)', message)
    if m:
        return m.group(1)
    return "0.0.0.0"


def _flush_loop() -> None:
    """Background thread that flushes buffered alerts to Kahu every 3 seconds."""
    while not _stop.is_set():
        time.sleep(3.0)
        _flush()


def _flush() -> None:
    with _lock:
        if not _buffer:
            return
        # Cap the batch to a rate the on-box LLM can actually triage. Anything
        # over the cap is dropped, not carried forward, so a high-intensity
        # generator can't back up Ollama's queue past the ingest timeout.
        batch = _buffer[:cfg.WEBHOOK_MAX_BATCH]
        dropped = len(_buffer) - len(batch)
        _buffer.clear()
    if dropped:
        log.debug("webhook: dropped %d overflow alerts (cap=%d)",
                  dropped, cfg.WEBHOOK_MAX_BATCH)

    headers = {}
    if cfg.KAHU_INGEST_TOKEN:
        headers["X-Ingest-Token"] = cfg.KAHU_INGEST_TOKEN

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(KAHU_INGEST_URL, json={"alerts": batch}, headers=headers)
            if resp.status_code == 200:
                _counter["sent"] += len(batch)
                log.info("webhook: flushed %d alerts to Kahu", len(batch))
            else:
                _counter["errors"] += len(batch)
                log.warning("webhook: ingest returned %d: %s",
                            resp.status_code, resp.text[:200])
    except Exception as exc:
        _counter["errors"] += len(batch)
        log.warning("webhook: flush failed: %s", exc)


def start() -> None:
    """Start the background flush thread."""
    global _flush_thread
    if _flush_thread and _flush_thread.is_alive():
        return
    _stop.clear()
    _flush_thread = threading.Thread(target=_flush_loop, daemon=True)
    _flush_thread.start()
    log.info("webhook: emitter started → %s", KAHU_INGEST_URL)


def stop() -> None:
    _stop.set()
    _flush()


def webhook_counters() -> dict:
    return dict(_counter)
