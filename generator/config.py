"""Configuration for the Kahu demo traffic generator.

Everything is driven by environment variables so the same image runs against a
lab appliance, a cloud demo appliance, or nothing at all (dry-run mode).
"""
import os


def _b(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


def _i(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


class Config:
    # --- where the appliance lives -------------------------------------
    # In the recommended deployment this is a WireGuard peer address
    # (e.g. 10.77.0.2), NOT a public IP. See ops/README.
    TARGET_HOST = os.getenv("TARGET_HOST", "127.0.0.1")

    SYSLOG_PORT = _i("SYSLOG_PORT", 514)
    SYSLOG_PROTO = os.getenv("SYSLOG_PROTO", "udp").lower()   # udp | tcp
    SYSLOG_FORMAT = os.getenv("SYSLOG_FORMAT", "rfc3164")     # rfc3164 | rfc5424

    SNMP_TRAP_PORT = _i("SNMP_TRAP_PORT", 162)
    SNMP_COMMUNITY = os.getenv("SNMP_COMMUNITY", "public")

    NETFLOW_PORT = _i("NETFLOW_PORT", 2055)

    # --- behaviour ------------------------------------------------------
    # Multiplier on baseline event volume. 1.0 ~= a quiet 60-person office.
    INTENSITY = float(os.getenv("INTENSITY", "1.0"))

    # Business-hours curve is computed in this timezone.
    TIMEZONE = os.getenv("TIMEZONE", "Pacific/Honolulu")

    # Dry run prints to stdout instead of sending on the wire. Handy for
    # verifying the stack before you point it at a real appliance.
    DRY_RUN = _b("DRY_RUN", "false")

    # Start emitting baseline traffic as soon as the container boots.
    AUTOSTART = _b("AUTOSTART", "true")

    # --- control plane --------------------------------------------------
    API_PORT = _i("API_PORT", 8080)
    # Shared secret required by the control API and demo panel.
    # There is no default on purpose - the container refuses to start without it.
    API_TOKEN = os.getenv("API_TOKEN", "")

    # --- Kahu ingest (webhook) ----------------------------------------
    KAHU_HOST = os.getenv("KAHU_HOST", "kahu-core:8000")
    KAHU_INGEST_URL = os.getenv("KAHU_INGEST_URL", "")
    # Shared secret sent as X-Ingest-Token so Kahu's token-authenticated
    # ingest route accepts the webhook. Must match core's INGEST_TOKEN.
    KAHU_INGEST_TOKEN = os.getenv("KAHU_INGEST_TOKEN", "")

    # --- synthetic org identity -----------------------------------------
    ORG_NAME = os.getenv("ORG_NAME", "Kai Pacific Engineering")
    ORG_DOMAIN = os.getenv("ORG_DOMAIN", "kaipacific.example")
    SITE_PREFIX = os.getenv("SITE_PREFIX", "hnl")


cfg = Config()
