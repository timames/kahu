from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_config_dir() -> Path:
    """Locate the JSON config directory (weights_schema.json, tuning_config.json, …).

    From a source checkout this file is ``<repo>/src/kahu/config.py``, so the
    sibling of ``src/`` is the repo root. From an installed wheel that walk lands
    somewhere in ``site-packages`` and there is no ``config/`` there — fall back to
    a path relative to the working directory, which is ``/app`` in the container
    (the Dockerfile copies ``config/`` to ``/app/config`` and sets
    ``KAHU_CONFIG_DIR`` explicitly).
    """
    checkout = Path(__file__).resolve().parents[2] / "config"
    if checkout.is_dir():
        return checkout
    return Path("config")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # JSON config directory. Same env var name kahu_tuner already uses, so a
    # deployment configures both services with one setting.
    kahu_config_dir: Path = Field(default_factory=_default_config_dir)

    # Database
    database_url: str = "postgresql+asyncpg://kahu:changeme@localhost:5432/kahu"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Ollama
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "mistral:7b-instruct-v0.3-q4_K_M"

    # Wazuh
    wazuh_api_url: str = "https://localhost:55000"
    wazuh_api_user: str = "wazuh-wui"
    wazuh_api_password: str = "changeme"  # noqa: S105
    wazuh_indexer_url: str = "https://localhost:9200"
    wazuh_indexer_user: str = "admin"
    wazuh_indexer_password: str = "changeme"  # noqa: S105

    # Greenbone (Vulnerability Scanner)
    greenbone_url: str = "http://localhost:9392"
    greenbone_user: str = "admin"
    greenbone_password: str = "admin"  # noqa: S105

    # Core
    log_level: str = "INFO"
    appliance_id: str = ""
    secret_key: str = "changeme-generate-a-real-key"  # noqa: S105
    debug: bool = False

    # Agent deployment — the external IP/hostname agents should connect to
    appliance_host: str = ""

    # Shared secret for machine-to-machine alert ingestion (the demo generator
    # and any external forwarder POSTing to /api/triage/ingest). Empty disables
    # the token-authenticated ingest route entirely.
    ingest_token: str = ""


settings = Settings()
