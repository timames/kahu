from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Database
    database_url: str = "postgresql+asyncpg://kuahene:changeme@localhost:5432/kuahene"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Ollama
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "mistral:7b-instruct-v0.3-q4_K_M"

    # Wazuh
    wazuh_api_url: str = "https://localhost:55000"
    wazuh_api_user: str = "wazuh-wui"
    wazuh_api_password: str = "changeme"
    wazuh_indexer_url: str = "https://localhost:9200"
    wazuh_indexer_user: str = "admin"
    wazuh_indexer_password: str = "changeme"

    # Core
    log_level: str = "INFO"
    appliance_id: str = ""
    secret_key: str = "changeme-generate-a-real-key"
    debug: bool = False

    # Agent deployment — the external IP/hostname agents should connect to
    appliance_host: str = ""


settings = Settings()
