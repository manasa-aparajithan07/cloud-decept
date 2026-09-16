import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings"""

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8080
    DEBUG: bool = False

    # External services (new architecture)
    EVENT_COLLECTOR_URL: str = "http://event-collector:8000"
    ADAPTIVE_ENGINE_URL: str = "http://adaptive-engine:8002"

    # Legacy (for backward compatibility)
    INTENT_ENGINE_URL: str = "http://intent-engine:8001"

    CLICKHOUSE_HOST: str = "clickhouse"
    CLICKHOUSE_PORT: int = 9000
    CLICKHOUSE_DB: str = "clouddecept"
    CLICKHOUSE_USER: str = "default"
    CLICKHOUSE_PASSWORD: str = "changeme"

    # Deception profiles
    DEFAULT_ORG_PROFILE: str = "tech-startup-aws"
    CONSISTENCY_ENABLED: bool = True

    # LLM Adaptation
    ADAPTATION_ENABLED: bool = True

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore"
    }


settings = Settings()