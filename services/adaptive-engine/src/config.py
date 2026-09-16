import os
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    """Adaptive Engine settings"""

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8002
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # Intent Engine (for reference)
    INTENT_ENGINE_URL: str = "http://intent-engine:8001"

    # Event Collector
    EVENT_COLLECTOR_URL: str = "http://event-collector:8000"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore"
    }


settings = Settings()