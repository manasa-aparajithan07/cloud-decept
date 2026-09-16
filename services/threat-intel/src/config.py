import os
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Threat Intelligence Engine settings"""

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8005
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # Databases
    CLICKHOUSE_HOST: str = "clickhouse"
    CLICKHOUSE_PORT: int = 9000
    CLICKHOUSE_DB: str = "clouddecept"
    CLICKHOUSE_USER: str = "default"
    CLICKHOUSE_PASSWORD: str = "changeme"

    POSTGRES_HOST: str = "postgres"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "clouddecept"
    POSTGRES_USER: str = "clouddecept"
    POSTGRES_PASSWORD: str = "changeme"

    # Event Collector
    EVENT_COLLECTOR_URL: str = "http://event-collector:8000"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore"
    }


settings = Settings()