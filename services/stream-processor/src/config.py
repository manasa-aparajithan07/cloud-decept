"""
Configuration for Stream Processor
Loads settings from environment variables with sensible defaults.
"""

from pydantic_settings import BaseSettings
from typing import List, Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Redis
    redis_url: str = "redis://redis:6379"
    consumer_group: str = "ai_processor"
    consumer_name: Optional[str] = None  # Auto-generated if not set
    batch_size: int = 10
    timeout_seconds: int = 10

    # Processing control
    enabled: bool = True
    from_id: str = "$"  # Start from new events only ($ = new events, 0 = from beginning)

    # AI Service URLs
    intent_engine_url: str = "http://intent-engine:8001"
    adaptive_engine_url: str = "http://adaptive-engine:8002"
    threat_intel_url: str = "http://threat-intel:8005"
    event_collector_url: str = "http://event-collector:8000"

    # HTTP Client
    http_timeout_seconds: int = 3
    max_retries: int = 0
    retry_backoff_seconds: float = 1.0

    # Session aggregation
    session_debounce_seconds: int = 30
    max_batch_commands: int = 50

    # Retry settings
    max_retries: int = 0
    retry_backoff_seconds: float = 1.0

    # Stream names
    honeypot_sessions_stream: str = "honeypot:sessions"
    honeypot_commands_stream: str = "honeypot:commands"
    honeypot_auth_stream: str = "honeypot:auth"
    honeypot_files_stream: str = "honeypot:files"

    intent_predictions_stream: str = "intent:predictions"
    adaptive_actions_stream: str = "adaptive:actions"
    threat_intelligence_stream: str = "threat:intelligence"
    llm_requests_stream: str = "llm:requests"
    llm_responses_stream: str = "llm:responses"

    # Aliases for processor compatibility
    INTENT_PREDICTIONS_STREAM: str = "intent:predictions"
    ADAPTIVE_ACTIONS_STREAM: str = "adaptive:actions"
    THREAT_INTELLIGENCE_STREAM: str = "threat:intelligence"
    HONEYPOT_SESSIONS_STREAM: str = "honeypot:sessions"
    HONEYPOT_COMMANDS_STREAM: str = "honeypot:commands"
    HONEYPOT_AUTH_STREAM: str = "honeypot:auth"
    HONEYPOT_FILES_STREAM: str = "honeypot:files"

    consumer_group: str = "ai_processor"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


settings = Settings()