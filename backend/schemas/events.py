"""
CloudDecept Shared Event Schema
Standard event definitions for all microservices communication via Redis Streams.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field, ConfigDict


class EventSource(str, Enum):
    """Source of the event"""
    COWRIE_SSH = "cowrie_ssh"
    COWRIE_TELNET = "cowrie_telnet"
    CLOUD_API_MOCK = "cloud_api_mock"
    EVENT_COLLECTOR = "event_collector"
    INTENT_ENGINE = "intent_engine"
    ADAPTIVE_ENGINE = "adaptive_engine"
    THREAT_INTEL = "threat_intel"
    LLM_GATEWAY = "llm_gateway"
    DASHBOARD = "dashboard"
    BACKEND_API = "backend_api"


class HoneypotType(str, Enum):
    """Type of honeypot generating the event"""
    SSH = "ssh"
    TELNET = "telnet"
    CLOUD_API = "cloud_api"


class Protocol(str, Enum):
    """Network protocol"""
    SSH = "ssh"
    TELNET = "telnet"
    HTTP = "http"
    HTTPS = "https"
    GRPC = "grpc"


class Severity(str, Enum):
    """Event severity level"""
    DEBUG = "debug"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IntentCategory(str, Enum):
    """Attacker intent categories"""
    CLOUD_RECON = "cloud_recon"
    CREDENTIAL_HUNTING = "credential_hunting"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_ACCESS = "data_access"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"
    UNKNOWN = "unknown"


class BaseEvent(BaseModel):
    """Base event model - all events inherit from this"""
    model_config = ConfigDict(
        extra="allow",
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
    )

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: EventSource
    honeypot_type: Optional[HoneypotType] = None
    session_id: str
    attacker_ip: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuthEvent(BaseEvent):
    """Authentication attempt event"""
    source: EventSource = EventSource.COWRIE_SSH
    honeypot_type: HoneypotType = HoneypotType.SSH

    username: str
    password: str
    protocol: Protocol = Protocol.SSH
    success: bool
    auth_method: str = "password"  # password, publickey, keyboard-interactive


class CommandEvent(BaseEvent):
    """Command execution event"""
    source: EventSource = EventSource.COWRIE_SSH
    honeypot_type: HoneypotType = HoneypotType.SSH

    command: str
    arguments: list[str] = Field(default_factory=list)
    working_directory: str = "/home/ubuntu"
    output: Optional[str] = None
    exit_code: Optional[int] = None
    duration_ms: Optional[int] = None


class CloudAPIEvent(BaseEvent):
    """Cloud API request/response event"""
    source: EventSource = EventSource.CLOUD_API_MOCK
    honeypot_type: HoneypotType = HoneypotType.CLOUD_API

    http_method: str
    endpoint: str
    path: str
    query_params: dict[str, str] = Field(default_factory=dict)
    request_body: Optional[dict[str, Any]] = None
    request_headers: dict[str, str] = Field(default_factory=dict)
    response_status: Optional[int] = None
    response_body: Optional[dict[str, Any]] = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    duration_ms: Optional[int] = None
    cloud_provider: str  # aws, azure, gcp
    api_version: Optional[str] = None


class FileTransferEvent(BaseEvent):
    """File upload/download event"""
    source: EventSource = EventSource.COWRIE_SSH
    honeypot_type: HoneypotType = HoneypotType.SSH

    filename: str
    size_bytes: int
    direction: str  # upload, download
    protocol: Protocol = Protocol.SSH
    remote_path: Optional[str] = None
    local_path: Optional[str] = None
    sha256: Optional[str] = None
    md5: Optional[str] = None


class NetworkConnectionEvent(BaseEvent):
    """Outbound network connection attempt"""
    source: EventSource = EventSource.COWRIE_SSH
    honeypot_type: HoneypotType = HoneypotType.SSH

    destination_ip: str
    destination_port: int
    protocol: Protocol = Protocol.SSH
    connection_type: str  # tcp, udp, ssh, http
    success: bool


class SessionStartEvent(BaseEvent):
    """New session started"""
    source: EventSource = EventSource.COWRIE_SSH
    honeypot_type: HoneypotType = HoneypotType.SSH

    protocol: Protocol = Protocol.SSH
    client_version: Optional[str] = None
    client_ip: str
    country: Optional[str] = None
    asn: Optional[str] = None
    org: Optional[str] = None


class SessionEndEvent(BaseEvent):
    """Session ended"""
    source: EventSource = EventSource.COWRIE_SSH
    honeypot_type: HoneypotType = HoneypotType.SSH

    duration_seconds: int
    commands_executed: int = 0
    files_transferred: int = 0
    credentials_tried: int = 0
    disconnection_reason: Optional[str] = None


class IntentPredictionEvent(BaseEvent):
    """Intent prediction from LLM"""
    source: EventSource = EventSource.INTENT_ENGINE

    intent: IntentCategory
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    skill_level: int = Field(ge=1, le=10)
    suggested_adaptation: Optional[str] = None
    prediction_latency_ms: int
    model_used: str
    commands_context: list[str] = Field(default_factory=list)


class AdaptationAppliedEvent(BaseEvent):
    """Adaptive response applied"""
    source: EventSource = EventSource.ADAPTIVE_ENGINE

    adaptation_type: str
    strategy: str
    original_response: Optional[str] = None
    adapted_response: Optional[str] = None
    trigger_intent: IntentCategory
    success: bool
    details: dict[str, Any] = Field(default_factory=dict)


class ThreatIntelligenceEvent(BaseEvent):
    """Threat intelligence finding"""
    source: EventSource = EventSource.THREAT_INTEL

    ioc_type: str  # ip, domain, hash, key, credential
    ioc_value: str
    confidence: float = Field(ge=0.0, le=1.0)
    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    severity: Severity
    context: str
    enrichment: dict[str, Any] = Field(default_factory=dict)


class LLMRequestEvent(BaseEvent):
    """LLM inference request"""
    source: EventSource = EventSource.LLM_GATEWAY

    prompt: str
    system_prompt: Optional[str] = None
    model: str
    temperature: float = 0.0
    max_tokens: int = 512
    request_type: str  # intent_classification, summarization, ioc_extraction


class LLMResponseEvent(BaseEvent):
    """LLM inference response"""
    source: EventSource = EventSource.LLM_GATEWAY

    request_id: str
    response: str
    model: str
    latency_ms: int
    tokens_used: dict[str, int] = Field(default_factory=dict)
    success: bool
    error: Optional[str] = None


class HealthCheckEvent(BaseEvent):
    """Service health check event"""
    source: EventSource = EventSource.DASHBOARD

    service_name: str
    status: str  # healthy, degraded, unhealthy
    latency_ms: Optional[int] = None
    details: dict[str, Any] = Field(default_factory=dict)


class MetricsEvent(BaseEvent):
    """System/service metrics"""
    source: EventSource = EventSource.DASHBOARD

    metric_name: str
    metric_value: float
    metric_unit: str
    tags: dict[str, str] = Field(default_factory=dict)


# Event type discriminator for deserialization
EVENT_TYPES = {
    "auth": AuthEvent,
    "command": CommandEvent,
    "cloud_api": CloudAPIEvent,
    "file_transfer": FileTransferEvent,
    "network_connection": NetworkConnectionEvent,
    "session_start": SessionStartEvent,
    "session_end": SessionEndEvent,
    "intent_prediction": IntentPredictionEvent,
    "adaptation_applied": AdaptationAppliedEvent,
    "threat_intelligence": ThreatIntelligenceEvent,
    "llm_request": LLMRequestEvent,
    "llm_response": LLMResponseEvent,
    "health_check": HealthCheckEvent,
    "metrics": MetricsEvent,
}


class EventEnvelope(BaseModel):
    """Wrapper for Redis Stream events with type info"""
    model_config = ConfigDict(use_enum_values=True)

    event_type: str
    payload: dict[str, Any]  # Use dict to preserve all payload fields including concrete type fields
    stream_name: str
    partition_key: Optional[str] = None
    version: str = "1.0"


# Redis Stream names
class StreamNames:
    """Redis Stream channel names"""
    HONEYPOT_EVENTS = "honeypot:events"
    AUTH_EVENTS = "honeypot:auth"
    COMMAND_EVENTS = "honeypot:commands"
    CLOUD_API_EVENTS = "honeypot:cloud_api"
    FILE_EVENTS = "honeypot:files"
    NETWORK_EVENTS = "honeypot:network"
    SESSION_EVENTS = "honeypot:sessions"
    INTENT_PREDICTIONS = "intent:predictions"
    ADAPTATIONS = "adaptive:actions"
    THREAT_INTEL = "threat:intelligence"
    LLM_REQUESTS = "llm:requests"
    LLM_RESPONSES = "llm:responses"
    HEALTH_CHECKS = "system:health"
    METRICS = "system:metrics"
    DEAD_LETTER = "system:dead_letter"


# Consumer group names
class ConsumerGroups:
    """Redis Stream consumer group names"""
    EVENT_COLLECTOR = "event_collector"
    INTENT_ENGINE = "intent_engine"
    ADAPTIVE_ENGINE = "adaptive_engine"
    THREAT_INTEL = "threat_intel"
    DASHBOARD = "dashboard"
    BACKEND_API = "backend_api"


# Alias for backward compatibility
EventTypes = EVENT_TYPES