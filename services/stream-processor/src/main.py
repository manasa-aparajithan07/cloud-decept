"""
Stream Processor - Main entry point.
Consumes honeypot events from Redis streams and drives AI pipeline.
"""

import logging
import os
import socket
import sys
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

from src.config import settings
from src.redis_client import RedisClient
from src.ai_clients import AIClients
from src.session_state import SessionStateManager
from src.processor import EventProcessor

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO")),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("stream-processor")


# Global instances
redis_client: RedisClient = None
ai_clients: AIClients = None
session_manager: SessionStateManager = None
processor: "EventProcessor" = None


class HealthResponse(BaseModel):
    status: str
    redis: str
    intent_engine: str
    adaptive_engine: str
    threat_intel: str


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global redis_client, ai_clients, session_manager, processor

    logger.info("Starting Stream Processor...")

    # Initialize Redis
    redis_client = RedisClient()
    await redis_client.connect()

    # Initialize AI clients
    ai_clients = AIClients()

    # Initialize session manager
    session_manager = SessionStateManager(
        debounce_seconds=30,
        max_batch_commands=50,
    )

    # Initialize processor
    processor = EventProcessor(
        redis_client=redis_client,
        ai_clients=ai_clients,
        session_manager=session_manager,
    )

    # Start processor background task
    import asyncio
    processor_task = asyncio.create_task(processor.start())

    logger.info("Stream Processor started successfully")

    yield

    # Shutdown
    logger.info("Shutting down Stream Processor...")
    if processor:
        await processor.stop()
    if ai_clients:
        await ai_clients.close()
    if redis_client:
        await redis_client.close()
    logger.info("Stream Processor stopped")


app = FastAPI(
    title="CloudDecept Stream Processor",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> dict:
    """Health check endpoint."""
    checks = {}

    # Check Redis
    try:
        if redis_client and redis_client.redis:
            await redis_client.redis.ping()
            checks["redis"] = "healthy"
        else:
            checks["redis"] = "disconnected"
    except Exception:
        checks["redis"] = "unhealthy"

    # Check AI services
    if ai_clients:
        ai_health = await ai_clients.health_check()
        checks["intent_engine"] = "configured" if ai_health.get("intent_engine") else "unavailable"
        checks["adaptive_engine"] = "configured" if ai_health.get("adaptive_engine") else "unavailable"
        checks["threat_intel"] = "configured" if ai_health.get("threat_intel") else "unavailable"
    else:
        checks["intent_engine"] = "unconfigured"
        checks["adaptive_engine"] = "unconfigured"
        checks["threat_intel"] = "unconfigured"

    overall = "healthy" if all(v in ("healthy", "configured") for v in checks.values()) else "degraded"

    return {
        "status": overall,
        **checks,
        "consumer_group": "ai_processor",
        "consumer_name": f"stream-processor-{socket.gethostname()}",
    }


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8006"))
    uvicorn.run("src.main:app", host="0.0.0.0", port=port, reload=False)