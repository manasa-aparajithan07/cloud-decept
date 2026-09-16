"""
Redis client wrapper for Stream Processor.
Provides high-level stream operations with consumer group support.
"""

import json
import logging
import socket
import uuid
from typing import Any, Dict, List, Optional, Tuple

import redis.asyncio as redis

from src.config import settings

logger = logging.getLogger(__name__)


class RedisClient:
    """Async Redis client with stream consumer group support."""

    def __init__(self):
        self.redis: Optional[redis.Redis] = None
        self.consumer_name = settings.consumer_name or f"stream-processor-{socket.gethostname()}-{uuid.uuid4().hex[:8]}"

    async def connect(self) -> None:
        """Initialize Redis connection."""
        self.redis = redis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            max_connections=20,
        )
        await self.redis.ping()
        logger.info(f"Redis connected: {settings.redis_url}")
        logger.info(f"Consumer name: {self.consumer_name}")

        # Ensure consumer group exists for all honeypot streams
        await self._ensure_consumer_groups()

    async def close(self) -> None:
        """Close Redis connection."""
        if self.redis:
            await self.redis.close()

    async def _ensure_consumer_groups(self) -> None:
        """Create consumer groups for honeypot streams."""
        if not self.redis:
            return

        streams = [
            "honeypot:sessions",
            "honeypot:commands",
            "honeypot:auth",
            "honeypot:files",
        ]

        for stream in streams:
            try:
                await self.redis.xgroup_create(
                    stream, settings.consumer_group, id=settings.from_id, mkstream=True
                )
                logger.info(f"Created consumer group '{settings.consumer_group}' for stream '{stream}'")
            except Exception as e:
                if "BUSYGROUP" in str(e):
                    logger.debug(f"Consumer group already exists for stream '{stream}'")
                else:
                    logger.warning(f"Could not create consumer group for {stream}: {e}")

    async def read_batch(
        self, stream: str, count: int = None, block_ms: int = 5000
    ) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Read a batch of new messages from a stream using consumer group.
        Returns list of (message_id, event_data) tuples.
        """
        if not self.redis:
            raise RuntimeError("Redis not connected")

        count = count or settings.batch_size

        try:
            results = await self.redis.xreadgroup(
                settings.consumer_group,
                self.consumer_name,
                {stream: ">"},
                count=count,
                block=block_ms,
            )

            messages = []
            for stream_name, messages_list in results:
                for msg_id, msg_data in messages_list:
                    # Parse the event data from the 'data' field
                    try:
                        event_data = json.loads(msg_data.get("data", "{}"))
                        messages.append((msg_id, event_data))
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse message {msg_id}: {e}")
                        # Still include the message for ACK but with empty data
                        messages.append((msg_id, {}))

            return messages

        except Exception as e:
            logger.error(f"Error reading from {stream}: {e}")
            return []

    async def ack(self, stream: str, message_ids: List[str]) -> int:
        """Acknowledge processed messages."""
        if not self.redis or not message_ids:
            return 0

        try:
            count = await self.redis.xack(settings.consumer_group, stream, *message_ids)
            logger.debug(f"ACKed {count} messages from {stream}")
            return count
        except Exception as e:
            logger.error(f"Failed to ACK messages from {stream}: {e}")
            return 0

    async def publish(self, stream: str, event_data: Dict[str, Any]) -> Optional[str]:
        """
        Publish event to output stream.
        Returns message ID or None on failure.
        """
        if not self.redis:
            raise RuntimeError("Redis not connected")

        try:
            envelope = {
                "data": json.dumps(event_data, default=str),
            }
            msg_id = await self.redis.xadd(stream, envelope)
            return msg_id
        except Exception as e:
            logger.error(f"Failed to publish to {stream}: {e}")
            return None

    async def get_stream_length(self, stream: str) -> int:
        """Get stream length."""
        if not self.redis:
            return 0
        try:
            return await self.redis.xlen(stream)
        except Exception:
            return 0

    async def get_consumer_group_info(self, stream: str) -> list:
        """Get consumer group info for a stream."""
        if not self.redis:
            return []
        try:
            return await self.redis.xinfo_groups(stream)
        except Exception:
            return []