"""
Stream Processor - Core event processing logic.
Consumes honeypot events from Redis streams and drives AI pipeline.
"""

import asyncio
import logging
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.config import settings
from src.redis_client import RedisClient
from src.ai_clients import AIClients
from src.session_state import SessionStateManager

logger = logging.getLogger(__name__)


class EventProcessor:
    """
    Main event processor that consumes honeypot events and drives AI pipeline.
    """

    def __init__(
        self,
        redis_client: RedisClient,
        ai_clients: AIClients,
        session_manager: SessionStateManager,
    ):
        self.redis_client = redis_client
        self.ai_clients = ai_clients
        self.session_manager = session_manager
        self._processed_event_ids: set = set()
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start the event processing loop."""
        if self._running:
            logger.warning("Stream processor already running")
            return
        self._running = True
        logger.info("Starting Stream Processor event loop")

        # Streams to consume
        streams = [
            (settings.honeypot_sessions_stream, "sessions"),
            (settings.honeypot_commands_stream, "commands"),
            (settings.honeypot_auth_stream, "auth"),
            (settings.honeypot_files_stream, "files"),
        ]

        while self._running:
            try:
                await self._process_streams()
                await asyncio.sleep(1)  # Small delay between polling cycles

            except asyncio.CancelledError:
                logger.info("Stream processor cancelled")
                break
            except Exception as e:
                logger.error(f"Error in processing loop: {e}", exc_info=True)
                await asyncio.sleep(5)  # Back off on error

    async def _process_streams(self) -> None:
        """Process streams sequentially."""
        streams = [
            (settings.honeypot_sessions_stream, "sessions"),
            (settings.honeypot_commands_stream, "commands"),
            (settings.honeypot_auth_stream, "auth"),
            (settings.honeypot_files_stream, "files"),
        ]

        for stream, stream_type in streams:
            try:
                await self._process_stream(stream, stream_type)
            except Exception as e:
                logger.error(f"Error processing stream {stream}: {e}", exc_info=True)

        # Small delay to prevent tight loop
        await asyncio.sleep(0.5)

    async def _process_stream(self, stream: str, stream_type: str) -> None:
        """Process a single stream."""
        messages = await self.redis_client.read_batch(stream, count=settings.batch_size)

        if not messages:
            return

        logger.info(f"Read {len(messages)} messages from {stream}")

        processed_count = 0

        for msg_id, event_data in messages:
            # Skip if already processed (dedup)
            if msg_id in self._processed_event_ids:
                logger.debug(f"Skipping duplicate event: {msg_id}")
                await self.redis_client.ack(stream, [msg_id])
                continue

            try:
                await self._process_event(stream, stream_type, msg_id, event_data)
                processed_count += 1

            except Exception as e:
                logger.error(f"Error processing event {msg_id} from {stream}: {e}", exc_info=True)
            finally:
                # Track processed events (bounded cache)
                self._processed_event_ids.add(msg_id)
                if len(self._processed_event_ids) > 10000:
                    # Keep only recent 5000
                    self._processed_event_ids = set(list(self._processed_event_ids)[-5000:])

        # ACK all processed messages
        if processed_count > 0:
            all_msg_ids = [msg_id for msg_id, _ in messages]
            await self.redis_client.ack(stream, all_msg_ids)

    async def _process_event(self, stream: str, stream_type: str, msg_id: str, event_data: Dict[str, Any]) -> None:
        """Process a single event based on its stream type."""
        event_type = event_data.get("event_type", "")
        payload = event_data.get("payload", {})

        # Redis stream fields are strings; decode JSON payloads.
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON payload for event {msg_id}: {payload[:500]}")
                return

        if not isinstance(payload, dict):
            logger.error(f"Invalid payload type for event {msg_id}: {type(payload).__name__}")
            return

        session_id = payload.get("session_id")

        if not session_id:
            logger.warning(f"Event missing session_id: {msg_id}")
            return

        # Track processed event IDs to avoid reprocessing
        if msg_id in self._processed_event_ids:
            return

        try:
            if stream == "honeypot:sessions":
                await self._handle_session_event(event_data, payload)

            elif stream == "honeypot:commands":
                await self._handle_command_event(event_data, payload)

            elif stream == "honeypot:auth":
                await self._handle_auth_event(event_data, payload)

            elif stream == "honeypot:files":
                await self._handle_file_event(event_data, payload)

        except Exception as e:
            logger.error(f"Error processing {stream_type} event {msg_id}: {e}", exc_info=True)

    async def _handle_session_event(self, event_data: Dict[str, Any], payload: Dict[str, Any]) -> None:
        """Process session start/end events."""
        event_type = event_data.get("event_type", "")

        # Handle both with and without underscore (Cowrie uses sessionstart/sessionend)
        if event_type in ("session_start", "sessionstart"):
            # Initialize session state
            session = self.session_manager.process_session_start(event_data)
            logger.info(f"Session initialized: {payload.get('session_id')}")

        elif event_type in ("session_end", "sessionend"):
            # Finalize session and trigger AI processing
            session = self.session_manager.process_session_end(event_data)
            if not session:
                return

            session_id = session.get("session_id")
            logger.info(f"Session ended: {session_id}")

            # Trigger AI processing for completed session
            await self._process_session_ai(session)

        else:
            logger.debug(f"Unknown session event type: {event_type}")

    async def _handle_command_event(self, event_data: Dict[str, Any], payload: Dict[str, Any]) -> None:
        """Process command event - accumulate in session context and trigger AI if needed."""
        session_id = payload.get("session_id")
        command = payload.get("command", "")

        if not session_id:
            logger.warning(f"Command event missing session_id: {payload}")
            return

        logger.info(f"Command received: session_id={session_id}, command={command[:80]}")

        session = self.session_manager.add_command({"payload": payload})

        # Check if we should trigger AI processing
        # Process when session has ended, or enough commands accumulate, or trigger command seen
        if session:
            trigger_commands = {"aws", "az", "gcloud", "kubectl", "ssh", "scp", "curl", "wget", "nc", "nmap"}
            cmd_lower = payload.get("command", "").lower()
            is_trigger = any(trigger in cmd_lower for trigger in trigger_commands)

            if session.get("end_time") or is_trigger or len(session.get("commands", [])) >= 5:
                logger.info(f"Triggering AI processing for session {session_id} (commands: {len(session.get('commands', []))})")
                await self._process_session_ai(session)

    async def _handle_auth_event(self, event_data: Dict[str, Any], payload: Dict[str, Any]) -> None:
        """Process authentication event."""
        session_id = payload.get("session_id")
        if not session_id:
            logger.warning(f"Auth event missing session_id: {payload}")
            return

        logger.info(f"Auth event: session={session_id}, user={payload.get('username')}, success={payload.get('success')}")
        self.session_manager.add_auth(event_data)

    async def _handle_file_event(self, event_data: Dict[str, Any], payload: Dict[str, Any]) -> None:
        """Process file transfer event."""
        self.session_manager.add_file_transfer({"payload": payload})
        logger.debug(f"File transfer recorded: {payload.get('filename')}")

    async def _process_session_ai(self, session: Dict[str, Any]) -> None:
        """
        Process session through AI engines.
        Called when session ends or enough commands accumulate.
        """
        if not session:
            return

        session_id = session.get("session_id")
        if not session_id:
            return

        # Check if AI already processed for this session
        ai_processed_key = f"ai_processed:{session_id}"
        curr_cmd_count = len(session.get("commands", []))
        prev_cmd_count = getattr(self, "_session_processed_cmd_counts", {}).get(session_id, -1)

        if ai_processed_key in self._processed_event_ids and curr_cmd_count <= prev_cmd_count:
            logger.debug(f"AI already processed for session {session_id} with {prev_cmd_count} commands")
            return

        self._processed_event_ids.add(ai_processed_key)
        if not hasattr(self, "_session_processed_cmd_counts"):
            self._session_processed_cmd_counts = {}
        self._session_processed_cmd_counts[session_id] = curr_cmd_count

        logger.info(f"Processing session {session_id} through AI pipeline")

        try:
            # ============================================================
            # 1. Intent Classification
            # ============================================================
            commands_list = [{"cmd": c.get("command"), "arguments": c.get("arguments", [])}
                           for c in session.get("commands", [])]

            context = {
                "attacker_ip": session.get("attacker_ip"),
                "country": session.get("country"),
                "asn": session.get("asn"),
                "protocol": session.get("protocol", "ssh"),
                "session_duration": self._calculate_duration(session.get("start_time"), session.get("end_time")),
                "previous_intents": session.get("intent_history", []),
            }

            intent_result = None
            try:
                intent_result = await self.ai_clients.classify_intent(
                    session_id=session.get("session_id"),
                    commands=commands_list,
                    context=context,
                )
            except Exception as ai_err:
                logger.warning(f"AI intent classification failed for {session_id}: {ai_err}")

            if intent_result:
                # Store intent prediction
                intent_event = {
                    "event_type": "intent_prediction",
                    "payload": {
                        "session_id": session_id,
                        "intent": intent_result.get("intent"),
                        "confidence": intent_result.get("confidence"),
                        "skill_level": intent_result.get("skill_level"),
                        "reasoning": intent_result.get("reasoning"),
                        "secondary_intents": intent_result.get("secondary_intents", []),
                        "adaptation_hint": intent_result.get("adaptation_hint", ""),
                        "processing_time_ms": intent_result.get("processing_time_ms", 0),
                        "fallback_used": intent_result.get("fallback_used", False),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                }
                await self._publish_intent_prediction(session_id, intent_event)

            # Persist metrics and AI classification to ClickHouse through the collector.
            try:
                update_payload = {
                    "session_id": session_id,
                    "commands_executed": len(session.get("commands", [])),
                    "credentials_tried": len(session.get("auth_attempts", [])),
                    "duration_seconds": self._calculate_duration(
                        session.get("start_time"),
                        session.get("end_time"),
                    ),
                }
                if intent_result:
                    update_payload["intent"] = intent_result.get("intent", "unknown")
                    update_payload["skill_level"] = intent_result.get("skill_level", 1)

                await self.ai_clients.client.post(
                    f"{settings.event_collector_url}/update-session",
                    json=update_payload,
                )
                logger.info(f"Persisted update for session {session_id}: cmds={update_payload['commands_executed']}, auth={update_payload['credentials_tried']}")
            except Exception as persist_error:
                logger.error(f"Failed to persist update for session {session_id}: {persist_error}")

            if intent_result:

                # ============================================================
                # Call Threat Intel
                # ============================================================
                threat_result = await self.ai_clients.analyze_threat(
                    session_id=session_id,
                    commands=session.get("commands", []),
                    outputs=[c.get("output", "") for c in session.get("commands", []) if c.get("output")],
                    intent_history=session.get("intent_history", []),
                    attacker_ip=session.get("attacker_ip", "unknown"),
                    attacker_country=session.get("country", "unknown"),
                    duration_seconds=self._calculate_duration(session.get("start_time"), session.get("end_time")),
                )

                if threat_result:
                    threat_event = {
                        "event_type": "threat_intelligence",
                        "payload": {
                            "session_id": session_id,
                            "iocs": threat_result.get("iocs", []),
                            "techniques": threat_result.get("techniques", []),
                            "tactic_summary": threat_result.get("tactic_summary", {}),
                            "summary": threat_result.get("summary"),
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                    }
                    await self._publish_threat_intel(session_id, threat_event)
                    logger.info(f"Threat analysis completed for session {session_id}")

                # ============================================================
                # Call Adaptive Engine
                # ============================================================
                intent = intent_result.get("intent", "unknown")
                adapt_result = await self.ai_clients.adapt_response(
                    intent=intent,
                    original_response={},
                    session_context={
                        "session_id": session_id,
                        "commands": session.get("commands", []),
                        "intent_history": session.get("intent_history", []),
                    },
                    endpoint="",
                    cloud_provider="aws",
                    org_profile="tech-startup-aws",
                )

                if adapt_result:
                    adapt_event = {
                        "event_type": "adaptation_applied",
                        "payload": {
                            "session_id": session_id,
                            "intent": intent,
                            "adaptation_applied": adapt_result.get("adaptation_applied", False),
                            "strategy": adapt_result.get("strategy", ""),
                            "adapted_response": adapt_result.get("adapted_response"),
                            "message": adapt_result.get("message", ""),
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                    }
                    await self._publish_adaptation(session_id, adapt_event)
                    logger.info(f"Adaptation applied for session {session_id}: {adapt_result.get('strategy')}")

        except Exception as e:
            logger.error(f"Error in AI pipeline for session {session_id}: {e}", exc_info=True)

    def _calculate_duration(self, start: Optional[str], end: Optional[str]) -> int:
        """Calculate duration in seconds."""
        if not start:
            return 0
        try:
            def _to_naive_utc(dt_val: datetime) -> datetime:
                if dt_val.tzinfo is not None:
                    return dt_val.astimezone(timezone.utc).replace(tzinfo=None)
                return dt_val

            start_dt = _to_naive_utc(datetime.fromisoformat(start.replace("Z", "+00:00")))
            if end:
                end_dt = _to_naive_utc(datetime.fromisoformat(end.replace("Z", "+00:00")))
                return max(0, int(round((end_dt - start_dt).total_seconds())))
            else:
                now = _to_naive_utc(datetime.now(timezone.utc))
                return max(0, int((now - start_dt).total_seconds()))
        except Exception:
            return 0

    async def _publish_intent_prediction(self, session_id: str, event: Dict[str, Any]) -> None:
        """Publish intent prediction to Redis stream."""
        if not self.redis_client:
            return

        event["payload"]["session_id"] = session_id
        msg_id = await self.redis_client.publish("intent:predictions", event)
        if msg_id:
            logger.info(f"Published intent prediction for session {session_id} (msg_id: {msg_id})")

    async def _publish_threat_intel(self, session_id: str, event: Dict[str, Any]) -> None:
        """Publish threat intelligence to Redis stream."""
        if not self.redis_client:
            return

        event["payload"]["session_id"] = session_id
        msg_id = await self.redis_client.publish("threat:intelligence", event)
        if msg_id:
            logger.info(f"Published threat intel for session {session_id} (msg_id: {msg_id})")

    async def _publish_adaptation(self, session_id: str, event: Dict[str, Any]) -> None:
        """Publish adaptation to Redis stream."""
        if not self.redis_client:
            return

        event["payload"]["session_id"] = session_id
        msg_id = await self.redis_client.publish("adaptive:actions", event)
        if msg_id:
            logger.info(f"Published adaptation for session {session_id} (msg_id: {msg_id})")

    async def stop(self) -> None:
        """Stop the event processing loop gracefully."""
        logger.info("Stopping Stream Processor...")
        self._running = False
        # Give the loop a moment to exit gracefully
        await asyncio.sleep(0.1)