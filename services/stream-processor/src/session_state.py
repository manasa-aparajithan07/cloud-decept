"""
Session state management for Stream Processor.
Tracks session context across events for AI enrichment.
"""

import logging
from typing import Any, Dict, List, Optional
from collections import defaultdict
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class SessionStateManager:
    """
    Manages in-memory session state for aggregation and context enrichment.

    Tracks commands, auth events, file transfers, and other session context
    across multiple Redis events for the same session.
    """

    def __init__(self, debounce_seconds: int = 30, max_batch_commands: int = 50):
        self.sessions: Dict[str, Dict] = {}
        self.debounce_seconds = debounce_seconds
        self.max_batch_commands = max_batch_commands

    def _ensure_session(self, session_id: str, payload: Dict[str, Any], event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get or initialize a session entry, updating metadata if available."""
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                "session_id": session_id,
                "attacker_ip": payload.get("attacker_ip") or payload.get("client_ip") or event_data.get("attacker_ip") or "unknown",
                "country": payload.get("country") or event_data.get("country", ""),
                "asn": payload.get("asn") or event_data.get("asn", ""),
                "protocol": payload.get("protocol") or event_data.get("protocol", "ssh"),
                "client_version": payload.get("client_version") or event_data.get("client_version", ""),
                "start_time": payload.get("timestamp") or event_data.get("timestamp"),
                "commands": [],
                "outputs": [],
                "auth_attempts": [],
                "file_transfers": [],
                "intent_history": [],
                "intent": None,
                "skill_level": None,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        else:
            session = self.sessions[session_id]
            attacker_ip = payload.get("attacker_ip") or payload.get("client_ip") or event_data.get("attacker_ip")
            if attacker_ip and session.get("attacker_ip") in ("unknown", "", None):
                session["attacker_ip"] = attacker_ip
            if payload.get("country") and not session.get("country"):
                session["country"] = payload.get("country")
            if payload.get("asn") and not session.get("asn"):
                session["asn"] = payload.get("asn")
            if payload.get("protocol") and not session.get("protocol"):
                session["protocol"] = payload.get("protocol")
            if payload.get("client_version") and not session.get("client_version"):
                session["client_version"] = payload.get("client_version")
            if not session.get("start_time"):
                session["start_time"] = payload.get("timestamp") or event_data.get("timestamp")
        return self.sessions[session_id]

    def process_session_start(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a session_start event and initialize session state.
        Returns the session context.
        """
        payload = event_data.get("payload", event_data)
        if not isinstance(payload, dict):
            payload = event_data

        session_id = payload.get("session_id") or event_data.get("partition_key") or event_data.get("session_id")
        if not session_id:
            logger.warning("Session start event missing session_id")
            return {}

        session = self._ensure_session(session_id, payload, event_data)
        start_time = payload.get("timestamp") or event_data.get("timestamp")
        if start_time:
            session["start_time"] = start_time
        attacker_ip = payload.get("attacker_ip") or payload.get("client_ip")
        if attacker_ip:
            session["attacker_ip"] = attacker_ip
        if payload.get("country"):
            session["country"] = payload.get("country")
        if payload.get("asn"):
            session["asn"] = payload.get("asn")
        if payload.get("protocol"):
            session["protocol"] = payload.get("protocol")
        if payload.get("client_version"):
            session["client_version"] = payload.get("client_version")
        if session.get("end_time") and (not session.get("duration_seconds") or session.get("duration_seconds") <= 0):
            calc_dur = self._calculate_duration(session)
            if calc_dur > 0:
                session["duration_seconds"] = calc_dur
        session["updated_at"] = datetime.now(timezone.utc).isoformat()

        logger.info(f"Initialized/updated session state for {session_id}")
        return session

    def process_session_end(self, event_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Process a session_end event and finalize session.
        Returns the complete session context for Threat Intel analysis.
        """
        payload = event_data.get("payload", event_data)
        if not isinstance(payload, dict):
            payload = event_data

        session_id = payload.get("session_id") or event_data.get("partition_key") or event_data.get("session_id")
        if not session_id:
            logger.warning("Session end event missing session_id")
            return None

        session = self._ensure_session(session_id, payload, event_data)

        session["end_time"] = payload.get("timestamp") or event_data.get("timestamp")
        raw_duration = payload.get("duration_seconds") or event_data.get("duration_seconds")
        if raw_duration is not None:
            session["duration_seconds"] = self._parse_duration(raw_duration)
        if not session.get("duration_seconds"):
            calc_dur = self._calculate_duration(session)
            if calc_dur > 0:
                session["duration_seconds"] = calc_dur

        session["disconnection_reason"] = payload.get("disconnection_reason", event_data.get("disconnection_reason", ""))
        session["updated_at"] = datetime.now(timezone.utc).isoformat()

        logger.info(f"Session {session_id} ended after {session.get('duration_seconds', 0)}s")
        return session


    def add_command(self, event_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Add a command to session context.
        Returns session context so caller can decide if processing should be triggered.
        """
        payload = event_data.get("payload", event_data)
        if not isinstance(payload, dict):
            payload = event_data

        session_id = payload.get("session_id") or event_data.get("partition_key") or event_data.get("session_id")
        if not session_id:
            return None

        session = self._ensure_session(session_id, payload, event_data)

        command_entry = {
            "command": payload.get("command", ""),
            "arguments": payload.get("arguments", []),
            "output": payload.get("output", ""),
            "timestamp": payload.get("timestamp") or event_data.get("timestamp"),
            "exit_code": payload.get("exit_code"),
            "duration_ms": payload.get("duration_ms"),
            "working_directory": payload.get("working_directory", "/home/ubuntu"),
        }

        session["commands"].append(command_entry)
        session["outputs"].append(command_entry.get("output", ""))
        session["updated_at"] = datetime.now(timezone.utc).isoformat()

        logger.debug(f"Added command to session {session_id}: {command_entry.get('command', '')[:50]}")
        return session

    def add_auth(self, event_data: Dict[str, Any]) -> None:
        """Add authentication event to session context."""
        payload = event_data.get("payload", event_data)
        if not isinstance(payload, dict):
            payload = event_data

        session_id = payload.get("session_id") or event_data.get("partition_key") or event_data.get("session_id")
        if not session_id:
            return

        session = self._ensure_session(session_id, payload, event_data)

        auth_entry = {
            "username": payload.get("username", ""),
            "password": payload.get("password", ""),
            "success": payload.get("success", False),
            "timestamp": payload.get("timestamp") or event_data.get("timestamp"),
            "auth_method": payload.get("auth_method", "password"),
        }
        session["auth_attempts"].append(auth_entry)
        session["updated_at"] = datetime.now(timezone.utc).isoformat()

    def add_file_transfer(self, event_data: Dict[str, Any]) -> None:
        """Add file transfer event to session context."""
        payload = event_data.get("payload", event_data)
        if not isinstance(payload, dict):
            payload = event_data

        session_id = payload.get("session_id") or event_data.get("partition_key") or event_data.get("session_id")
        if not session_id:
            return

        session = self._ensure_session(session_id, payload, event_data)

        file_entry = {
            "filename": payload.get("filename", ""),
            "size_bytes": payload.get("size_bytes", 0),
            "direction": payload.get("direction", "upload"),
            "timestamp": payload.get("timestamp") or event_data.get("timestamp"),
        }
        session["file_transfers"].append(file_entry)
        session["updated_at"] = datetime.now(timezone.utc).isoformat()

    def get_session_context(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get current session context for AI enrichment."""
        return self.sessions.get(session_id)

    def should_process_session(self, session_id: str) -> bool:
        """
        Determine if we should process a session through AI engines.
        Triggers when we have enough commands or session ended.
        """
        session = self.sessions.get(session_id)
        if not session:
            return False

        # Process if we have accumulated commands
        return len(session["commands"]) >= 1

    def get_context_for_intent(self, session_id: str) -> Dict[str, Any]:
        """Build context for Intent Engine classification."""
        session = self.sessions.get(session_id, {})
        return {
            "attacker_ip": session.get("attacker_ip", "unknown"),
            "country": session.get("country", ""),
            "asn": session.get("asn", ""),
            "protocol": session.get("protocol", "ssh"),
            "session_duration": self._calculate_duration(session),
            "previous_intents": session.get("intent_history", []),
        }

    def get_context_for_threat_intel(self, session_id: str) -> Dict[str, Any]:
        """Build context for Threat Intel analysis."""
        session = self.sessions.get(session_id, {})
        return {
            "session_id": session_id,
            "attacker_ip": session.get("attacker_ip", "unknown"),
            "attacker_country": session.get("country", "unknown"),
            "duration_seconds": self._parse_duration(session.get("duration_seconds", 0)),
        }

    def get_context_for_adaptive(self, session_id: str) -> Dict[str, Any]:
        """Build context for Adaptive Engine."""
        session = self.sessions.get(session_id, {})
        return {
            "session_id": session_id,
            "attacker_ip": session.get("attacker_ip", "unknown"),
            "commands": session.get("commands", []),
            "outputs": session.get("outputs", []),
            "intent_history": session.get("intent_history", []),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def record_intent_result(self, session_id: str, intent_result: Dict[str, Any]) -> None:
        """Store intent prediction result in session state."""
        if session_id not in self.sessions:
            return

        session = self.sessions[session_id]
        session["intent"] = intent_result.get("intent")
        session["skill_level"] = intent_result.get("skill_level")
        session["confidence"] = intent_result.get("confidence")
        session["intent_history"].append(intent_result.get("intent"))
        session["updated_at"] = datetime.now(timezone.utc).isoformat()

    def record_adaptation_result(self, session_id: str, adapt_result: Dict[str, Any]) -> None:
        """Store adaptation result in session state."""
        if session_id not in self.sessions:
            return

        self.sessions[session_id]["adaptation_history"] = self.sessions[session_id].get("adaptation_history", [])
        self.sessions[session_id]["adaptation_history"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "adaptation": adapt_result,
        })
        self.sessions[session_id]["updated_at"] = datetime.now(timezone.utc).isoformat()

    def record_threat_result(self, session_id: str, threat_result: Dict[str, Any]) -> None:
        """Store threat intel result in session state."""
        if session_id not in self.sessions:
            return

        self.sessions[session_id]["threat_intel"] = threat_result
        self.sessions[session_id]["updated_at"] = datetime.now(timezone.utc).isoformat()

    def _calculate_duration(self, session: Dict[str, Any]) -> int:
        """Calculate session duration in seconds."""
        start = session.get("start_time")
        end = session.get("end_time")

        if not start:
            return 0

        def _to_naive_utc(dt_val: datetime) -> datetime:
            if dt_val.tzinfo is not None:
                return dt_val.astimezone(timezone.utc).replace(tzinfo=None)
            return dt_val

        try:
            start_dt = _to_naive_utc(datetime.fromisoformat(start.replace("Z", "+00:00")))
            if end:
                end_dt = _to_naive_utc(datetime.fromisoformat(end.replace("Z", "+00:00")))
                return max(0, int(round((end_dt - start_dt).total_seconds())))
            else:
                # Ongoing session
                now = _to_naive_utc(datetime.now(timezone.utc))
                return max(0, int((now - start_dt).total_seconds()))
        except Exception:
            return 0

    def _parse_duration(self, duration: Any) -> int:
        """Parse duration to integer seconds."""
        if isinstance(duration, (int, float)):
            return int(duration)
        if isinstance(duration, str):
            try:
                return int(float(duration))
            except ValueError:
                pass
        return 0