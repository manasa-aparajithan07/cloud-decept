"""
Unit tests for event schemas and envelope serialization.
Verifies that session_id and payload fields are correctly structured in EventEnvelope.
"""
import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from schemas.events import (
    EventEnvelope,
    SessionStartEvent,
    SessionEndEvent,
    CommandEvent,
    AuthEvent,
    EventSource,
    HoneypotType,
    Protocol,
    StreamNames,
)


class TestEventSchemas(unittest.TestCase):

    def test_session_start_envelope_payload(self):
        event = SessionStartEvent(
            session_id="sess-test-100",
            attacker_ip="203.0.113.195",
            client_ip="203.0.113.195",
            country="US",
            asn="AS13335",
            source=EventSource.COWRIE_SSH,
        )
        envelope = EventEnvelope(
            event_type="session_start",
            payload=event.model_dump(mode="json"),
            stream_name=StreamNames.SESSION_EVENTS,
            partition_key=event.session_id,
        )
        data = envelope.model_dump(mode="json")
        self.assertEqual(data["event_type"], "session_start")
        self.assertIn("payload", data)
        self.assertEqual(data["payload"]["session_id"], "sess-test-100")
        self.assertEqual(data["payload"]["attacker_ip"], "203.0.113.195")
        self.assertEqual(data["payload"]["country"], "US")

    def test_command_envelope_payload(self):
        cmd = CommandEvent(
            session_id="sess-test-100",
            attacker_ip="203.0.113.195",
            command="whoami",
            arguments=[],
            output="root",
            exit_code=0,
            duration_ms=5,
            source=EventSource.COWRIE_SSH,
        )
        envelope = EventEnvelope(
            event_type="command",
            payload=cmd.model_dump(mode="json"),
            stream_name=StreamNames.COMMAND_EVENTS,
            partition_key=cmd.session_id,
        )
        data = envelope.model_dump(mode="json")
        self.assertEqual(data["payload"]["session_id"], "sess-test-100")
        self.assertEqual(data["payload"]["command"], "whoami")
        self.assertEqual(data["payload"]["output"], "root")

    def test_session_end_duration_mapping(self):
        end_event = SessionEndEvent(
            session_id="sess-test-100",
            attacker_ip="203.0.113.195",
            duration_seconds=42,
            disconnection_reason="Connection closed",
            source=EventSource.COWRIE_SSH,
        )
        envelope = EventEnvelope(
            event_type="session_end",
            payload=end_event.model_dump(mode="json"),
            stream_name=StreamNames.SESSION_EVENTS,
            partition_key=end_event.session_id,
        )
        data = envelope.model_dump(mode="json")
        self.assertEqual(data["payload"]["duration_seconds"], 42)
        self.assertEqual(data["payload"]["disconnection_reason"], "Connection closed")


if __name__ == "__main__":
    unittest.main()
