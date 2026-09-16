"""
Unit tests for Stream Processor SessionStateManager.
Validates event ordering resilience, data preservation, and AI context extraction.
"""
import unittest
import sys
import os

# Add service directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "services", "stream-processor", "src")))

from session_state import SessionStateManager


class TestSessionStateManager(unittest.TestCase):

    def test_standard_session_lifecycle(self):
        sm = SessionStateManager()
        start_payload = {
            "session_id": "sess-std-1",
            "attacker_ip": "192.168.1.50",
            "country": "US",
            "asn": "AS15169",
            "protocol": "ssh",
            "client_version": "SSH-2.0-OpenSSH_8.2p1",
            "timestamp": "2026-09-05T12:00:00Z",
        }
        session = sm.process_session_start({"payload": start_payload})
        self.assertEqual(session["session_id"], "sess-std-1")
        self.assertEqual(session["attacker_ip"], "192.168.1.50")
        self.assertEqual(session["country"], "US")

        # Add command
        cmd_payload = {
            "session_id": "sess-std-1",
            "command": "whoami",
            "arguments": [],
            "output": "root\n",
            "timestamp": "2026-09-05T12:00:05Z",
            "exit_code": 0,
            "duration_ms": 12,
        }
        sm.add_command({"payload": cmd_payload})

        # Add auth
        auth_payload = {
            "session_id": "sess-std-1",
            "username": "root",
            "password": "toor",
            "success": True,
            "timestamp": "2026-09-05T12:00:01Z",
        }
        sm.add_auth({"payload": auth_payload})

        # End session
        end_payload = {
            "session_id": "sess-std-1",
            "timestamp": "2026-09-05T12:00:30Z",
            "duration_seconds": 30,
            "disconnection_reason": "Connection closed by remote host",
        }
        end_session = sm.process_session_end({"payload": end_payload})
        self.assertEqual(end_session["duration_seconds"], 30)
        self.assertEqual(len(end_session["commands"]), 1)
        self.assertEqual(len(end_session["auth_attempts"]), 1)

    def test_commands_before_session_start(self):
        """Commands arriving before session_start must not be dropped or overwritten."""
        sm = SessionStateManager()
        cmd_payload = {
            "session_id": "sess-early-cmd",
            "command": "cat /etc/passwd",
            "arguments": ["/etc/passwd"],
            "output": "root:x:0:0:root:/root:/bin/bash\n",
            "timestamp": "2026-09-05T12:00:05Z",
            "exit_code": 0,
        }
        session = sm.add_command({"payload": cmd_payload})
        self.assertIsNotNone(session)
        self.assertEqual(len(session["commands"]), 1)

        # Late session start arrives
        start_payload = {
            "session_id": "sess-early-cmd",
            "attacker_ip": "10.0.0.1",
            "country": "DE",
            "timestamp": "2026-09-05T12:00:00Z",
        }
        updated_session = sm.process_session_start({"payload": start_payload})
        # Commands must be preserved!
        self.assertEqual(len(updated_session["commands"]), 1)
        self.assertEqual(updated_session["commands"][0]["command"], "cat /etc/passwd")
        self.assertEqual(updated_session["attacker_ip"], "10.0.0.1")
        self.assertEqual(updated_session["country"], "DE")

    def test_auth_before_session_start(self):
        """Auth attempts before session_start must not be dropped."""
        sm = SessionStateManager()
        auth_payload = {
            "session_id": "sess-early-auth",
            "username": "admin",
            "password": "password123",
            "success": False,
            "timestamp": "2026-09-05T12:00:01Z",
        }
        sm.add_auth({"payload": auth_payload})
        ctx = sm.get_session_context("sess-early-auth")
        self.assertIsNotNone(ctx)
        self.assertEqual(len(ctx["auth_attempts"]), 1)
        self.assertEqual(ctx["auth_attempts"][0]["username"], "admin")

    def test_session_end_without_prior_start(self):
        """Session end for an untracked session must create minimal session and compute duration."""
        sm = SessionStateManager()
        end_payload = {
            "session_id": "sess-orphan-end",
            "timestamp": "2026-09-05T12:05:00Z",
            "duration_seconds": 45,
            "disconnection_reason": "timeout",
        }
        end_session = sm.process_session_end({"payload": end_payload})
        self.assertIsNotNone(end_session)
        self.assertEqual(end_session["session_id"], "sess-orphan-end")
        self.assertEqual(end_session["duration_seconds"], 45)
        self.assertEqual(end_session["disconnection_reason"], "timeout")

    def test_duration_fallback_calculation(self):
        """If duration_seconds is missing or 0, calculate from timestamps."""
        sm = SessionStateManager()
        sm.process_session_start({
            "payload": {
                "session_id": "sess-dur-calc",
                "timestamp": "2026-09-05T12:00:00Z",
            }
        })
        end_session = sm.process_session_end({
            "payload": {
                "session_id": "sess-dur-calc",
                "timestamp": "2026-09-05T12:01:15Z",
                "duration_seconds": 0,
            }
        })
        self.assertEqual(end_session["duration_seconds"], 75)

    def test_duration_fallback_calculation_mixed_timezones(self):
        """Duration calculation handles mixed offset-aware and naive timestamps without exceptions."""
        sm = SessionStateManager()
        # Start time with explicit UTC timezone
        sm.process_session_start({
            "payload": {
                "session_id": "45dfa3c32596",
                "timestamp": "2026-09-06T06:36:42+00:00",
            }
        })
        # End time in naive format (space separated) and 0 duration_seconds
        end_session = sm.process_session_end({
            "payload": {
                "session_id": "45dfa3c32596",
                "timestamp": "2026-09-06 06:36:48",
                "duration_seconds": 0,
            }
        })
        self.assertEqual(end_session["duration_seconds"], 6)

    def test_ai_context_extraction(self):
        sm = SessionStateManager()
        sm.process_session_start({
            "payload": {
                "session_id": "sess-ai-ctx",
                "attacker_ip": "1.2.3.4",
                "country": "NL",
                "asn": "AS1103",
                "protocol": "ssh",
                "timestamp": "2026-09-05T12:00:00Z",
            }
        })
        sm.add_command({
            "payload": {
                "session_id": "sess-ai-ctx",
                "command": "uname -a",
                "output": "Linux honeypot 5.15.0",
            }
        })
        intent_ctx = sm.get_context_for_intent("sess-ai-ctx")
        self.assertEqual(intent_ctx["attacker_ip"], "1.2.3.4")
        self.assertEqual(intent_ctx["country"], "NL")

        threat_ctx = sm.get_context_for_threat_intel("sess-ai-ctx")
        self.assertEqual(threat_ctx["attacker_ip"], "1.2.3.4")
        self.assertEqual(threat_ctx["attacker_country"], "NL")

        adaptive_ctx = sm.get_context_for_adaptive("sess-ai-ctx")
        self.assertEqual(len(adaptive_ctx["commands"]), 1)

    def test_session_ordering_session_start_session_end_commands_auth(self):
        """Cross-stream inverted ordering: session_start -> session_end -> commands -> auth.
        Verifies that final state has duration_seconds=6, 7 commands, 1 auth attempt.
        """
        sm = SessionStateManager()
        sid = "order-test-1"

        # 1. session_start
        sm.process_session_start({
            "payload": {
                "session_id": sid,
                "timestamp": "2026-09-06T06:36:42Z",
                "attacker_ip": "1.2.3.4",
            }
        })
        # 2. session_end (before commands and auth)
        sm.process_session_end({
            "payload": {
                "session_id": sid,
                "timestamp": "2026-09-06T06:36:48Z",
                "duration_seconds": 0,
            }
        })
        # 3. commands
        for cmd in ["whoami", "pwd", "uname -a", "ls -la", "sleep 3", "cat /etc/passwd", "exit"]:
            sm.add_command({
                "payload": {
                    "session_id": sid,
                    "command": cmd,
                    "timestamp": "2026-09-06T06:36:45Z",
                }
            })
        # 4. auth
        sm.add_auth({
            "payload": {
                "session_id": sid,
                "username": "root",
                "password": "password123",
                "timestamp": "2026-09-06T06:36:43Z",
            }
        })

        ctx = sm.get_session_context(sid)
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx["duration_seconds"], 6)
        self.assertEqual(len(ctx["commands"]), 7)
        self.assertEqual(len(ctx["auth_attempts"]), 1)

    def test_session_ordering_normal_order(self):
        """Normal ordering: session_start -> commands -> auth -> session_end.
        Must produce identical final state.
        """
        sm = SessionStateManager()
        sid = "order-test-2"

        # 1. session_start
        sm.process_session_start({
            "payload": {
                "session_id": sid,
                "timestamp": "2026-09-06T06:36:42Z",
                "attacker_ip": "1.2.3.4",
            }
        })
        # 2. commands
        for cmd in ["whoami", "pwd", "uname -a", "ls -la", "sleep 3", "cat /etc/passwd", "exit"]:
            sm.add_command({
                "payload": {
                    "session_id": sid,
                    "command": cmd,
                    "timestamp": "2026-09-06T06:36:45Z",
                }
            })
        # 3. auth
        sm.add_auth({
            "payload": {
                "session_id": sid,
                "username": "root",
                "password": "password123",
                "timestamp": "2026-09-06T06:36:43Z",
            }
        })
        # 4. session_end
        sm.process_session_end({
            "payload": {
                "session_id": sid,
                "timestamp": "2026-09-06T06:36:48Z",
                "duration_seconds": 0,
            }
        })

        ctx = sm.get_session_context(sid)
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx["duration_seconds"], 6)
        self.assertEqual(len(ctx["commands"]), 7)
        self.assertEqual(len(ctx["auth_attempts"]), 1)

    def test_session_ordering_session_end_first(self):
        """Extreme inverted ordering: session_end -> commands -> auth -> session_start.
        Must also produce identical final state once session_start arrives.
        """
        sm = SessionStateManager()
        sid = "order-test-3"

        # 1. session_end first
        sm.process_session_end({
            "payload": {
                "session_id": sid,
                "timestamp": "2026-09-06T06:36:48Z",
                "duration_seconds": 0,
            }
        })
        # 2. commands
        for cmd in ["whoami", "pwd", "uname -a", "ls -la", "sleep 3", "cat /etc/passwd", "exit"]:
            sm.add_command({
                "payload": {
                    "session_id": sid,
                    "command": cmd,
                    "timestamp": "2026-09-06T06:36:45Z",
                }
            })
        # 3. auth
        sm.add_auth({
            "payload": {
                "session_id": sid,
                "username": "root",
                "password": "password123",
                "timestamp": "2026-09-06T06:36:43Z",
            }
        })
        # 4. session_start arrives last
        sm.process_session_start({
            "payload": {
                "session_id": sid,
                "timestamp": "2026-09-06T06:36:42Z",
                "attacker_ip": "1.2.3.4",
            }
        })

        ctx = sm.get_session_context(sid)
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx["duration_seconds"], 6)
        self.assertEqual(len(ctx["commands"]), 7)
        self.assertEqual(len(ctx["auth_attempts"]), 1)


if __name__ == "__main__":
    unittest.main()
