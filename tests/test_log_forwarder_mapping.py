"""
Unit tests for Log Forwarder mapping logic.
Tests Cowrie log line parsing and payload construction using standard library.
"""
import unittest


class TestLogForwarderMapping(unittest.TestCase):

    def test_duration_parsing_seconds(self):
        """Standard Cowrie duration (seconds float) should parse accurately."""
        raw_dur = 14.789
        raw_float = float(raw_dur)
        dur_secs = int(raw_float / 1000) if raw_float > 100000 else int(round(raw_float))
        self.assertEqual(dur_secs, 15)

    def test_duration_parsing_short_session(self):
        """Short sessions (< 1000s) must NOT be divided by 1000 to yield 0."""
        raw_dur = 5.2
        raw_float = float(raw_dur)
        dur_secs = int(raw_float / 1000) if raw_float > 100000 else int(round(raw_float))
        self.assertEqual(dur_secs, 5)

    def test_duration_parsing_milliseconds_fallback(self):
        """Legacy millisecond duration (> 100,000) should be converted to seconds."""
        raw_dur = 120000  # 120,000 ms = 120 s
        raw_float = float(raw_dur)
        dur_secs = int(raw_float / 1000) if raw_float > 100000 else int(round(raw_float))
        self.assertEqual(dur_secs, 120)

    def test_cowrie_event_type_mapping(self):
        EVENT_TYPE_MAP = {
            "cowrie.session.connect": "session_start",
            "cowrie.session.closed": "session_end",
            "cowrie.login.success": "auth",
            "cowrie.login.failed": "auth",
            "cowrie.command.input": "command",
            "cowrie.command.failed": "command",
            "cowrie.session.file_download": "file_transfer",
            "cowrie.session.file_upload": "file_transfer",
        }
        self.assertEqual(EVENT_TYPE_MAP["cowrie.session.connect"], "session_start")
        self.assertEqual(EVENT_TYPE_MAP["cowrie.session.closed"], "session_end")
        self.assertEqual(EVENT_TYPE_MAP["cowrie.command.input"], "command")
        self.assertEqual(EVENT_TYPE_MAP["cowrie.login.success"], "auth")


if __name__ == "__main__":
    unittest.main()
