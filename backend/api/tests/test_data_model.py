
import unittest
from pathlib import Path
import os

API_MAIN = Path(os.path.join(os.path.dirname(__file__), "..", "main.py")).resolve()
COLLECTOR_MAIN = Path(os.path.join(os.path.dirname(__file__), "..", "..", "collector", "main.py")).resolve()

class TestDataModelCorrectness(unittest.TestCase):
    def test_api_schema_is_merge_tree(self):
        content = API_MAIN.read_text(encoding="utf-8")
        self.assertIn("ENGINE = MergeTree()", content)
        self.assertIn("ORDER BY (start_time, session_id)", content)

    def test_collector_schema_is_replacing(self):
        content = COLLECTOR_MAIN.read_text(encoding="utf-8")
        self.assertIn("ENGINE = ReplacingMergeTree", content)

    def test_api_stats_uses_uniq_exact(self):
        content = API_MAIN.read_text(encoding="utf-8")
        self.assertNotIn("SELECT count() FROM clouddecept.sessions", content)
        self.assertIn("uniqExact(session_id)", content)

    def test_api_attackers_uses_subquery_dedup(self):
        content = API_MAIN.read_text(encoding="utf-8")
        self.assertIn("max(commands_executed)", content)
        self.assertIn("GROUP BY attacker_ip, session_id", content)

    def test_threat_distribution_query(self):
        content = API_MAIN.read_text(encoding="utf-8")
        self.assertIn("SELECT lower(severity), count(*)", content)
        self.assertIn("FROM threat_intelligence", content)

if __name__ == "__main__":
    unittest.main()

