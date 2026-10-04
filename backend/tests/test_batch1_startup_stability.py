import os
import sys
import json
import shutil
import tempfile
import sqlite3
import unittest
from fastapi.testclient import TestClient

# Ensure backend is on sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from security.block_manager import BlockManager
from security.live_monitor import LiveMonitor
from app.database import check_and_recover_sqlite_db
from app.main import app
from main import find_available_port, record_runtime_port

class TestBatch1StartupStability(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_db = os.path.join(self.temp_dir, "test_stability.db")
        self.client = TestClient(app)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_block_manager_in_memory_cache_no_redis(self):
        """Verify BlockManager functions with in-memory cache and SQLite without Redis"""
        bm = BlockManager(db_path=self.test_db)
        self.assertFalse(bm.use_redis)
        self.assertIsInstance(bm._cache, dict)

        # Block IP
        res = bm.block("ip", "198.51.100.1", "Port scanning", "admin@internal.local", apply_firewall=False)
        self.assertTrue(res.get("success"))

        # Cached immediately
        self.assertIn("block:ip:198.51.100.1", bm._cache)
        self.assertTrue(bm.is_blocked("ip", "198.51.100.1"))
        self.assertFalse(bm.is_blocked("ip", "198.51.100.2"))

        # Unblock removes from cache and updates DB
        unblock_res = bm.unblock("ip", "198.51.100.1", "admin@internal.local", "Resolved")
        self.assertTrue(unblock_res.get("success"))
        self.assertNotIn("block:ip:198.51.100.1", bm._cache)
        self.assertFalse(bm.is_blocked("ip", "198.51.100.1"))

    def test_database_corruption_detection_and_recovery(self):
        """Verify corrupt DB file is detected, backed up, and cleanly recreated"""
        corrupt_db_path = os.path.join(self.temp_dir, "corrupt.db")
        with open(corrupt_db_path, "wb") as f:
            f.write(b"NOT A VALID SQLITE DATABASE HEADER GIBBERISH")

        # Run recovery
        check_and_recover_sqlite_db(f"sqlite:///{corrupt_db_path}")

        # The corrupt DB should be removed and a backup created
        self.assertFalse(os.path.exists(corrupt_db_path))
        backups = [f for f in os.listdir(self.temp_dir) if "corrupt" in f and f.endswith(".bak")]
        self.assertEqual(len(backups), 1)

    def test_free_port_selection(self):
        """Verify free port selection and recording"""
        # Find port starting from 8000
        port = find_available_port(8000, "127.0.0.1")
        self.assertIsInstance(port, int)
        self.assertGreater(port, 1024)

        record_runtime_port(port, "127.0.0.1")
        appdata = os.environ.get("APPDATA") or os.path.expanduser("~\\AppData\\Roaming")
        runtime_file = os.path.join(appdata, "AIFirewall", "runtime_port.json")
        self.assertTrue(os.path.exists(runtime_file))
        with open(runtime_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertEqual(data["port"], port)
            self.assertEqual(data["host"], "127.0.0.1")

    def test_live_monitor_imports_and_instantiation(self):
        """Verify live_monitor imports work cleanly"""
        lm = LiveMonitor()
        self.assertIsNotNone(lm)
        self.assertFalse(lm.running)

    def test_api_health_endpoint_per_feature_status(self):
        """Verify /api/health and /health return comprehensive per-feature status"""
        for endpoint in ["/api/health", "/health"]:
            response = self.client.get(endpoint)
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertIn("status", data)
            self.assertIn("admin_rights", data)
            self.assertIn("features", data)
            features = data["features"]
            self.assertIn("database", features)
            self.assertIn("in_memory_cache", features)
            self.assertIn("ai_models", features)
            self.assertIn("network_monitor", features)
            self.assertIn("website_blocker", features)
            self.assertIn("firewall_rules", features)
            self.assertIn("log_file", data)
            self.assertTrue(os.path.exists(os.path.dirname(data["log_file"])))

    def test_rotating_log_file_created(self):
        """Verify rotating log file exists in %APPDATA%\\AIFirewall\\logs"""
        appdata = os.environ.get("APPDATA") or os.path.expanduser("~\\AppData\\Roaming")
        log_dir = os.path.join(appdata, "AIFirewall", "logs")
        log_file = os.path.join(log_dir, "aifirewall.log")
        self.assertTrue(os.path.exists(log_dir))
        # Write a test log entry
        import logging
        logging.getLogger("ai_firewall.test").info("Batch 1 verification log entry")
        self.assertTrue(os.path.exists(log_file))

if __name__ == "__main__":
    unittest.main()
