import sys
import os
import sqlite3
import unittest
from datetime import datetime

# Add root and backend to sys.path
_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if _root not in sys.path:
    sys.path.insert(0, _root)
_backend = os.path.join(_root, 'backend')
if _backend not in sys.path:
    sys.path.insert(0, _backend)

from backend.security.traffic_controller import TrafficController
from backend.security.geo_tracker import GeoTracker
from backend.security.block_manager import BlockManager
from backend.ai.phishing_detector import PhishingDetector
from backend.security.live_monitor import LiveMonitor
from backend.app.admin_utils import is_admin
from passlib.context import CryptContext

class TestFixesAndNewFeatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_db = "test_firewall_suite.db"
        if os.path.exists(cls.test_db):
            try:
                os.remove(cls.test_db)
            except Exception:
                pass

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.test_db):
            try:
                os.remove(cls.test_db)
            except Exception:
                pass

    def test_01_phishing_detector_and_error_safety(self):
        detector = PhishingDetector()
        # Normal detection
        text_res = detector.analyze_text("URGENT: Your account has been suspended! Verify here: http://paypal-fake-verify.tk")
        self.assertTrue(text_res['is_phishing'])
        self.assertGreater(text_res['score'], 50)
        self.assertTrue(len(text_res['indicators']) > 0)

        # URL analysis
        url_res = detector.analyze_url("http://bankofamerica-login-confirm.ga/login.php")
        self.assertTrue(url_res['is_phishing'])
        self.assertGreater(url_res['score'], 50)

        # Empty and non-standard safe text
        safe_res = detector.analyze_text("Meeting at 3pm in the conference room")
        self.assertFalse(safe_res['is_phishing'])
        self.assertLess(safe_res['score'], 30)

    def test_02_traffic_controller_resilience(self):
        tc = TrafficController(db_path=self.test_db)
        
        # Add admin-locked rule
        add_res = tc.add_rule(
            rule_name="TEST_SSH_LOCK",
            direction="in",
            action="block",
            protocol="tcp",
            local_port="22",
            created_by="admin@internal.local",
            admin_locked=True
        )
        if not is_admin():
            self.assertFalse(add_res.get('success'))
            self.assertEqual(add_res.get('error'), 'admin_required')
        else:
            self.assertTrue(add_res.get('success'))

            # User attempt to remove locked rule must fail
            del_user_res = tc.remove_rule("TEST_SSH_LOCK", requested_by="user1", is_admin_flag=False)
            self.assertFalse(del_user_res.get('success'))
            self.assertIn("admin-locked", del_user_res.get('error', '').lower())

            # Admin removal must succeed
            del_admin_res = tc.remove_rule("TEST_SSH_LOCK", requested_by="admin", is_admin_flag=True)
            self.assertTrue(del_admin_res.get('success'))

    def test_03_geo_tracker_resilience(self):
        gt = GeoTracker(db_path=self.test_db)
        
        # Localhost IP
        local_data = gt.lookup_ip("127.0.0.1")
        self.assertEqual(local_data['city'], 'Local')
        self.assertEqual(local_data['country'], 'Local Network')

        # Private IP range
        private_data = gt.lookup_ip("192.168.1.105")
        self.assertEqual(private_data['city'], 'Private Network')

        # Public IP lookup should return dict with all keys without error
        public_data = gt.lookup_ip("8.8.8.8")
        self.assertIn('city', public_data)
        self.assertIn('country', public_data)
        self.assertIn('isp', public_data)
        self.assertIn('timezone', public_data)

        # Log access event
        log_res = gt.log_access("127.0.0.1", "admin@test.com", "Chrome", "login", 0)
        self.assertEqual(log_res['user_email'], "admin@test.com")
        logs = gt.get_access_logs()
        self.assertGreaterEqual(len(logs), 1)

    def test_04_block_manager_sqlite_memory_cache(self):
        # Initializing block manager uses high-speed in-memory cache and SQLite persistence
        bm = BlockManager(db_path=self.test_db)
        self.assertFalse(getattr(bm, 'use_redis', False))

        # Block an IP
        block_res = bm.block("ip", "203.0.113.50", "Malicious scanner", "admin@test.com", apply_firewall=False)
        self.assertTrue(block_res.get('success'))

        # Fast is_blocked check
        self.assertTrue(bm.is_blocked("ip", "203.0.113.50"))
        self.assertFalse(bm.is_blocked("ip", "1.1.1.1"))

        # Unblock IP
        unblock_res = bm.unblock("ip", "203.0.113.50", "admin@test.com", "Verified partner")
        self.assertTrue(unblock_res.get('success'))
        self.assertFalse(bm.is_blocked("ip", "203.0.113.50"))

    def test_05_live_monitor_events(self):
        monitor = LiveMonitor()
        received_events = []

        def callback(evt):
            received_events.append(evt)

        monitor.add_callback(callback)
        monitor.emit("new_connection", {
            "local": "127.0.0.1:5000",
            "remote_ip": "1.2.3.4",
            "remote_port": 443,
            "process": "chrome.exe",
            "threat_level": "LOW"
        })

        self.assertEqual(len(received_events), 1)
        self.assertEqual(received_events[0]['type'], "new_connection")
        self.assertEqual(received_events[0]['data']['process'], "chrome.exe")

    def test_06_user_management_database_and_pwd(self):
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        with sqlite3.connect(self.test_db) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS managed_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    department TEXT DEFAULT '',
                    can_view_logs INTEGER DEFAULT 1,
                    can_manage_blocks INTEGER DEFAULT 0,
                    can_manage_rules INTEGER DEFAULT 0,
                    is_active INTEGER DEFAULT 1,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_login TEXT,
                    login_count INTEGER DEFAULT 0,
                    force_password_change INTEGER DEFAULT 0
                )
            """)
            
            pwd_hash = pwd_context.hash("Secret123!")
            conn.execute("""
                INSERT INTO managed_users 
                (email, password_hash, full_name, role, department, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, ("alice@test.com", pwd_hash, "Alice Cooper", "analyst", "SOC", "admin", datetime.now().isoformat()))
            conn.commit()

            user = conn.execute("SELECT id, email, password_hash, is_active FROM managed_users WHERE email=?", ("alice@test.com",)).fetchone()
            self.assertIsNotNone(user)
            self.assertEqual(user[1], "alice@test.com")
            self.assertTrue(pwd_context.verify("Secret123!", user[2]))

            # Toggle active
            conn.execute("UPDATE managed_users SET is_active = NOT is_active WHERE id=?", (user[0],))
            conn.commit()
            updated = conn.execute("SELECT is_active FROM managed_users WHERE id=?", (user[0],)).fetchone()
            self.assertEqual(updated[0], 0)

if __name__ == '__main__':
    unittest.main()
