import sys
import unittest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app import models, database
from backend.app.website_security_service import website_security_service, sanitize_url
from backend.app.website_blocker import website_blocker

# Setup in-memory SQLite database for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

models.Base.metadata.create_all(bind=engine)


class TestWebsiteSecurity(unittest.TestCase):
    def setUp(self):
        models.Base.metadata.create_all(bind=engine)
        self.db = TestingSessionLocal()

    def tearDown(self):
        self.db.close()

    def test_sanitize_url(self):
        domain, sanitized = sanitize_url("http://example.com/login?token=supersecret123&user=john")
        self.assertEqual(domain, "example.com")
        self.assertNotIn("supersecret123", sanitized)
        self.assertIn("[REDACTED]", sanitized)

    def test_safe_website_evaluation(self):
        result = website_security_service.evaluate_url("https://paruluniversity.ac.in", self.db)
        self.assertEqual(result["domain"], "paruluniversity.ac.in")
        self.assertEqual(result["threat_status"], "Safe")
        self.assertLess(result["threat_score"], 30.0)
        self.assertEqual(result["action_taken"], "allowed")
        self.assertFalse(result["blocked"])

    def test_malicious_typosquatting_detection(self):
        result = website_security_service.evaluate_url("http://paypal-security-verify.xyz/login", self.db)
        self.assertEqual(result["domain"], "paypal-security-verify.xyz")
        self.assertGreaterEqual(result["threat_score"], 80.0)
        self.assertEqual(result["threat_status"], "Malicious")
        self.assertTrue(result["blocked"])
        self.assertEqual(result["action_taken"], "blocked")

    def test_whitelist_override(self):
        domain = "custom-partner-site.com"
        entry = models.WebsiteWhitelist(domain=domain, added_by="Admin", reason="Trusted Partner", is_permanent=True)
        self.db.add(entry)
        self.db.commit()

        result = website_security_service.evaluate_url(f"http://{domain}", self.db)
        self.assertEqual(result["threat_status"], "Safe")
        self.assertEqual(result["threat_score"], 0.0)
        self.assertEqual(result["action_taken"], "allowed")
        self.assertEqual(result["category"], "Whitelisted")

    def test_manual_blacklist_and_unblock(self):
        domain = "bad-malware-test.com"
        block_entry = models.BlockedWebsite(domain=domain, reason="Manual test block", threat_score=95.0, added_by="Admin")
        self.db.add(block_entry)
        self.db.commit()

        result = website_security_service.evaluate_url(f"http://{domain}", self.db)
        self.assertTrue(result["blocked"])
        self.assertEqual(result["action_taken"], "blocked")

        block_entry.is_active = False
        self.db.commit()
        website_blocker.unblock_domain_os_level(domain)

    def test_html_block_page_rendering(self):
        html = website_blocker.render_block_page_html(
            domain="example-malicious-site.com",
            threat_score=91.0,
            reason="Possible phishing / malicious activity detected.",
            category="Phishing/Malware",
            timestamp_str="2026-09-07 17:00:00 UTC",
            user_name="Test User"
        )
        self.assertIn("Harmful Website Access Blocked", html)
        self.assertIn("example-malicious-site.com", html)
        self.assertIn("91.0 / 100", html)
        self.assertIn("Possible phishing", html)


if __name__ == "__main__":
    unittest.main()
