import json
import os
import sqlite3
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.ai.phishing_detector import MAX_TEXT_LENGTH, PhishingDetector, detector
from backend.app import database, models
from backend.app.ai.markov_model import SequenceAnalyzer
from backend.app.ai.scoring_engine import ScoringEngine
from backend.app.behavior_tracking import (
    _load_json_dict,
    _load_json_list,
    _parse_json,
    serialize_behavior_profile,
)
from backend.app.main import app, get_current_user
from backend.app.auth import create_access_token
from backend.app.spam_detection_service import SpamDetectionService
from backend.security.geo_tracker import GeoTracker, is_private_or_local_ip
from backend.usb_security_module import (
    DEFAULT_QUARANTINE_ROOT,
    EICAR_SIGNATURE,
    ActionLogger,
    FileScanner,
    QuarantineManager,
    ScanSummary,
    SignatureDatabase,
    USBDevice,
    USBSecurityModule,
)


@pytest.fixture
def test_db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    models.Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def auth_client(test_db_session):
    def override_get_db():
        try:
            yield test_db_session
        finally:
            pass

    test_user = models.User(
        id=99,
        username="batch4user",
        hashed_password="hashed_dummy_password",
        role="user",
    )
    test_db_session.add(test_user)
    test_db_session.commit()

    def override_get_current_user():
        return test_user

    app.dependency_overrides[database.get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()


# ============================================================================
# 1. USB SECURITY TESTS
# ============================================================================

def test_usb_drive_removed_mid_scan():
    """Verify that if a drive or file disappears mid-scan (FileNotFoundError/OSError),
    the scan is marked 'interrupted' without crashing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        test_file = tmp_path / "test.txt"
        test_file.write_text("dummy test content", encoding="utf-8")

        device = USBDevice(
            device_id="E:\\",
            mountpoint=tmp_path,
            label="TestDrive",
            filesystem="FAT32",
            source="test",
        )

        mock_scanner = MagicMock()
        mock_scanner.scan_file.side_effect = FileNotFoundError("Drive disconnected [WinError 21]")

        mock_quarantine = MagicMock()
        mock_logger = MagicMock()

        module = USBSecurityModule(
            detector=MagicMock(),
            scanner=mock_scanner,
            quarantine=mock_quarantine,
            logger=mock_logger,
            quarantine_level="malicious",
            poll_interval=2.0,
        )

        summary = module._scan_device(device)
        assert summary.status == "interrupted"
        assert mock_logger.alert.called


def test_usb_eicar_detection_and_quarantine():
    """Verify that the standard EICAR test string is recognized as malicious
    and quarantined into the configured quarantine directory."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        tmp_path = Path(tmpdir)
        eicar_file = tmp_path / "eicar.com"
        eicar_file.write_bytes(EICAR_SIGNATURE)

        sig_db = SignatureDatabase(tmp_path / "empty_signatures.json")
        scanner = FileScanner(sig_db)
        finding = scanner.scan_file(eicar_file)

        assert finding.severity == "malicious"
        assert "eicar_test_signature" in finding.reasons

        quarantine_dir = tmp_path / "quarantine"
        logger = ActionLogger(tmp_path / "usb.log")
        try:
            qm = QuarantineManager(quarantine_dir, logger)

            device = USBDevice(
                device_id="F:\\",
                mountpoint=tmp_path,
                label="EicarDrive",
                filesystem="FAT32",
                source="test",
            )

            dest = qm.quarantine(eicar_file, device, finding)
            assert dest.exists()
            assert not eicar_file.exists()
            assert dest.read_bytes() == EICAR_SIGNATURE
        finally:
            logger.close()


def test_powershell_execution_policy_bypass_in_scripts():
    """Verify that every PowerShell execution in the codebase includes -NoProfile -ExecutionPolicy Bypass."""
    monitoring_py = Path("backend/app/monitoring.py").read_text(encoding="utf-8")
    block_manager_py = Path("backend/security/block_manager.py").read_text(encoding="utf-8")
    live_monitor_py = Path("backend/security/live_monitor.py").read_text(encoding="utf-8")

    assert "'-ExecutionPolicy', 'Bypass'" in block_manager_py or '"-ExecutionPolicy", "Bypass"' in block_manager_py
    assert '"-ExecutionPolicy", "Bypass"' in monitoring_py
    assert "'-ExecutionPolicy', 'Bypass'" in live_monitor_py


# ============================================================================
# 2. GEOLOCATION TESTS
# ============================================================================

def test_geolocation_skips_private_and_local_ips():
    """Verify that local and private IPs are classified immediately without HTTP network lookups."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = str(Path(tmpdir) / "test_geo.db")
        tracker = GeoTracker(db_path=db_path)

        local_ips = ["127.0.0.1", "192.168.1.100", "10.0.0.1", "172.16.0.1", "::1", "localhost"]
        for ip in local_ips:
            assert is_private_or_local_ip(ip) is True
            res = tracker.lookup_ip(ip)
            assert res["city"] in ("Local Network", "Local", "Private Network")
            assert res["country"] in ("Local Network", "Local", "Private Network")


def test_geolocation_sqlite_caching_and_offline_fallback():
    """Verify that geolocation results are cached in SQLite for 24h, and offline/error returns unknown fallback."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = str(Path(tmpdir) / "test_geo.db")
        tracker = GeoTracker(db_path=db_path)

        public_ip = "8.8.8.8"
        # Mock requests.get to return a mock response
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "city": "Mountain View",
            "regionName": "California",
            "country": "United States",
            "countryCode": "US",
            "lat": 37.422,
            "lon": -122.084,
            "isp": "Google LLC",
            "timezone": "America/Los_Angeles",
            "proxy": False,
            "hosting": True,
        }

        with patch("requests.get", return_value=mock_resp) as mock_get:
            res1 = tracker.lookup_ip(public_ip)
            assert res1["city"] == "Mountain View"
            assert mock_get.call_count == 1

            # Second lookup should hit SQLite cache without calling requests.get again
            res2 = tracker.lookup_ip(public_ip)
            assert res2["city"] == "Mountain View"
            assert mock_get.call_count == 1  # Still 1!

        # Offline / timeout fallback test
        with patch("requests.get", side_effect=Exception("Connection timed out")):
            offline_res = tracker.lookup_ip("1.1.1.1")
            assert offline_res["city"] == "Unknown"
            assert offline_res["country"] == "Unknown"


def test_geo_cache_stores_hashed_ip_and_encrypted_payload():
    """Verify that geo_cache stores only hashed IP keys and encrypted payloads, not plaintext IPs."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = os.path.join(tmpdir, "test_geo_secure.db")
        tracker = GeoTracker(db_path=db_path)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "city": "Tokyo",
            "regionName": "Tokyo",
            "country": "Japan",
            "countryCode": "JP",
            "lat": 35.6762,
            "lon": 139.6503,
            "isp": "NTT",
            "timezone": "Asia/Tokyo",
            "proxy": False,
            "hosting": False,
        }

        test_ip = "133.242.0.1"
        with patch("requests.get", return_value=mock_resp):
            res = tracker.lookup_ip(test_ip)
            assert res["city"] == "Tokyo"

        # Check raw SQLite table: no raw IP in plaintext!
        import sqlite3
        from contextlib import closing
        with closing(sqlite3.connect(db_path)) as conn:
            rows = conn.execute("SELECT ip, data_json FROM geo_cache").fetchall()
            assert len(rows) == 1
            cached_ip_key, cached_json = rows[0]
            # Key is SHA-256 hash (64 hex characters)
            assert len(cached_ip_key) == 64
            assert test_ip not in cached_ip_key
            assert test_ip not in cached_json or cached_json.startswith("enc::")


# ============================================================================
# 3. SPAM DETECTOR TESTS
# ============================================================================

def test_spam_detector_raw_text_payload_no_422(auth_client):
    """Verify that /api/spam-detection/scan accepts raw text payloads without 422 error."""
    payload = {"text": "Congratulations! You won the $1,000,000 cash lottery prize! Claim now immediately!"}
    res = auth_client.post("/api/spam-detection/scan", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["threat_type"] in ("High Risk", "Critical", "Medium Risk")
    assert data["action_taken"] in ("blocked", "allowed")
    assert "text-payload" in data["domain"]


def test_spam_detector_url_payload(auth_client):
    """Verify that /api/spam-detection/scan accepts standard URL payloads."""
    payload = {"url": "https://paypal-security-login-update.tk/signin"}
    res = auth_client.post("/api/spam-detection/scan", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_score"] > 50
    assert data["threat_type"] in ("High Risk", "Critical")


def test_spam_detector_ssl_probing_offline_handling(test_db_session):
    """Verify that when offline, SSL probing is skipped gracefully without penalty."""
    service = SpamDetectionService()
    with patch("backend.app.spam_detection_service.is_system_offline", return_value=True):
        res = service.scan_url("https://example.com/test", test_db_session)
        assert res["risk_score"] < 50
        scan_report = json.loads(res["scan_report"])
        assert scan_report["offline_mode"] is True
        assert "SSL probing skipped" in scan_report["ssl_issuer"]


# ============================================================================
# 4. WEBSOCKET TESTS
# ============================================================================

def test_websocket_requires_valid_token():
    """Verify that WebSocket rejected without valid auth token (close code 4401)."""
    with TestClient(app) as client:
        with pytest.raises(Exception):
            with client.websocket_connect("/api/ws/monitor?token=invalid_garbage_token") as ws:
                pass


def test_websocket_accepts_valid_authenticated_user(test_db_session):
    """Verify that WebSocket accepts connection with valid auth token."""
    user = models.User(
        id=101,
        username="ws_test_user",
        hashed_password="pw",
        role="user",
    )
    test_db_session.add(user)
    test_db_session.commit()

    token = create_access_token({"sub": "ws_test_user"})

    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_db_session.get_bind())

    with patch.object(database, "SessionLocal", TestingSessionLocal):
        with TestClient(app) as client:
            with client.websocket_connect(f"/api/ws/monitor?token={token}") as ws:
                # Connected successfully!
                assert ws is not None


# ============================================================================
# 5. BEHAVIOR BASELINE & THREAT SCORE LEARNING MODE & CORRUPT JSON TESTS
# ============================================================================

def test_behavior_profile_learning_mode_for_new_users():
    """Verify that a user with little or no activity history is marked in learning_mode."""
    user = models.User(id=202, username="newbie", hashed_password="!", role="user")
    serialized = serialize_behavior_profile(user, None)
    assert serialized["learning_mode"] is True

    # User with a fresh profile but < 10 events
    profile = models.BehaviorProfile(
        user_id=202,
        total_logins=2,
        total_application_events=1,
        total_file_events=2,
    )
    serialized_profile = serialize_behavior_profile(user, profile)
    assert serialized_profile["learning_mode"] is True


def test_scoring_engine_indicates_learning_mode():
    """Verify that the ScoringEngine sets learning_mode: True when training samples are sparse."""
    engine = ScoringEngine()
    current_act = {
        "action_type": "file_access",
        "network_activity": 1.2,
        "device": "desktop",
    }
    history = [
        {"action_type": "login", "network_activity": 0.5, "device": "desktop"},
        {"action_type": "app_usage", "network_activity": 0.8, "device": "desktop"},
    ]

    result = engine.evaluate_threat(user_id=1, current_activity=current_act, recent_activities=history)
    assert result["learning_mode"] is True
    assert result["learning_state"]["learning_mode"] is True


def test_corrupt_json_fallback_safe():
    """Verify that corrupt JSON strings in behavior profile fields fall back safely without crashing."""
    corrupt_str = "{bad: json... non_existent_token"
    dict_res = _load_json_dict(corrupt_str)
    assert dict_res == {}

    list_res = _load_json_list(corrupt_str)
    assert list_res == []

    parse_res = _parse_json(corrupt_str)
    assert parse_res is None


# ============================================================================
# 6. MARKOV SEQUENCE MODEL (RENAMED FROM LSTM) TESTS
# ============================================================================

def test_markov_sequence_analyzer():
    """Verify that SequenceAnalyzer works as a Markov sequence model."""
    analyzer = SequenceAnalyzer()
    history = ["login", "app_usage", "file_access", "file_access", "app_usage"]

    # Normal sequence
    score_normal = analyzer.predict_sequence_anomaly(["app_usage", "file_access"], history)
    # Rare out-of-order sequence
    score_abnormal = analyzer.predict_sequence_anomaly(["usb_insertion", "file_transfer"], history)

    assert score_abnormal > score_normal


def test_zero_occurrences_of_lstm_in_source_code():
    """Verify that zero files or contents contain 'lstm' (case-insensitive) across project source files."""
    matched_names = []
    matched_contents = []
    for root, dirs, files in os.walk("."):
        if any(x in root for x in ("node_modules", ".git", "build", "dist", "release", "build-resources", "__pycache__", "tests", ".gemini", "scratch")):
            continue
        for f in files:
            if "lstm" in f.lower():
                matched_names.append(os.path.join(root, f))
            if f.endswith((".py", ".js", ".jsx", ".html", ".md", ".json", ".txt")):
                p = os.path.join(root, f)
                try:
                    for idx, line in enumerate(open(p, "r", encoding="utf-8", errors="ignore")):
                        if "lstm" in line.lower():
                            matched_contents.append((p, idx + 1, line.strip()))
                except Exception:
                    pass

    assert len(matched_names) == 0, f"Found files with 'lstm' in their name: {matched_names}"
    assert len(matched_contents) == 0, f"Found lines with 'lstm' in content: {matched_contents}"


# ============================================================================
# 7. PHISHING CHECKER TESTS
# ============================================================================

def test_phishing_checker_input_length_limit():
    """Verify that inputs exceeding MAX_TEXT_LENGTH (50,000) are truncated safely."""
    huge_text = "URGENT NOTICE! Verify your account immediately! " + ("A" * 60000)
    res = detector.analyze_text(huge_text)
    assert res is not None
    assert any("truncated" in indicator.lower() for indicator in res["indicators"])


def test_phishing_checker_try_except_fallback():
    """Verify that unexpected exceptions in phishing analysis fall back gracefully without raising."""
    p_detector = PhishingDetector()
    with patch("re.findall", side_effect=RuntimeError("Regex engine failure")):
        res = p_detector.analyze_text("Some text")
        assert res["score"] == 0
        assert res["is_phishing"] is False
        assert any("fallback" in ind.lower() for ind in res["indicators"])
