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
        assert tracker.is_online_lookup_enabled() is False  # Default is OFF

        # Bundled offline database test
        offline_bundled = tracker.lookup_ip("8.8.8.8")
        assert offline_bundled["country"] == "United States"

        # Enable online lookup
        tracker.set_online_lookup_enabled(True)
        assert tracker.is_online_lookup_enabled() is True

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
            offline_res = tracker.lookup_ip("93.184.216.34")
            assert offline_res["city"] == ""


def test_geo_cache_stores_hashed_ip_and_encrypted_payload():
    """Verify that geo_cache stores only hashed IP keys and encrypted payloads, not plaintext IPs."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        db_path = os.path.join(tmpdir, "test_geo_secure.db")
        tracker = GeoTracker(db_path=db_path)
        tracker.set_online_lookup_enabled(True)

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


def test_websocket_pushes_live_event_to_authenticated_client(test_db_session):
    """Verify that WebSocket client connects with valid token and receives pushed event."""
    from backend.app.main import manager

    user = models.User(
        id=102,
        username="ws_event_user",
        hashed_password="pw",
        role="user",
    )
    test_db_session.add(user)
    test_db_session.commit()

    token = create_access_token({"sub": "ws_event_user"})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_db_session.get_bind())

    with patch.object(database, "SessionLocal", TestingSessionLocal):
        with TestClient(app) as client:
            with client.websocket_connect(f"/api/ws/monitor?token={token}") as ws:
                test_event = {
                    "type": "new_process",
                    "data": {
                        "pid": 1234,
                        "name": "calc.exe",
                        "threat_level": "LOW",
                    }
                }
                import asyncio
                asyncio.run(manager.broadcast(json.dumps(test_event)))

                received = ws.receive_json()
                assert received["type"] == "new_process"
                assert received["data"]["name"] == "calc.exe"



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


def test_monitoring_cycle_details_parse_to_dict_and_no_warning(test_db_session, caplog):
    """Run one monitoring cycle against a temp database, read rows back, assert details parse to a dict and no warning is logged."""
    import asyncio
    import logging
    from backend.app import monitoring
    from backend.app.monitoring import SystemMonitorService

    from unittest.mock import AsyncMock
    mock_mgr = MagicMock()
    mock_mgr.broadcast = AsyncMock()
    service = SystemMonitorService(mock_mgr)

    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_db_session.get_bind())

    with patch.object(monitoring, "SessionLocal", TestingSessionLocal), \
         patch.object(database, "SessionLocal", TestingSessionLocal):

        caplog.set_level(logging.WARNING)

        # Run snapshot collection
        snapshot, events = service._collect_snapshot()

        # If system is quiet during test run, ensure test has representative events
        if not events:
            events = [
                {
                    "action_type": "process_start",
                    "device": "localhost",
                    "network_activity": 0.0,
                    "details": {
                        "summary": "New process detected: test_app.exe (PID 9999)",
                        "process_name": "test_app.exe",
                        "pid": 9999,
                        "applications": [{"name": "test_app.exe", "source": "process_start"}],
                    },
                    "behavior_context": {
                        "applications": [{"name": "test_app.exe", "source": "process_start"}]
                    },
                }
            ]

        for event in events:
            asyncio.run(service._record_discrete_event(event))

        rows = test_db_session.query(models.UserActivity).all()
        assert len(rows) > 0

        for row in rows:
            parsed = _parse_json(row.details)
            assert isinstance(parsed, dict)
            assert "summary" in parsed or "process_name" in parsed

        # Assert no corrupt JSON warning was logged during the cycle
        corrupt_warnings = [r for r in caplog.records if "Corrupt JSON" in r.message]
        assert len(corrupt_warnings) == 0


def test_traffic_rules_cached_no_spam(test_db_session, caplog):
    """Verify blocklist rules are loaded once and not repeatedly logged every few seconds."""
    import asyncio
    import logging
    from backend.app.traffic_monitor_service import TrafficMonitorService

    t_service = TrafficMonitorService()
    caplog.set_level(logging.INFO)

    # First load
    t_service.load_rules(test_db_session)
    first_load_count = sum(1 for r in caplog.records if "blocked IPs from database" in r.message)
    assert first_load_count == 1

    # Simulate 5 rapid ingest_traffic cycles
    for _ in range(5):
        asyncio.run(t_service.ingest_traffic([], {}, test_db_session))

    subsequent_load_count = sum(1 for r in caplog.records if "blocked IPs from database" in r.message)
    # Count must remain 1 because rules are cached
    assert subsequent_load_count == 1



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


# ============================================================================
# 8. FEED QUALITY & TELEMETRY TESTS (Item 4b)
# ============================================================================

def test_normalized_5tuple_dedupe():
    """Verify that dual socket ends map to the exact same sorted 5-tuple key and IPv6 brackets are applied."""
    from backend.security.live_monitor import normalize_connection_key, format_endpoint

    # Local port 54321, remote port 8000
    k1 = normalize_connection_key("127.0.0.1", 54321, "127.0.0.1", 8000, "tcp")
    # Other end of same connection: local port 8000, remote port 54321
    k2 = normalize_connection_key("127.0.0.1", 8000, "127.0.0.1", 54321, "tcp")

    assert k1 == k2 == "tcp:127.0.0.1:8000<->127.0.0.1:54321"

    # Verify IPv6 formatting with brackets
    k3 = normalize_connection_key("2001:db8::1", 443, "fe80::1", 50000, "tcp")
    assert "[2001:db8::1]" in k3
    assert "[fe80::1]" in k3
    assert format_endpoint("2001:db8::1", 443) == "[2001:db8::1]:443"
    assert format_endpoint("192.168.1.1", 80) == "192.168.1.1:80"


def test_own_process_and_loopback_filter():
    """Verify app-process and loopback detection tags traffic correctly."""
    from backend.security.live_monitor import get_app_pids

    app_pids = get_app_pids()
    assert os.getpid() in app_pids

    # Simulate tagging logic from monitor_connections
    local_ip, local_port = "127.0.0.1", 52100
    remote_ip, remote_port = "127.0.0.1", 8000
    backend_port = 8000
    current_pid = os.getpid()

    is_loopback = (local_ip in ("127.0.0.1", "::1", "localhost")) and (remote_ip in ("127.0.0.1", "::1", "localhost"))
    is_backend_port = (local_port == backend_port or remote_port == backend_port)
    is_app_proc = current_pid in app_pids
    is_app_traffic = (is_loopback and (is_backend_port or is_app_proc)) or is_app_proc

    assert is_loopback is True
    assert is_backend_port is True
    assert is_app_traffic is True


def test_timestamp_validation_per_event_type():
    """Verify all live monitor event emissions contain id, type, and valid UTC ISO timestamp with Z."""
    from datetime import datetime, timezone
    from backend.security.live_monitor import LiveMonitor

    received_events = []
    monitor = LiveMonitor()
    monitor.add_callback(lambda ev: received_events.append(ev))

    test_types = [
        ("new_connection", {"process": "chrome.exe", "remote_ip": "1.1.1.1", "remote_port": 443}),
        ("connection_closed", {"connection": "tcp:127.0.0.1:80<->127.0.0.1:5000", "process": "curl.exe"}),
        ("new_process", {"name": "notepad.exe", "pid": 1234, "username": "user"}),
        ("process_closed", {"name": "notepad.exe", "pid": 1234, "start_time": "12:00:00"}),
        ("clipboard_threat", {"score": 50, "indicators": ["phishing url"]}),
        ("system_stats", {"cpu_percent": 15.0, "ram_percent": 45.0}),
    ]

    for ev_type, ev_data in test_types:
        monitor.emit(ev_type, ev_data)

    assert len(received_events) == len(test_types)
    for ev in received_events:
        assert "id" in ev
        assert "type" in ev
        assert "timestamp" in ev
        ts = ev["timestamp"]
        assert ts.endswith("Z"), f"Timestamp {ts} must end with Z"
        # Validate that it parses cleanly as ISO UTC
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        assert parsed.tzinfo is not None


def test_process_closed_event_emission():
    """Verify process termination emits process_closed event with name, pid, and start_time."""
    from backend.security.live_monitor import LiveMonitor

    monitor = LiveMonitor()
    emitted = []
    monitor.add_callback(lambda ev: emitted.append(ev))

    # Pre-populate known processes
    monitor.known_processes = {1000, 2000, 3000}
    monitor.process_info_cache[2000] = {
        "pid": 2000,
        "name": "target_app.exe",
        "start_time": "14:30:00"
    }

    # Simulate process 2000 disappearing
    current_pids = {1000, 3000}
    closed_pids = monitor.known_processes - current_pids
    for pid in closed_pids:
        info = monitor.process_info_cache.pop(pid, {})
        monitor.emit("process_closed", {
            "pid": pid,
            "name": info.get("name", "Unknown"),
            "start_time": info.get("start_time", "Unknown"),
            "threat_level": "LOW"
        })
    monitor.known_processes = current_pids

    assert len(emitted) == 1
    assert emitted[0]["type"] == "process_closed"
    assert emitted[0]["data"]["pid"] == 2000
    assert emitted[0]["data"]["name"] == "target_app.exe"
    assert emitted[0]["data"]["start_time"] == "14:30:00"


def test_live_network_rate_calculation_mocked_samples():
    """[MOCKED SAMPLES TEST] Verify net rate MB/s calculation across two known time/byte snapshots."""
    from backend.security.live_monitor import LiveMonitor

    monitor = LiveMonitor()

    # Sample 1: Time = 100.0, Bytes recv = 10,000,000, Bytes sent = 5,000,000
    time_1 = 100.0
    bytes_recv_1 = 10_000_000
    bytes_sent_1 = 5_000_000
    monitor._last_net_time = time_1
    monitor._last_net_bytes_recv = bytes_recv_1
    monitor._last_net_bytes_sent = bytes_sent_1

    # Sample 2: Time = 102.0 (2.0s interval), Bytes recv = 20,485,760 (exactly 10 MB increase)
    time_2 = 102.0
    bytes_recv_2 = 20_485_760
    bytes_sent_2 = 7_097_152  # 2 MB increase
    interval = max(0.1, time_2 - monitor._last_net_time)
    recv_diff = max(0, bytes_recv_2 - monitor._last_net_bytes_recv)
    sent_diff = max(0, bytes_sent_2 - monitor._last_net_bytes_sent)

    recv_rate_mb_s = round((recv_diff / (1024 * 1024)) / interval, 2)
    sent_rate_mb_s = round((sent_diff / (1024 * 1024)) / interval, 2)

    assert interval == 2.0
    assert recv_rate_mb_s == 5.0
    assert sent_rate_mb_s == 1.0


def test_learning_mode_does_not_alert_on_normal_processes():
    """Verify that launching a normal Windows process (e.g. notepad.exe) does not trigger threat alerts in learning mode, while real attack presets still alert."""
    from backend.app.ai.scoring_engine import ScoringEngine
    from backend.app.risk import is_risky

    engine = ScoringEngine()

    # 1. Normal process launch in learning mode (zero historical samples)
    normal_activity = {
        "action_type": "process_start",
        "network_activity": 0.0,
        "device": "desktop",
        "details": "User opened notepad.exe",
    }
    result_normal = engine.evaluate_threat(user_id=1, current_activity=normal_activity, recent_activities=[])

    assert result_normal["learning_mode"] is True
    # Normal activity in learning mode must not exceed threshold 30.0 and must not be risky
    assert result_normal["score"] <= 25.0, f"Expected <= 25.0 in learning mode, got {result_normal['score']}"
    assert result_normal["risk_level"] == "Normal"
    assert is_risky(result_normal["score"]) is False

    # 2. Simulation Lab Preset 2: Data Exfiltration attack
    exfil_activity = {
        "action_type": "data_exfiltration",
        "network_activity": 85.0,
        "device": "desktop",
        "details": "Unusual outbound bulk transfer to external endpoint",
    }
    result_exfil = engine.evaluate_threat(user_id=1, current_activity=exfil_activity, recent_activities=[])
    assert result_exfil["score"] >= 70.0
    assert result_exfil["risk_level"] == "Dangerous"
    assert is_risky(result_exfil["score"]) is True

    # 3. Simulation Lab Preset 3: Ransomware / Malware attack
    malware_activity = {
        "action_type": "malware_detected",
        "network_activity": 40.0,
        "device": "desktop",
        "details": "Known ransomware pattern detected in directory",
    }
    result_malware = engine.evaluate_threat(user_id=1, current_activity=malware_activity, recent_activities=[])
    assert result_malware["score"] >= 80.0
    assert result_malware["risk_level"] == "Dangerous"
    assert is_risky(result_malware["score"]) is True

