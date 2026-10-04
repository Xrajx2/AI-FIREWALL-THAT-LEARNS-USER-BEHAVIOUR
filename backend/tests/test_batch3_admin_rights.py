import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

backend_dir = str(Path(__file__).resolve().parent.parent)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.admin_utils import is_admin, admin_required_response
from app.main import app, PROTECTED_PROCESS_NAMES, get_current_user, require_admin
from app.models import User
from app.website_blocker import WebsiteBlockerEngine, validate_block_domain, BLOCK_MARKER
from app.desktop_security import desktop_security_service, FirewallRuleRequest
from security.traffic_controller import TrafficController


@pytest.fixture(scope="module")
def mock_admin_user():
    return User(id=1, username="admin_tester", role="admin", is_active=True, is_locked=False)


@pytest.fixture(scope="module")
def client(mock_admin_user):
    app.dependency_overrides[get_current_user] = lambda: mock_admin_user
    app.dependency_overrides[require_admin] = lambda: mock_admin_user
    test_client = TestClient(app)
    yield test_client
    app.dependency_overrides.clear()


def test_is_admin_helper_and_response_schema():
    """Verify is_admin() returns boolean and admin_required_response matches standard schema"""
    admin_state = is_admin()
    assert isinstance(admin_state, bool)

    resp = admin_required_response("Firewall rule management")
    assert resp["error"] == "admin_required"
    assert "Administrator" in resp["message"]


def test_protected_process_list():
    """Verify critical system processes are in PROTECTED_PROCESS_NAMES"""
    required_protected = {"system", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe"}
    for proc in required_protected:
        assert proc in PROTECTED_PROCESS_NAMES, f"{proc} must be in PROTECTED_PROCESS_NAMES"


def test_process_kill_prevents_critical_processes(client):
    """Killing critical system processes or the app's own process is blocked with 403"""
    # 1. App's own backend PID
    own_pid = os.getpid()
    r_own = client.post("/api/traffic-monitor/disconnect", json={"pid": own_pid})
    assert r_own.status_code == 403
    assert r_own.json()["detail"]["error"] == "protected_process"
    assert "backend itself" in r_own.json()["detail"]["message"].lower()

    # 2. System PID (PID 4 or PID 0)
    r_sys = client.post("/api/traffic-monitor/disconnect", json={"pid": 4})
    assert r_sys.status_code == 403
    assert r_sys.json()["detail"]["error"] == "protected_process"

    # 3. Process named csrss.exe
    mock_proc = MagicMock()
    mock_proc.name.return_value = "csrss.exe"
    with patch("psutil.Process", return_value=mock_proc):
        r_csrss = client.post("/api/traffic-monitor/disconnect", json={"pid": 9999})
        assert r_csrss.status_code == 403
        assert r_csrss.json()["detail"]["error"] == "protected_process"


def test_process_kill_handles_no_such_process_and_access_denied(client):
    """Catch psutil.NoSuchProcess (404) and psutil.AccessDenied (403 admin_required)"""
    import psutil

    # 1. NoSuchProcess
    with patch("psutil.Process", side_effect=psutil.NoSuchProcess(pid=999999)):
        r_gone = client.post("/api/traffic-monitor/disconnect", json={"pid": 999999})
        assert r_gone.status_code == 404
        assert r_gone.json()["detail"]["error"] == "not_found"

    # 2. AccessDenied
    mock_proc = MagicMock()
    mock_proc.name.return_value = "unprivileged_victim.exe"
    mock_proc.terminate.side_effect = psutil.AccessDenied(pid=1234)
    with patch("psutil.Process", return_value=mock_proc):
        r_denied = client.post("/api/traffic-monitor/disconnect", json={"pid": 1234})
        assert r_denied.status_code == 403
        assert r_denied.json()["detail"]["error"] == "admin_required"


def test_netsh_firewall_prefix_and_admin_check():
    """Verify rule prefix AIFirewall- and admin_required rejection when not elevated"""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_db:
        tmp_db_path = tmp_db.name

    try:
        tc = TrafficController(db_path=tmp_db_path)

        with patch("security.traffic_controller.is_admin", return_value=False):
            res = tc.add_rule(
                rule_name="CUSTOM_TEST",
                direction="out",
                action="block"
            )
            assert res["success"] is False
            assert res["error"] == "admin_required"

        # Verify rule name prefix starts with AIFirewall-
        with patch("security.traffic_controller.is_admin", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stderr = ""
            mock_run.return_value.stdout = ""
            res_ok = tc.add_rule(
                rule_name="CUSTOM_TEST",
                direction="out",
                action="block"
            )
            assert res_ok["success"] is True
            # Check command sent to subprocess
            called_cmd = mock_run.call_args[0][0]
            rule_arg = [arg for arg in called_cmd if arg.startswith("name=")][0]
            assert rule_arg.startswith("name=AIFirewall-"), f"Rule name must start with AIFirewall-, got {rule_arg}"
    finally:
        if os.path.exists(tmp_db_path):
            try:
                os.remove(tmp_db_path)
            except Exception:
                pass


def test_firewall_endpoints_return_403_when_not_admin(client):
    """POST and DELETE /api/desktop/firewall/rules return 403 admin_required if not admin"""
    with patch("app.main.is_admin", return_value=False):
        r_post = client.post(
            "/api/desktop/firewall/rules",
            json={"application_path": "C:\\test\\app.exe", "action": "block"}
        )
        assert r_post.status_code == 403
        assert r_post.json()["detail"]["error"] == "admin_required"

        r_del = client.delete("/api/desktop/firewall/rules/999")
        assert r_del.status_code == 403
        assert r_del.json()["detail"]["error"] == "admin_required"


def test_hosts_domain_validation():
    """Domain validator rejects spaces, newlines, '#', and IP strings"""
    # Invalid: spaces
    ok, err = validate_block_domain("bad domain.com")
    assert ok is False
    assert "spaces" in err.lower()

    # Invalid: newlines / tabs
    ok, err = validate_block_domain("evil.com\n127.0.0.1 hacked.local")
    assert ok is False

    # Invalid: hash comments
    ok, err = validate_block_domain("evil.com#comment")
    assert ok is False

    # Invalid: IP address literals
    ok, err = validate_block_domain("192.168.1.1")
    assert ok is False
    assert "ip address" in err.lower()

    # Valid domain
    ok, err = validate_block_domain("malicious-phishing-site.xyz")
    assert ok is True
    assert err is None


def test_hosts_file_backup_and_safe_atomic_write():
    """Hosts file is backed up before every edit and written via temp file replacement"""
    with tempfile.TemporaryDirectory() as tmpdir:
        fake_hosts = os.path.join(tmpdir, "hosts")
        initial_content = "127.0.0.1 localhost\n::1 localhost\n192.168.1.50 custom-intranet.local\n"
        with open(fake_hosts, "w", encoding="utf-8") as f:
            f.write(initial_content)

        engine = WebsiteBlockerEngine(hosts_path=fake_hosts)

        # Block domain
        res_block = engine.block_domain_os_level("phishing-test.com")
        assert res_block["success"] is True

        # Check content: new domain added with marker
        with open(fake_hosts, "r", encoding="utf-8") as f:
            content_after = f.read()
        assert "127.0.0.1 phishing-test.com # AIFirewall-Block:" in content_after or "127.0.0.1 phishing-test.com # AI-FIREWALL-BLOCK:" in content_after
        # Custom line preserved
        assert "192.168.1.50 custom-intranet.local" in content_after

        # Verify backup was created in backup dir
        backup_dir = engine._get_backup_dir()
        backups = [f for f in os.listdir(backup_dir) if f.startswith("hosts.bak.")]
        assert len(backups) >= 1
        assert len(backups) <= 5


def test_hosts_unblock_removes_only_marked_lines():
    """Unblocking removes ONLY lines with # AI-FIREWALL-BLOCK: and keeps user custom entries"""
    with tempfile.TemporaryDirectory() as tmpdir:
        fake_hosts = os.path.join(tmpdir, "hosts")
        test_content = (
            "127.0.0.1 localhost\n"
            "10.0.0.1 internal-server.com # User custom comment\n"
            "127.0.0.1 target-site.com # AI-FIREWALL-BLOCK: target-site.com\n"
            "127.0.0.1 www.target-site.com # AI-FIREWALL-BLOCK: target-site.com\n"
            "192.168.1.10 target-site.com # Important custom intranet entry\n"
        )
        with open(fake_hosts, "w", encoding="utf-8") as f:
            f.write(test_content)

        engine = WebsiteBlockerEngine(hosts_path=fake_hosts)
        res_unblock = engine.unblock_domain_os_level("target-site.com")
        assert res_unblock["success"] is True

        with open(fake_hosts, "r", encoding="utf-8") as f:
            remaining = f.read()

        # Marked lines removed
        assert "# AI-FIREWALL-BLOCK: target-site.com" not in remaining
        # Crucial: Unmarked custom entry must NOT be deleted even if it shares the domain!
        assert "192.168.1.10 target-site.com # Important custom intranet entry" in remaining
        assert "10.0.0.1 internal-server.com # User custom comment" in remaining


def test_hosts_unblock_removes_both_old_and_new_markers():
    """Unblocking removes BOTH old (# AI-FIREWALL-BLOCK:) and new (# AIFirewall-Block:) markers."""
    with tempfile.TemporaryDirectory() as tmpdir:
        fake_hosts = os.path.join(tmpdir, "hosts")
        test_content = (
            "127.0.0.1 localhost\n"
            "127.0.0.1 old-bad-site.com # AI-FIREWALL-BLOCK: old-bad-site.com\n"
            "127.0.0.1 new-bad-site.com # AIFirewall-Block: new-bad-site.com\n"
            "192.168.1.50 safe-intranet.com # Important system entry\n"
        )
        with open(fake_hosts, "w", encoding="utf-8") as f:
            f.write(test_content)

        engine = WebsiteBlockerEngine(hosts_path=fake_hosts)
        res1 = engine.unblock_domain_os_level("old-bad-site.com")
        assert res1["success"] is True

        res2 = engine.unblock_domain_os_level("new-bad-site.com")
        assert res2["success"] is True

        with open(fake_hosts, "r", encoding="utf-8") as f:
            remaining = f.read()

        assert "old-bad-site.com" not in remaining
        assert "new-bad-site.com" not in remaining
        assert "192.168.1.50 safe-intranet.com # Important system entry" in remaining


def test_hosts_write_permission_error_returns_clean_admin_required():
    """If hosts write raises PermissionError, returns clean admin_required without crashing"""
    with tempfile.TemporaryDirectory() as tmpdir:
        fake_hosts = os.path.join(tmpdir, "hosts")
        with open(fake_hosts, "w", encoding="utf-8") as f:
            f.write("127.0.0.1 localhost\n")

        engine = WebsiteBlockerEngine(hosts_path=fake_hosts)

        # Mock permission error on writing
        with patch.object(engine, "_safe_write_hosts", return_value=(False, "admin_required")):
            res = engine.block_domain_os_level("malicious-attack.xyz")
            assert res["success"] is False
            assert res["error"] == "admin_required"
            assert "Administrator" in res["message"]


def test_socket_sniffer_falls_back_to_per_process_on_access_denied():
    """If psutil.net_connections raises AccessDenied, falls back to per-process connections and flags limited view"""
    import psutil
    from collections import namedtuple

    Conn = namedtuple("Conn", ["status", "laddr", "raddr"])
    Addr = namedtuple("Addr", ["ip", "port"])

    mock_conn = Conn(status="ESTABLISHED", laddr=Addr("127.0.0.1", 5000), raddr=Addr("93.184.216.34", 443))

    # Mock process with connections
    mock_proc = MagicMock()
    mock_proc.info = {"pid": 4321, "name": "browser.exe"}
    mock_proc.connections.return_value = [mock_conn]

    with patch("psutil.net_connections", side_effect=psutil.AccessDenied(pid=0)), \
         patch("psutil.process_iter", return_value=[mock_proc]):

        snapshot = desktop_security_service.get_traffic_snapshot()
        assert snapshot["is_limited_view"] is True
        assert "limited view (run as Administrator)" in snapshot["view_mode"]
        assert len(snapshot["connections"]) >= 1
        assert snapshot["connections"][0]["remote_ip"] == "93.184.216.34"
        assert snapshot["connections"][0]["process"] == "browser.exe"
