import os
import sys
import tempfile
import subprocess
from unittest.mock import patch, MagicMock

# Ensure backend directory is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.process_utils import run_hidden, get_launch_stats, reset_launch_stats


def test_run_hidden_applies_create_no_window_and_sw_hide():
    """Verify run_hidden unconditionally sets CREATE_NO_WINDOW and SW_HIDE on Windows"""
    with patch("subprocess.run") as mock_sub_run:
        mock_sub_run.return_value = MagicMock(returncode=0, stdout="mock_output", stderr="")
        res = run_hidden(["testcmd", "arg1"], timeout=10)
        assert res.stdout == "mock_output"
        assert mock_sub_run.called

        kwargs = mock_sub_run.call_args[1]
        assert kwargs.get("timeout") == 10
        assert kwargs.get("capture_output") is True
        assert kwargs.get("text") is True

        if os.name == "nt":
            creationflags = kwargs.get("creationflags", 0)
            assert (creationflags & subprocess.CREATE_NO_WINDOW) != 0, "CREATE_NO_WINDOW flag must be set!"
            startupinfo = kwargs.get("startupinfo")
            assert startupinfo is not None, "startupinfo must be provided on Windows!"
            assert (startupinfo.dwFlags & subprocess.STARTF_USESHOWWINDOW) != 0, "STARTF_USESHOWWINDOW must be set!"
            assert startupinfo.wShowWindow == 0, "wShowWindow must be 0 (SW_HIDE)!"


def test_launch_stats_tracking_and_no_secrets_in_logs():
    """Verify launch stats counts commands and callers without leaking arguments/secrets"""
    reset_launch_stats()
    with patch("subprocess.run") as mock_sub_run:
        mock_sub_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        run_hidden(["netsh", "advfirewall", "firewall", "secret_arg_12345"])
        run_hidden(["powershell", "-NoProfile", "secret_code_xyz"])

    stats = get_launch_stats()
    assert stats["total"] == 2
    assert "netsh" in stats["by_command"]
    assert "powershell" in stats["by_command"]
    # Ensure raw secret arguments are NOT keys in by_command
    assert "secret_arg_12345" not in stats["by_command"]
    assert "secret_code_xyz" not in stats["by_command"]


def test_website_blocker_calls_run_hidden_mocked():
    """Verify website blocker dns flush and netsh rules route through run_hidden (Mocked)"""
    from app.website_blocker import WebsiteBlockerEngine
    blocker = WebsiteBlockerEngine()
    with patch("app.process_utils.run_hidden") as mock_run_hidden:
        mock_run_hidden.return_value = MagicMock(returncode=0, stdout="", stderr="")
        blocker._flush_dns_cache()
        assert mock_run_hidden.called
        call_cmd = mock_run_hidden.call_args[0][0]
        assert "ipconfig" in call_cmd[0] or "flushdns" in call_cmd


def test_traffic_controller_calls_run_hidden_mocked():
    """Verify traffic controller rules route through run_hidden (Mocked)"""
    from security.traffic_controller import TrafficController
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_db:
        tmp_db_path = tmp_db.name
        tmp_db.close()
    try:
        tc = TrafficController(db_path=tmp_db_path)
        with patch("security.traffic_controller.is_admin", return_value=True), \
             patch("app.process_utils.run_hidden") as mock_run_hidden:
            mock_run_hidden.return_value = MagicMock(returncode=0, stdout="", stderr="")
            res = tc.add_rule("UNIT_TEST_RULE", "out", "block", protocol="tcp", remote_ip="1.2.3.4")
            assert res.get("success") is True
            assert mock_run_hidden.called
            call_cmd = mock_run_hidden.call_args[0][0]
            assert call_cmd[0] == "netsh"
    finally:
        try:
            if os.path.exists(tmp_db_path):
                os.remove(tmp_db_path)
        except Exception:
            pass


def test_block_manager_calls_run_hidden_mocked():
    """Verify block manager IP and domain routines route through run_hidden (Mocked)"""
    from security.block_manager import BlockManager
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp_db:
        tmp_db_path = tmp_db.name
        tmp_db.close()
    try:
        bm = BlockManager(db_path=tmp_db_path)
        with patch("app.process_utils.run_hidden") as mock_run_hidden:
            mock_run_hidden.return_value = MagicMock(returncode=0, stdout="", stderr="")
            bm._block_ip_firewall("192.0.2.1", "test reason")
            assert mock_run_hidden.called
            call_cmd = mock_run_hidden.call_args[0][0]
            assert call_cmd[0] == "netsh"
    finally:
        try:
            if os.path.exists(tmp_db_path):
                os.remove(tmp_db_path)
        except Exception:
            pass
