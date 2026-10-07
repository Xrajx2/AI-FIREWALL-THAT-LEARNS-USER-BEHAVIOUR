import logging
import os
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger("ai_firewall.process_utils")

# Thread-safe launch tracking counter
_stats_lock = threading.Lock()
_launch_stats: Dict[str, Any] = {
    "total": 0,
    "by_command": {},
    "by_caller": {},
    "launches": [],
}


def get_launch_stats() -> Dict[str, Any]:
    with _stats_lock:
        return {
            "total": _launch_stats["total"],
            "by_command": dict(_launch_stats["by_command"]),
            "by_caller": dict(_launch_stats["by_caller"]),
            "launches_count": len(_launch_stats["launches"]),
        }


def reset_launch_stats():
    with _stats_lock:
        _launch_stats["total"] = 0
        _launch_stats["by_command"].clear()
        _launch_stats["by_caller"].clear()
        _launch_stats["launches"].clear()


def run_hidden(
    cmd: Union[List[str], str],
    *,
    timeout: float = 15.0,
    check: bool = False,
    capture_output: bool = True,
    text: bool = True,
    shell: bool = False,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    **kwargs: Any,
) -> subprocess.CompletedProcess:
    """
    Executes a subprocess hidden from view on Windows with CREATE_NO_WINDOW and SW_HIDE.
    Always enforces a timeout and logs the launch at DEBUG level (command and caller only).
    """
    # Identify caller (file:func)
    caller = "unknown"
    try:
        frame = sys._getframe(1)
        caller = f"{os.path.basename(frame.f_code.co_filename)}:{frame.f_code.co_name}"
    except Exception:
        pass

    # Extract command binary name safely without any sensitive arguments
    if isinstance(cmd, (list, tuple)) and cmd:
        cmd_name = str(cmd[0])
    elif isinstance(cmd, str):
        cmd_name = cmd.strip().split()[0] if cmd.strip() else "unknown"
    else:
        cmd_name = "unknown"
    cmd_name = os.path.basename(cmd_name)

    # Track metrics
    with _stats_lock:
        _launch_stats["total"] += 1
        _launch_stats["by_command"][cmd_name] = _launch_stats["by_command"].get(cmd_name, 0) + 1
        _launch_stats["by_caller"][caller] = _launch_stats["by_caller"].get(caller, 0) + 1
        _launch_stats["launches"].append(
            {"timestamp": time.time(), "command": cmd_name, "caller": caller}
        )
        # Keep launch history bounded
        if len(_launch_stats["launches"]) > 1000:
            _launch_stats["launches"] = _launch_stats["launches"][-500:]

    logger.debug("Child process launch: cmd=%s caller=%s (total=%d)", cmd_name, caller, _launch_stats["total"])

    # Configure hidden window flags on Windows
    creationflags = kwargs.pop("creationflags", 0)
    startupinfo = kwargs.pop("startupinfo", None)

    if os.name == "nt":
        creationflags |= subprocess.CREATE_NO_WINDOW
        if startupinfo is None:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0  # SW_HIDE

    # Always ensure a timeout is set
    effective_timeout = timeout if (timeout is not None and timeout > 0) else 15.0

    return subprocess.run(
        cmd,
        timeout=effective_timeout,
        check=check,
        capture_output=capture_output,
        text=text,
        shell=shell,
        cwd=cwd,
        env=env,
        creationflags=creationflags,
        startupinfo=startupinfo,
        **kwargs,
    )
