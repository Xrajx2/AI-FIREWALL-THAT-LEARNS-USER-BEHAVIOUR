import os
import sys
import threading
import time
import passlib.handlers.bcrypt
import uvicorn
from app.main import app


def start_parent_watchdog():
    """
    Monitors parent Electron process. If parent process is killed or crashes,
    terminates the backend immediately to prevent orphan processes.
    """
    try:
        parent_pid = int(os.environ.get("AI_FIREWALL_PARENT_PID", "0"))
    except Exception:
        parent_pid = 0

    if not parent_pid:
        try:
            import psutil
            parent_pid = psutil.Process().ppid()
        except Exception:
            parent_pid = 0

    if not parent_pid or parent_pid <= 4:
        return

    def _watchdog_loop():
        # Primary Windows method: kernel wait on parent process handle with SYNCHRONIZE
        if os.name == "nt":
            try:
                import ctypes
                SYNCHRONIZE = 0x00100000
                h_proc = ctypes.windll.kernel32.OpenProcess(SYNCHRONIZE, False, parent_pid)
                if h_proc:
                    # Blocks with 0 CPU overhead until parent process terminates
                    ctypes.windll.kernel32.WaitForSingleObject(h_proc, 0xFFFFFFFF)
                    ctypes.windll.kernel32.CloseHandle(h_proc)
                    os._exit(0)
            except Exception:
                pass

        # Fallback polling method using psutil
        try:
            import psutil
            proc = psutil.Process(parent_pid)
            while proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
                time.sleep(1)
            os._exit(0)
        except Exception:
            os._exit(0)

    t = threading.Thread(target=_watchdog_loop, name="ParentWatchdog", daemon=True)
    t.start()


def main():
    start_parent_watchdog()
    try:
        from app.paths import get_database_url
    except ImportError:
        from backend.app.paths import get_database_url

    os.environ.setdefault("AI_FIREWALL_DESKTOP", "1")
    os.environ.setdefault("DATABASE_URL", get_database_url())
    os.environ.setdefault("MONITOR_INTERVAL_SECONDS", "5")
    port = int(os.getenv("AI_FIREWALL_PORT", "8000"))
    host = os.getenv("AI_FIREWALL_HOST", "127.0.0.1")
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
