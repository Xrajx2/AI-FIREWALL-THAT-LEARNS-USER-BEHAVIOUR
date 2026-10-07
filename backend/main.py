import ctypes
import os
import sys
from pathlib import Path

if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")

# Prevent joblib/loky from executing PowerShell to probe CPU cores on Windows
os.environ.setdefault("LOKY_MAX_CPU_COUNT", str(os.cpu_count() or 4))
try:
    import joblib.externals.loky.backend.context as loky_context
    loky_context.physical_cores_cache = os.cpu_count() or 4
except Exception:
    pass

# Add backend directory to sys.path
backend_dir = str(Path(__file__).resolve().parent)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def ensure_admin():
    if os.name == 'nt' and not is_admin() and not os.environ.get("AI_FIREWALL_NO_UAC"):
        try:
            if getattr(sys, 'frozen', False):
                exe = sys.executable
                args = " ".join([f'"{a}"' for a in sys.argv[1:]])
            else:
                exe = sys.executable
                args = " ".join([f'"{a}"' for a in sys.argv])
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, args, None, 1)
            if ret > 32:
                sys.exit(0)
        except Exception as e:
            print(f"Elevation warning: {e}", file=sys.stderr)

def find_available_port(preferred_port: int, host: str = "127.0.0.1") -> int:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, preferred_port))
            return preferred_port
        except OSError:
            pass
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]

def record_runtime_port(port: int, host: str):
    import json
    from datetime import datetime, timezone
    try:
        from app.paths import get_runtime_port_file
    except ImportError:
        from backend.app.paths import get_runtime_port_file

    payload = {
        "port": port,
        "host": host,
        "url": f"http://{host}:{port}",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    try:
        port_file = get_runtime_port_file()
        with open(port_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
    except Exception:
        pass

def start_parent_watchdog():
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
        if os.name == "nt":
            try:
                import ctypes
                SYNCHRONIZE = 0x00100000
                h_proc = ctypes.windll.kernel32.OpenProcess(SYNCHRONIZE, False, parent_pid)
                if h_proc:
                    ctypes.windll.kernel32.WaitForSingleObject(h_proc, 0xFFFFFFFF)
                    ctypes.windll.kernel32.CloseHandle(h_proc)
                    os._exit(0)
            except Exception:
                pass
        try:
            import psutil
            proc = psutil.Process(parent_pid)
            while proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
                import time
                time.sleep(1)
            os._exit(0)
        except Exception:
            os._exit(0)

    import threading
    t = threading.Thread(target=_watchdog_loop, name="ParentWatchdog", daemon=True)
    t.start()

def main():
    start_parent_watchdog()
    ensure_admin()
    try:
        from app.paths import get_database_url
    except ImportError:
        from backend.app.paths import get_database_url

    os.environ.setdefault("AI_FIREWALL_DESKTOP", "1")
    os.environ.setdefault("DATABASE_URL", get_database_url())
    os.environ.setdefault("MONITOR_INTERVAL_SECONDS", "30")

    import uvicorn
    import passlib.handlers.bcrypt  # Pre-import bcrypt for PyInstaller bundler
    from app.main import app

    preferred_port = int(os.getenv("AI_FIREWALL_PORT", "8000"))
    host = os.getenv("AI_FIREWALL_HOST", "127.0.0.1")
    port = find_available_port(preferred_port, host)
    os.environ["AI_FIREWALL_PORT"] = str(port)
    record_runtime_port(port, host)

    print(f"[AI Firewall Backend] Starting on http://{host}:{port} (Admin: {is_admin()})", flush=True)
    uvicorn.run(app, host=host, port=port, log_level="info")

if __name__ == "__main__":
    main()
