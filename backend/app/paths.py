import os
import sys
from pathlib import Path


def get_appdata_dir() -> Path:
    """Return %APPDATA%\\AIFirewall root directory, creating it if needed."""
    appdata = os.environ.get("APPDATA") or os.path.expanduser("~\\AppData\\Roaming")
    p = Path(appdata) / "AIFirewall"
    p.mkdir(parents=True, exist_ok=True)
    return p


def get_database_path() -> Path:
    """Return default SQLite database file path in AppData."""
    return get_appdata_dir() / "aifirewall.db"


def get_database_url() -> str:
    """Return SQLite database URL pointing to AppData."""
    env_url = os.getenv("DATABASE_URL")
    if env_url:
        return env_url
    return f"sqlite:///{get_database_path()}"


def get_logs_dir() -> Path:
    """Return logs directory in AppData."""
    p = get_appdata_dir() / "logs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def get_quarantine_dir() -> Path:
    """Return quarantine directory in AppData."""
    p = get_appdata_dir() / "quarantine"
    p.mkdir(parents=True, exist_ok=True)
    return p


def get_keys_dir() -> Path:
    """Return encryption keys directory in AppData."""
    p = get_appdata_dir() / "keys"
    p.mkdir(parents=True, exist_ok=True)
    return p


def get_backups_dir() -> Path:
    """Return backups directory in AppData."""
    p = get_appdata_dir() / "backups"
    p.mkdir(parents=True, exist_ok=True)
    return p


def get_runtime_port_file() -> Path:
    """Return runtime port tracking JSON file path in AppData."""
    return get_appdata_dir() / "runtime_port.json"


def get_resource_path(relative_path: str) -> Path:
    """
    Load read-only application asset files (malware_signatures.json, models, .ps1).
    Works in source tree and inside a PyInstaller frozen build (one-folder / one-file).
    """
    rel = Path(relative_path)
    if getattr(sys, "frozen", False):
        if hasattr(sys, "_MEIPASS"):
            base_dir = Path(sys._MEIPASS)
        else:
            base_dir = Path(sys.executable).parent
    else:
        # Dev source tree: repository root is 2 levels up from backend/app
        base_dir = Path(__file__).resolve().parent.parent.parent

    # Try direct relative to base_dir
    target = (base_dir / rel).resolve()
    if target.exists():
        return target

    # Try relative to base_dir / backend
    target_backend = (base_dir / "backend" / rel).resolve()
    if target_backend.exists():
        return target_backend

    # If rel starts with "backend", try without "backend" prefix
    if len(rel.parts) > 1 and rel.parts[0] == "backend":
        sub_rel = Path(*rel.parts[1:])
        target_sub = (base_dir / sub_rel).resolve()
        if target_sub.exists():
            return target_sub

    return target
