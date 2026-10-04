import os
from pathlib import Path
from backend.app.paths import (
    get_appdata_dir,
    get_logs_dir,
    get_quarantine_dir,
    get_database_path,
    get_database_url,
    get_runtime_port_file,
)


def get_data_dir() -> Path:
    return get_appdata_dir()


def get_runtime_dir() -> Path:
    return get_appdata_dir()


def sqlite_url(path: Path) -> str:
    return f"sqlite:///{str(path.resolve()).replace(os.sep, '/')}"
