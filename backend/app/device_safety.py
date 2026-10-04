from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


BACKEND_ROOT = Path(__file__).resolve().parents[1]

# Use a fixed stable directory so the path is the same whether running from
# source, from a PyInstaller .exe (where __file__ points to a random _MEIXXXX
# temp folder that changes on every restart), or from Docker.
# Override with AI_FIREWALL_DATA_DIR env var if needed.
_configured = os.getenv("AI_FIREWALL_DATA_DIR")
if _configured:
    _DATA_DIR = Path(_configured)
elif os.name == "nt":
    _local = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA") or str(Path.home())
    _DATA_DIR = Path(_local) / "AI Firewall"
else:
    _DATA_DIR = Path.home() / ".ai-firewall"

RUNTIME_DIR = _DATA_DIR / "runtime"
COMMAND_FILE = RUNTIME_DIR / "device_safety_command.json"
STATUS_FILE = RUNTIME_DIR / "device_safety_status.json"


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_runtime_dir() -> Path:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    return RUNTIME_DIR


def atomic_write_json(path: Path, payload: Dict[str, Any]) -> None:
    ensure_runtime_dir()
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    temp_path.replace(path)


def read_json_file(path: Path, default: Dict[str, Any]) -> Dict[str, Any]:
    try:
        if not path.exists():
            return dict(default)
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else dict(default)
    except Exception:
        return dict(default)


def default_device_safety_status() -> Dict[str, Any]:
    return {
        "agent": {
            "running": False,
            "version": None,
            "last_heartbeat_at": None,
            "last_command_id": None,
        },
        "scanner": {
            "state": "idle",
            "live_watch_enabled": False,
            "current_job": None,
            "last_error": None,
        },
        "targets": [],
        "recent_live_events": [],
        "scan_history": [],
        "last_scan": None,
    }


def read_device_safety_status() -> Dict[str, Any]:
    status = default_device_safety_status()
    payload = read_json_file(STATUS_FILE, status)
    if isinstance(payload.get("agent"), dict):
        status["agent"].update(payload["agent"])
        
        # Determine online status on the backend to avoid client clock-drift issues
        last_hb = payload["agent"].get("last_heartbeat_at")
        is_online = bool(payload["agent"].get("running"))
        if last_hb:
            try:
                parsed = datetime.fromisoformat(last_hb)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                diff = abs((now - parsed).total_seconds())
                is_online = diff <= 60.0
            except Exception:
                pass
        status["agent"]["online"] = is_online

    if isinstance(payload.get("scanner"), dict):
        status["scanner"].update(payload["scanner"])
    for key in ("targets", "recent_live_events", "scan_history"):
        value = payload.get(key)
        if isinstance(value, list):
            status[key] = value
    if isinstance(payload.get("last_scan"), dict) or payload.get("last_scan") is None:
        status["last_scan"] = payload.get("last_scan")
    return status


def write_device_safety_status(payload: Dict[str, Any]) -> None:
    atomic_write_json(STATUS_FILE, payload)


def queue_device_safety_command(action: str, **payload: Any) -> Dict[str, Any]:
    command = {
        "command_id": str(uuid.uuid4()),
        "action": action,
        "payload": payload,
        "requested_at": utcnow_iso(),
    }
    atomic_write_json(COMMAND_FILE, command)
    return command
