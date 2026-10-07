from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger("ai_firewall.device_safety")

BACKEND_ROOT = Path(__file__).resolve().parents[1]

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
QUARANTINE_DIR = _DATA_DIR / "quarantine"


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def ensure_runtime_dir() -> Path:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    return RUNTIME_DIR


def ensure_quarantine_dir() -> Path:
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    return QUARANTINE_DIR


def atomic_write_json(path: Path, payload: Dict[str, Any]) -> None:
    ensure_runtime_dir()
    temp_path = path.with_suffix(path.suffix + f".{uuid.uuid4().hex[:6]}.tmp")
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


def get_available_targets() -> List[Dict[str, Any]]:
    targets: List[Dict[str, Any]] = [
        {
            "id": "quick_all",
            "label": "Quick System Safety (Downloads & Temp)",
            "kind": "aggregate",
            "path": "Downloads & Temp",
        },
        {
            "id": "downloads",
            "label": "User Downloads Folder",
            "kind": "user_folder",
            "path": str(Path.home() / "Downloads"),
        },
        {
            "id": "temp",
            "label": "System Temp Directory",
            "kind": "system_folder",
            "path": tempfile.gettempdir(),
        },
    ]

    # Enumerate removable USB drives if available
    try:
        if psutil is not None:
            for part in psutil.disk_partitions(all=True):
                opts = (part.opts or "").lower()
                fstype = (part.fstype or "").lower()
                is_removable = "removable" in opts or fstype in ("fat", "fat32", "exfat")
                if is_removable and part.mountpoint:
                    mount = part.mountpoint
                    targets.append({
                        "id": f"drive_{mount.replace(':', '').replace('\\', '').replace('/', '')}",
                        "label": f"Removable Drive ({mount})",
                        "kind": "removable_drive",
                        "path": mount,
                    })
    except Exception as exc:
        logger.debug(f"Target drive discovery warning: {exc}")

    return targets


def default_device_safety_status() -> Dict[str, Any]:
    return {
        "agent": {
            "running": True,
            "version": "1.0.0",
            "last_heartbeat_at": utcnow_iso(),
            "last_command_id": None,
            "online": True,
        },
        "scanner": {
            "state": "idle",
            "live_watch_enabled": False,
            "current_job": None,
            "last_error": None,
        },
        "targets": get_available_targets(),
        "recent_live_events": [],
        "scan_history": [],
        "last_scan": None,
    }


def read_device_safety_status() -> Dict[str, Any]:
    status = default_device_safety_status()
    payload = read_json_file(STATUS_FILE, {})

    if isinstance(payload.get("scanner"), dict):
        status["scanner"].update(payload["scanner"])
    if isinstance(payload.get("scan_history"), list):
        status["scan_history"] = payload["scan_history"]
    if isinstance(payload.get("last_scan"), dict):
        status["last_scan"] = payload["last_scan"]
    if isinstance(payload.get("recent_live_events"), list):
        status["recent_live_events"] = payload["recent_live_events"]

    # Always ensure agent heartbeat is current and real targets are populated
    status["agent"]["running"] = True
    status["agent"]["online"] = True
    status["agent"]["last_heartbeat_at"] = utcnow_iso()
    status["targets"] = get_available_targets()
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

    # Immediately execute supported actions in-process
    if action == "scan_target":
        target_id = payload.get("target_id") or "quick_all"
        requested_by = payload.get("requested_by") or "admin"
        return execute_device_safety_scan(target_id, requested_by)
    elif action == "set_live_watch":
        enabled = bool(payload.get("enabled", False))
        status = read_device_safety_status()
        status["scanner"]["live_watch_enabled"] = enabled
        status["scanner"]["state"] = "watching" if enabled else "idle"
        write_device_safety_status(status)
        return {"status": "success", "live_watch_enabled": enabled}

    return command


def execute_device_safety_scan(target_id: str, requested_by: str = "admin") -> Dict[str, Any]:
    """Perform a real pure-Python file safety scan of the specified target."""
    from usb_security_module import (
        FileScanner,
        QuarantineManager,
        SignatureDatabase,
        USBDevice,
        _resolve_default_signature_db,
    )

    targets = get_available_targets()
    matched_target = next((t for t in targets if t["id"] == target_id), None)
    if not matched_target:
        # Check if target_id is directly a path
        if os.path.exists(target_id):
            matched_target = {
                "id": "custom",
                "label": f"Custom Path ({target_id})",
                "kind": "custom",
                "path": target_id,
            }
        else:
            matched_target = targets[0]

    scan_paths: List[Path] = []
    if matched_target["id"] == "quick_all":
        for t in targets:
            if t["id"] not in ("quick_all",) and os.path.exists(t["path"]):
                scan_paths.append(Path(t["path"]))
    else:
        p = Path(matched_target["path"])
        if p.exists():
            scan_paths.append(p)

    sig_db_path = _resolve_default_signature_db()
    sig_db = SignatureDatabase(sig_db_path)
    scanner = FileScanner(sig_db)
    quarantine_root = ensure_quarantine_dir()
    qm = QuarantineManager(quarantine_root, None)

    files_scanned = 0
    suspicious_count = 0
    malicious_count = 0
    quarantined_count = 0
    findings: List[Dict[str, Any]] = []

    # Traverse target paths (up to 500 files per scan for UI responsiveness)
    max_scan_files = 500
    for root_path in scan_paths:
        if files_scanned >= max_scan_files:
            break
        if root_path.is_file():
            candidates = [root_path]
        else:
            try:
                candidates = []
                for entry in os.scandir(root_path):
                    if entry.is_file():
                        candidates.append(Path(entry.path))
                        if len(candidates) >= max_scan_files:
                            break
            except Exception:
                candidates = []

        for f_path in candidates:
            if files_scanned >= max_scan_files:
                break
            try:
                finding = scanner.scan_file(f_path)
                files_scanned += 1
                if finding.severity in ("suspicious", "malicious"):
                    if finding.severity == "malicious":
                        malicious_count += 1
                    else:
                        suspicious_count += 1

                    action_taken = "flagged"
                    # Quarantine malicious files
                    if finding.severity == "malicious":
                        try:
                            dummy_device = USBDevice(
                                device_id="system-scan",
                                mountpoint=root_path,
                                label=matched_target["label"],
                                filesystem="ntfs" if os.name == "nt" else "posix",
                                source="device-safety-scan",
                            )
                            q_dest = qm.quarantine(f_path, dummy_device, finding)
                            quarantined_count += 1
                            action_taken = "quarantined"
                        except Exception as q_exc:
                            logger.error(f"Quarantine failed for {f_path}: {q_exc}")
                            action_taken = "quarantine_failed"

                    findings.append({
                        "file_name": f_path.name,
                        "file_path": str(f_path),
                        "severity": finding.severity,
                        "score": finding.score,
                        "reasons": finding.reasons,
                        "sha256": finding.sha256,
                        "size_bytes": finding.size_bytes,
                        "action": action_taken,
                    })
            except Exception:
                continue

    verdict = "unsafe" if malicious_count > 0 else "review" if suspicious_count > 0 else "safe"
    completed_time = utcnow_iso()
    scan_id = str(uuid.uuid4())

    scan_result = {
        "id": scan_id,
        "target_id": matched_target["id"],
        "target_label": matched_target["label"],
        "target_path": matched_target["path"],
        "completed_at": completed_time,
        "files_scanned": files_scanned,
        "suspicious_count": suspicious_count,
        "malicious_count": malicious_count,
        "quarantined_count": quarantined_count,
        "verdict": verdict,
        "findings": findings,
        "requested_by": requested_by,
    }

    # Update in-memory and persistent status
    current_status = read_device_safety_status()
    current_status["last_scan"] = scan_result
    history = current_status.get("scan_history") or []
    current_status["scan_history"] = [scan_result, *history][:20]
    current_status["scanner"]["state"] = "watching" if current_status["scanner"]["live_watch_enabled"] else "idle"
    current_status["scanner"]["current_job"] = None

    # Add to recent live events
    live_event = {
        "id": scan_id,
        "action": "manual_scan_complete",
        "entity_type": "scan",
        "verdict": verdict,
        "summary": f"Scanned {files_scanned} files on {matched_target['label']}. Found {malicious_count} malicious, {quarantined_count} quarantined.",
        "timestamp": completed_time,
    }
    events = current_status.get("recent_live_events") or []
    current_status["recent_live_events"] = [live_event, *events][:20]

    write_device_safety_status(current_status)
    return scan_result


def list_quarantine_items() -> List[Dict[str, Any]]:
    """List all quarantined files and their metadata."""
    quarantine_root = ensure_quarantine_dir()
    items: List[Dict[str, Any]] = []
    if not quarantine_root.exists():
        return items

    for meta_file in quarantine_root.rglob("*.quarantine.json"):
        try:
            data = json.loads(meta_file.read_text(encoding="utf-8"))
            # Corresponding payload file has same name without .quarantine.json
            payload_name = meta_file.name[:-len(".quarantine.json")]
            payload_file = meta_file.with_name(payload_name)
            if payload_file.exists():
                data["exists_in_quarantine"] = True
                data["quarantine_path"] = str(payload_file)
                data["quarantine_file_name"] = payload_file.name
                items.append(data)
        except Exception:
            continue

    items.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return items


def restore_quarantine_file(quarantine_path: str) -> Dict[str, Any]:
    """Restore a quarantined file to its original location."""
    target = Path(quarantine_path).resolve()
    meta_path = target.with_name(target.name + ".quarantine.json")
    if not meta_path.exists():
        raise FileNotFoundError(f"Quarantine metadata not found for {target}")

    metadata = json.loads(meta_path.read_text(encoding="utf-8"))
    original_path = Path(metadata["original_path"]).resolve()

    original_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(target), str(original_path))
    try:
        meta_path.unlink()
    except Exception:
        pass

    return {
        "success": True,
        "restored_path": str(original_path),
        "quarantine_path": str(target),
        "file_name": original_path.name,
    }
