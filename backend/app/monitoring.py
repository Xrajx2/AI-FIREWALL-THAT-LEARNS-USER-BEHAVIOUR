import asyncio
import ipaddress
import json
import os
import platform
import subprocess
import uuid
import psutil
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session

from . import models
from .ai.scoring_engine import engine as ai_engine
from .behavior_tracking import update_behavior_profile
from .database import SessionLocal
from .risk import is_risky, score_to_recommended_action, score_to_risk_level
from .security import encrypt_sensitive_value
from .usb_control import (
    ENABLE_USB_SCANNING,
    empty_usb_snapshot,
    filter_usb_activities,
    is_usb_action_type,
    is_usb_related_text,
)


MONITOR_INTERVAL_SECONDS = float(os.getenv("MONITOR_INTERVAL_SECONDS", "30"))
FILE_EVENT_WINDOW_SECONDS = float(os.getenv("FILE_EVENT_WINDOW_SECONDS", "15"))
EXTERNAL_MONITOR_TTL_SECONDS = float(os.getenv("EXTERNAL_MONITOR_TTL_SECONDS", "20"))
EXTERNAL_MONITOR_STATE_PATH = Path(
    os.getenv("EXTERNAL_MONITOR_STATE_PATH", "/tmp/aifirewall-system-monitor.json")
)


class SystemMonitorService:
    def __init__(self, connection_manager):
        self.connection_manager = connection_manager
        self.snapshot: Dict[str, Any] = self._empty_snapshot()
        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()
        self._known_processes: Set[int] = set()
        self._known_usb_devices: Set[str] = set()
        self._file_state: Dict[str, float] = {}
        self._known_remote_ips_by_process: Dict[str, Set[str]] = {}
        self._blocked_remote_ips: Set[str] = set()
        self._workspace_root = Path.cwd()
        self._external_state_path = EXTERNAL_MONITOR_STATE_PATH
        self._monitored_paths = self._resolve_monitored_paths()
        self._last_event_at: Dict[str, float] = {}
        self._external_snapshot: Optional[Dict[str, Any]] = None
        self._external_snapshot_received_at: Optional[datetime] = None
        self._ignored_dir_names = {
            ".git",
            ".venv",
            "__pycache__",
            "node_modules",
            "dist",
            "build",
            ".next",
        }

    async def start(self):
        if self._task and not self._task.done():
            return
        self._stop_event = asyncio.Event()
        self._task = asyncio.create_task(self._run(), name="system-monitor")

    async def stop(self):
        self._stop_event.set()
        if self._task:
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            finally:
                self._task = None

    async def _run(self):
        while not self._stop_event.is_set():
            try:
                external_snapshot = self._load_persisted_external_snapshot()
                if external_snapshot:
                    self.snapshot = external_snapshot
                else:
                    snapshot, events = await asyncio.to_thread(self._collect_snapshot)
                    now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                    await self.connection_manager.broadcast(
                        json.dumps({
                            "id": str(uuid.uuid4()),
                            "type": "SYSTEM_MONITOR_UPDATE",
                            "timestamp": now_utc,
                            "data": snapshot,
                        }),
                        admin_only=True,
                    )
                    for event in events:
                        await self._record_discrete_event(event)
            except Exception as exc:
                self.snapshot = {
                    **self._empty_snapshot(),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "status": "degraded",
                    "errors": [str(exc)],
                }
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=MONITOR_INTERVAL_SECONDS)
            except asyncio.TimeoutError:
                continue

    async def ingest_external_snapshot(self, snapshot: Dict[str, Any], events: List[Dict[str, Any]]):
        normalized_snapshot = self._normalize_external_snapshot(snapshot)
        self._external_snapshot = normalized_snapshot
        self._external_snapshot_received_at = datetime.now(timezone.utc)
        self._persist_external_snapshot(normalized_snapshot)
        self.snapshot = normalized_snapshot
        now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        await self.connection_manager.broadcast(
            json.dumps({
                "id": str(uuid.uuid4()),
                "type": "SYSTEM_MONITOR_UPDATE",
                "timestamp": now_utc,
                "data": normalized_snapshot,
            }),
            admin_only=True,
        )
        for event in filter_usb_activities(events)[:10]:
            await self._record_discrete_event(event)

    def get_current_snapshot(self) -> Dict[str, Any]:
        external_snapshot = self._load_persisted_external_snapshot()
        if external_snapshot:
            self.snapshot = external_snapshot
        return self.snapshot

    def _collect_snapshot(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        process_summary, process_events = self._collect_processes()
        if ENABLE_USB_SCANNING:
            usb_summary, usb_events = self._collect_usb_devices()
        else:
            usb_summary = {**empty_usb_snapshot(), "errors": []}
            usb_events = []
        file_summary, file_events = self._collect_file_activity()
        network_summary, network_events = self._collect_network_activity(process_summary["index"])

        snapshot = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "running",
            "collector": "native-host" if os.name == "nt" else "container-fallback",
            "scope": "host" if os.name == "nt" else "container",
            "host": platform.node() or "localhost",
            "platform": platform.platform(),
            "poll_interval_seconds": MONITOR_INTERVAL_SECONDS,
            "monitored_paths": file_summary["watched_paths"],
            "processes": {
                "count": process_summary["count"],
                "new_since_last_scan": process_summary["new_since_last_scan"],
                "top": process_summary["top"],
            },
            "files": {
                "changed_count": file_summary["changed_count"],
                "recent": file_summary["recent"],
            },
            "usb": empty_usb_snapshot() if not ENABLE_USB_SCANNING else {
                "enabled": usb_summary["enabled"],
                "connected_count": usb_summary["connected_count"],
                "recent_insertions": usb_summary["recent_insertions"],
                "devices": usb_summary["devices"],
            },
            "network": network_summary,
            "errors": process_summary["errors"] + usb_summary["errors"] + file_summary["errors"] + network_summary["errors"],
        }

        events = process_events + usb_events + file_events + network_events
        return snapshot, events

    def _collect_processes(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        errors: List[str] = []
        process_index: Dict[int, str] = {}
        all_pids: Set[int] = set()
        top_processes: List[Dict[str, Any]] = []

        # Pure Python enumeration via psutil (0 child processes)
        if psutil is not None:
            try:
                candidate_procs: List[Dict[str, Any]] = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'exe']):
                    try:
                        pinfo = proc.info
                        pid = pinfo.get('pid')
                        if pid is None:
                            continue
                        name = pinfo.get('name') or 'unknown'
                        exe_path = pinfo.get('exe') or ''
                        cpu = float(pinfo.get('cpu_percent') or 0.0)
                        mem_info = pinfo.get('memory_info')
                        mem_mb = round(mem_info.rss / (1024 * 1024), 2) if mem_info else 0.0
                        all_pids.add(pid)
                        process_index[pid] = name
                        candidate_procs.append({
                            "pid": pid,
                            "name": name,
                            "cpu": cpu,
                            "memory_mb": mem_mb,
                            "path": exe_path,
                        })
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                candidate_procs.sort(key=lambda p: (p.get("cpu", 0.0), p.get("memory_mb", 0.0)), reverse=True)
                top_processes = candidate_procs[:12]
            except Exception as exc:
                errors.append(f"psutil process enumeration error: {exc}")

        # Fallback to PowerShell only if psutil returned nothing and we are on Windows
        if not all_pids and os.name == "nt":
            processes = self._run_powershell_json(
                """
                Get-Process |
                  Sort-Object -Property CPU -Descending |
                  Select-Object -First 12 Id, ProcessName,
                    @{Name='CPU';Expression={if ($_.CPU) { [math]::Round($_.CPU, 2) } else { 0 }}},
                    @{Name='MemoryMB';Expression={[math]::Round($_.WS / 1MB, 2)}},
                    Path |
                  ConvertTo-Json -Compress
                """,
                errors,
            )
            process_inventory = self._run_powershell_json(
                """
                Get-Process |
                  Select-Object Id, ProcessName |
                  ConvertTo-Json -Compress
                """,
                errors,
            )
            for item in self._ensure_list(processes):
                pid = self._safe_int(item.get("Id"))
                name = item.get("ProcessName") or "unknown"
                if pid is None:
                    continue
                process_index[pid] = name
                top_processes.append(
                    {
                        "pid": pid,
                        "name": name,
                        "cpu": self._safe_float(item.get("CPU"), 0.0),
                        "memory_mb": self._safe_float(item.get("MemoryMB"), 0.0),
                        "path": item.get("Path") or "",
                    }
                )
            for item in self._ensure_list(process_inventory):
                pid = self._safe_int(item.get("Id"))
                name = item.get("ProcessName") or "unknown"
                if pid is None:
                    continue
                all_pids.add(pid)
                process_index.setdefault(pid, name)

        live_pids = all_pids or set(process_index.keys())
        had_previous_processes = bool(self._known_processes)
        new_pids = sorted(pid for pid in live_pids if pid not in self._known_processes)
        self._known_processes = live_pids

        process_events = []
        if had_previous_processes:
            process_events = [
                {
                    "action_type": "process_start",
                    "device": platform.node() or "localhost",
                    "network_activity": 0.0,
                    "details": {
                        "summary": f"New process detected: {process_index[pid]} (PID {pid})",
                        "process_name": process_index[pid],
                        "pid": pid,
                        "applications": [
                            {
                                "name": process_index[pid],
                                "source": "process_start",
                            }
                        ],
                    },
                    "behavior_context": {
                        "applications": [
                            {
                                "name": process_index[pid],
                                "source": "process_start",
                            }
                        ]
                    },
                }
                for pid in new_pids[:5]
            ]

        return (
            {
                "count": len(live_pids),
                "new_since_last_scan": len(new_pids),
                "top": top_processes,
                "index": process_index,
                "errors": errors,
            },
            process_events,
        )

    def _collect_usb_devices(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        if not ENABLE_USB_SCANNING:
            return ({**empty_usb_snapshot(), "errors": []}, [])

        errors: List[str] = []
        devices_json = []

        # Pure Python removable drive detection (0 child processes)
        if os.name == "nt":
            try:
                import ctypes
                import shutil
                bitmask = ctypes.windll.kernel32.GetLogicalDrives()
                for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                    if bitmask & 1:
                        root = f"{letter}:\\"
                        drive_type = ctypes.windll.kernel32.GetDriveTypeW(root)
                        if drive_type == 2:  # DRIVE_REMOVABLE
                            vol_name_buf = ctypes.create_unicode_buffer(261)
                            ctypes.windll.kernel32.GetVolumeInformationW(
                                root, vol_name_buf, ctypes.sizeof(vol_name_buf),
                                None, None, None, None, 0
                            )
                            vol_name = vol_name_buf.value
                            try:
                                usage = shutil.disk_usage(root)
                                size_gb = round(usage.total / (1024**3), 2)
                                free_gb = round(usage.free / (1024**3), 2)
                            except Exception:
                                size_gb, free_gb = 0.0, 0.0
                            devices_json.append({
                                "DeviceID": f"{letter}:",
                                "VolumeName": vol_name,
                                "SizeGB": size_gb,
                                "FreeGB": free_gb,
                            })
                    bitmask >>= 1
            except Exception as e:
                errors.append(f"ctypes removable drive check failed: {e}")

        # Fallback to PowerShell only if ctypes failed with an exception on Windows
        ctypes_failed = any("ctypes removable drive check failed" in str(e) for e in errors)
        if not devices_json and os.name == "nt" and ctypes_failed:
            devices_json = self._run_powershell_json(
                """
                Get-CimInstance Win32_LogicalDisk |
                  Where-Object { $_.DriveType -eq 2 } |
                  Select-Object DeviceID, VolumeName,
                    @{Name='SizeGB';Expression={if ($_.Size) { [math]::Round($_.Size / 1GB, 2) } else { 0 }}},
                    @{Name='FreeGB';Expression={if ($_.FreeSpace) { [math]::Round($_.FreeSpace / 1GB, 2) } else { 0 }}}
                  ConvertTo-Json -Compress
                """,
                errors,
            )
        devices = []
        current_ids: Set[str] = set()

        for item in self._ensure_list(devices_json):
            device_id = item.get("DeviceID") or ""
            instance_id = f"{device_id}\\" if device_id else ""
            if not instance_id:
                continue
            current_ids.add(instance_id)
            label = f"{device_id} ({item.get('VolumeName')})" if item.get("VolumeName") else device_id
            devices.append(
                {
                    "name": label or "USB drive",
                    "instance_id": instance_id,
                    "status": "Online",
                    "class": "RemovableDrive",
                    "size_gb": self._safe_float(item.get("SizeGB"), 0.0),
                    "free_gb": self._safe_float(item.get("FreeGB"), 0.0),
                }
            )

        inserted_ids = current_ids - self._known_usb_devices
        self._known_usb_devices = current_ids
        insertions = [device for device in devices if device["instance_id"] in inserted_ids][:5]
        usb_events = [
            {
                "action_type": "usb_insertion",
                "device": device["name"],
                "network_activity": 0.0,
                "details": {
                    "summary": f"USB device inserted: {device['name']}",
                    "device_name": device["name"],
                    "instance_id": device.get("instance_id", ""),
                },
            }
            for device in insertions
        ]

        return (
            {
                "enabled": True,
                "connected_count": len(devices),
                "recent_insertions": insertions,
                "devices": devices,
                "errors": errors,
            },
            usb_events,
        )

    def _collect_file_activity(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        errors: List[str] = []
        now_ts = datetime.now(timezone.utc).timestamp()
        recent_changes: List[Dict[str, Any]] = []
        next_state: Dict[str, float] = {}

        for root in self._monitored_paths:
            try:
                for file_path in self._iter_files(root):
                    stat = file_path.stat()
                    modified_ts = stat.st_mtime
                    key = str(file_path)
                    next_state[key] = modified_ts
                    previous_ts = self._file_state.get(key)
                    if previous_ts is None:
                        continue
                    if modified_ts > previous_ts and (now_ts - modified_ts) <= FILE_EVENT_WINDOW_SECONDS:
                        recent_changes.append(
                            {
                                "path": key,
                                "modified_at": datetime.fromtimestamp(modified_ts, tz=timezone.utc).isoformat(),
                                "size_kb": round(stat.st_size / 1024, 2),
                            }
                        )
            except Exception as exc:
                errors.append(f"File scan failed for {root}: {exc}")

        self._file_state = next_state
        recent_changes.sort(key=lambda item: item["modified_at"], reverse=True)
        recent_changes = recent_changes[:20]

        file_events: List[Dict[str, Any]] = []
        if recent_changes and self._should_emit("file_access", now_ts, cooldown_seconds=15):
            sample_paths = ", ".join(Path(item["path"]).name for item in recent_changes[:3])
            file_events.append(
                {
                    "action_type": "file_access",
                    "device": platform.node() or "localhost",
                    "network_activity": 0.0,
                    "details": {
                        "summary": f"Detected {len(recent_changes)} file changes. Sample: {sample_paths}",
                        "files": [
                            {
                                "path": item["path"],
                                "action": item.get("action", "modified"),
                            }
                            for item in recent_changes[:8]
                        ],
                    },
                    "behavior_context": {
                        "files": [
                            {
                                "path": item["path"],
                                "directory": str(Path(item["path"]).parent),
                                "extension": Path(item["path"]).suffix.lower() or "[no extension]",
                            }
                            for item in recent_changes[:10]
                        ]
                    },
                }
            )

        return (
            {
                "changed_count": len(recent_changes),
                "recent": recent_changes,
                "watched_paths": [str(path) for path in self._monitored_paths],
                "errors": errors,
            },
            file_events,
        )

    def _collect_network_activity(self, process_index: Dict[int, str]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        errors: List[str] = []
        connections_data: List[Dict[str, Any]] = []

        # Pure Python connection gathering (0 child processes)
        if psutil is not None:
            try:
                for c in psutil.net_connections(kind="tcp"):
                    if c.status == psutil.CONN_ESTABLISHED and c.raddr:
                        connections_data.append({
                            "LocalAddress": c.laddr.ip if c.laddr else "",
                            "LocalPort": c.laddr.port if c.laddr else 0,
                            "RemoteAddress": c.raddr.ip,
                            "RemotePort": c.raddr.port,
                            "OwningProcess": c.pid or 0,
                        })
                        if len(connections_data) >= 40:
                            break
            except Exception as exc:
                errors.append(f"psutil net_connections check failed: {exc}")

        # Fallback to PowerShell only if psutil net_connections check failed with an exception on Windows
        psutil_net_failed = any("psutil net_connections check failed" in str(e) for e in errors)
        if not connections_data and os.name == "nt" and psutil_net_failed:
            connections_data = self._ensure_list(
                self._run_powershell_json(
                    """
                    Get-NetTCPConnection -State Established |
                      Select-Object -First 40 LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
                      ConvertTo-Json -Compress
                    """,
                    errors,
                )
            )

        connections: List[Dict[str, Any]] = []
        suspicious_connections: List[Dict[str, Any]] = []
        blocked_connections: List[Dict[str, Any]] = []
        remote_ips: Set[str] = set()
        process_counter: Counter = Counter()
        tracked_ip_index: Dict[str, Dict[str, Any]] = {}

        for item in connections_data:
            pid = self._safe_int(item.get("OwningProcess"))
            process_name = process_index.get(pid or -1, f"PID {pid}" if pid else "Unknown")
            remote_ip = item.get("RemoteAddress") or ""
            remote_port = self._safe_int(item.get("RemotePort"), 0) or 0
            if remote_ip:
                remote_ips.add(remote_ip)
            process_counter[process_name] += 1
            analysis = self._classify_connection(process_name, remote_ip, remote_port)
            connection = {
                "process": process_name,
                "pid": pid,
                "local": f"{item.get('LocalAddress')}:{item.get('LocalPort')}",
                "remote": f"{remote_ip}:{item.get('RemotePort')}",
                "local_address": item.get("LocalAddress") or "",
                "local_port": self._safe_int(item.get("LocalPort"), 0) or 0,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "ip_scope": analysis["ip_scope"],
                "public_ip": analysis["public_ip"],
                "is_new_remote": analysis["is_new_remote"],
                "risk_score": analysis["risk_score"],
                "risk_level": analysis["risk_level"],
                "recommended_action": analysis["recommended_action"],
                "blocked": False,
                "reasons": analysis["reasons"],
                "direction": "outbound",
            }
            connections.append(connection)

            if remote_ip:
                tracked_entry = tracked_ip_index.setdefault(
                    remote_ip,
                    {
                        "ip": remote_ip,
                        "scope": analysis["ip_scope"],
                        "count": 0,
                        "highest_risk_score": 0.0,
                        "highest_risk_level": "Normal",
                        "processes": set(),
                    },
                )
                tracked_entry["count"] += 1
                tracked_entry["highest_risk_score"] = max(tracked_entry["highest_risk_score"], analysis["risk_score"])
                tracked_entry["highest_risk_level"] = score_to_risk_level(tracked_entry["highest_risk_score"])
                tracked_entry["processes"].add(process_name)

            if is_risky(analysis["risk_score"]):
                suspicious_connections.append(connection)

        top_processes = [
            {"name": name, "connections": count}
            for name, count in process_counter.most_common(5)
        ]

        tracked_ips = [
            {
                "ip": ip,
                "scope": item["scope"],
                "count": item["count"],
                "highest_risk_score": round(item["highest_risk_score"], 2),
                "highest_risk_level": item["highest_risk_level"],
                "processes": sorted(item["processes"])[:5],
            }
            for ip, item in tracked_ip_index.items()
        ]
        tracked_ips.sort(key=lambda item: (-item["highest_risk_score"], -item["count"], item["ip"]))
        suspicious_connections.sort(key=lambda item: (-item["risk_score"], item["remote_ip"]))

        network_events: List[Dict[str, Any]] = []
        now_ts = datetime.now(timezone.utc).timestamp()
        if len(connections) >= 12 and self._should_emit("network_spike", now_ts, cooldown_seconds=30):
            network_events.append(
                {
                    "action_type": "network_spike",
                    "device": platform.node() or "localhost",
                    "network_activity": float(len(connections)),
                    "details": {
                        "summary": f"Detected {len(connections)} established TCP connections across {len(remote_ips)} remote IPs",
                        "connection_count": len(connections),
                        "remote_ips": list(remote_ips)[:10],
                    },
                    "behavior_context": {
                        "network": {
                            "connection_count": len(connections),
                            "remote_ips": list(remote_ips)[:10],
                        }
                    },
                }
            )
        if suspicious_connections and self._should_emit("network_connection_suspicious", now_ts, cooldown_seconds=20):
            network_events.extend(
                self._build_network_event("network_connection_suspicious", connection)
                for connection in suspicious_connections[:3]
            )

        return (
            {
                "connection_count": len(connections),
                "unique_remote_ips": len(remote_ips),
                "tracked_ip_count": len(tracked_ips),
                "top_processes": top_processes,
                "tracked_ips": tracked_ips[:12],
                "connections": connections[:12],
                "suspicious_connections": suspicious_connections[:8],
                "blocked_connections": blocked_connections,
                "auto_block_enabled": False,
                "block_threshold": 55,
                "errors": errors,
            },
            network_events,
        )

    async def _record_discrete_event(self, event: Dict[str, Any]):
        if not ENABLE_USB_SCANNING and is_usb_action_type(event.get("action_type")):
            return

        db = SessionLocal()
        try:
            system_user = self._ensure_system_user(db)
            raw_details = event.get("details")
            if isinstance(raw_details, dict):
                details_str = json.dumps(raw_details)
                summary_text = raw_details.get("summary") or event.get("action_type", "")
            elif isinstance(raw_details, str):
                try:
                    parsed = json.loads(raw_details)
                    if isinstance(parsed, dict):
                        details_str = raw_details
                        summary_text = parsed.get("summary") or parsed.get("message") or raw_details
                    else:
                        details_str = json.dumps({"summary": raw_details})
                        summary_text = raw_details
                except (ValueError, TypeError, json.JSONDecodeError):
                    details_str = json.dumps({"summary": raw_details})
                    summary_text = raw_details
            else:
                details_str = json.dumps({"summary": str(raw_details or "")})
                summary_text = str(raw_details or "")

            db_activity = models.UserActivity(
                user_id=system_user.id,
                action_type=event["action_type"],
                device=event["device"],
                network_activity=event.get("network_activity", 0.0),
                details=encrypt_sensitive_value(details_str),
            )
            db.add(db_activity)
            db.commit()
            db.refresh(db_activity)
            update_behavior_profile(db, system_user.id, db_activity, event.get("behavior_context"))
            db.commit()

            threat_assessment = self._assess_activity(db, system_user.id, db_activity)
            db_activity.risk_score = threat_assessment["score"]
            db_activity.risk_level = threat_assessment["risk_level"]
            db.add(db_activity)
            db.commit()

            activity_summary = threat_assessment.get("summary") or summary_text or db_activity.action_type
            now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            activity_msg = {
                "id": str(uuid.uuid4()),
                "type": "NEW_ACTIVITY",
                "timestamp": now_utc,
                "data": {
                    "user": system_user.username,
                    "action": db_activity.action_type,
                    "network": db_activity.network_activity,
                    "score": threat_assessment["score"],
                    "risk_level": threat_assessment["risk_level"],
                    "details": activity_summary,
                    "timestamp": now_utc,
                },
            }
            await self.connection_manager.broadcast(json.dumps(activity_msg), user_id=system_user.id)

            if is_risky(threat_assessment["score"]):
                threat_log = models.ThreatLog(
                    user_id=system_user.id,
                    anomaly_score=threat_assessment["score"],
                    threat_level=threat_assessment["level"],
                    action_taken=threat_assessment.get("recommended_action", "monitor"),
                    details=encrypt_sensitive_value(activity_summary),
                )
                db.add(threat_log)
                db.commit()
                alert_msg = {
                    "id": str(uuid.uuid4()),
                    "type": "THREAT_ALERT",
                    "timestamp": now_utc,
                    "data": {
                        "user": system_user.username,
                        "score": threat_assessment["score"],
                        "level": threat_assessment["level"],
                        "action": db_activity.action_type,
                        "risk_level": threat_assessment["risk_level"],
                        "details": activity_summary,
                        "timestamp": now_utc,
                    },
                }
                await self.connection_manager.broadcast(
                    json.dumps(alert_msg),
                    user_id=system_user.id,
                )
        finally:
            db.close()

    def _assess_activity(self, db: Session, user_id: int, db_activity: models.UserActivity) -> Dict[str, Any]:
        recent_activities = (
            db.query(models.UserActivity)
            .filter(models.UserActivity.user_id == user_id)
            .order_by(models.UserActivity.timestamp.desc())
            .limit(100)
            .all()
        )
        recent_activities = list(reversed(filter_usb_activities(recent_activities)))
        return ai_engine.evaluate_threat(
            user_id=user_id,
            current_activity=db_activity,
            recent_activities=recent_activities,
        )

    def _build_network_event(self, action_type: str, connection: Dict[str, Any]) -> Dict[str, Any]:
        leading_reason = connection["reasons"][0] if connection["reasons"] else "the connection broke the outbound policy"
        details = (
            f"{connection['risk_level']} outbound connection: {connection['process']} -> "
            f"{connection['remote_ip']}:{connection['remote_port']} because {leading_reason.lower()}"
        )
        return {
            "action_type": action_type,
            "device": platform.node() or "localhost",
            "network_activity": float(connection["risk_score"]),
            "details": {
                "summary": details,
                "process_name": connection.get("process", ""),
                "remote_ip": connection.get("remote_ip", ""),
                "remote_port": connection.get("remote_port", 0),
                "reasons": connection.get("reasons", []),
            },
            "behavior_context": {
                "applications": [
                    {
                        "name": connection["process"],
                        "source": action_type,
                    }
                ]
            },
        }

    def _classify_connection(self, process_name: str, remote_ip: str, remote_port: int) -> Dict[str, Any]:
        process_key = (process_name or "unknown").strip().lower()
        ip_scope = self._classify_ip_scope(remote_ip)
        public_ip = ip_scope == "public"
        is_new_remote = self._remember_remote_ip(process_key, remote_ip)

        score = 0.0
        reasons: List[str] = []
        high_risk_ports = {21, 23, 25, 135, 139, 445, 3389, 4444, 5555, 5985, 5986, 6667}
        safe_ports = {53, 80, 123, 443}
        suspicious_processes = {
            "bitsadmin",
            "certutil",
            "cmd",
            "cscript",
            "mshta",
            "powershell",
            "python",
            "regsvr32",
            "rundll32",
            "wscript",
            "wmic",
        }

        if public_ip:
            score += 18.0
            reasons.append("it targets a public remote IP outside the local network")
        if is_new_remote and public_ip:
            score += 18.0
            reasons.append("the process connected to a remote IP that has not been seen before")
        if remote_port and remote_port not in safe_ports:
            score += 10.0
            reasons.append("it uses a non-standard outbound port")
        if remote_port in high_risk_ports:
            score += 22.0
            reasons.append("it uses a high-risk outbound port")
        if process_key in suspicious_processes:
            score += 28.0
            reasons.append("the connection originated from a scripting or administrative process")

        known_remote_count = len(self._known_remote_ips_by_process.get(process_key, set()))
        if public_ip and known_remote_count >= 8:
            score += 12.0
            reasons.append("the process is spreading traffic across many different remote IPs")

        normalized_score = round(min(100.0, score), 2)
        return {
            "risk_score": normalized_score,
            "risk_level": score_to_risk_level(normalized_score),
            "recommended_action": score_to_recommended_action(normalized_score),
            "ip_scope": ip_scope,
            "public_ip": public_ip,
            "is_new_remote": is_new_remote,
            "reasons": reasons[:3],
        }

    def _remember_remote_ip(self, process_key: str, remote_ip: str) -> bool:
        if not process_key or not remote_ip:
            return False

        seen = self._known_remote_ips_by_process.setdefault(process_key, set())
        is_new_remote = remote_ip not in seen
        seen.add(remote_ip)
        return is_new_remote

    @staticmethod
    def _classify_ip_scope(remote_ip: str) -> str:
        if not remote_ip:
            return "unknown"
        try:
            parsed = ipaddress.ip_address(remote_ip)
        except ValueError:
            return "unknown"

        if parsed.is_loopback:
            return "loopback"
        if parsed.is_link_local:
            return "link_local"
        if parsed.is_private:
            return "private"
        if parsed.is_reserved:
            return "reserved"
        if parsed.is_multicast:
            return "multicast"
        return "public"

    def _ensure_system_user(self, db: Session) -> models.User:
        system_user = db.query(models.User).filter(models.User.username == "system-monitor").first()
        if system_user:
            return system_user

        system_user = models.User(username="system-monitor", hashed_password="!", role="user")
        db.add(system_user)
        db.commit()
        db.refresh(system_user)
        return system_user

    def _resolve_monitored_paths(self) -> List[Path]:
        configured = os.getenv("MONITORED_PATHS")
        if configured:
            candidates = [Path(item.strip()) for item in configured.split(";") if item.strip()]
        else:
            candidates = [self._workspace_root]
            user_profile = Path(os.getenv("USERPROFILE", ""))
            for extra in ("Desktop", "Documents", "Downloads"):
                extra_path = user_profile / extra
                if str(user_profile) and extra_path.exists():
                    candidates.append(extra_path)

        unique_paths: List[Path] = []
        seen: Set[str] = set()
        for path in candidates:
            resolved = path.resolve()
            key = str(resolved).lower()
            if resolved.exists() and key not in seen:
                seen.add(key)
                unique_paths.append(resolved)
        return unique_paths

    def _iter_files(self, root: Path):
        for current_root, dir_names, file_names in os.walk(root):
            dir_names[:] = [name for name in dir_names if name not in self._ignored_dir_names]
            for file_name in file_names:
                yield Path(current_root) / file_name

    def _should_emit(self, key: str, now_ts: float, cooldown_seconds: float) -> bool:
        last_seen = self._last_event_at.get(key)
        if last_seen is not None and (now_ts - last_seen) < cooldown_seconds:
            return False
        self._last_event_at[key] = now_ts
        return True

    def _run_powershell_json(self, script: str, errors: List[str]):
        raw = self._run_powershell_text(script, errors)
        if not raw:
            return []
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            errors.append(f"PowerShell JSON parse failed: {exc}")
            return []

    def _run_powershell_text(self, script: str, errors: List[str]) -> str:
        if os.name != "nt":
            return ""
        # Clean script newlines to prevent PowerShell from splitting the command block
        cleaned_script = " ".join(line.strip() for line in script.splitlines() if line.strip())
        try:
            from app.process_utils import run_hidden
            completed = run_hidden(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cleaned_script],
                timeout=10,
                check=False,
            )
        except Exception as exc:
            errors.append(f"PowerShell execution failed: {exc}")
            return ""

        if completed.returncode != 0:
            stderr = (completed.stderr or completed.stdout or "").strip()
            if stderr:
                errors.append(stderr.splitlines()[0])
            return ""
        return (completed.stdout or "").strip()

    def _has_fresh_external_snapshot(self) -> bool:
        if not self._external_snapshot or not self._external_snapshot_received_at:
            return False
        age_seconds = (datetime.now(timezone.utc) - self._external_snapshot_received_at).total_seconds()
        return age_seconds <= EXTERNAL_MONITOR_TTL_SECONDS

    def _persist_external_snapshot(self, snapshot: Dict[str, Any]):
        try:
            payload = {
                "received_at": datetime.now(timezone.utc).isoformat(),
                "snapshot": snapshot,
            }
            self._external_state_path.parent.mkdir(parents=True, exist_ok=True)
            self._external_state_path.write_text(json.dumps(payload), encoding="utf-8")
        except Exception:
            return

    def _load_persisted_external_snapshot(self) -> Optional[Dict[str, Any]]:
        try:
            if not self._external_state_path.exists():
                return None

            payload = json.loads(self._external_state_path.read_text(encoding="utf-8"))
            received_at_raw = payload.get("received_at")
            snapshot = payload.get("snapshot")
            if not received_at_raw or not isinstance(snapshot, dict):
                return None

            received_at = datetime.fromisoformat(received_at_raw)
            if received_at.tzinfo is None:
                received_at = received_at.replace(tzinfo=timezone.utc)

            age_seconds = (datetime.now(timezone.utc) - received_at).total_seconds()
            if age_seconds > EXTERNAL_MONITOR_TTL_SECONDS:
                return None

            normalized_snapshot = self._normalize_external_snapshot(snapshot)
            self._external_snapshot = normalized_snapshot
            self._external_snapshot_received_at = received_at
            return normalized_snapshot
        except Exception:
            return None

    def _normalize_external_snapshot(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        base = self._empty_snapshot()
        normalized = {
            **base,
            **snapshot,
            "collector": snapshot.get("collector") or "windows-host-agent",
            "scope": snapshot.get("scope") or "host",
            "timestamp": snapshot.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "status": snapshot.get("status") or "running",
            "host": snapshot.get("host") or platform.node() or "localhost",
            "platform": snapshot.get("platform") or platform.platform(),
            "poll_interval_seconds": snapshot.get("poll_interval_seconds") or MONITOR_INTERVAL_SECONDS,
            "monitored_paths": snapshot.get("monitored_paths") or [],
            "errors": [
                error for error in (snapshot.get("errors") or [])
                if ENABLE_USB_SCANNING or not is_usb_related_text(error)
            ],
        }
        normalized["processes"] = {
            **base["processes"],
            **(snapshot.get("processes") or {}),
        }
        normalized["files"] = {
            **base["files"],
            **(snapshot.get("files") or {}),
        }
        normalized["usb"] = base["usb"] if not ENABLE_USB_SCANNING else {
            **base["usb"],
            **(snapshot.get("usb") or {}),
            "enabled": True,
        }
        normalized["network"] = {
            **base["network"],
            **(snapshot.get("network") or {}),
        }
        return normalized

    def _empty_snapshot(self) -> Dict[str, Any]:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "starting",
            "collector": "container-fallback",
            "scope": "container",
            "host": platform.node() or "localhost",
            "platform": platform.platform(),
            "poll_interval_seconds": MONITOR_INTERVAL_SECONDS,
            "monitored_paths": [],
            "processes": {"count": 0, "new_since_last_scan": 0, "top": []},
            "files": {"changed_count": 0, "recent": []},
            "usb": empty_usb_snapshot(),
            "network": {
                "connection_count": 0,
                "unique_remote_ips": 0,
                "tracked_ip_count": 0,
                "top_processes": [],
                "tracked_ips": [],
                "connections": [],
                "suspicious_connections": [],
                "blocked_connections": [],
                "auto_block_enabled": False,
                "block_threshold": 55,
            },
            "errors": [],
        }

    @staticmethod
    def _ensure_list(value: Any) -> List[Dict[str, Any]]:
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            return [value]
        return []

    @staticmethod
    def _safe_int(value: Any, default: Optional[int] = None) -> Optional[int]:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _safe_float(value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default
