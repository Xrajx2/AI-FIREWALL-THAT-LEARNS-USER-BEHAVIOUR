from __future__ import annotations

import os
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(BACKEND_DIR.parent) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR.parent))

from app.device_safety import (
    BACKEND_ROOT,
    COMMAND_FILE,
    RUNTIME_DIR,
    read_device_safety_status,
    read_json_file,
    utcnow_iso,
    write_device_safety_status,
)
from usb_security_module import (
    DEFAULT_SIGNATURE_DB,
    FileScanner,
    SignatureDatabase,
    USBDetector,
)


AGENT_VERSION = "2026.04.09.2"
POLL_SECONDS = float(os.getenv("DEVICE_SAFETY_POLL_SECONDS", "2"))
MAX_SCAN_FILES_PER_TARGET = int(os.getenv("DEVICE_SAFETY_MAX_SCAN_FILES", "1500"))
MAX_RECENT_EVENTS = 40
MAX_SCAN_HISTORY = 18
MAX_STORED_FINDINGS_PER_SCAN = 100
PROJECT_ROOT = BACKEND_ROOT.parent.resolve()
IGNORED_TREE_PATHS = {
    PROJECT_ROOT,
    RUNTIME_DIR.resolve(),
    BACKEND_ROOT.joinpath("__pycache__").resolve(),
}


@dataclass(frozen=True)
class SafetyTarget:
    id: str
    label: str
    path: Path
    kind: str
    removable: bool = False


class DeviceSafetyAgent:
    def __init__(self) -> None:
        self.signatures = SignatureDatabase(DEFAULT_SIGNATURE_DB)
        self.signatures.load()
        self.scanner = FileScanner(self.signatures)
        self.usb_detector = USBDetector()
        self.status = read_device_safety_status()
        self.live_watch_enabled = bool(self.status.get("scanner", {}).get("live_watch_enabled"))
        self.last_command_id = self.status.get("agent", {}).get("last_command_id")
        self.snapshots: Dict[str, Dict[str, Dict[str, object]]] = {}

    def step(self) -> None:
        try:
            self._refresh_targets()
            self._handle_command()
            if self.live_watch_enabled:
                self._poll_live_watch()
            self._write_status()
        except Exception as exc:
            self.status["scanner"]["last_error"] = str(exc)
            self.status["scanner"]["state"] = "watching" if self.live_watch_enabled else "idle"
            self._write_status()

    def run(self) -> None:
        self._refresh_targets()
        if self.live_watch_enabled:
            self._prime_live_watch_snapshots()
        self._write_status()

        while True:
            try:
                self.step()
            except KeyboardInterrupt:
                return
            time.sleep(POLL_SECONDS)

    def _refresh_targets(self) -> None:
        targets = self._build_targets()
        self.status["targets"] = [
            {
                "id": target.id,
                "label": target.label,
                "path": str(target.path),
                "kind": target.kind,
                "removable": target.removable,
            }
            for target in targets
        ]

    def _build_targets(self) -> List[SafetyTarget]:
        targets: List[SafetyTarget] = []
        user_profile = Path(os.getenv("USERPROFILE", "")).expanduser()
        onedrive_root = user_profile / "OneDrive"
        common_dirs = [
            ("downloads", "Downloads", [user_profile / "Downloads", onedrive_root / "Downloads"]),
            ("desktop", "Desktop", [user_profile / "Desktop", onedrive_root / "Desktop"]),
            ("documents", "Documents", [user_profile / "Documents", onedrive_root / "Documents"]),
        ]
        for target_id, label, candidates in common_dirs:
            selected_path = next((candidate for candidate in candidates if candidate.exists()), None)
            if selected_path:
                targets.append(SafetyTarget(id=target_id, label=label, path=selected_path, kind="folder", removable=False))

        for device in self.usb_detector._enumerate_devices().values():
            targets.append(
                SafetyTarget(
                    id=f"removable::{device.device_id.replace(':', '').replace('\\', '').replace('/', '_')}",
                    label=f"{device.label or device.device_id} ({device.mountpoint})",
                    path=device.mountpoint,
                    kind="removable_drive",
                    removable=True,
                )
            )

        deduped: Dict[str, SafetyTarget] = {}
        for target in targets:
            deduped[target.id] = target
        return list(deduped.values())

    def _handle_command(self) -> None:
        command = read_json_file(COMMAND_FILE, {})
        command_id = command.get("command_id")
        if not command_id or command_id == self.last_command_id:
            return

        self.last_command_id = command_id
        action = str(command.get("action") or "").strip().lower()
        payload = command.get("payload") or {}
        self.status["scanner"]["last_error"] = None

        if action == "set_live_watch":
            self.live_watch_enabled = bool(payload.get("enabled"))
            self.status["scanner"]["live_watch_enabled"] = self.live_watch_enabled
            self.status["scanner"]["state"] = "watching" if self.live_watch_enabled else "idle"
            if self.live_watch_enabled:
                self._prime_live_watch_snapshots()
                self._append_live_event(
                    {
                        "id": str(uuid.uuid4()),
                        "timestamp": utcnow_iso(),
                        "target_label": "Device Safety",
                        "target_id": "live_watch",
                        "action": "watch_started",
                        "entity_type": "service",
                        "name": "Live Watch",
                        "path": "",
                        "verdict": "info",
                        "summary": "Live safety watch is active. New or modified files in watched folders will be checked automatically.",
                    }
                )
            else:
                self.snapshots = {}
                self._append_live_event(
                    {
                        "id": str(uuid.uuid4()),
                        "timestamp": utcnow_iso(),
                        "target_label": "Device Safety",
                        "target_id": "live_watch",
                        "action": "watch_stopped",
                        "entity_type": "service",
                        "name": "Live Watch",
                        "path": "",
                        "verdict": "info",
                        "summary": "Live safety watch is paused.",
                    }
                )
        elif action == "scan_target":
            self._run_manual_scan(str(payload.get("target_id") or "quick_all"), requested_by=str(payload.get("requested_by") or "user"))

    def _run_manual_scan(self, target_id: str, *, requested_by: str) -> None:
        all_targets = self._build_targets()
        target_map = {target.id: target for target in all_targets}
        if target_id == "quick_all":
            selected_targets = all_targets
            label = "Fast Safety Scan"
        else:
            selected = target_map.get(target_id)
            if not selected:
                self.status["scanner"]["last_error"] = f"Unknown scan target: {target_id}"
                return
            selected_targets = [selected]
            label = selected.label

        started_at = utcnow_iso()
        self.status["scanner"]["state"] = "scanning"
        self.status["scanner"]["current_job"] = {
            "label": label,
            "target_id": target_id,
            "requested_by": requested_by,
            "started_at": started_at,
        }
        self._write_status()

        files_scanned = 0
        clean_count = 0
        suspicious_count = 0
        malicious_count = 0
        truncated = False
        findings: List[Dict[str, object]] = []

        for target in selected_targets:
            target_result = self._scan_target(target)
            files_scanned += int(target_result["files_scanned"])
            clean_count += int(target_result["clean_count"])
            suspicious_count += int(target_result["suspicious_count"])
            malicious_count += int(target_result["malicious_count"])
            truncated = truncated or bool(target_result["truncated"])
            findings.extend(target_result["findings"])

        findings = self._sort_findings(findings)
        total_flagged_count = suspicious_count + malicious_count
        stored_findings = findings[:MAX_STORED_FINDINGS_PER_SCAN]

        completed_at = utcnow_iso()
        if malicious_count > 0:
            verdict = "unsafe"
            summary = f"Scan found {malicious_count} dangerous and {suspicious_count} suspicious files."
        elif suspicious_count > 0:
            verdict = "review"
            summary = f"Scan found {suspicious_count} suspicious files and no dangerous files."
        else:
            verdict = "safe"
            summary = "Scan completed and everything checked so far looks safe."

        scan_entry = {
            "id": str(uuid.uuid4()),
            "label": label,
            "target_id": target_id,
            "requested_by": requested_by,
            "started_at": started_at,
            "completed_at": completed_at,
            "files_scanned": files_scanned,
            "clean_count": clean_count,
            "suspicious_count": suspicious_count,
            "malicious_count": malicious_count,
            "truncated": truncated,
            "verdict": verdict,
            "summary": summary,
            "total_flagged_count": total_flagged_count,
            "stored_finding_count": len(stored_findings),
            "hidden_finding_count": max(0, total_flagged_count - len(stored_findings)),
            "findings": stored_findings,
        }

        self.status["last_scan"] = scan_entry
        self.status["scan_history"] = [scan_entry, *(self.status.get("scan_history") or [])][:MAX_SCAN_HISTORY]
        self.status["scanner"]["current_job"] = None
        self.status["scanner"]["state"] = "watching" if self.live_watch_enabled else "idle"
        self._append_live_event(
            {
                "id": str(uuid.uuid4()),
                "timestamp": completed_at,
                "target_label": label,
                "target_id": target_id,
                "action": "manual_scan_complete",
                "entity_type": "scan",
                "name": label,
                "path": "",
                "verdict": verdict,
                "summary": summary,
            }
        )

    def _scan_target(self, target: SafetyTarget) -> Dict[str, object]:
        files = self._collect_scan_files(target.path)
        truncated = len(files) >= MAX_SCAN_FILES_PER_TARGET
        clean_count = 0
        suspicious_count = 0
        malicious_count = 0
        findings: List[Dict[str, object]] = []

        for file_path in files:
            try:
                finding = self.scanner.scan_file(file_path)
            except Exception:
                continue

            if finding.severity == "clean":
                clean_count += 1
                continue
            if finding.severity == "malicious":
                malicious_count += 1
            else:
                suspicious_count += 1

            findings.append(
                {
                    "path": str(file_path),
                    "name": file_path.name,
                    "severity": finding.severity,
                    "score": finding.score,
                    "reasons": finding.reasons[:6],
                    "signature_name": finding.signature_name,
                    "signature_description": finding.signature_description,
                }
            )

        return {
            "files_scanned": len(files),
            "clean_count": clean_count,
            "suspicious_count": suspicious_count,
            "malicious_count": malicious_count,
            "truncated": truncated,
            "findings": findings,
        }

    def _sort_findings(self, findings: List[Dict[str, object]]) -> List[Dict[str, object]]:
        severity_order = {
            "malicious": 0,
            "suspicious": 1,
            "clean": 2,
        }
        return sorted(
            findings,
            key=lambda finding: (
                severity_order.get(str(finding.get("severity") or "").lower(), 3),
                -int(finding.get("score") or 0),
                str(finding.get("name") or ""),
            ),
        )

    def _collect_scan_files(self, root: Path) -> List[Path]:
        if not root.exists():
            return []
        files: List[Path] = []
        for current_root, dir_names, file_names in os.walk(root):
            current_path = Path(current_root)
            dir_names[:] = [
                name
                for name in dir_names
                if name.lower() not in {".git", "node_modules", "__pycache__", "dist", "build"}
                and not self._is_ignored_path(current_path / name)
            ]
            if self._is_ignored_path(current_path):
                continue
            for file_name in file_names:
                file_path = current_path / file_name
                if not self._is_ignored_path(file_path):
                    files.append(file_path)
        files.sort(key=lambda item: item.stat().st_mtime if item.exists() else 0, reverse=True)
        return files[:MAX_SCAN_FILES_PER_TARGET]

    def _prime_live_watch_snapshots(self) -> None:
        self.snapshots = {}
        for target in self._build_watch_targets():
            self.snapshots[target.id] = self._snapshot_tree(target.path)

    def _build_watch_targets(self) -> List[SafetyTarget]:
        return self._build_targets()

    def _snapshot_tree(self, root: Path) -> Dict[str, Dict[str, object]]:
        snapshot: Dict[str, Dict[str, object]] = {}
        if not root.exists():
            return snapshot
        try:
            for current_root, dir_names, file_names in os.walk(root):
                current_path = Path(current_root)
                dir_names[:] = [
                    name
                    for name in dir_names
                    if name.lower() not in {".git", "node_modules", "__pycache__", "dist", "build"}
                    and not self._is_ignored_path(current_path / name)
                ]
                if self._is_ignored_path(current_path):
                    continue
                snapshot[str(current_path)] = {
                    "path": str(current_path),
                    "name": current_path.name or str(current_path),
                    "entity_type": "directory",
                    "signature": "directory",
                    "size": 0,
                }
                for file_name in file_names:
                    file_path = current_path / file_name
                    try:
                        stat_result = file_path.stat()
                    except OSError:
                        continue
                    snapshot[str(file_path)] = {
                        "path": str(file_path),
                        "name": file_path.name,
                        "entity_type": "file",
                        "signature": f"{stat_result.st_size}:{int(stat_result.st_mtime)}",
                        "size": int(stat_result.st_size),
                    }
        except Exception:
            return snapshot
        return snapshot

    def _is_ignored_path(self, path: Path) -> bool:
        try:
            resolved = path.resolve()
        except OSError:
            return False
        for ignored_path in IGNORED_TREE_PATHS:
            try:
                resolved.relative_to(ignored_path)
                return True
            except ValueError:
                continue
        return False

    def _poll_live_watch(self) -> None:
        targets = self._build_watch_targets()
        current_target_ids = {target.id for target in targets}
        for target_id in list(self.snapshots.keys()):
            if target_id not in current_target_ids:
                self.snapshots.pop(target_id, None)

        for target in targets:
            previous_snapshot = self.snapshots.get(target.id, {})
            current_snapshot = self._snapshot_tree(target.path)
            events = self._compare_snapshots(target, previous_snapshot, current_snapshot)
            self.snapshots[target.id] = current_snapshot
            for event in events:
                self._append_live_event(event)

        self.status["scanner"]["state"] = "watching"

    def _compare_snapshots(
        self,
        target: SafetyTarget,
        previous_snapshot: Dict[str, Dict[str, object]],
        current_snapshot: Dict[str, Dict[str, object]],
    ) -> List[Dict[str, object]]:
        events: List[Dict[str, object]] = []

        for path, item in current_snapshot.items():
            previous_item = previous_snapshot.get(path)
            if previous_item is None:
                events.append(self._build_live_event(target, item, "created"))
            elif item["entity_type"] == "file" and item["signature"] != previous_item.get("signature"):
                events.append(self._build_live_event(target, item, "modified"))

        for path, item in previous_snapshot.items():
            if path in current_snapshot:
                continue
            removed_item = dict(item)
            events.append(self._build_live_event(target, removed_item, "deleted"))

        events.sort(key=lambda item: item.get("timestamp", ""), reverse=True)
        return events[:8]

    def _build_live_event(self, target: SafetyTarget, item: Dict[str, object], action: str) -> Dict[str, object]:
        timestamp = utcnow_iso()
        entity_type = str(item.get("entity_type") or "file")
        path = str(item.get("path") or "")
        name = str(item.get("name") or path or target.label)

        if entity_type == "file" and action in {"created", "modified"} and Path(path).exists():
            verdict = "safe"
            summary = f"{name} looks safe."
            reasons: List[str] = []
            try:
                finding = self.scanner.scan_file(Path(path))
                reasons = finding.reasons[:6]
                if finding.severity == "malicious":
                    verdict = "unsafe"
                    summary = f"{name} looks dangerous and should be reviewed immediately."
                elif finding.severity == "suspicious":
                    verdict = "review"
                    summary = f"{name} needs review because it matched suspicious patterns."
            except Exception:
                verdict = "unknown"
                summary = f"{name} changed, but the quick safety check could not finish."
                reasons = []
        elif entity_type == "directory":
            verdict = "info"
            summary = f"Folder {action}: {name}"
            reasons = []
        else:
            verdict = "info"
            summary = f"File {action}: {name}"
            reasons = []

        return {
            "id": str(uuid.uuid4()),
            "timestamp": timestamp,
            "target_label": target.label,
            "target_id": target.id,
            "action": action,
            "entity_type": entity_type,
            "name": name,
            "path": path,
            "verdict": verdict,
            "summary": summary,
            "reasons": reasons,
        }

    def _append_live_event(self, event: Dict[str, object]) -> None:
        recent_events = self.status.get("recent_live_events") or []
        self.status["recent_live_events"] = [event, *recent_events][:MAX_RECENT_EVENTS]

    def _write_status(self) -> None:
        self.status.setdefault("agent", {})
        self.status["agent"]["running"] = True
        self.status["agent"]["version"] = AGENT_VERSION
        self.status["agent"]["last_heartbeat_at"] = utcnow_iso()
        self.status["agent"]["last_command_id"] = self.last_command_id
        self.status.setdefault("scanner", {})
        self.status["scanner"]["live_watch_enabled"] = self.live_watch_enabled
        write_device_safety_status(self.status)


def main() -> int:
    agent = DeviceSafetyAgent()
    agent.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
