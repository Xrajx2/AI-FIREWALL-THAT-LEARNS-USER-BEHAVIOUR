from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import string
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:
    import psutil
except ImportError:  # pragma: no cover - handled at runtime
    psutil = None

try:  # pragma: no cover - optional dependency
    import pyudev
except ImportError:  # pragma: no cover - optional dependency
    pyudev = None


SCRIPT_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".com",
    ".hta",
    ".js",
    ".jse",
    ".lnk",
    ".ps1",
    ".pif",
    ".reg",
    ".scr",
    ".vbe",
    ".vbs",
    ".wsf",
}
BINARY_EXTENSIONS = {".dll", ".exe", ".msi"}
MACRO_EXTENSIONS = {".docm", ".pptm", ".xlsm"}
CONTENT_INSPECTION_EXTENSIONS = SCRIPT_EXTENSIONS | MACRO_EXTENSIONS | {".doc", ".docx", ".inf", ".txt"}
DOUBLE_EXTENSION_PATTERN = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|gif|txt|zip)\.(exe|bat|cmd|scr|js|vbs|ps1)$",
    re.IGNORECASE,
)
SUSPICIOUS_NAME_PATTERN = re.compile(
    r"(autorun|backdoor|crack|dropper|keygen|loader|payload|ransom|stealer|trojan)",
    re.IGNORECASE,
)
TEXT_SIGNATURES = {
    b"powershell -enc": "encoded_powershell_command",
    b"invoke-expression": "powershell_invoke_expression",
    b"downloadstring(": "download_string_payload",
    b"frombase64string(": "base64_decode_behavior",
    b"wscript.shell": "wscript_shell_usage",
    b"createobject(": "createobject_macro_behavior",
    b"shell.application": "shell_application_com_usage",
    b"cmd.exe /c": "shell_command_launcher",
    b"autoopen": "macro_autoopen_behavior",
    b"wmic process call create": "wmic_process_spawn",
}
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
WINDOWS_DRIVE_REMOVABLE = 2
MAX_CONTENT_INSPECTION_BYTES = 1024 * 1024
LARGE_BINARY_THRESHOLD_BYTES = 100 * 1024 * 1024
def _resolve_default_quarantine_root() -> Path:
    try:
        from app.paths import get_quarantine_dir
        return get_quarantine_dir()
    except ImportError:
        try:
            from backend.app.paths import get_quarantine_dir
            return get_quarantine_dir()
        except ImportError:
            return Path(os.environ.get("APPDATA", ".")) / "AIFirewall" / "quarantine"

def _resolve_default_log_file() -> Path:
    try:
        from app.paths import get_logs_dir
        return get_logs_dir() / "usb_security_module.log"
    except ImportError:
        try:
            from backend.app.paths import get_logs_dir
            return get_logs_dir() / "usb_security_module.log"
        except ImportError:
            return Path(os.environ.get("APPDATA", ".")) / "AIFirewall" / "logs" / "usb_security_module.log"

def _resolve_default_signature_db() -> Path:
    try:
        from app.paths import get_resource_path
        return get_resource_path("backend/security/malware_signatures.json")
    except ImportError:
        try:
            from backend.app.paths import get_resource_path
            return get_resource_path("backend/security/malware_signatures.json")
        except ImportError:
            return Path(__file__).resolve().parent / "security" / "malware_signatures.json"

DEFAULT_LOG_FILE = _resolve_default_log_file()
DEFAULT_QUARANTINE_ROOT = _resolve_default_quarantine_root()
DEFAULT_SIGNATURE_DB = _resolve_default_signature_db()
EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@dataclass(frozen=True)
class USBDevice:
    device_id: str
    mountpoint: Path
    label: str
    filesystem: str
    source: str


@dataclass
class ScanFinding:
    file_path: Path
    severity: str
    score: int
    reasons: List[str]
    sha256: str
    size_bytes: int
    signature_name: str = ""
    signature_description: str = ""
    action: str = "allow"
    quarantine_path: Optional[Path] = None


@dataclass
class ScanSummary:
    device: USBDevice
    files_scanned: int = 0
    suspicious_count: int = 0
    malicious_count: int = 0
    quarantined_count: int = 0
    status: str = "completed"
    findings: List[ScanFinding] = field(default_factory=list)


class ActionLogger:
    def __init__(self, log_file: Path):
        self.log_file = log_file.resolve()
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        self._logger = logging.getLogger("ai_firewall.usb_security")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        self._logger.handlers.clear()

        formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self._logger.addHandler(console_handler)

        file_handler = logging.FileHandler(self.log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        self._logger.addHandler(file_handler)

    def event(self, category: str, message: str) -> None:
        self._logger.info("%s | %s", category, message)

    def alert(self, message: str) -> None:
        self._logger.warning("ALERT | %s", message)

    def error(self, message: str) -> None:
        self._logger.error("%s", message)

    def close(self) -> None:
        for handler in list(self._logger.handlers):
            try:
                handler.close()
            except Exception:
                pass
            self._logger.removeHandler(handler)


class SignatureDatabase:
    def __init__(self, signature_path: Path):
        self.signature_path = signature_path.resolve()
        self.entries: Dict[str, Dict[str, object]] = {}

    def load(self) -> None:
        self.entries = {}
        if not self.signature_path.exists():
            return
        with self.signature_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        for entry in data:
            sha256 = str(entry.get("sha256", "")).strip().upper()
            if not sha256:
                continue
            self.entries[sha256] = entry

    def lookup(self, sha256: str) -> Optional[Dict[str, object]]:
        return self.entries.get(sha256.upper())


class QuarantineManager:
    def __init__(self, quarantine_root: Path, logger: ActionLogger):
        self.quarantine_root = quarantine_root.resolve()
        self.logger = logger
        self.quarantine_root.mkdir(parents=True, exist_ok=True)

    def quarantine(self, file_path: Path, device: USBDevice, finding: ScanFinding) -> Path:
        device_slug = slugify(device.device_id)
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        relative_path = safe_relative_path(file_path, device.mountpoint)
        destination = self.quarantine_root / device_slug / timestamp / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination = unique_path(destination)
        shutil.move(str(file_path), str(destination))

        metadata_path = destination.with_name(destination.name + ".quarantine.json")
        metadata = {
            "original_path": str(file_path),
            "quarantine_path": str(destination),
            "device_id": device.device_id,
            "device_label": device.label,
            "severity": finding.severity,
            "score": finding.score,
            "reasons": finding.reasons,
            "sha256": finding.sha256,
            "signature_name": finding.signature_name,
            "signature_description": finding.signature_description,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        return destination


class USBDetector:
    def __init__(self):
        self._known_devices: Dict[str, USBDevice] = {}
        self._platform_name = platform.system().lower()

    def prime(self) -> List[USBDevice]:
        self._known_devices = self._enumerate_devices()
        return list(self._known_devices.values())

    def poll_changes(self) -> Tuple[List[USBDevice], List[USBDevice]]:
        current_devices = self._enumerate_devices()
        inserted = [current_devices[key] for key in sorted(current_devices.keys() - self._known_devices.keys())]
        removed = [self._known_devices[key] for key in sorted(self._known_devices.keys() - current_devices.keys())]
        self._known_devices = current_devices
        return inserted, removed

    def _enumerate_devices(self) -> Dict[str, USBDevice]:
        if self._platform_name == "windows":
            return self._enumerate_windows_devices()
        if self._platform_name == "linux":
            return self._enumerate_linux_devices()
        return self._enumerate_portable_devices()

    def _enumerate_windows_devices(self) -> Dict[str, USBDevice]:
        partitions_by_mount = {
            normalize_mountpoint(partition.mountpoint): partition for partition in psutil.disk_partitions(all=True)
        }
        devices: Dict[str, USBDevice] = {}
        for drive in list_windows_drives():
            if get_windows_drive_type(drive) != WINDOWS_DRIVE_REMOVABLE:
                continue
            partition = partitions_by_mount.get(normalize_mountpoint(drive))
            devices[drive] = USBDevice(
                device_id=drive,
                mountpoint=Path(drive),
                label=get_windows_volume_label(drive),
                filesystem=partition.fstype if partition else "unknown",
                source="windows-removable-drive",
            )
        return devices

    def _enumerate_linux_devices(self) -> Dict[str, USBDevice]:
        usb_nodes: Set[str] = set()
        if pyudev is not None:
            try:
                context = pyudev.Context()
                for device in context.list_devices(subsystem="block"):
                    if device.get("DEVTYPE") not in {"disk", "partition"}:
                        continue
                    has_usb_parent = device.find_parent("usb", "usb_device") is not None
                    if device.get("ID_BUS") == "usb" or has_usb_parent:
                        if device.device_node:
                            usb_nodes.add(device.device_node)
            except Exception:
                usb_nodes = set()

        devices: Dict[str, USBDevice] = {}
        for partition in psutil.disk_partitions(all=True):
            mountpoint = partition.mountpoint or ""
            is_usb_mount = partition.device in usb_nodes or mountpoint.startswith(("/media/", "/run/media/", "/mnt/"))
            if not is_usb_mount:
                continue
            device_id = f"{partition.device}|{partition.mountpoint}"
            devices[device_id] = USBDevice(
                device_id=device_id,
                mountpoint=Path(partition.mountpoint),
                label=Path(partition.mountpoint).name or partition.device,
                filesystem=partition.fstype or "unknown",
                source="linux-usb-mount",
            )
        return devices

    def _enumerate_portable_devices(self) -> Dict[str, USBDevice]:
        devices: Dict[str, USBDevice] = {}
        for partition in psutil.disk_partitions(all=True):
            mountpoint = partition.mountpoint or ""
            opts = (partition.opts or "").lower()
            is_usb_mount = "removable" in opts or mountpoint.startswith("/Volumes/")
            if not is_usb_mount:
                continue
            device_id = f"{partition.device}|{partition.mountpoint}"
            devices[device_id] = USBDevice(
                device_id=device_id,
                mountpoint=Path(partition.mountpoint),
                label=Path(partition.mountpoint).name or partition.device,
                filesystem=partition.fstype or "unknown",
                source="portable-usb-mount",
            )
        return devices


class FileScanner:
    def __init__(self, signatures: SignatureDatabase):
        self.signatures = signatures

    def scan_file(self, file_path: Path) -> ScanFinding:
        stat_result = file_path.stat()
        name = file_path.name
        extension = file_path.suffix.lower()
        size_bytes = stat_result.st_size
        reasons: List[str] = []
        score = 0

        if extension in SCRIPT_EXTENSIONS:
            score += 4
            reasons.append(f"script_extension:{extension}")

        if extension in BINARY_EXTENSIONS:
            score += 2
            reasons.append(f"executable_extension:{extension}")

        if extension in MACRO_EXTENSIONS:
            score += 4
            reasons.append("macro_enabled_document")

        if name.lower() == "autorun.inf":
            score += 8
            reasons.append("autorun_file")

        if DOUBLE_EXTENSION_PATTERN.search(name):
            score += 8
            reasons.append("double_extension")

        if SUSPICIOUS_NAME_PATTERN.search(name):
            score += 3
            reasons.append("suspicious_filename")

        if extension in BINARY_EXTENSIONS and size_bytes >= LARGE_BINARY_THRESHOLD_BYTES:
            score += 2
            reasons.append("large_binary_on_usb")

        if is_hidden_or_system_file(stat_result):
            score += 2
            reasons.append("hidden_or_system")

        content_bytes = b""
        if size_bytes <= MAX_CONTENT_INSPECTION_BYTES or extension in CONTENT_INSPECTION_EXTENSIONS or name.lower() == "autorun.inf":
            content_bytes = read_file_prefix(file_path, MAX_CONTENT_INSPECTION_BYTES)
            lowered = content_bytes.lower()
            if EICAR_SIGNATURE in content_bytes:
                score = max(score, 12)
                reasons.append("eicar_test_signature")
            for pattern, reason in TEXT_SIGNATURES.items():
                if pattern in lowered:
                    score += 2
                    reasons.append(reason)

        sha256 = sha256sum(file_path)
        signature = self.signatures.lookup(sha256)
        if signature:
            score = max(score, int(signature.get("severity", 90)))
            reasons.append("signature_match")

        severity = classify_severity(score, reasons)
        return ScanFinding(
            file_path=file_path,
            severity=severity,
            score=score,
            reasons=sorted(set(reasons)),
            sha256=sha256,
            size_bytes=size_bytes,
            signature_name=str(signature.get("name", "")) if signature else "",
            signature_description=str(signature.get("description", "")) if signature else "",
        )


class USBSecurityModule:
    def __init__(
        self,
        *,
        detector: USBDetector,
        scanner: FileScanner,
        quarantine: QuarantineManager,
        logger: ActionLogger,
        quarantine_level: str,
        poll_interval: float,
        test_device_path: Optional[Path] = None,
    ):
        self.detector = detector
        self.scanner = scanner
        self.quarantine = quarantine
        self.logger = logger
        self.quarantine_level = quarantine_level
        self.poll_interval = poll_interval
        self.test_device_path = test_device_path.resolve() if test_device_path else None
        self._handled_test_path = False

    def close(self) -> None:
        if self.logger:
            self.logger.close()

    def run(self, *, once: bool = False) -> None:
        self.logger.event(
            "USB_SECURITY_START",
            f"poll_interval={self.poll_interval:.1f}s quarantine_level={self.quarantine_level} quarantine_root={self.quarantine.quarantine_root}",
        )

        current_devices = self.detector.prime()
        for device in current_devices:
            self._handle_device_insertion(device, startup=True)

        if self.test_device_path and not self._handled_test_path:
            test_device = USBDevice(
                device_id=f"test::{self.test_device_path}",
                mountpoint=self.test_device_path,
                label=self.test_device_path.name or "test-device",
                filesystem="directory",
                source="test-path",
            )
            self._handle_device_insertion(test_device, startup=True)
            self._handled_test_path = True

        if once:
            return

        while True:
            try:
                inserted, removed = self.detector.poll_changes()
                for device in inserted:
                    self._handle_device_insertion(device, startup=False)
                for device in removed:
                    self._handle_device_removal(device)
                time.sleep(self.poll_interval)
            except KeyboardInterrupt:
                self.logger.event("USB_SECURITY_STOP", "Keyboard interrupt received, shutting down")
                return
            except Exception as exc:
                self.logger.error(f"USB monitor loop failed: {exc}")
                time.sleep(self.poll_interval)

    def _handle_device_insertion(self, device: USBDevice, *, startup: bool) -> None:
        state = "USB_PRESENT" if startup else "USB_INSERT"
        self.logger.event(
            state,
            f"device_id={device.device_id} label={device.label or 'unknown'} mountpoint={device.mountpoint} filesystem={device.filesystem} source={device.source}",
        )
        summary = self._scan_device(device)
        self.logger.event(
            "USB_SCAN_COMPLETE",
            " ".join(
                [
                    f"device_id={device.device_id}",
                    f"files_scanned={summary.files_scanned}",
                    f"suspicious={summary.suspicious_count}",
                    f"malicious={summary.malicious_count}",
                    f"quarantined={summary.quarantined_count}",
                ]
            ),
        )
        if summary.suspicious_count or summary.malicious_count:
            self.logger.alert(
                "USB threats detected "
                f"device={device.label or device.device_id} suspicious={summary.suspicious_count} malicious={summary.malicious_count}"
            )

    def _handle_device_removal(self, device: USBDevice) -> None:
        self.logger.event(
            "USB_REMOVE",
            f"device_id={device.device_id} label={device.label or 'unknown'} mountpoint={device.mountpoint}",
        )

    def _scan_device(self, device: USBDevice) -> ScanSummary:
        summary = ScanSummary(device=device)
        if not device.mountpoint.exists():
            self.logger.error(f"Cannot scan missing USB path: {device.mountpoint}")
            summary.status = "interrupted"
            return summary

        try:
            for file_path in iter_files(device.mountpoint):
                if not device.mountpoint.exists():
                    self.logger.alert(f"USB drive disconnected during scan: {device.mountpoint}")
                    summary.status = "interrupted"
                    break

                try:
                    finding = self.scanner.scan_file(file_path)
                except (FileNotFoundError, OSError) as exc:
                    self.logger.alert(f"USB drive or file disappeared mid-scan: {file_path} ({exc})")
                    summary.status = "interrupted"
                    break
                except Exception as exc:
                    self.logger.error(f"Failed to scan {file_path}: {exc}")
                    continue

                summary.files_scanned += 1

                if finding.severity == "clean":
                    continue

                if finding.severity == "suspicious":
                    summary.suspicious_count += 1
                elif finding.severity == "malicious":
                    summary.malicious_count += 1

                self.logger.alert(
                    "Suspicious file detected "
                    f"path={file_path} severity={finding.severity} score={finding.score} reasons={'; '.join(finding.reasons)}"
                )

                if self._should_quarantine(finding):
                    try:
                        quarantine_path = self.quarantine.quarantine(file_path, device, finding)
                        finding.action = "quarantined"
                        finding.quarantine_path = quarantine_path
                        summary.quarantined_count += 1
                        self.logger.event(
                            "USB_QUARANTINE",
                            f"source={file_path} destination={quarantine_path} severity={finding.severity}",
                        )
                    except (FileNotFoundError, OSError) as exc:
                        finding.action = "quarantine_failed"
                        self.logger.alert(f"USB drive disconnected during quarantine: {exc}")
                        summary.status = "interrupted"
                        break
                    except Exception as exc:
                        finding.action = "quarantine_failed"
                        self.logger.error(f"Failed to quarantine {file_path}: {exc}")

                summary.findings.append(finding)
        except (FileNotFoundError, OSError) as exc:
            self.logger.alert(f"USB drive traversal interrupted: {exc}")
            summary.status = "interrupted"

        return summary

    def _should_quarantine(self, finding: ScanFinding) -> bool:
        if self.quarantine_level == "suspicious":
            return finding.severity in {"suspicious", "malicious"}
        return finding.severity == "malicious"


def ensure_dependencies() -> None:
    if psutil is None:
        raise SystemExit("Missing required package: psutil. Install with `py -3 -m pip install -r backend/requirements.txt`.")


def slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return slug or "usb-device"


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    counter = 1
    while True:
        candidate = path.with_name(f"{path.stem}_{counter}{path.suffix}")
        if not candidate.exists():
            return candidate
        counter += 1


def safe_relative_path(file_path: Path, root: Path) -> Path:
    try:
        return file_path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except ValueError:
        return Path(file_path.name)


def classify_severity(score: int, reasons: List[str]) -> str:
    reason_set = set(reasons)
    if "signature_match" in reason_set or "eicar_test_signature" in reason_set or score >= 10:
        return "malicious"
    if score >= 4:
        return "suspicious"
    return "clean"


def sha256sum(file_path: Path) -> str:
    digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def read_file_prefix(file_path: Path, max_bytes: int) -> bytes:
    with file_path.open("rb") as handle:
        return handle.read(max_bytes)


def is_hidden_or_system_file(stat_result: os.stat_result) -> bool:
    file_attributes = getattr(stat_result, "st_file_attributes", 0)
    return bool(file_attributes & FILE_ATTRIBUTE_HIDDEN or file_attributes & FILE_ATTRIBUTE_SYSTEM)


def iter_files(root: Path) -> Iterable[Path]:
    for current_root, dir_names, file_names in os.walk(root):
        dir_names[:] = [name for name in dir_names if name.lower() not in KNOWN_CONTAINER_DIR_NAMES]
        for file_name in file_names:
            path = Path(current_root) / file_name
            if path.is_symlink():
                continue
            yield path


def normalize_mountpoint(value: str) -> str:
    return str(Path(value)).rstrip("\\/").lower() + "\\"


def list_windows_drives() -> List[str]:
    try:
        # SEM_FAILCRITICALERRORS (0x0001) | SEM_NOOPENFILEERRORBOX (0x8000)
        ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x8000)
    except Exception:
        pass
    drive_mask = ctypes.windll.kernel32.GetLogicalDrives()
    drives: List[str] = []
    for index, letter in enumerate(string.ascii_uppercase):
        if drive_mask & (1 << index):
            drives.append(f"{letter}:\\")
    return drives


def get_windows_drive_type(drive: str) -> int:
    try:
        ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x8000)
    except Exception:
        pass
    return int(ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(drive)))


def get_windows_volume_label(drive: str) -> str:
    try:
        ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x8000)
    except Exception:
        pass
    volume_name = ctypes.create_unicode_buffer(261)
    filesystem_name = ctypes.create_unicode_buffer(261)
    serial_number = ctypes.c_uint(0)
    max_component_length = ctypes.c_uint(0)
    filesystem_flags = ctypes.c_uint(0)
    success = ctypes.windll.kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p(drive),
        volume_name,
        len(volume_name),
        ctypes.byref(serial_number),
        ctypes.byref(max_component_length),
        ctypes.byref(filesystem_flags),
        filesystem_name,
        len(filesystem_name),
    )
    if not success:
        return drive.rstrip("\\")
    return volume_name.value or drive.rstrip("\\")


def resolve_path(raw_path: str | Path) -> Path:
    return Path(raw_path).expanduser().resolve(strict=False)


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple USB security module for the AI Firewall project.")
    parser.add_argument("--poll-interval", type=float, default=2.0, help="Seconds between USB device checks.")
    parser.add_argument(
        "--signature-db",
        default=str(DEFAULT_SIGNATURE_DB),
        help="Path to the JSON malware signature database.",
    )
    parser.add_argument(
        "--quarantine-root",
        default=str(DEFAULT_QUARANTINE_ROOT),
        help="Directory used to quarantine suspicious or malicious files.",
    )
    parser.add_argument(
        "--quarantine-level",
        choices=("malicious", "suspicious"),
        default="malicious",
        help="Quarantine only malicious files or both suspicious and malicious files.",
    )
    parser.add_argument(
        "--log-file",
        default=str(DEFAULT_LOG_FILE),
        help="File used to persist USB security events.",
    )
    parser.add_argument(
        "--test-device-path",
        help="Treat a normal directory as a USB device so you can test scanning without real hardware.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single startup scan for currently connected devices and exit.",
    )
    return parser.parse_args(argv)


def build_module(args: argparse.Namespace) -> USBSecurityModule:
    ensure_dependencies()

    logger = ActionLogger(resolve_path(args.log_file))
    signatures = SignatureDatabase(resolve_path(args.signature_db))
    signatures.load()
    logger.event(
        "SIGNATURE_DB",
        f"path={signatures.signature_path} loaded_entries={len(signatures.entries)} pyudev_available={bool(pyudev)}",
    )

    detector = USBDetector()
    scanner = FileScanner(signatures)
    quarantine = QuarantineManager(resolve_path(args.quarantine_root), logger)
    test_device_path = resolve_path(args.test_device_path) if args.test_device_path else None
    if test_device_path and not test_device_path.exists():
        raise SystemExit(f"Test device path does not exist: {test_device_path}")

    return USBSecurityModule(
        detector=detector,
        scanner=scanner,
        quarantine=quarantine,
        logger=logger,
        quarantine_level=args.quarantine_level,
        poll_interval=max(1.0, float(args.poll_interval)),
        test_device_path=test_device_path,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    module = build_module(args)
    module.run(once=bool(args.once))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
