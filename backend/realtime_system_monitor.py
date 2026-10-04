from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import sys
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:
    import psutil
except ImportError:  # pragma: no cover - handled at runtime
    psutil = None

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:  # pragma: no cover - handled at runtime
    FileSystemEventHandler = object
    Observer = None


SUSPICIOUS_PROCESS_NAMES = {
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

SAFE_REMOTE_PORTS = {53, 80, 123, 443}
HIGH_RISK_REMOTE_PORTS = {21, 23, 25, 135, 139, 445, 3389, 4444, 5555, 5985, 5986, 6667}
IGNORED_DIR_NAMES = {".git", ".venv", "__pycache__", "build", "dist", "logs", "node_modules", "venv"}


@dataclass
class MonitorConfig:
    watch_paths: List[Path]
    poll_interval: float = 3.0
    process_learning_cycles: int = 2
    bulk_file_threshold: int = 25
    bulk_file_window_seconds: float = 10.0
    network_spike_threshold_mb: float = 25.0
    unusual_remote_threshold: int = 8
    top_process_count: int = 5
    top_connection_count: int = 5
    log_file: Path = field(
        default_factory=lambda: Path(__file__).resolve().parent / "logs" / "realtime_system_monitor.log"
    )


class MonitorLogger:
    def __init__(self, log_file: Path):
        self.log_file = log_file.resolve()
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        self._logger = logging.getLogger("ai_firewall.realtime_monitor")
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


def ensure_dependencies() -> None:
    missing = []
    if psutil is None:
        missing.append("psutil")
    if Observer is None:
        missing.append("watchdog")

    if missing:
        joined = ", ".join(missing)
        raise SystemExit(
            f"Missing required packages: {joined}. Install them with `py -3 -m pip install -r backend/requirements.txt`."
        )


def normalize_process_name(name: str) -> str:
    value = (name or "unknown").strip().lower()
    return value[:-4] if value.endswith(".exe") else value


def resolve_path(raw_path: str | Path) -> Path:
    candidate = Path(raw_path).expanduser()
    return candidate.resolve(strict=False)


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def format_bytes(num_bytes: float) -> str:
    value = float(max(0.0, num_bytes))
    units = ["B", "KB", "MB", "GB", "TB"]
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            return f"{value:.2f}{unit}"
        value /= 1024.0
    return f"{value:.2f}TB"


def looks_user_writable_path(exe_path: str) -> bool:
    if not exe_path:
        return False
    lowered = exe_path.lower()
    suspicious_markers = (
        "\\appdata\\local\\temp\\",
        "\\downloads\\",
        "\\temp\\",
        "/downloads/",
        "/tmp/",
        "/var/tmp/",
    )
    return any(marker in lowered for marker in suspicious_markers)


def is_public_ip(ip_value: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_value)
    except ValueError:
        return False
    return not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


class FileActivityHandler(FileSystemEventHandler):
    def __init__(self, monitor: "FileMonitor"):
        self.monitor = monitor

    def on_created(self, event) -> None:
        self.monitor.record_event("CREATE", getattr(event, "src_path", ""), is_directory=event.is_directory)

    def on_deleted(self, event) -> None:
        self.monitor.record_event("DELETE", getattr(event, "src_path", ""), is_directory=event.is_directory)

    def on_modified(self, event) -> None:
        self.monitor.record_event("MODIFY", getattr(event, "src_path", ""), is_directory=event.is_directory)

    def on_moved(self, event) -> None:
        self.monitor.record_event(
            "MOVE",
            getattr(event, "src_path", ""),
            dest_path=getattr(event, "dest_path", ""),
            is_directory=event.is_directory,
        )


class FileMonitor:
    def __init__(self, config: MonitorConfig, logger: MonitorLogger):
        self.config = config
        self.logger = logger
        self.observer = Observer()
        self._lock = threading.Lock()
        self._recent_events: Deque[Tuple[float, str]] = deque()
        self._last_bulk_alert_at = 0.0
        self._ignored_prefixes = [logger.log_file.parent]

    def start(self) -> None:
        handler = FileActivityHandler(self)
        for path in self.config.watch_paths:
            self.observer.schedule(handler, str(path), recursive=True)
            self.logger.event("FILE_WATCH", f"path={path}")
        self.observer.start()

    def stop(self) -> None:
        self.observer.stop()
        self.observer.join(timeout=5)

    def record_event(
        self,
        action: str,
        src_path: str,
        *,
        dest_path: str = "",
        is_directory: bool = False,
    ) -> None:
        if is_directory or not src_path:
            return

        source = resolve_path(src_path)
        if self._should_ignore(source):
            return

        message = f"action={action} path={source}"
        if dest_path:
            destination = resolve_path(dest_path)
            if self._should_ignore(destination):
                return
            message = f"{message} dest={destination}"

        self.logger.event("FILE_EVENT", message)

        now = time.time()
        with self._lock:
            self._recent_events.append((now, str(source)))
            while self._recent_events and (now - self._recent_events[0][0]) > self.config.bulk_file_window_seconds:
                self._recent_events.popleft()

            total_events = len(self._recent_events)
            unique_files = len({path for _, path in self._recent_events})
            if (
                total_events >= self.config.bulk_file_threshold
                and unique_files >= max(5, self.config.bulk_file_threshold // 3)
                and (now - self._last_bulk_alert_at) >= self.config.bulk_file_window_seconds
            ):
                self._last_bulk_alert_at = now
                self.logger.alert(
                    "Bulk file activity detected "
                    f"events={total_events} unique_files={unique_files} "
                    f"window={self.config.bulk_file_window_seconds:.0f}s"
                )

    def _should_ignore(self, path: Path) -> bool:
        parts = {part.lower() for part in path.parts}
        if parts.intersection(IGNORED_DIR_NAMES):
            return True
        return any(is_relative_to(path, prefix) for prefix in self._ignored_prefixes)


class ProcessMonitor:
    def __init__(self, config: MonitorConfig, logger: MonitorLogger):
        self.config = config
        self.logger = logger
        self._cpu_count = max(psutil.cpu_count(logical=True) or 1, 1)
        self._baseline_names: Set[str] = set()
        self._known_pids: Set[int] = set()
        self._alerted_processes: Set[Tuple[str, str]] = set()
        self._learning_cycles_remaining = max(0, config.process_learning_cycles)
        self._prime_cpu_counters()

    def scan(self) -> List[Dict[str, object]]:
        current_pids: Set[int] = set()
        current_by_pid: Dict[int, Dict[str, object]] = {}
        process_rows: List[Dict[str, object]] = []

        for process in psutil.process_iter(["pid", "name", "exe", "memory_info"]):
            try:
                info = process.info
                pid = int(info.get("pid"))
                name = str(info.get("name") or "unknown")
                exe = str(info.get("exe") or "")
                memory_info = info.get("memory_info")
                memory_mb = round((memory_info.rss if memory_info else 0) / (1024 * 1024), 2)
                cpu_percent = float(process.cpu_percent(interval=None)) / self._cpu_count
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, TypeError, ValueError):
                continue

            row = {
                "pid": pid,
                "name": name,
                "normalized_name": normalize_process_name(name),
                "cpu_percent": cpu_percent,
                "memory_mb": memory_mb,
                "exe": exe,
            }
            current_pids.add(pid)
            current_by_pid[pid] = row
            process_rows.append(row)

        process_rows.sort(key=lambda item: (float(item["cpu_percent"]), float(item["memory_mb"])), reverse=True)
        self.logger.event(
            "PROCESS_SCAN",
            f"count={len(process_rows)} top={self._format_top_processes(process_rows[: self.config.top_process_count])}",
        )

        if self._learning_cycles_remaining > 0:
            self._baseline_names.update(str(row["normalized_name"]) for row in process_rows)
            self._learning_cycles_remaining -= 1
            if self._learning_cycles_remaining == 0:
                self.logger.event("BASELINE_READY", f"learned_process_names={len(self._baseline_names)}")
        else:
            new_pids = sorted(current_pids - self._known_pids)
            stopped_pids = sorted(self._known_pids - current_pids)

            for pid in new_pids:
                row = current_by_pid[pid]
                self.logger.event(
                    "PROCESS_START",
                    " ".join(
                        [
                            f"name={row['name']}",
                            f"pid={row['pid']}",
                            f"cpu={float(row['cpu_percent']):.1f}%",
                            f"memory={float(row['memory_mb']):.2f}MB",
                        ]
                    ),
                )
                reasons = self._build_reasons(row)
                alert_key = (str(row["normalized_name"]), str(row["exe"]))
                if reasons and alert_key not in self._alerted_processes:
                    self._alerted_processes.add(alert_key)
                    self.logger.alert(
                        "Suspicious process detected "
                        f"name={row['name']} pid={row['pid']} exe={row['exe'] or 'unknown'} "
                        f"reasons={' ; '.join(reasons)}"
                    )
                self._baseline_names.add(str(row["normalized_name"]))

            for pid in stopped_pids[:10]:
                self.logger.event("PROCESS_STOP", f"pid={pid}")

        self._known_pids = current_pids
        return process_rows

    def _build_reasons(self, row: Dict[str, object]) -> List[str]:
        reasons: List[str] = []
        normalized_name = str(row["normalized_name"])
        exe_path = str(row["exe"])
        if normalized_name not in self._baseline_names:
            reasons.append("name not seen during baseline learning")
        if normalized_name in SUSPICIOUS_PROCESS_NAMES:
            reasons.append("process is a scripting or administrative tool")
        if looks_user_writable_path(exe_path):
            reasons.append("executable is running from a user-writable or temporary path")
        return reasons

    def _prime_cpu_counters(self) -> None:
        for process in psutil.process_iter(["pid"]):
            try:
                process.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    @staticmethod
    def _format_top_processes(rows: Sequence[Dict[str, object]]) -> str:
        if not rows:
            return "none"
        return ", ".join(
            f"{row['name']}(pid={row['pid']},cpu={float(row['cpu_percent']):.1f}%,mem={float(row['memory_mb']):.1f}MB)"
            for row in rows
        )


class USBMonitor:
    def __init__(self, logger: MonitorLogger):
        self.logger = logger
        self._known_devices: Dict[str, Dict[str, str]] = {}
        self._initialized = False

    def scan(self) -> List[Dict[str, str]]:
        current_devices = self._list_devices()
        current_keys = set(current_devices)
        previous_keys = set(self._known_devices)

        if self._initialized:
            for device_id in sorted(current_keys - previous_keys):
                device = current_devices[device_id]
                self.logger.event(
                    "USB_INSERT",
                    f"device={device['device']} mountpoint={device['mountpoint']} fstype={device['fstype']}",
                )

            for device_id in sorted(previous_keys - current_keys):
                device = self._known_devices[device_id]
                self.logger.event(
                    "USB_REMOVE",
                    f"device={device['device']} mountpoint={device['mountpoint']} fstype={device['fstype']}",
                )

        self._known_devices = current_devices
        self._initialized = True
        return list(current_devices.values())

    def _list_devices(self) -> Dict[str, Dict[str, str]]:
        devices: Dict[str, Dict[str, str]] = {}
        for partition in psutil.disk_partitions(all=True):
            opts = (partition.opts or "").lower()
            mountpoint = (partition.mountpoint or "").lower()
            if "cdrom" in opts:
                continue
            if not (
                "removable" in opts
                or mountpoint.startswith("/media/")
                or mountpoint.startswith("/run/media/")
                or mountpoint.startswith("/volumes/")
            ):
                continue

            device_id = f"{partition.device}|{partition.mountpoint}"
            devices[device_id] = {
                "device": partition.device,
                "mountpoint": partition.mountpoint,
                "fstype": partition.fstype or "unknown",
                "opts": partition.opts or "",
            }
        return devices


class NetworkMonitor:
    def __init__(self, config: MonitorConfig, logger: MonitorLogger):
        self.config = config
        self.logger = logger
        self._known_public_ips: Set[str] = set()
        self._alerted_connections: Set[Tuple[str, str, int]] = set()
        self._seen_connections: Set[Tuple[str, str, int]] = set()
        self._previous_io = psutil.net_io_counters()
        self._process_name_cache: Dict[int, str] = {}
        self._initialized = False

    def scan(self) -> List[Dict[str, object]]:
        try:
            raw_connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as exc:
            self.logger.error(f"NETWORK_SCAN failed: {exc}")
            return []

        tracked_connections: List[Dict[str, object]] = []
        current_connection_keys: Set[Tuple[str, str, int]] = set()
        current_public_ips: Set[str] = set()
        new_public_ips: Set[str] = set()
        suspicious_examples: List[Tuple[Dict[str, object], List[str]]] = []

        for connection in raw_connections:
            if not getattr(connection, "raddr", None):
                continue

            remote_ip = getattr(connection.raddr, "ip", None)
            remote_port = int(getattr(connection.raddr, "port", 0) or 0)
            local_ip = getattr(connection.laddr, "ip", None)
            local_port = int(getattr(connection.laddr, "port", 0) or 0)

            if not remote_ip:
                continue

            pid = int(connection.pid) if connection.pid else 0
            process_name = self._get_process_name(pid)
            row = {
                "process_name": process_name,
                "pid": pid,
                "status": getattr(connection, "status", "UNKNOWN"),
                "local": f"{local_ip}:{local_port}",
                "remote": f"{remote_ip}:{remote_port}",
                "remote_ip": remote_ip,
                "remote_port": remote_port,
            }
            tracked_connections.append(row)
            if is_public_ip(remote_ip):
                current_public_ips.add(remote_ip)
                if remote_ip not in self._known_public_ips:
                    new_public_ips.add(remote_ip)

            reasons = self._classify_connection(process_name, remote_ip, remote_port)
            alert_key = (normalize_process_name(process_name), remote_ip, remote_port)
            current_connection_keys.add(alert_key)
            if (
                self._initialized
                and reasons
                and alert_key not in self._seen_connections
                and alert_key not in self._alerted_connections
            ):
                self._alerted_connections.add(alert_key)
                suspicious_examples.append((row, reasons))

        tracked_connections.sort(key=lambda item: (str(item["process_name"]), str(item["remote"])))
        sent_delta, recv_delta = self._consume_io_delta()

        self.logger.event(
            "NETWORK_SCAN",
            " ".join(
                [
                    f"connections={len(tracked_connections)}",
                    f"sent_delta={format_bytes(sent_delta)}",
                    f"recv_delta={format_bytes(recv_delta)}",
                    f"top={self._format_top_connections(tracked_connections[: self.config.top_connection_count])}",
                ]
            ),
        )

        total_delta_mb = (sent_delta + recv_delta) / (1024 * 1024)
        if total_delta_mb >= self.config.network_spike_threshold_mb:
            self.logger.alert(
                "Unusual network throughput detected "
                f"total_delta={total_delta_mb:.2f}MB threshold={self.config.network_spike_threshold_mb:.2f}MB"
            )

        if self._initialized and len(new_public_ips) >= self.config.unusual_remote_threshold:
            sample_ips = ", ".join(sorted(new_public_ips)[:5])
            self.logger.alert(
                "Large number of new public network destinations detected "
                f"count={len(new_public_ips)} sample={sample_ips}"
            )

        for row, reasons in suspicious_examples[:3]:
            self.logger.alert(
                "Suspicious network connection detected "
                f"process={row['process_name']} pid={row['pid']} remote={row['remote']} "
                f"reasons={' ; '.join(reasons)}"
            )

        self._known_public_ips.update(current_public_ips)
        self._seen_connections.update(current_connection_keys)
        self._initialized = True
        return tracked_connections

    def _classify_connection(self, process_name: str, remote_ip: str, remote_port: int) -> List[str]:
        reasons: List[str] = []
        normalized_name = normalize_process_name(process_name)
        is_public = is_public_ip(remote_ip)

        if remote_port in HIGH_RISK_REMOTE_PORTS:
            reasons.append("remote port is commonly abused")
        if is_public and normalized_name in SUSPICIOUS_PROCESS_NAMES:
            reasons.append("scripting or administrative process is talking to a public IP")
        if is_public and remote_port not in SAFE_REMOTE_PORTS and normalized_name in SUSPICIOUS_PROCESS_NAMES:
            reasons.append("scripting or administrative process is using a non-standard public port")
        if is_public and remote_ip not in self._known_public_ips and normalized_name in SUSPICIOUS_PROCESS_NAMES:
            reasons.append("process connected to a new public IP")
        return reasons

    def _consume_io_delta(self) -> Tuple[float, float]:
        current_io = psutil.net_io_counters()
        sent_delta = max(0.0, float(current_io.bytes_sent - self._previous_io.bytes_sent))
        recv_delta = max(0.0, float(current_io.bytes_recv - self._previous_io.bytes_recv))
        self._previous_io = current_io
        return sent_delta, recv_delta

    def _get_process_name(self, pid: int) -> str:
        if pid <= 0:
            return "unknown"
        cached_name = self._process_name_cache.get(pid)
        if cached_name:
            return cached_name
        try:
            process_name = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            process_name = f"PID-{pid}"
        self._process_name_cache[pid] = process_name
        return process_name

    @staticmethod
    def _format_top_connections(rows: Sequence[Dict[str, object]]) -> str:
        if not rows:
            return "none"
        return ", ".join(f"{row['process_name']}:{row['remote']}[{row['status']}]" for row in rows)


class RealTimeSystemMonitor:
    def __init__(self, config: MonitorConfig):
        self.config = config
        self.logger = MonitorLogger(config.log_file)
        self.file_monitor = FileMonitor(config, self.logger)
        self.process_monitor = ProcessMonitor(config, self.logger)
        self.usb_monitor = USBMonitor(self.logger)
        self.network_monitor = NetworkMonitor(config, self.logger)

    def run(self) -> None:
        watch_path_summary = ", ".join(str(path) for path in self.config.watch_paths)
        self.logger.event(
            "MONITOR_START",
            f"watch_paths={watch_path_summary} poll_interval={self.config.poll_interval:.1f}s log_file={self.logger.log_file}",
        )
        self.file_monitor.start()
        try:
            while True:
                self.process_monitor.scan()
                self.usb_monitor.scan()
                self.network_monitor.scan()
                time.sleep(self.config.poll_interval)
        except KeyboardInterrupt:
            self.logger.event("MONITOR_STOP", "Keyboard interrupt received, shutting down")
        finally:
            self.file_monitor.stop()


def resolve_watch_paths(raw_paths: Iterable[str]) -> List[Path]:
    env_paths = [item.strip() for item in os.getenv("MONITORED_PATHS", "").split(";") if item.strip()]
    candidate_paths = list(raw_paths) or env_paths or [str(Path.cwd())]

    unique_paths: List[Path] = []
    seen: Set[str] = set()
    for raw_path in candidate_paths:
        resolved = resolve_path(raw_path)
        if resolved.is_file():
            resolved = resolved.parent
        if not resolved.exists():
            continue
        key = str(resolved).lower()
        if key not in seen:
            seen.add(key)
            unique_paths.append(resolved)

    if not unique_paths:
        unique_paths.append(Path.cwd().resolve())
    return unique_paths


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple realtime system monitor for the AI Firewall project.")
    parser.add_argument(
        "--watch-path",
        action="append",
        default=[],
        help="Directory to monitor for file activity. Repeat the flag to watch multiple locations.",
    )
    parser.add_argument("--poll-interval", type=float, default=3.0, help="Seconds between process and network scans.")
    parser.add_argument(
        "--learning-cycles",
        type=int,
        default=2,
        help="How many process scans to use for baseline learning before unknown-process alerts begin.",
    )
    parser.add_argument(
        "--bulk-file-threshold",
        type=int,
        default=25,
        help="How many file events inside the window trigger a bulk-access alert.",
    )
    parser.add_argument(
        "--bulk-file-window",
        type=float,
        default=10.0,
        help="Seconds to use when evaluating bulk file activity.",
    )
    parser.add_argument(
        "--network-spike-mb",
        type=float,
        default=25.0,
        help="Combined sent and received MB per poll interval that triggers an unusual network alert.",
    )
    parser.add_argument(
        "--unusual-remote-threshold",
        type=int,
        default=8,
        help="How many new public IPs in one scan trigger an unusual network destination alert.",
    )
    parser.add_argument(
        "--log-file",
        default=str(Path(__file__).resolve().parent / "logs" / "realtime_system_monitor.log"),
        help="File used to persist monitor events.",
    )
    return parser.parse_args(argv)


def build_config(args: argparse.Namespace) -> MonitorConfig:
    return MonitorConfig(
        watch_paths=resolve_watch_paths(args.watch_path),
        poll_interval=max(1.0, float(args.poll_interval)),
        process_learning_cycles=max(0, int(args.learning_cycles)),
        bulk_file_threshold=max(5, int(args.bulk_file_threshold)),
        bulk_file_window_seconds=max(2.0, float(args.bulk_file_window)),
        network_spike_threshold_mb=max(1.0, float(args.network_spike_mb)),
        unusual_remote_threshold=max(1, int(args.unusual_remote_threshold)),
        log_file=resolve_path(args.log_file),
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    ensure_dependencies()
    config = build_config(args)
    monitor = RealTimeSystemMonitor(config)
    monitor.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
