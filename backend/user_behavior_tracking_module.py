from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import platform
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Sequence, Set

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

from sqlalchemy import inspect, text

from app import models
from app.behavior_tracking import serialize_behavior_profile, update_behavior_profile
from app.database import SessionLocal, engine
from app.risk import is_risky, score_to_recommended_action, score_to_risk_level


DEFAULT_LOG_FILE = Path(__file__).resolve().parent / "logs" / "user_behavior_tracking.log"
IGNORED_DIR_NAMES = {".git", ".venv", "__pycache__", "build", "dist", "logs", "node_modules", "quarantine", "venv"}
DEFAULT_WATCH_PATHS = [Path.cwd()]
MIN_LOGIN_BASELINE = 4
MIN_APP_BASELINE = 5
MIN_FILE_BASELINE = 6
FILE_BURST_THRESHOLD = 8
FILE_BURST_WINDOW_SECONDS = 10.0


@dataclass
class Assessment:
    score: float = 0.0
    reasons: List[str] = field(default_factory=list)
    summary: str = "Behavior matched the learned baseline."

    @property
    def risk_level(self) -> str:
        return score_to_risk_level(self.score)

    @property
    def recommended_action(self) -> str:
        return score_to_recommended_action(self.score)


@dataclass
class BehaviorSnapshot:
    total_logins: int = 0
    login_distribution: Dict[int, int] = field(default_factory=dict)
    total_application_events: int = 0
    known_applications: Set[str] = field(default_factory=set)
    total_file_events: int = 0
    known_directories: Set[str] = field(default_factory=set)
    known_extensions: Set[str] = field(default_factory=set)


class ActivityLogger:
    def __init__(self, log_file: Path):
        self.log_file = log_file.resolve()
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        self._logger = logging.getLogger("ai_firewall.user_behavior")
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


class BehaviorRepository:
    def __init__(self, logger: ActivityLogger):
        self.logger = logger
        models.Base.metadata.create_all(bind=engine)
        self._ensure_runtime_schema()

    def ensure_user(self, username: str) -> models.User:
        normalized_username = normalize_username(username)
        db = SessionLocal()
        try:
            user = db.query(models.User).filter(models.User.username == normalized_username).first()
            if user:
                db.expunge(user)
                return user

            user = models.User(
                username=normalized_username,
                email=f"{normalized_username}@local.monitor",
                hashed_password="local-behavior-tracker",
                role="system_agent" if normalized_username.endswith("-agent") else "user",
                is_active=True,
                is_locked=False,
                is_email_verified=True,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            self.logger.event("USER_BOOTSTRAP", f"created_local_user username={normalized_username} id={user.id}")
            db.expunge(user)
            return user
        finally:
            db.close()

    def get_snapshot(self, user_id: int) -> BehaviorSnapshot:
        db = SessionLocal()
        try:
            profile = db.query(models.BehaviorProfile).filter(models.BehaviorProfile.user_id == user_id).first()
            if not profile:
                return BehaviorSnapshot()

            login_distribution = load_json_dict(profile.login_hour_distribution)
            frequent_applications = load_json_list(profile.frequent_applications)
            file_directories = load_json_list(profile.file_directory_habits)
            file_extensions = load_json_list(profile.file_extension_habits)
            return BehaviorSnapshot(
                total_logins=int(profile.total_logins or 0),
                login_distribution={int(hour): int(count) for hour, count in login_distribution.items()},
                total_application_events=int(profile.total_application_events or 0),
                known_applications={
                    normalize_process_name(str(item.get("name", "")))
                    for item in frequent_applications
                    if str(item.get("name", "")).strip()
                },
                total_file_events=int(profile.total_file_events or 0),
                known_directories={str(item.get("path", "")).strip() for item in file_directories if item.get("path")},
                known_extensions={str(item.get("extension", "")).strip().lower() for item in file_extensions if item.get("extension")},
            )
        finally:
            db.close()

    def record_activity(
        self,
        *,
        user_id: int,
        action_type: str,
        device: str,
        details_payload: Dict[str, Any],
        behavior_context: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None,
        risk_score: float = 0.0,
        learn_from_activity: bool = True,
    ) -> models.UserActivity:
        db = SessionLocal()
        try:
            event_time = timestamp or datetime.now()
            activity = models.UserActivity(
                user_id=user_id,
                timestamp=event_time,
                action_type=action_type,
                device=device,
                network_activity=0.0,
                details=json.dumps(details_payload),
                risk_score=float(risk_score or 0.0),
                risk_level=score_to_risk_level(risk_score),
            )
            db.add(activity)
            db.flush()
            if learn_from_activity:
                update_behavior_profile(db, user_id, activity, behavior_context)
            db.commit()
            db.refresh(activity)
            db.expunge(activity)
            return activity
        finally:
            db.close()

    def record_threat(self, *, user_id: int, assessment: Assessment, details: str) -> None:
        db = SessionLocal()
        try:
            threat = models.ThreatLog(
                user_id=user_id,
                anomaly_score=float(assessment.score or 0.0),
                threat_level=assessment.risk_level,
                action_taken=assessment.recommended_action,
                details=details,
            )
            db.add(threat)
            db.commit()
        finally:
            db.close()

    def get_baseline_summary(self, user_id: int) -> Dict[str, Any]:
        db = SessionLocal()
        try:
            user = db.query(models.User).filter(models.User.id == user_id).first()
            profile = db.query(models.BehaviorProfile).filter(models.BehaviorProfile.user_id == user_id).first()
            if not user:
                raise ValueError(f"Unknown user id: {user_id}")
            return serialize_behavior_profile(user, profile)
        finally:
            db.close()

    def _ensure_runtime_schema(self) -> None:
        runtime_columns = {
            "users": {
                "email": "VARCHAR",
                "created_at": "TIMESTAMP",
                "is_active": "BOOLEAN DEFAULT TRUE",
                "is_locked": "BOOLEAN DEFAULT FALSE",
                "is_email_verified": "BOOLEAN DEFAULT TRUE",
                "last_login_at": "TIMESTAMP",
                "last_login_ip": "VARCHAR",
                "last_login_device": "VARCHAR",
            },
            "behavior_profiles": {
                "login_hour_distribution": "TEXT DEFAULT '{}'",
                "frequent_applications": "TEXT DEFAULT '[]'",
                "file_directory_habits": "TEXT DEFAULT '[]'",
                "file_extension_habits": "TEXT DEFAULT '[]'",
                "recent_file_samples": "TEXT DEFAULT '[]'",
                "total_logins": "INTEGER DEFAULT 0",
                "total_application_events": "INTEGER DEFAULT 0",
                "total_file_events": "INTEGER DEFAULT 0",
            },
            "user_activity": {
                "risk_score": "FLOAT DEFAULT 0",
                "risk_level": "VARCHAR DEFAULT 'Normal'",
            },
        }

        with engine.begin() as connection:
            inspector = inspect(connection)
            existing_tables = set(inspector.get_table_names())
            for table_name, column_map in runtime_columns.items():
                if table_name not in existing_tables:
                    continue
                existing_columns = {column["name"] for column in inspector.get_columns(table_name)}
                for column_name, column_sql in column_map.items():
                    if column_name not in existing_columns:
                        connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_sql}"))


class BehaviorAnalyzer:
    def assess_login(self, snapshot: BehaviorSnapshot, when: datetime) -> Assessment:
        if snapshot.total_logins < MIN_LOGIN_BASELINE:
            return Assessment(summary="Learning normal login-time behavior.")

        current_hour = when.hour
        if current_hour in snapshot.login_distribution:
            return Assessment(summary="Login happened during a known hour window.")

        ranked_hours = sorted(snapshot.login_distribution.items(), key=lambda item: (-item[1], item[0]))
        peak_hours = [hour for hour, _ in ranked_hours[:3]]
        if any(hour_distance(current_hour, hour) <= 1 for hour in peak_hours):
            return Assessment(summary="Login time is close to the normal baseline window.")

        reasons = [f"login at hour {current_hour} is outside the learned pattern"]
        return Assessment(score=58.0, reasons=reasons, summary=f"Unusual login time detected: {reasons[0]}.")

    def assess_application(self, snapshot: BehaviorSnapshot, app_name: str) -> Assessment:
        normalized_name = normalize_process_name(app_name)
        if snapshot.total_application_events < MIN_APP_BASELINE or len(snapshot.known_applications) < 2:
            return Assessment(summary="Learning frequently used applications.")
        if normalized_name in snapshot.known_applications:
            return Assessment(summary=f"Application {app_name} matches the learned baseline.")

        reasons = [f"application {app_name} has not been seen in the learned baseline"]
        return Assessment(score=54.0, reasons=reasons, summary=f"Unknown application usage detected: {app_name}.")

    def assess_file_access(self, snapshot: BehaviorSnapshot, file_path: Path, burst_count: int) -> Assessment:
        if snapshot.total_file_events < MIN_FILE_BASELINE:
            return Assessment(summary="Learning normal file access habits.")

        reasons: List[str] = []
        score = 0.0
        directory = normalize_directory(file_path)
        extension = file_path.suffix.lower() or "[no extension]"

        if directory and directory not in snapshot.known_directories:
            score += 28.0
            reasons.append(f"directory {directory} is outside the learned baseline")
        if extension and extension not in snapshot.known_extensions:
            score += 22.0
            reasons.append(f"file type {extension} is unusual for this user")
        if burst_count >= FILE_BURST_THRESHOLD:
            score += 35.0
            reasons.append(f"bulk file activity spike detected ({burst_count} events in {int(FILE_BURST_WINDOW_SECONDS)}s)")

        if not reasons:
            return Assessment(summary=f"File access for {file_path.name} matches the learned baseline.")

        return Assessment(
            score=min(100.0, score),
            reasons=reasons,
            summary=f"Abnormal file access detected for {file_path.name}: {', '.join(reasons)}.",
        )


class BehaviorTrackingService:
    def __init__(self, *, username: str, repository: BehaviorRepository, analyzer: BehaviorAnalyzer, logger: ActivityLogger):
        self.username = normalize_username(username)
        self.repository = repository
        self.analyzer = analyzer
        self.logger = logger
        self.user = repository.ensure_user(self.username)
        self.user_id = self.user.id
        self.device = platform.node() or getpass.getuser() or "localhost"

    def record_login(self, when: Optional[datetime] = None) -> Assessment:
        login_time = when or datetime.now()
        snapshot = self.repository.get_snapshot(self.user_id)
        assessment = self.analyzer.assess_login(snapshot, login_time)
        self.repository.record_activity(
            user_id=self.user_id,
            action_type="login",
            device=self.device,
            details_payload={
                "summary": f"Login recorded for {self.username}",
                "login_time": login_time.isoformat(),
                "username": self.username,
            },
            timestamp=login_time,
            risk_score=assessment.score,
            learn_from_activity=not is_risky(assessment.score),
        )
        self.logger.event(
            "LOGIN_EVENT",
            f"user={self.username} timestamp={login_time.isoformat()} risk={assessment.risk_level}",
        )
        self._maybe_alert(assessment)
        return assessment

    def record_application(self, app_name: str, source: str = "manual", when: Optional[datetime] = None) -> Assessment:
        event_time = when or datetime.now()
        snapshot = self.repository.get_snapshot(self.user_id)
        assessment = self.analyzer.assess_application(snapshot, app_name)
        self.repository.record_activity(
            user_id=self.user_id,
            action_type="application_open",
            device=self.device,
            details_payload={
                "summary": f"Application used: {app_name}",
                "process_name": app_name,
                "source": source,
            },
            behavior_context={"applications": [{"name": app_name, "source": source}]},
            timestamp=event_time,
            risk_score=assessment.score,
            learn_from_activity=not is_risky(assessment.score),
        )
        self.logger.event(
            "APP_EVENT",
            f"user={self.username} app={app_name} source={source} timestamp={event_time.isoformat()} risk={assessment.risk_level}",
        )
        self._maybe_alert(assessment)
        return assessment

    def record_file_access(
        self,
        file_path: Path,
        *,
        action_label: str = "file_access",
        source: str = "manual",
        burst_count: int = 1,
        when: Optional[datetime] = None,
    ) -> Assessment:
        event_time = when or datetime.now()
        path_value = file_path.resolve(strict=False)
        snapshot = self.repository.get_snapshot(self.user_id)
        assessment = self.analyzer.assess_file_access(snapshot, path_value, burst_count)
        self.repository.record_activity(
            user_id=self.user_id,
            action_type="file_access",
            device=self.device,
            details_payload={
                "summary": f"File {action_label}: {path_value}",
                "action": action_label,
                "source": source,
                "file_path": str(path_value),
            },
            behavior_context={
                "files": [
                    {
                        "path": str(path_value),
                        "directory": normalize_directory(path_value),
                        "extension": path_value.suffix.lower() or "[no extension]",
                    }
                ]
            },
            timestamp=event_time,
            risk_score=assessment.score,
            learn_from_activity=not is_risky(assessment.score),
        )
        self.logger.event(
            "FILE_EVENT",
            f"user={self.username} action={action_label} path={path_value} source={source} burst_count={burst_count} risk={assessment.risk_level}",
        )
        self._maybe_alert(assessment)
        return assessment

    def show_baseline(self) -> Dict[str, Any]:
        summary = self.repository.get_baseline_summary(self.user_id)
        self.logger.event("BASELINE", json.dumps(summary, indent=2))
        return summary

    def _maybe_alert(self, assessment: Assessment) -> None:
        if is_risky(assessment.score):
            self.repository.record_threat(user_id=self.user_id, assessment=assessment, details=assessment.summary)
            self.logger.alert(f"{assessment.risk_level} | {assessment.summary}")


class FileActivityHandler(FileSystemEventHandler):
    def __init__(self, monitor: "FileActivityMonitor"):
        self.monitor = monitor

    def on_created(self, event) -> None:
        self.monitor.handle_event("create", getattr(event, "src_path", ""), is_directory=event.is_directory)

    def on_modified(self, event) -> None:
        self.monitor.handle_event("modify", getattr(event, "src_path", ""), is_directory=event.is_directory)

    def on_deleted(self, event) -> None:
        self.monitor.handle_event("delete", getattr(event, "src_path", ""), is_directory=event.is_directory)

    def on_moved(self, event) -> None:
        self.monitor.handle_event("move", getattr(event, "dest_path", ""), is_directory=event.is_directory)


class FileActivityMonitor:
    def __init__(self, *, service: BehaviorTrackingService, logger: ActivityLogger, watch_paths: List[Path]):
        self.service = service
        self.logger = logger
        self.watch_paths = watch_paths
        self.observer = Observer()
        self._recent_events: Deque[float] = deque()
        self._lock = threading.Lock()

    def start(self) -> None:
        handler = FileActivityHandler(self)
        for path in self.watch_paths:
            self.observer.schedule(handler, str(path), recursive=True)
            self.logger.event("FILE_WATCH", f"user={self.service.username} path={path}")
        self.observer.start()

    def stop(self) -> None:
        self.observer.stop()
        self.observer.join(timeout=5)

    def handle_event(self, action: str, raw_path: str, *, is_directory: bool) -> None:
        if is_directory or not raw_path:
            return
        path = Path(raw_path).resolve(strict=False)
        if should_ignore_path(path):
            return

        burst_count = self._remember_event()
        self.service.record_file_access(path, action_label=action, source="watchdog", burst_count=burst_count)

    def _remember_event(self) -> int:
        now_ts = time.time()
        with self._lock:
            self._recent_events.append(now_ts)
            while self._recent_events and (now_ts - self._recent_events[0]) > FILE_BURST_WINDOW_SECONDS:
                self._recent_events.popleft()
            return len(self._recent_events)


class ProcessMonitor:
    def __init__(self, *, service: BehaviorTrackingService, logger: ActivityLogger, poll_interval: float):
        self.service = service
        self.logger = logger
        self.poll_interval = poll_interval
        self._known_pids: Set[int] = set()
        self._current_pid = os.getpid()

    def start(self) -> None:
        self._prime()
        self.logger.event("PROCESS_MONITOR", f"user={self.service.username} poll_interval={self.poll_interval:.1f}s")

    def poll_once(self) -> None:
        current_rows = self._snapshot_processes()
        current_pids = {row["pid"] for row in current_rows}
        new_rows = [row for row in current_rows if row["pid"] not in self._known_pids]
        self._known_pids = current_pids
        for row in new_rows:
            self.service.record_application(str(row["name"]), source="process_monitor")

    def _prime(self) -> None:
        self._known_pids = {row["pid"] for row in self._snapshot_processes()}

    def _snapshot_processes(self) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for process in psutil.process_iter(["pid", "name"]):
            try:
                pid = int(process.info.get("pid"))
                name = str(process.info.get("name") or "unknown")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, TypeError, ValueError):
                continue
            if pid in {0, self._current_pid}:
                continue
            rows.append({"pid": pid, "name": name})
        return rows


class BehaviorMonitorRunner:
    def __init__(
        self,
        *,
        service: BehaviorTrackingService,
        logger: ActivityLogger,
        watch_paths: List[Path],
        poll_interval: float,
        login_now: bool,
    ):
        self.service = service
        self.logger = logger
        self.watch_paths = watch_paths
        self.poll_interval = poll_interval
        self.login_now = login_now
        self.file_monitor = FileActivityMonitor(service=service, logger=logger, watch_paths=watch_paths)
        self.process_monitor = ProcessMonitor(service=service, logger=logger, poll_interval=poll_interval)

    def run(self) -> None:
        if self.login_now:
            self.service.record_login()

        self.logger.event(
            "BEHAVIOR_MONITOR_START",
            f"user={self.service.username} watch_paths={', '.join(str(path) for path in self.watch_paths)} poll_interval={self.poll_interval:.1f}s",
        )

        self.process_monitor.start()
        self.file_monitor.start()
        try:
            while True:
                self.process_monitor.poll_once()
                time.sleep(self.poll_interval)
        except KeyboardInterrupt:
            self.logger.event("BEHAVIOR_MONITOR_STOP", "Keyboard interrupt received, shutting down")
        finally:
            self.file_monitor.stop()


def ensure_dependencies() -> None:
    missing = []
    if psutil is None:
        missing.append("psutil")
    if Observer is None:
        missing.append("watchdog")
    if missing:
        raise SystemExit(
            f"Missing required packages: {', '.join(missing)}. Install with `py -3 -m pip install -r backend/requirements.txt`."
        )


def normalize_username(value: str) -> str:
    cleaned = (value or "").strip().lower().replace(" ", "-")
    return cleaned or f"local-{getpass.getuser().lower()}"


def normalize_process_name(name: str) -> str:
    value = (name or "unknown").strip().lower()
    return value[:-4] if value.endswith(".exe") else value


def normalize_directory(file_path: Path) -> str:
    parent = str(file_path.parent)
    return "" if parent in {"", "."} else parent


def hour_distance(a: int, b: int) -> int:
    return min(abs(a - b), 24 - abs(a - b))


def load_json_dict(raw_value: Optional[str]) -> Dict[str, Any]:
    if not raw_value:
        return {}
    try:
        parsed = json.loads(raw_value)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def load_json_list(raw_value: Optional[str]) -> List[Dict[str, Any]]:
    if not raw_value:
        return []
    try:
        parsed = json.loads(raw_value)
    except (TypeError, ValueError):
        return []
    return parsed if isinstance(parsed, list) else []


def resolve_watch_paths(raw_paths: Iterable[str]) -> List[Path]:
    candidate_paths = [Path(item).expanduser().resolve(strict=False) for item in raw_paths if str(item).strip()]
    candidate_paths = candidate_paths or [path.resolve(strict=False) for path in DEFAULT_WATCH_PATHS]

    unique_paths: List[Path] = []
    seen: Set[str] = set()
    for path in candidate_paths:
        if path.is_file():
            path = path.parent
        if not path.exists():
            continue
        key = str(path).lower()
        if key not in seen:
            seen.add(key)
            unique_paths.append(path)
    return unique_paths or [Path.cwd().resolve()]


def should_ignore_path(path: Path) -> bool:
    parts = {part.lower() for part in path.parts}
    return bool(parts.intersection(IGNORED_DIR_NAMES))


def parse_timestamp(raw_value: Optional[str]) -> Optional[datetime]:
    if not raw_value:
        return None
    return datetime.fromisoformat(raw_value)


def build_service(username: str, log_file: Path) -> BehaviorTrackingService:
    logger = ActivityLogger(log_file)
    repository = BehaviorRepository(logger)
    analyzer = BehaviorAnalyzer()
    return BehaviorTrackingService(username=username, repository=repository, analyzer=analyzer, logger=logger)


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple user behavior tracking module for the AI Firewall project.")
    parser.add_argument(
        "--username",
        default=f"local-{getpass.getuser().lower()}",
        help="Local username whose behavior baseline should be tracked.",
    )
    parser.add_argument(
        "--log-file",
        default=str(DEFAULT_LOG_FILE),
        help="File used to persist behavior-tracking events.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    monitor_parser = subparsers.add_parser("monitor", help="Continuously track app usage and file activity.")
    monitor_parser.add_argument("--watch-path", action="append", default=[], help="Directory to watch for file activity.")
    monitor_parser.add_argument("--poll-interval", type=float, default=3.0, help="Seconds between process scans.")
    monitor_parser.add_argument("--login-now", action="store_true", help="Record a login event when monitoring starts.")

    login_parser = subparsers.add_parser("login", help="Record a login event and evaluate login-time behavior.")
    login_parser.add_argument("--timestamp", help="Optional ISO timestamp such as 2026-03-30T09:15:00.")

    app_parser = subparsers.add_parser("app", help="Record an application-usage event.")
    app_parser.add_argument("app_name", help="Application or process name to record.")
    app_parser.add_argument("--source", default="manual", help="Source label for the application event.")

    file_parser = subparsers.add_parser("file", help="Record a file-access event.")
    file_parser.add_argument("path", help="Path to the file that was accessed.")
    file_parser.add_argument("--action", default="file_access", help="Action label such as open, modify, or delete.")
    file_parser.add_argument("--source", default="manual", help="Source label for the file event.")
    file_parser.add_argument("--burst-count", type=int, default=1, help="Optional file-burst count to evaluate.")

    subparsers.add_parser("baseline", help="Print the learned baseline for this user.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    ensure_dependencies()

    log_file = Path(args.log_file).expanduser().resolve(strict=False)
    service = build_service(args.username, log_file)

    if args.command == "monitor":
        watch_paths = resolve_watch_paths(args.watch_path)
        runner = BehaviorMonitorRunner(
            service=service,
            logger=service.logger,
            watch_paths=watch_paths,
            poll_interval=max(1.0, float(args.poll_interval)),
            login_now=bool(args.login_now),
        )
        runner.run()
        return 0

    if args.command == "login":
        service.record_login(parse_timestamp(args.timestamp))
        return 0

    if args.command == "app":
        service.record_application(args.app_name, source=args.source)
        return 0

    if args.command == "file":
        service.record_file_access(
            Path(args.path),
            action_label=args.action,
            source=args.source,
            burst_count=max(1, int(args.burst_count)),
        )
        return 0

    if args.command == "baseline":
        summary = service.show_baseline()
        print(json.dumps(summary, indent=2))
        return 0

    raise SystemExit(f"Unsupported command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
