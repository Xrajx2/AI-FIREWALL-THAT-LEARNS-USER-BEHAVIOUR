import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from . import models
from .security import decrypt_sensitive_value
from .usb_control import ENABLE_USB_SCANNING, is_usb_action_type

logger = logging.getLogger("ai_firewall.behavior_tracking")


def rebuild_behavior_profiles(db: Session):
    db.query(models.BehaviorProfile).delete()
    db.flush()

    historical_activities = (
        db.query(models.UserActivity)
        .order_by(models.UserActivity.user_id.asc(), models.UserActivity.timestamp.asc())
        .all()
    )
    for activity in historical_activities:
        if not ENABLE_USB_SCANNING and is_usb_action_type(activity.action_type):
            continue
        update_behavior_profile(db, activity.user_id, activity)


def update_behavior_profile(
    db: Session,
    user_id: int,
    activity: models.UserActivity,
    behavior_context: Optional[Dict[str, Any]] = None,
) -> models.BehaviorProfile:
    if not ENABLE_USB_SCANNING and is_usb_action_type(activity.action_type):
        profile = _get_behavior_profile(db, user_id)
        if profile:
            return profile
        profile = models.BehaviorProfile(
            user_id=user_id,
            avg_data_transfer=0.0,
            frequent_devices="[]",
            login_hour_distribution="{}",
            frequent_applications="[]",
            file_directory_habits="[]",
            file_extension_habits="[]",
            recent_file_samples="[]",
            total_logins=0,
            total_application_events=0,
            total_file_events=0,
        )
        db.add(profile)
        db.flush()
        return profile

    profile = _get_behavior_profile(db, user_id)
    if not profile:
        profile = models.BehaviorProfile(
            user_id=user_id,
            avg_data_transfer=0.0,
            frequent_devices="[]",
            login_hour_distribution="{}",
            frequent_applications="[]",
            file_directory_habits="[]",
            file_extension_habits="[]",
            recent_file_samples="[]",
            total_logins=0,
            total_application_events=0,
            total_file_events=0,
        )
        db.add(profile)
        db.flush()

    timestamp = activity.timestamp or datetime.utcnow()
    details_payload = _parse_json(activity.details)

    _update_avg_network(profile, activity.network_activity)
    _update_device_habits(profile, activity.device, timestamp)

    if activity.action_type == "login":
        _update_login_patterns(profile, timestamp)

    applications = _extract_application_entries(activity, behavior_context, details_payload)
    if applications:
        stored_apps = _load_json_list(profile.frequent_applications)
        for app in applications:
            stored_apps = _update_ranked_list(
                stored_apps,
                key_field="name",
                key_value=app["name"],
                timestamp=timestamp,
                extra_fields={"source": app.get("source", activity.action_type)},
                limit=10,
            )
        profile.frequent_applications = json.dumps(stored_apps)
        profile.total_application_events = int(profile.total_application_events or 0) + len(applications)

    file_entries = _extract_file_entries(activity, behavior_context, details_payload)
    if file_entries:
        directory_habits = _load_json_list(profile.file_directory_habits)
        extension_habits = _load_json_list(profile.file_extension_habits)
        recent_samples = _load_json_list(profile.recent_file_samples)

        for file_entry in file_entries:
            directory = file_entry.get("directory") or ""
            extension = file_entry.get("extension") or "[no extension]"
            path_value = file_entry.get("path") or ""

            if directory:
                directory_habits = _update_ranked_list(
                    directory_habits,
                    key_field="path",
                    key_value=directory,
                    timestamp=timestamp,
                    limit=8,
                )
            if extension:
                extension_habits = _update_ranked_list(
                    extension_habits,
                    key_field="extension",
                    key_value=extension,
                    timestamp=timestamp,
                    limit=8,
                )
            if path_value:
                recent_samples = _update_recent_file_samples(recent_samples, path_value, timestamp)

        profile.file_directory_habits = json.dumps(directory_habits)
        profile.file_extension_habits = json.dumps(extension_habits)
        profile.recent_file_samples = json.dumps(recent_samples)
        profile.total_file_events = int(profile.total_file_events or 0) + len(file_entries)

    profile.last_updated = timestamp
    db.add(profile)
    return profile


def _get_behavior_profile(db: Session, user_id: int) -> Optional[models.BehaviorProfile]:
    profile = db.query(models.BehaviorProfile).filter(models.BehaviorProfile.user_id == user_id).first()
    if profile:
        return profile

    for pending in db.new:
        if isinstance(pending, models.BehaviorProfile) and pending.user_id == user_id:
            return pending

    return None


def serialize_behavior_profile(user: models.User, profile: Optional[models.BehaviorProfile]) -> Dict[str, Any]:
    if not profile:
        return {
            "user_id": user.id,
            "username": user.username,
            "last_updated": None,
            "learning_mode": True,
            "login_pattern": {
                "login_count": 0,
                "window_start": None,
                "window_end": None,
                "peak_hours": [],
                "hour_distribution": [],
            },
            "frequent_applications": [],
            "file_access_habits": {
                "event_count": 0,
                "directories": [],
                "file_types": [],
                "recent_files": [],
            },
            "device_habits": [],
        }

    total_events = (
        int(profile.total_logins or 0)
        + int(profile.total_application_events or 0)
        + int(profile.total_file_events or 0)
    )
    learning_mode = total_events < 10

    login_distribution = _load_json_dict(profile.login_hour_distribution)
    peak_hours = _compute_peak_hours(login_distribution)

    return {
        "user_id": user.id,
        "username": user.username,
        "last_updated": profile.last_updated.isoformat() if profile.last_updated else None,
        "learning_mode": learning_mode,
        "login_pattern": {
            "login_count": int(profile.total_logins or 0),
            "window_start": profile.normal_login_time_start,
            "window_end": profile.normal_login_time_end,
            "peak_hours": peak_hours,
            "hour_distribution": [
                {"hour": int(hour), "count": int(count)}
                for hour, count in sorted(
                    ((int(hour), int(count)) for hour, count in login_distribution.items()),
                    key=lambda item: item[0],
                )
            ],
        },
        "frequent_applications": _load_json_list(profile.frequent_applications),
        "file_access_habits": {
            "event_count": int(profile.total_file_events or 0),
            "directories": _load_json_list(profile.file_directory_habits),
            "file_types": _load_json_list(profile.file_extension_habits),
            "recent_files": _load_json_list(profile.recent_file_samples),
        },
        "device_habits": _load_json_list(profile.frequent_devices),
    }


def _update_avg_network(profile: models.BehaviorProfile, network_activity: float):
    value = float(network_activity or 0.0)
    if value <= 0:
        return

    existing = float(profile.avg_data_transfer or 0.0)
    if existing <= 0:
        profile.avg_data_transfer = value
    else:
        profile.avg_data_transfer = round(((existing * 4.0) + value) / 5.0, 2)


def _update_device_habits(profile: models.BehaviorProfile, device: str, timestamp: datetime):
    if not device:
        return

    stored_devices = _load_json_list(profile.frequent_devices)
    stored_devices = _update_ranked_list(
        stored_devices,
        key_field="device",
        key_value=device,
        timestamp=timestamp,
        limit=6,
    )
    profile.frequent_devices = json.dumps(stored_devices)


def _update_login_patterns(profile: models.BehaviorProfile, timestamp: datetime):
    distribution = _load_json_dict(profile.login_hour_distribution)
    hour_key = str(timestamp.hour)
    distribution[hour_key] = int(distribution.get(hour_key, 0)) + 1
    profile.login_hour_distribution = json.dumps(distribution)
    profile.total_logins = int(profile.total_logins or 0) + 1

    peak_hours = _compute_peak_hours(distribution)
    if peak_hours:
        ordered = sorted(peak_hours)
        profile.normal_login_time_start = ordered[0]
        profile.normal_login_time_end = (ordered[-1] + 1) % 24


def _extract_application_entries(
    activity: models.UserActivity,
    behavior_context: Optional[Dict[str, Any]],
    details_payload: Optional[Dict[str, Any]],
) -> List[Dict[str, str]]:
    context_apps = behavior_context.get("applications", []) if behavior_context else []
    if context_apps:
        return [
            {
                "name": app.get("name", "").strip(),
                "source": app.get("source", activity.action_type),
            }
            for app in context_apps
            if app.get("name")
        ]

    if details_payload:
        parsed_apps = details_payload.get("applications", [])
        if isinstance(parsed_apps, list):
            return [
                {
                    "name": str(app.get("name", "")).strip(),
                    "source": str(app.get("source", activity.action_type)),
                }
                for app in parsed_apps
                if isinstance(app, dict) and app.get("name")
            ]

        single_app = details_payload.get("process_name") or details_payload.get("application_name")
        if single_app:
            return [{"name": str(single_app).strip(), "source": activity.action_type}]

    if activity.action_type not in {"process_start", "app_usage", "application_open"}:
        return []

    details = activity.details or ""
    marker = "New process detected:"
    if marker in details:
        parsed = details.split(marker, 1)[1].strip()
        parsed = parsed.split("(PID", 1)[0].strip()
        if parsed:
            return [{"name": parsed, "source": activity.action_type}]

    return []


def _extract_file_entries(
    activity: models.UserActivity,
    behavior_context: Optional[Dict[str, Any]],
    details_payload: Optional[Dict[str, Any]],
) -> List[Dict[str, str]]:
    files = behavior_context.get("files", []) if behavior_context else []
    if files:
        normalized_files: List[Dict[str, str]] = []
        for item in files:
            entry = _normalize_file_entry(item)
            if entry:
                normalized_files.append(entry)
        return normalized_files

    if details_payload:
        payload_files = details_payload.get("files") or details_payload.get("file_paths")
        if isinstance(payload_files, list):
            normalized = []
            for item in payload_files:
                entry = _normalize_file_entry(item)
                if entry:
                    normalized.append(entry)
            return normalized

    if activity.action_type not in {"file_access", "file_open", "file_transfer"}:
        return []

    details = activity.details or ""
    if "Sample:" not in details:
        return []

    sample_text = details.split("Sample:", 1)[1]
    normalized = []
    for chunk in sample_text.split(","):
        path_value = chunk.strip()
        if not path_value:
            continue
        entry = _normalize_file_entry(path_value)
        if entry:
            normalized.append(entry)
    return normalized


def _normalize_file_entry(item: Any) -> Optional[Dict[str, str]]:
    if isinstance(item, dict):
        path_value = str(item.get("path", "")).strip()
    else:
        path_value = str(item).strip()

    if not path_value:
        return None

    path_obj = Path(path_value)
    extension = path_obj.suffix.lower() or "[no extension]"
    directory = str(path_obj.parent) if str(path_obj.parent) not in {".", ""} else ""
    return {
        "path": path_value,
        "directory": directory,
        "extension": extension,
    }


def _update_ranked_list(
    items: List[Dict[str, Any]],
    key_field: str,
    key_value: str,
    timestamp: datetime,
    extra_fields: Optional[Dict[str, Any]] = None,
    limit: int = 8,
) -> List[Dict[str, Any]]:
    normalized_value = (key_value or "").strip()
    if not normalized_value:
        return items

    timestamp_text = timestamp.isoformat()
    entry = next((item for item in items if item.get(key_field) == normalized_value), None)
    if not entry:
        entry = {
            key_field: normalized_value,
            "count": 0,
            "last_seen": timestamp_text,
        }
        items.append(entry)

    entry["count"] = int(entry.get("count", 0)) + 1
    entry["last_seen"] = timestamp_text
    if extra_fields:
        entry.update({key: value for key, value in extra_fields.items() if value is not None})

    items.sort(key=lambda item: (-int(item.get("count", 0)), str(item.get(key_field, ""))))
    return items[:limit]


def _update_recent_file_samples(items: List[Dict[str, Any]], path_value: str, timestamp: datetime) -> List[Dict[str, Any]]:
    deduped = [item for item in items if item.get("path") != path_value]
    deduped.insert(
        0,
        {
            "path": path_value,
            "last_seen": timestamp.isoformat(),
        },
    )
    return deduped[:8]


def _compute_peak_hours(distribution: Dict[str, Any]) -> List[int]:
    if not distribution:
        return []

    sorted_hours = sorted(
        ((int(hour), int(count)) for hour, count in distribution.items()),
        key=lambda item: (-item[1], item[0]),
    )
    return [hour for hour, _ in sorted_hours[:3]]


def _load_json_dict(raw_value: Optional[str]) -> Dict[str, Any]:
    if not raw_value:
        return {}
    try:
        decrypted = decrypt_sensitive_value(raw_value) or ""
        parsed = json.loads(decrypted)
        if isinstance(parsed, dict):
            return parsed
        logger.warning("Corrupt JSON dict in behavior profile (not a dict), falling back to safe default {}.")
        return {}
    except Exception as exc:
        logger.warning(f"Corrupt JSON dict in behavior profile, falling back to safe default {{}}: {exc}")
        return {}


def _load_json_list(raw_value: Optional[str]) -> List[Dict[str, Any]]:
    if not raw_value:
        return []
    try:
        decrypted = decrypt_sensitive_value(raw_value) or ""
        parsed = json.loads(decrypted)
        if isinstance(parsed, list):
            return parsed
        logger.warning("Corrupt JSON list in behavior profile (not a list), falling back to safe default [].")
        return []
    except Exception as exc:
        logger.warning(f"Corrupt JSON list in behavior profile, falling back to safe default []: {exc}")
        return []


def _parse_json(raw_value: Optional[str]) -> Optional[Dict[str, Any]]:
    if not raw_value:
        return None
    try:
        decrypted = decrypt_sensitive_value(raw_value) or ""
        parsed = json.loads(decrypted)
        if isinstance(parsed, dict):
            return parsed
        logger.warning("Corrupt JSON details in behavior activity (not a dict), falling back to None.")
        return None
    except Exception as exc:
        logger.warning(f"Corrupt JSON details in behavior activity, falling back to None: {exc}")
        return None
