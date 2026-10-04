from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from math import cos, log1p, pi, sin
from typing import Any, Dict, Iterable, List, Sequence

import numpy as np

from ..security import decrypt_sensitive_value


ACTION_BUCKETS = [
    "login",
    "logout",
    "web_browsing",
    "file_access",
    "file_transfer",
    "usb_insertion",
    "usb_scan_complete",
    "usb_threat_mitigated",
    "process_start",
    "network_spike",
    "network_connection_suspicious",
    "network_connection_blocked",
    "other",
]

SUSPICIOUS_KEYWORDS = [
    "abnormal",
    "blocked",
    "dangerous",
    "exfiltration",
    "macro",
    "malicious",
    "outgoing",
    "powershell",
    "quarantine",
    "remote",
    "ransom",
    "script",
    "suspicious",
    "threat",
    "trojan",
    "unknown",
    "usb",
]


def _get_value(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def coerce_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            pass

    return datetime.now(timezone.utc)


def normalize_activity(item: Any) -> Dict[str, Any]:
    timestamp = coerce_timestamp(_get_value(item, "timestamp"))
    action_type = str(_get_value(item, "action_type", "other") or "other").strip().lower()
    device = str(_get_value(item, "device", "") or "").strip()
    details = decrypt_sensitive_value(_get_value(item, "details", "") or "") or ""
    network_activity = float(_get_value(item, "network_activity", 0.0) or 0.0)

    return {
        "timestamp": timestamp,
        "action_type": action_type,
        "device": device,
        "details": details,
        "network_activity": network_activity,
    }


class ActivityFeatureEncoder:
    def __init__(self):
        self.feature_names = [
            "sin_hour",
            "cos_hour",
            "hour_normalized",
            "is_after_hours",
            "is_weekend",
            "log_network",
            "network_zscore",
            "network_ratio",
            "action_seen_ratio",
            "device_seen_ratio",
            "transition_seen_ratio",
            "same_action_streak",
            "recent_hour_activity_ratio",
            "keyword_density",
        ] + [f"action::{bucket}" for bucket in ACTION_BUCKETS]

    def vectorize(self, activity: Any, history: Sequence[Any]) -> np.ndarray:
        normalized = normalize_activity(activity)
        history_rows = [normalize_activity(item) for item in history]

        hour = normalized["timestamp"].hour
        network_value = float(normalized["network_activity"])
        action_type = normalized["action_type"]
        device = normalized["device"]
        details = normalized["details"].lower()

        hours = [item["timestamp"].hour for item in history_rows]
        network_history = [float(item["network_activity"]) for item in history_rows]
        action_history = [item["action_type"] for item in history_rows]
        device_history = [item["device"] for item in history_rows if item["device"]]
        transition_history = list(zip(action_history[:-1], action_history[1:]))

        hour_angle = (2 * pi * hour) / 24.0
        after_hours = 1.0 if hour < 6 or hour > 20 else 0.0
        weekend = 1.0 if normalized["timestamp"].weekday() >= 5 else 0.0

        action_counts = Counter(action_history)
        device_counts = Counter(device_history)
        transition_counts = Counter(transition_history)

        non_zero_network = [value for value in network_history if value > 0]
        avg_network = float(np.mean(non_zero_network)) if non_zero_network else 0.0
        std_network = float(np.std(non_zero_network)) if len(non_zero_network) > 1 else 0.0
        network_zscore = 0.0
        if std_network > 0:
            network_zscore = abs((network_value - avg_network) / std_network)
        network_ratio = network_value / max(avg_network, 1.0)

        action_seen_ratio = action_counts.get(action_type, 0) / max(len(action_history), 1)
        device_seen_ratio = device_counts.get(device, 0) / max(len(device_history), 1) if device else 0.0

        previous_action = action_history[-1] if action_history else None
        transition_seen_ratio = 0.0
        if previous_action:
            outgoing_total = sum(
                count for (source, _), count in transition_counts.items() if source == previous_action
            )
            if outgoing_total:
                transition_seen_ratio = transition_counts.get((previous_action, action_type), 0) / outgoing_total

        same_action_streak = 0
        for item in reversed(action_history):
            if item != action_type:
                break
            same_action_streak += 1
        same_action_streak = min(same_action_streak / 5.0, 1.0)

        recent_cutoff = normalized["timestamp"].timestamp() - 3600
        recent_hour_events = sum(1 for item in history_rows if item["timestamp"].timestamp() >= recent_cutoff)
        recent_hour_activity_ratio = recent_hour_events / max(len(history_rows), 1)

        keyword_hits = sum(1 for keyword in SUSPICIOUS_KEYWORDS if keyword in details)
        keyword_density = keyword_hits / max(len(SUSPICIOUS_KEYWORDS), 1)

        base_features = [
            sin(hour_angle),
            cos(hour_angle),
            hour / 23.0,
            after_hours,
            weekend,
            log1p(max(network_value, 0.0)),
            network_zscore,
            network_ratio,
            action_seen_ratio,
            device_seen_ratio,
            transition_seen_ratio,
            same_action_streak,
            recent_hour_activity_ratio,
            keyword_density,
        ]

        action_vector = [0.0 for _ in ACTION_BUCKETS]
        bucket_name = action_type if action_type in ACTION_BUCKETS else "other"
        action_vector[ACTION_BUCKETS.index(bucket_name)] = 1.0

        return np.array(base_features + action_vector, dtype=float)

    def build_training_matrix(self, activities: Sequence[Any]) -> np.ndarray:
        normalized_rows = [normalize_activity(item) for item in activities]
        vectors: List[np.ndarray] = []

        for index, row in enumerate(normalized_rows):
            history = normalized_rows[:index]
            vectors.append(self.vectorize(row, history))

        if not vectors:
            return np.empty((0, len(self.feature_names)))

        return np.vstack(vectors)

    def summarize_context(self, activity: Any, history: Sequence[Any]) -> Dict[str, Any]:
        normalized = normalize_activity(activity)
        history_rows = [normalize_activity(item) for item in history]

        login_hours = [item["timestamp"].hour for item in history_rows if item["action_type"] == "login"]
        network_values = [float(item["network_activity"]) for item in history_rows if item["network_activity"] > 0]
        action_counts = Counter(item["action_type"] for item in history_rows)
        device_counts = Counter(item["device"] for item in history_rows if item["device"])

        avg_network = float(np.mean(network_values)) if network_values else 0.0
        std_network = float(np.std(network_values)) if len(network_values) > 1 else 0.0
        peak_login_hours = [hour for hour, _ in Counter(login_hours).most_common(3)]

        return {
            "current_hour": normalized["timestamp"].hour,
            "current_action": normalized["action_type"],
            "current_device": normalized["device"],
            "current_network_activity": normalized["network_activity"],
            "avg_network_activity": avg_network,
            "std_network_activity": std_network,
            "known_action_count": action_counts.get(normalized["action_type"], 0),
            "known_device_count": device_counts.get(normalized["device"], 0),
            "peak_login_hours": peak_login_hours,
        }
