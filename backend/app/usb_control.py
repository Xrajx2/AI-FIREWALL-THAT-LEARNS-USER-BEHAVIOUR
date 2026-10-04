import os
from typing import Any, Iterable, List


USB_ACTION_TYPES = {
    "usb_insertion",
    "usb_removal",
    "usb_live_activity",
    "usb_scan_complete",
    "usb_threat_mitigated",
}

USB_DETAIL_TERMS = (
    "usb",
    "removable drive",
    "removable media",
)


def _env_flag(name: str, default: str = "true") -> bool:
    value = os.getenv(name, default)
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


ENABLE_USB_SCANNING = _env_flag("ENABLE_USB_SCANNING", "true")


def is_usb_action_type(action_type: Any) -> bool:
    normalized = str(action_type or "").strip().lower()
    return normalized in USB_ACTION_TYPES


def is_usb_related_activity(activity: Any) -> bool:
    action_type = activity.get("action_type") if isinstance(activity, dict) else getattr(activity, "action_type", None)
    return is_usb_action_type(action_type)


def filter_usb_activities(items: Iterable[Any]) -> List[Any]:
    if ENABLE_USB_SCANNING:
        return list(items)
    return [item for item in items if not is_usb_related_activity(item)]


def is_usb_related_text(value: Any) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    return any(term in text for term in USB_DETAIL_TERMS)


def empty_usb_snapshot() -> dict:
    return {
        "enabled": ENABLE_USB_SCANNING,
        "connected_count": 0,
        "recent_insertions": [],
        "devices": [],
    }
