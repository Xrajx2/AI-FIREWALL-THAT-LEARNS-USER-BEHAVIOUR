import ctypes
import os
from typing import Any, Dict
from fastapi import HTTPException


def is_admin() -> bool:
    """Check if the current process is running with elevated Windows Administrator privileges."""
    try:
        if os.name != 'nt':
            return True
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def admin_required_response(feature_name: str = "This feature") -> Dict[str, Any]:
    """Standard error response required across all administrative endpoints."""
    return {
        "error": "admin_required",
        "message": f"{feature_name} requires Windows Administrator privileges. Please run AI Firewall as Administrator."
    }


def raise_admin_required(feature_name: str = "This feature"):
    """Raise HTTP 403 Forbidden with standard admin_required payload."""
    raise HTTPException(
        status_code=403,
        detail=admin_required_response(feature_name)
    )
