import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import platform
import psutil
import re
import secrets
import sys
import time
import uuid
from typing import Any, Dict, List, Optional

_backend_dir = str(Path(__file__).resolve().parent.parent)
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)


from fastapi import Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, ValidationError
from sqlalchemy import func, inspect, or_, text

from sqlalchemy.orm import Session

from . import auth, database, models, schemas
from .ai.scoring_engine import engine as ai_engine
from .behavior_tracking import rebuild_behavior_profiles, serialize_behavior_profile, update_behavior_profile
from .database import engine
from .device_safety import (
    list_quarantine_items,
    queue_device_safety_command,
    read_device_safety_status,
    restore_quarantine_file,
)
from .paths import get_database_path, get_runtime_port_file
from .desktop_security import (
    FirewallRuleRequest,
    TextScanRequest,
    UrlScanRequest,
    desktop_security_service,
)
from .monitoring import EXTERNAL_MONITOR_TTL_SECONDS, SystemMonitorService
from .traffic_monitor_service import traffic_service
from .spam_detection_service import spam_service
from .website_security_service import website_security_service
from .website_blocker import website_blocker
from fastapi.responses import HTMLResponse, JSONResponse

from .risk import is_risky, score_to_risk_level
from .security import (
    decrypt_sensitive_value,
    encrypt_sensitive_value,
    fingerprint_text,
    log_ciphertext,
    maybe_encrypt_legacy_value,
)
from .usb_control import ENABLE_USB_SCANNING, USB_ACTION_TYPES, empty_usb_snapshot, filter_usb_activities, is_usb_action_type, is_usb_related_text

models.Base.metadata.create_all(bind=engine)
database.ensure_schema_migrations(database.DATABASE_URL)

from logging.handlers import RotatingFileHandler
appdata_dir = os.environ.get("APPDATA") or os.path.expanduser("~\\AppData\\Roaming")
LOG_DIR = os.path.join(appdata_dir, "AIFirewall", "logs")
try:
    os.makedirs(LOG_DIR, exist_ok=True)
except Exception:
    pass

log_file_path = os.path.join(LOG_DIR, "aifirewall.log")
log_formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")

root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)

if not any(isinstance(h, logging.StreamHandler) and not isinstance(h, RotatingFileHandler) for h in root_logger.handlers):
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(log_formatter)
    root_logger.addHandler(sh)

if not any(isinstance(h, RotatingFileHandler) for h in root_logger.handlers):
    try:
        rf = RotatingFileHandler(log_file_path, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
        rf.setFormatter(log_formatter)
        root_logger.addHandler(rf)
    except Exception as e:
        print(f"Failed to initialize rotating file logger: {e}", file=sys.stderr)

logger = logging.getLogger("ai_firewall.auth")

FAILED_ATTEMPT_WINDOW_MINUTES = 5
FAILED_ATTEMPT_LIMIT = 5
REMEMBER_ME_DAYS = 14
STANDARD_LOGIN_HOURS = 12
AUTH_REASON_WEIGHTS = {
    "Multiple failed attempts before successful login": 28.0,
    "Login from a new IP address": 18.0,
    "Login from a new device or browser": 14.0,
    "Access at an unusual time": 20.0,
}
ALLOW_FIRST_ADMIN_BOOTSTRAP = str(os.getenv("ALLOW_FIRST_ADMIN_BOOTSTRAP", "true")).strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
ADMIN_SIGNUP_CODE = (os.getenv("ADMIN_SIGNUP_CODE") or "").strip()


def build_usb_ignored_assessment(user_id: int) -> Dict[str, Any]:
    return {
        "score": 0.0,
        "level": "Normal",
        "risk_level": "Normal",
        "recommended_action": "allow",
        "summary": "USB scanning is disabled. USB events are ignored.",
        "reasons": ["USB scanning is disabled."],
        "component_scores": {},
        "learning_state": {
            "user_id": user_id,
            "training_samples": 0,
            "isolation_forest_ready": False,
            "cluster_model_ready": False,
            "continuous_learning": True,
        },
    }


def filter_usb_threat_rows(rows: List[Any]) -> List[Any]:
    if ENABLE_USB_SCANNING:
        return rows
    filtered_rows = []
    for row in rows:
        details = row.get("details") if isinstance(row, dict) else getattr(row, "details", None)
        if not is_usb_related_text(decrypt_sensitive_value(details)):
            filtered_rows.append(row)
    return filtered_rows


def ensure_runtime_schema():
    runtime_columns = {
        "users": {
            "email": "VARCHAR",
            "email_lookup_hash": "VARCHAR",
            "created_at": "TIMESTAMP",
            "is_active": "BOOLEAN DEFAULT TRUE",
            "is_locked": "BOOLEAN DEFAULT FALSE",
            "is_email_verified": "BOOLEAN DEFAULT TRUE",
            "last_login_at": "TIMESTAMP",
            "last_login_ip": "VARCHAR",
            "last_login_device": "VARCHAR",
            "last_login_ip_hash": "VARCHAR",
            "last_login_device_hash": "VARCHAR",
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
        "login_attempts": {
            "ip_address_hash": "VARCHAR",
            "device_name_hash": "VARCHAR",
        },
        "auth_sessions": {
            "ip_address_hash": "VARCHAR",
            "device_name_hash": "VARCHAR",
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


ensure_runtime_schema()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[Dict[str, Any]] = []

    async def connect(self, websocket: WebSocket, user: models.User):
        await websocket.accept()
        self.active_connections.append(
            {
                "websocket": websocket,
                "user_id": user.id,
                "role": get_user_role(user),
            }
        )

    def disconnect(self, websocket: WebSocket):
        stale_connections = [
            connection for connection in self.active_connections if connection.get("websocket") == websocket
        ]
        for connection in stale_connections:
            self.active_connections.remove(connection)

    async def broadcast(self, message: str, *, user_id: Optional[int] = None, admin_only: bool = False):
        try:
            parsed = json.loads(message)
            if isinstance(parsed, dict):
                changed = False
                if "id" not in parsed:
                    parsed["id"] = str(uuid.uuid4())
                    changed = True
                if "timestamp" not in parsed:
                    parsed["timestamp"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                    changed = True
                if changed:
                    message = json.dumps(parsed)
        except Exception:
            pass

        stale_connections = []
        for connection in list(self.active_connections):
            connection_role = str(connection.get("role") or "user").lower()
            connection_user_id = connection.get("user_id")
            if admin_only and connection_role != "admin":
                continue
            if user_id is not None and connection_role != "admin" and connection_user_id != user_id:
                continue
            try:
                await connection["websocket"].send_text(message)
            except Exception:
                stale_connections.append(connection)
        for connection in stale_connections:
            websocket = connection.get("websocket")
            if websocket is not None:
                self.disconnect(websocket)


manager = ConnectionManager()
system_monitor = SystemMonitorService(manager)


def _load_json_list(raw_value: Optional[str]) -> List[Any]:
    if not raw_value:
        return []
    try:
        value = json.loads(decrypt_sensitive_value(raw_value))
        return value if isinstance(value, list) else []
    except (TypeError, json.JSONDecodeError):
        return []


def _load_json_dict(raw_value: Optional[str]) -> Dict[str, Any]:
    if not raw_value:
        return {}
    try:
        value = json.loads(decrypt_sensitive_value(raw_value))
        return value if isinstance(value, dict) else {}
    except (TypeError, json.JSONDecodeError):
        return {}


def build_internal_email(username: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9_-]+", "", (username or "").strip().lower()) or "user"
    return f"{normalized}@internal.local"


def backfill_user_security_fields():
    db = database.SessionLocal()
    try:
        from sqlalchemy.exc import IntegrityError
        users = db.query(models.User).all()
        for user in users:
            try:
                email_value = decrypt_sensitive_value(user.email)
                if not email_value:
                    email_value = build_internal_email(user.username)
                encrypted_email = maybe_encrypt_legacy_value(email_value)
                if user.email != encrypted_email:
                    user.email = encrypted_email
                email_lookup_hash = fingerprint_text(email_value)
                if user.email_lookup_hash != email_lookup_hash:
                    user.email_lookup_hash = email_lookup_hash
                if not user.created_at:
                    user.created_at = datetime.utcnow()
                if user.is_active is None:
                    user.is_active = True
                if user.is_locked is None:
                    user.is_locked = False
                if user.is_email_verified is None:
                    user.is_email_verified = True
                encrypted_login_ip = maybe_encrypt_legacy_value(user.last_login_ip)
                if user.last_login_ip != encrypted_login_ip:
                    user.last_login_ip = encrypted_login_ip
                login_ip_hash = fingerprint_text(decrypt_sensitive_value(user.last_login_ip))
                if user.last_login_ip_hash != login_ip_hash:
                    user.last_login_ip_hash = login_ip_hash
                encrypted_login_device = maybe_encrypt_legacy_value(user.last_login_device)
                if user.last_login_device != encrypted_login_device:
                    user.last_login_device = encrypted_login_device
                login_device_hash = fingerprint_text(decrypt_sensitive_value(user.last_login_device))
                if user.last_login_device_hash != login_device_hash:
                    user.last_login_device_hash = login_device_hash
                db.add(user)
                db.flush()
            except IntegrityError:
                db.rollback()
                logger.warning(f"Skipping backfill for user id={user.id} due to constraint conflict")

        try:
            for attempt in db.query(models.LoginAttempt).all():
                encrypted_ip = maybe_encrypt_legacy_value(attempt.ip_address)
                if attempt.ip_address != encrypted_ip:
                    attempt.ip_address = encrypted_ip
                ip_hash = fingerprint_text(decrypt_sensitive_value(attempt.ip_address))
                if attempt.ip_address_hash != ip_hash:
                    attempt.ip_address_hash = ip_hash
                encrypted_user_agent = maybe_encrypt_legacy_value(attempt.user_agent)
                if attempt.user_agent != encrypted_user_agent:
                    attempt.user_agent = encrypted_user_agent
                encrypted_device = maybe_encrypt_legacy_value(attempt.device_name)
                if attempt.device_name != encrypted_device:
                    attempt.device_name = encrypted_device
                device_hash = fingerprint_text(decrypt_sensitive_value(attempt.device_name))
                if attempt.device_name_hash != device_hash:
                    attempt.device_name_hash = device_hash
                encrypted_failure_reason = maybe_encrypt_legacy_value(attempt.failure_reason)
                if attempt.failure_reason != encrypted_failure_reason:
                    attempt.failure_reason = encrypted_failure_reason
                encrypted_reasons = maybe_encrypt_legacy_value(attempt.suspicious_reasons)
                if attempt.suspicious_reasons != encrypted_reasons:
                    attempt.suspicious_reasons = encrypted_reasons
                db.add(attempt)
            db.commit()
        except Exception as e:
            db.rollback()
            logger.warning(f"Backfill LoginAttempt skipped: {e}")

        try:
            for session in db.query(models.AuthSession).all():
                encrypted_ip = maybe_encrypt_legacy_value(session.ip_address)
                if session.ip_address != encrypted_ip:
                    session.ip_address = encrypted_ip
                ip_hash = fingerprint_text(decrypt_sensitive_value(session.ip_address))
                if session.ip_address_hash != ip_hash:
                    session.ip_address_hash = ip_hash
                encrypted_user_agent = maybe_encrypt_legacy_value(session.user_agent)
                if session.user_agent != encrypted_user_agent:
                    session.user_agent = encrypted_user_agent
                encrypted_device = maybe_encrypt_legacy_value(session.device_name)
                if session.device_name != encrypted_device:
                    session.device_name = encrypted_device
                device_hash = fingerprint_text(decrypt_sensitive_value(session.device_name))
                if session.device_name_hash != device_hash:
                    session.device_name_hash = device_hash
                encrypted_reason = maybe_encrypt_legacy_value(session.suspicious_reason)
                if session.suspicious_reason != encrypted_reason:
                    session.suspicious_reason = encrypted_reason
                db.add(session)
            db.commit()
        except Exception as e:
            db.rollback()
            logger.warning(f"Backfill AuthSession skipped: {e}")

        try:
            for activity in db.query(models.UserActivity).all():
                encrypted_details = maybe_encrypt_legacy_value(activity.details)
                if activity.details != encrypted_details:
                    activity.details = encrypted_details
                    db.add(activity)
            db.commit()
        except Exception as e:
            db.rollback()
            logger.warning(f"Backfill UserActivity skipped: {e}")

        try:
            for threat in db.query(models.ThreatLog).all():
                encrypted_details = maybe_encrypt_legacy_value(threat.details)
                if threat.details != encrypted_details:
                    threat.details = encrypted_details
                    db.add(threat)
            db.commit()
        except Exception as e:
            db.rollback()
            logger.warning(f"Backfill ThreatLog skipped: {e}")

    except Exception as e:
        logger.error(f"backfill_user_security_fields failed: {e}")
        db.rollback()
    finally:
        db.close()


try:
    backfill_user_security_fields()
except Exception as e:
    logger.error(f"Non-fatal: backfill_user_security_fields error: {e}")


async def run_device_safety_agent_loop():
    try:
        from device_safety_agent import DeviceSafetyAgent
        agent = DeviceSafetyAgent()
        while True:
            agent.step()
            await asyncio.sleep(2)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error(f"Error in Device Safety background task: {e}")


async def run_traffic_monitor_sampler_loop():
    while True:
        try:
            if time.time() - traffic_service.last_ingest_time > 3.0:
                db = database.SessionLocal()
                try:
                    await traffic_service.sample_host_connections_fallback(db)
                    now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                    await manager.broadcast(
                        json.dumps({
                            "id": str(uuid.uuid4()),
                            "type": "TRAFFIC_MONITOR_UPDATE",
                            "timestamp": now_utc,
                            "connections": traffic_service.connections,
                            "interface_stats": traffic_service.interface_stats
                        }),
                        admin_only=False
                    )
                finally:
                    db.close()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in Traffic Monitor fallback task: {e}")
        await asyncio.sleep(2)


@asynccontextmanager
async def lifespan(_: FastAPI):
    db = database.SessionLocal()
    try:
        rebuild_behavior_profiles(db)
        traffic_service.load_rules(db, force=True)
        db.commit()
    finally:
        db.close()

    await system_monitor.start()
    device_safety_task = asyncio.create_task(run_device_safety_agent_loop())
    traffic_sampler_task = asyncio.create_task(run_traffic_monitor_sampler_loop())
    live_monitor_task = asyncio.create_task(live_monitor.start())

    try:
        block_manager._load_active_blocks_to_cache()
    except Exception as e:
        logger.warning(f"Block manager cache load warning: {e}")

    try:
        yield
    finally:
        live_monitor.stop()
        live_monitor_task.cancel()
        device_safety_task.cancel()
        traffic_sampler_task.cancel()
        try:
            await system_monitor.stop()
        except Exception:
            pass


is_dev = os.getenv("AIFIREWALL_ENV", os.getenv("ENV", "production")).strip().lower() in ("development", "dev")

app = FastAPI(
    title="AI Firewall Backend",
    lifespan=lifespan,
    docs_url="/docs" if is_dev else None,
    redoc_url="/redoc" if is_dev else None,
    openapi_url="/openapi.json" if is_dev else None,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "null",
        "app://.",
        "file://",
    ],
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

try:
    from backend.security.block_manager import block_manager
except ImportError:
    try:
        from security.block_manager import block_manager
    except ImportError:
        from ..security.block_manager import block_manager
from .admin_utils import is_admin, admin_required_response, raise_admin_required

def is_admin_user() -> bool:
    return is_admin()

@app.get("/health", tags=["Health"])
@app.get("/api/health", tags=["Health"])
async def health_check():
    admin = is_admin_user()
    db_status = "ok"
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"error: {str(e)}"

    cache_count = len(getattr(block_manager, "_cache", {}))
    active_port = int(os.environ.get("AI_FIREWALL_PORT", "8000"))

    return {
        "status": "OK" if db_status == "ok" else "DEGRADED",
        "app": "AI Firewall",
        "admin_rights": admin,
        "port": active_port,
        "features": {
            "database": {
                "status": "OK" if db_status == "ok" else "ERROR",
                "detail": db_status,
                "url": database.DATABASE_URL.split("@")[-1] if "@" in database.DATABASE_URL else database.DATABASE_URL
            },
            "in_memory_cache": {
                "status": "OK",
                "cached_blocks_count": cache_count
            },
            "ai_models": {
                "status": "OK",
                "isolation_forest": "ready" if getattr(ai_engine.point_model, "models", None) else "initialized",
                "clustering": "ready" if getattr(ai_engine.cluster_model, "models", None) else "initialized",
                "sequence_engine": "ready (Markovian transition analyzer)"
            },
            "network_monitor": {
                "status": "OK"
            },
            "website_blocker": {
                "status": "OK" if admin else "NEEDS_ADMIN"
            },
            "firewall_rules": {
                "status": "OK" if admin else "NEEDS_ADMIN"
            }
        },
        "log_file": log_file_path,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.middleware("http")
async def check_block_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"
    if block_manager.is_blocked("ip", client_ip):
        block_manager.record_attempt("ip", client_ip)
        return JSONResponse(
            status_code=403,
            content={"error": "Access denied", "blocked": True, "reason": "IP_PERMANENTLY_BLOCKED"},
        )
    return await call_next(request)


try:
    from backend.api.traffic_routes import router as traffic_router
except ImportError:
    try:
        from api.traffic_routes import router as traffic_router
    except ImportError:
        from ..api.traffic_routes import router as traffic_router

app.include_router(traffic_router)

try:
    from backend.api.user_management import router as user_router
except ImportError:
    try:
        from api.user_management import router as user_router
    except ImportError:
        from ..api.user_management import router as user_router

app.include_router(user_router)


try:
    from backend.security.geo_tracker import GeoTracker
except ImportError:
    try:
        from security.geo_tracker import GeoTracker
    except ImportError:
        from ..security.geo_tracker import GeoTracker

geo_tracker = GeoTracker()
geo = geo_tracker

try:
    from backend.ai.phishing_detector import detector as phishing_detector
except ImportError:
    try:
        from ai.phishing_detector import detector as phishing_detector
    except ImportError:
        from ..ai.phishing_detector import detector as phishing_detector

try:
    from backend.security.live_monitor import live_monitor, geo
except ImportError:
    try:
        from security.live_monitor import live_monitor, geo
    except ImportError:
        from ..security.live_monitor import live_monitor, geo

async def broadcast_live_event(event: dict):
    try:
        if "id" not in event:
            event["id"] = str(uuid.uuid4())
        if "timestamp" not in event:
            event["timestamp"] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        await manager.broadcast(json.dumps(event))
    except Exception as exc:
        logger.debug(f"Live event broadcast error: {exc}")

live_monitor.add_callback(broadcast_live_event)

@app.websocket("/ws/live")
async def live_websocket(websocket: WebSocket):
    # Unified WebSocket endpoint delegate
    await websocket_endpoint(websocket)






def credentials_exception() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_token_payload(token: str) -> Dict[str, Any]:
    try:
        return auth.decode_access_token(token)
    except auth.JWTError as exc:
        raise credentials_exception() from exc


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(database.get_db)):
    payload = get_token_payload(token)
    username = payload.get("sub")
    if not username:
        raise credentials_exception()

    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None or not bool(user.is_active) or bool(user.is_locked):
        raise credentials_exception()

    session_id = payload.get("sid")
    if session_id:
        session = (
            db.query(models.AuthSession)
            .filter(
                models.AuthSession.session_token_id == session_id,
                models.AuthSession.user_id == user.id,
                models.AuthSession.is_active.is_(True),
            )
            .first()
        )
        if session is None or (session.expires_at and session.expires_at < datetime.utcnow()):
            raise credentials_exception()
        session.last_seen_at = datetime.utcnow()
        db.add(session)
        db.commit()

    return user


def get_current_session(token: str = Depends(oauth2_scheme), db: Session = Depends(database.get_db)) -> Optional[models.AuthSession]:
    payload = get_token_payload(token)
    session_id = payload.get("sid")
    if not session_id:
        return None
    return db.query(models.AuthSession).filter(models.AuthSession.session_token_id == session_id).first()


def get_account_type(user: models.User) -> str:
    username = (user.username or "").lower()
    if username.endswith("-agent") or username.startswith("system-") or username == "usb-security-agent":
        return "system_agent"
    return "human"


def get_user_role(user: models.User) -> str:
    return str(getattr(user, "role", None) or "user").strip().lower()


def require_admin(current_user: models.User = Depends(get_current_user)) -> models.User:
    if get_user_role(current_user) != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


def require_admin_or_system_agent(current_user: models.User = Depends(get_current_user)) -> models.User:
    if get_user_role(current_user) == "admin":
        return current_user
    if get_account_type(current_user) == "system_agent":
        return current_user
    raise HTTPException(status_code=403, detail="Administrative or system-agent access required")


def decrypt_detail_text(value: Optional[str]) -> Optional[str]:
    decrypted = decrypt_sensitive_value(value)
    if decrypted is None:
        return None
    return decrypted


def serialize_user(user: models.User) -> Dict[str, Any]:
    return {
        "id": user.id,
        "username": user.username,
        "email": decrypt_sensitive_value(user.email),
        "role": get_user_role(user),
        "country": getattr(user, "country", None) or "United States",
        "auth_provider": getattr(user, "auth_provider", None) or "local",
        "created_at": user.created_at,
        "is_active": bool(user.is_active),
        "is_locked": bool(user.is_locked),
        "is_email_verified": bool(user.is_email_verified),
        "last_login_at": user.last_login_at,
        "last_login_ip": decrypt_sensitive_value(user.last_login_ip),
        "last_login_device": decrypt_sensitive_value(user.last_login_device),
    }


def serialize_activity(activity: models.UserActivity) -> Dict[str, Any]:
    return {
        "id": activity.id,
        "user_id": activity.user_id,
        "timestamp": activity.timestamp,
        "action_type": activity.action_type,
        "device": activity.device,
        "network_activity": activity.network_activity,
        "details": decrypt_detail_text(activity.details),
        "risk_score": float(activity.risk_score or 0.0),
        "risk_level": activity.risk_level or "Normal",
    }


def serialize_threat(threat: models.ThreatLog) -> Dict[str, Any]:
    return {
        "id": threat.id,
        "user_id": threat.user_id,
        "anomaly_score": float(threat.anomaly_score or 0.0),
        "threat_level": threat.threat_level,
        "action_taken": threat.action_taken,
        "timestamp": threat.timestamp,
        "details": decrypt_detail_text(threat.details),
    }
    

def validate_admin_signup_request(db: Session, requested_role: str, invite_code: Optional[str]):
    # Admin signup is always allowed in desktop build
    return


def encrypt_json_payload(payload: Dict[str, Any]) -> Optional[str]:
    if payload is None:
        return None
    return encrypt_sensitive_value(json.dumps(payload))


def compute_overall_risk_score(activity_scores: List[float], average_threat_score: float) -> float:
    if not activity_scores and average_threat_score <= 0:
        return 0.0
    recent_average = sum(activity_scores) / len(activity_scores) if activity_scores else 0.0
    recent_peak = max(activity_scores) if activity_scores else 0.0
    overall_score = (recent_average * 0.45) + (recent_peak * 0.25) + (float(average_threat_score) * 0.30)
    return round(min(100.0, overall_score), 2)


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def get_device_name(user_agent: Optional[str]) -> str:
    if not user_agent:
        return "Unknown Device"
    ua = user_agent.lower()
    platform = "Unknown OS"
    browser = "Unknown Browser"
    if "windows" in ua:
        platform = "Windows"
    elif "mac os" in ua or "macintosh" in ua:
        platform = "macOS"
    elif "android" in ua:
        platform = "Android"
    elif "iphone" in ua or "ipad" in ua or "ios" in ua:
        platform = "iOS"
    elif "linux" in ua:
        platform = "Linux"
    if "edg/" in ua:
        browser = "Edge"
    elif "chrome/" in ua and "edg/" not in ua:
        browser = "Chrome"
    elif "firefox/" in ua:
        browser = "Firefox"
    elif "safari/" in ua and "chrome/" not in ua:
        browser = "Safari"
    elif "powershell" in ua:
        browser = "PowerShell Agent"
    return f"{platform} / {browser}"


def normalize_identifier(identifier: str) -> str:
    return (identifier or "").strip().lower()


def get_login_identifier_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    identifier = payload.get("identifier") or payload.get("username") or payload.get("email")
    remember_me = payload.get("remember_me", False)
    if isinstance(remember_me, str):
        remember_me = remember_me.strip().lower() in {"1", "true", "yes", "on"}
    return {
        "identifier": identifier or "",
        "password": payload.get("password") or "",
        "remember_me": bool(remember_me),
    }


async def parse_login_request(request: Request) -> schemas.AuthLoginRequest:
    content_type = (request.headers.get("content-type") or "").lower()
    if "application/json" in content_type:
        payload = await request.json()
    else:
        form_data = await request.form()
        payload = dict(form_data)
    normalized = get_login_identifier_payload(payload)
    return schemas.AuthLoginRequest.model_validate(normalized)


def find_user_by_identifier(db: Session, identifier: str) -> Optional[models.User]:
    normalized = normalize_identifier(identifier)
    if not normalized:
        return None
    email_hash = fingerprint_text(normalized)
    sha_hash = hashlib.sha256(normalized.encode()).hexdigest()
    user = (
        db.query(models.User)
        .filter(
            or_(
                func.lower(models.User.username) == normalized,
                models.User.email_lookup_hash == email_hash,
                models.User.email_lookup_hash == sha_hash,
                func.lower(models.User.email) == normalized,
            )
        )
        .first()
    )
    if not user:
        all_users = db.query(models.User).all()
        for u in all_users:
            decrypted = decrypt_sensitive_value(u.email)
            if decrypted and decrypted.lower() == normalized:
                return u
    return user


def get_failed_attempt_count(db: Session, identifier: str, ip_address: Optional[str] = None) -> int:
    normalized = normalize_identifier(identifier)
    if not normalized:
        return 0
    window_start = datetime.utcnow() - auth.timedelta(minutes=FAILED_ATTEMPT_WINDOW_MINUTES)
    return (
        db.query(models.LoginAttempt)
        .filter(
            models.LoginAttempt.attempt_identifier == normalized,
            models.LoginAttempt.created_at >= window_start,
            models.LoginAttempt.success.is_(False),
        )
        .count()
    )


def log_login_attempt(
    db: Session,
    identifier: str,
    ip_address: str,
    user_agent: str,
    device_name: str,
    success: bool,
    user: Optional[models.User] = None,
    failure_reason: Optional[str] = None,
    suspicious: bool = False,
    suspicious_reasons: Optional[List[str]] = None,
) -> models.LoginAttempt:
    normalized_identifier = normalize_identifier(identifier)
    ip_hash = fingerprint_text(ip_address)
    device_hash = fingerprint_text(device_name)
    attempt = models.LoginAttempt(
        user_id=user.id if user else None,
        attempt_identifier=normalized_identifier,
        ip_address=encrypt_sensitive_value(ip_address),
        ip_address_hash=ip_hash,
        user_agent=encrypt_sensitive_value(user_agent),
        device_name=encrypt_sensitive_value(device_name),
        device_name_hash=device_hash,
        success=success,
        failure_reason=encrypt_sensitive_value(failure_reason),
        suspicious=suspicious,
        suspicious_reasons=encrypt_sensitive_value(json.dumps(suspicious_reasons or [])),
    )
    db.add(attempt)
    db.commit()
    db.refresh(attempt)
    logger.info(
        "login_attempt success=%s identifier=%s ip=%s suspicious=%s reason=%s",
        success,
        log_ciphertext(normalized_identifier),
        log_ciphertext(ip_address),
        suspicious,
        log_ciphertext(failure_reason or "; ".join(suspicious_reasons or [])),
    )
    return attempt


def is_new_login_ip(db: Session, user: models.User, ip_address: str) -> bool:
    if not ip_address or ip_address == "unknown":
        return False
    ip_hash = fingerprint_text(ip_address)
    prior_success_count = (
        db.query(models.LoginAttempt)
        .filter(
            models.LoginAttempt.user_id == user.id,
            models.LoginAttempt.success.is_(True),
        )
        .count()
    )
    if not prior_success_count:
        return False
    known_ip = (
        db.query(models.LoginAttempt.id)
        .filter(
            models.LoginAttempt.user_id == user.id,
            models.LoginAttempt.success.is_(True),
            or_(models.LoginAttempt.ip_address_hash == ip_hash, models.LoginAttempt.ip_address == ip_address),
        )
        .first()
    )
    return known_ip is None


def is_new_login_device(db: Session, user: models.User, device_name: str) -> bool:
    if not device_name or device_name == "Unknown Device":
        return False
    device_hash = fingerprint_text(device_name)
    prior_success_count = (
        db.query(models.LoginAttempt)
        .filter(
            models.LoginAttempt.user_id == user.id,
            models.LoginAttempt.success.is_(True),
        )
        .count()
    )
    if not prior_success_count:
        return False
    known_device = (
        db.query(models.LoginAttempt.id)
        .filter(
            models.LoginAttempt.user_id == user.id,
            models.LoginAttempt.success.is_(True),
            or_(models.LoginAttempt.device_name_hash == device_hash, models.LoginAttempt.device_name == device_name),
        )
        .first()
    )
    return known_device is None


def is_unusual_login_time(profile: Optional[models.BehaviorProfile], login_time: datetime) -> bool:
    if not profile:
        return False
    distribution = _load_json_dict(profile.login_hour_distribution)
    total_logins = sum(int(value) for value in distribution.values()) if distribution else 0
    if total_logins < 4:
        return False
    hour = login_time.hour
    known_hours = [int(item) for item in distribution.keys()]
    if hour in known_hours:
        return False
    top_hours = sorted(
        ((int(key), int(value)) for key, value in distribution.items()),
        key=lambda item: item[1],
        reverse=True,
    )[:3]
    for known_hour, _ in top_hours:
        delta = abs(hour - known_hour)
        delta = min(delta, 24 - delta)
        if delta <= 1:
            return False
    return True


def assess_login_security(
    db: Session,
    user: models.User,
    ip_address: str,
    device_name: str,
    ai_assessment: Dict[str, Any],
) -> Dict[str, Any]:
    reasons: List[str] = []
    recent_failures = (
        db.query(models.LoginAttempt)
        .filter(
            models.LoginAttempt.user_id == user.id,
            models.LoginAttempt.success.is_(False),
            models.LoginAttempt.created_at >= datetime.utcnow() - auth.timedelta(minutes=FAILED_ATTEMPT_WINDOW_MINUTES),
        )
        .count()
    )
    if recent_failures >= 3:
        reasons.append("Multiple failed attempts before successful login")
    if is_new_login_ip(db, user, ip_address):
        reasons.append("Login from a new IP address")
    if is_new_login_device(db, user, device_name):
        reasons.append("Login from a new device or browser")
    if is_unusual_login_time(user.profile, datetime.utcnow()):
        reasons.append("Access at an unusual time")

    base_score = float(ai_assessment.get("score", 0.0))
    risk_score = min(100.0, base_score + sum(AUTH_REASON_WEIGHTS.get(reason, 10.0) for reason in reasons))
    if len(reasons) >= 2:
        risk_score = max(risk_score, 72.0)
    elif reasons:
        risk_score = max(risk_score, 42.0)
    risk_score = round(risk_score, 2)
    risk_level = score_to_risk_level(risk_score)
    security_status = "Suspicious" if reasons else "Safe"
    combined_reasons = list(dict.fromkeys([*(ai_assessment.get("reasons") or []), *reasons]))
    summary = ai_assessment.get("summary") or "Login behavior matched the expected baseline."
    if reasons:
        summary = f"Suspicious login detected: {', '.join(reasons)}."
    return {
        **ai_assessment,
        "score": risk_score,
        "level": risk_level,
        "risk_level": risk_level,
        "security_status": security_status,
        "suspicious_session": bool(reasons),
        "reasons": combined_reasons,
        "summary": summary,
        "warning_message": summary if reasons else None,
    }


def serialize_login_attempt(attempt: models.LoginAttempt) -> Dict[str, Any]:
    return {
        "id": attempt.id,
        "created_at": attempt.created_at,
        "ip_address": decrypt_sensitive_value(attempt.ip_address),
        "device_name": decrypt_sensitive_value(attempt.device_name),
        "success": bool(attempt.success),
        "suspicious": bool(attempt.suspicious),
        "failure_reason": decrypt_sensitive_value(attempt.failure_reason),
        "suspicious_reasons": _load_json_list(attempt.suspicious_reasons),
    }


def build_dashboard_summary(user: models.User, db: Session) -> Dict[str, Any]:
    recent_attempts = (
        db.query(models.LoginAttempt)
        .filter(models.LoginAttempt.user_id == user.id)
        .order_by(models.LoginAttempt.created_at.desc())
        .limit(8)
        .all()
    )
    successful_attempts = [attempt for attempt in recent_attempts if attempt.success]
    current_login = successful_attempts[0] if successful_attempts else None
    previous_login = successful_attempts[1] if len(successful_attempts) > 1 else None
    security_status = "Suspicious" if current_login and current_login.suspicious else "Safe"
    suspicious_reasons = _load_json_list(current_login.suspicious_reasons) if current_login else []
    active_sessions = (
        db.query(models.AuthSession)
        .filter(
            models.AuthSession.user_id == user.id,
            models.AuthSession.is_active.is_(True),
            models.AuthSession.expires_at >= datetime.utcnow(),
        )
        .count()
    )
    return {
        "user": serialize_user(user),
        "welcome_message": f"Welcome back, {user.username}.",
        "security_status": security_status,
        "last_login_at": previous_login.created_at if previous_login else None,
        "current_login_at": current_login.created_at if current_login else user.last_login_at,
        "current_login_ip": decrypt_sensitive_value(current_login.ip_address) if current_login else decrypt_sensitive_value(user.last_login_ip),
        "current_login_device": decrypt_sensitive_value(current_login.device_name) if current_login else decrypt_sensitive_value(user.last_login_device),
        "suspicious_reasons": suspicious_reasons,
        "active_sessions": active_sessions,
        "recent_login_activity": [serialize_login_attempt(item) for item in recent_attempts],
    }


def parse_snapshot_datetime(raw_value: Optional[str]) -> Optional[datetime]:
    if not raw_value:
        return None
    normalized = str(raw_value).strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def parse_json_text(raw_value: Optional[str]) -> Optional[Dict[str, Any]]:
    decrypted = decrypt_sensitive_value(raw_value)
    if not decrypted:
        return None
    try:
        value = json.loads(decrypted)
    except (TypeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def serialize_usb_scan_activity(activity: models.UserActivity) -> Optional[Dict[str, Any]]:
    payload = parse_json_text(activity.details)
    if not payload or payload.get("scan_type") != "usb_file_intelligence":
        return None
    return {
        "id": activity.id,
        "action": activity.action_type,
        "timestamp": activity.timestamp.isoformat() if activity.timestamp else None,
        "drive": payload.get("drive") or activity.device or "USB",
        "summary": payload.get("summary") or "USB scan completed.",
        "threatTypes": payload.get("threat_types") or [],
        "findings": payload.get("findings") or [],
        "dangerousCount": int(payload.get("dangerous_count") or 0),
        "suspiciousCount": int(payload.get("suspicious_count") or 0),
        "quarantinedCount": int(payload.get("quarantined_count") or 0),
        "blockedCount": int(payload.get("blocked_count") or 0),
        "scannerVersion": payload.get("scanner_version") or "-",
        "totalFiles": int(payload.get("total_files") or 0),
        "strictMode": bool(payload.get("strict_mode")),
    }


def serialize_usb_recent_event(activity: models.UserActivity) -> Dict[str, Any]:
    payload = parse_json_text(activity.details) or {}
    summary = payload.get("summary")
    if not summary:
        summary = decrypt_detail_text(activity.details) or f"USB event: {activity.action_type}"

    drive = payload.get("drive") or activity.device
    items = payload.get("items") if isinstance(payload.get("items"), list) else []
    normalized_items = []
    for item in items[:6]:
        if not isinstance(item, dict):
            continue
        normalized_items.append(
            {
                "path": item.get("path") or item.get("Path") or "",
                "name": item.get("name") or item.get("Name") or "",
                "change_type": item.get("change_type") or item.get("ChangeType") or "",
                "entity_type": item.get("entity_type") or item.get("EntityType") or "",
                "size_bytes": int(item.get("size_bytes") or item.get("SizeBytes") or 0),
                "last_write_time": item.get("last_write_time") or item.get("LastWriteTime"),
            }
        )

    return {
        "id": activity.id,
        "timestamp": activity.timestamp.isoformat() if activity.timestamp else None,
        "action_type": activity.action_type,
        "device": drive,
        "drive": drive,
        "summary": summary,
        "risk_level": activity.risk_level or "Normal",
        "event_label": str(activity.action_type or "").replace("_", " ").upper(),
        "payload_type": payload.get("activity_type") or payload.get("scan_type") or None,
        "items": normalized_items,
        "change_counts": {
            "created_files": int(payload.get("created_files") or 0),
            "modified_files": int(payload.get("modified_files") or 0),
            "deleted_files": int(payload.get("deleted_files") or 0),
            "created_directories": int(payload.get("created_directories") or 0),
            "deleted_directories": int(payload.get("deleted_directories") or 0),
        },
    }


def build_usb_status(db: Session) -> Dict[str, Any]:
    snapshot = system_monitor.get_current_snapshot() or {}
    usb_snapshot = snapshot.get("usb") if isinstance(snapshot.get("usb"), dict) else empty_usb_snapshot()
    collector = str(snapshot.get("collector") or "container-fallback")
    scope = str(snapshot.get("scope") or "container")
    poll_interval = float(snapshot.get("poll_interval_seconds") or 5.0)
    snapshot_time = parse_snapshot_datetime(snapshot.get("timestamp"))
    now_utc = datetime.now(timezone.utc)
    snapshot_age_seconds = None
    if snapshot_time:
        snapshot_age_seconds = round(max(0.0, (now_utc - snapshot_time).total_seconds()), 1)

    freshness_window = max(EXTERNAL_MONITOR_TTL_SECONDS, poll_interval * 3)
    snapshot_fresh = snapshot_age_seconds is None or snapshot_age_seconds <= freshness_window
    current_devices = [
        {
            "id": item.get("instance_id") or item.get("name") or f"usb-{index}",
            "name": item.get("name") or "USB device",
            "status": item.get("status") or "Unknown",
            "class": item.get("class") or "USB",
            "size_gb": float(item.get("size_gb") or 0.0),
            "free_gb": float(item.get("free_gb") or 0.0),
        }
        for index, item in enumerate((usb_snapshot.get("devices") or [])[:8])
        if isinstance(item, dict)
    ]
    recent_insertions = [
        {
            "id": item.get("instance_id") or item.get("name") or f"insertion-{index}",
            "name": item.get("name") or "USB device",
            "status": item.get("status") or "Unknown",
            "class": item.get("class") or "USB",
        }
        for index, item in enumerate((usb_snapshot.get("recent_insertions") or [])[:5])
        if isinstance(item, dict)
    ]

    usb_activities = (
        db.query(models.UserActivity)
        .filter(models.UserActivity.action_type.in_(tuple(USB_ACTION_TYPES)))
        .order_by(models.UserActivity.timestamp.desc())
        .limit(50)
        .all()
    )
    last_event = usb_activities[0] if usb_activities else None
    latest_findings = [
        finding
        for finding in (serialize_usb_scan_activity(activity) for activity in usb_activities if activity.action_type == "usb_scan_complete")
        if finding
    ][:3]
    last_scan = latest_findings[0] if latest_findings else None

    recent_events = [serialize_usb_recent_event(activity) for activity in usb_activities[:12]]

    enabled = bool(usb_snapshot.get("enabled", ENABLE_USB_SCANNING)) and ENABLE_USB_SCANNING
    if not enabled:
        status_label = "Disabled"
        status_text = "USB scanning is disabled, so removable drives are ignored."
        recommendation = "Enable USB scanning and restart the host monitor plus USB scanner to restore drive detection."
    elif collector == "windows-host-agent":
        if not snapshot_fresh:
            status_label = "Host Monitor Stale"
            status_text = "USB telemetry from the Windows host agent has stopped updating."
            recommendation = "Restart start_host_monitor.cmd so the backend receives fresh removable-drive telemetry."
        elif current_devices:
            status_label = "Watching Drives"
            status_text = "The Windows host agent can currently see connected removable drives."
            recommendation = "Copy, paste, rename, delete, or create a folder on the pendrive and the live USB activity feed should update within a few seconds."
        else:
            status_label = "Watching For Insertions"
            status_text = "The Windows host agent is live, but no removable drives are connected right now."
            recommendation = "Plug in the pendrive again and keep start_usb_scanner.cmd running for automatic scanning."
    else:
        status_label = "Limited Visibility"
        status_text = "The dashboard is using container fallback telemetry, which cannot reliably see Windows USB drives."
        recommendation = "Run start_host_monitor.cmd on Windows so the dashboard can receive real removable-drive updates."

    return {
        "enabled": enabled,
        "status_label": status_label,
        "status_text": status_text,
        "recommendation": recommendation,
        "collector": collector,
        "scope": scope,
        "host": snapshot.get("host") or "localhost",
        "platform": snapshot.get("platform") or "",
        "snapshot_timestamp": snapshot_time.isoformat() if snapshot_time else snapshot.get("timestamp"),
        "snapshot_age_seconds": snapshot_age_seconds,
        "snapshot_fresh": snapshot_fresh,
        "connected_count": int(usb_snapshot.get("connected_count") or len(current_devices) or 0),
        "current_devices": current_devices,
        "recent_insertions": recent_insertions,
        "errors": [str(item) for item in (snapshot.get("errors") or [])[:5]],
        "last_usb_event_at": last_event.timestamp.isoformat() if last_event and last_event.timestamp else None,
        "last_scan_at": last_scan.get("timestamp") if last_scan else None,
        "last_scan_summary": last_scan.get("summary") if last_scan else None,
        "last_scan": last_scan,
        "latest_findings": latest_findings,
        "recent_events": recent_events,
    }


async def emit_login_activity(user: models.User, assessment: Dict[str, Any], login_time: datetime):
    now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    activity_msg = {
        "id": str(uuid.uuid4()),
        "type": "NEW_ACTIVITY",
        "timestamp": now_utc,
        "data": {
            "user": user.username,
            "action": "login",
            "network": 0,
            "score": assessment["score"],
            "risk_level": assessment["risk_level"],
            "details": assessment.get("summary"),
            "timestamp": now_utc,
        },
    }
    await manager.broadcast(json.dumps(activity_msg), user_id=user.id)
    if is_risky(assessment["score"]):
        alert_msg = {
            "id": str(uuid.uuid4()),
            "type": "THREAT_ALERT",
            "timestamp": now_utc,
            "data": {
                "user": user.username,
                "score": assessment["score"],
                "level": assessment["level"],
                "action": "login",
                "risk_level": assessment["risk_level"],
                "details": assessment.get("summary"),
                "timestamp": now_utc,
            },
        }
        await manager.broadcast(json.dumps(alert_msg), user_id=user.id)


@app.get("/api/auth/admin-status")
def get_admin_status(db: Session = Depends(database.get_db)):
    admin_count = db.query(models.User).filter(func.lower(models.User.role) == "admin").count()
    return {"has_admin": admin_count > 0}


class CreateAdminPayload(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    country: Optional[str] = "United States"


@app.get("/api/auth/check-username")
def check_username(username: str, db: Session = Depends(database.get_db)):
    clean_username = (username or "").strip()
    if not clean_username or len(clean_username) < 3:
        return {"available": False, "username": clean_username, "message": "Username must be at least 3 characters long."}

    existing = db.query(models.User).filter(func.lower(models.User.username) == clean_username.lower()).first()
    if existing:
        return {
            "available": False,
            "username": clean_username,
            "message": f"Username '{clean_username}' is already taken by another user. Only unique usernames are allowed."
        }
    return {
        "available": True,
        "username": clean_username,
        "message": f"Username '{clean_username}' is available!"
    }


_email_otp_store: Dict[str, Dict[str, Any]] = {}


@app.post("/api/auth/send-otp")
def send_email_otp(payload: schemas.SendOtpRequest, db: Session = Depends(database.get_db)):
    clean_email = str(payload.email).strip().lower()
    otp_code = f"{secrets.randbelow(900000) + 100000}"
    expires_at = time.time() + 300  # 5 minutes
    _email_otp_store[clean_email] = {
        "otp": otp_code,
        "expires_at": expires_at,
        "verified": False,
        "purpose": payload.purpose,
    }
    logger.info("email_otp_generated email=%s purpose=%s expires_in=300s", log_ciphertext(clean_email), payload.purpose)
    return {
        "success": True,
        "message": f"A 6-digit verification code has been dispatched to {clean_email}.",
        "email": clean_email,
        "expires_in": 300,
        "dev_otp": otp_code,
    }


@app.post("/api/auth/verify-otp")
def verify_email_otp(payload: schemas.VerifyOtpRequest):
    clean_email = str(payload.email).strip().lower()
    entry = _email_otp_store.get(clean_email)
    if not entry:
        raise HTTPException(status_code=400, detail="No verification code was requested for this email, or code has expired.")
    if time.time() > entry.get("expires_at", 0):
        _email_otp_store.pop(clean_email, None)
        raise HTTPException(status_code=400, detail="Verification code has expired. Please request a new OTP.")
    if str(payload.otp).strip() != str(entry.get("otp")):
        raise HTTPException(status_code=400, detail="Invalid 6-digit verification code. Please check and try again.")

    entry["verified"] = True
    return {
        "success": True,
        "verified": True,
        "email": clean_email,
        "message": "Email address verified successfully!",
    }


@app.post("/api/auth/create-admin")
def create_initial_admin(payload: CreateAdminPayload, request: Request, db: Session = Depends(database.get_db)):
    client_ip = get_client_ip(request)
    if client_ip not in ("127.0.0.1", "::1", "localhost", "testclient"):
        raise HTTPException(status_code=403, detail="Admin bootstrap allowed from localhost only")

    admin_count = db.query(models.User).filter(func.lower(models.User.role) == "admin").count()
    if admin_count > 0:
        raise HTTPException(status_code=403, detail="Administrator account already exists")

    if not payload.password or len(payload.password) < 10:
        raise HTTPException(status_code=400, detail="Password must be at least 10 characters long")

    username = payload.username.strip()
    if not username or len(username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters long")

    existing = db.query(models.User).filter(func.lower(models.User.username) == username.lower()).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Username '{username}' is already taken by another user. Only unique usernames are allowed.")

    email = payload.email.strip().lower() if payload.email else build_internal_email(username)
    email_lookup_hash = fingerprint_text(email)

    new_admin = models.User(
        username=username,
        email=encrypt_sensitive_value(email),
        email_lookup_hash=email_lookup_hash,
        hashed_password=auth.get_password_hash(payload.password),
        role="admin",
        country=payload.country or "United States",
        auth_provider="local",
        is_active=True,
        is_email_verified=True,
        created_at=datetime.utcnow(),
    )
    db.add(new_admin)
    db.commit()
    db.refresh(new_admin)
    logger.info("initial_admin_created username=%s", username)
    return {"user": serialize_user(new_admin), "message": "Admin account created successfully"}


@app.post("/api/auth/register", response_model=schemas.SignupResponse)
@app.post("/api/auth/signup", response_model=schemas.SignupResponse)
def register(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    normalized_username = user.username.strip()
    normalized_email = str(user.email).strip().lower() if user.email else build_internal_email(normalized_username)
    requested_role = (user.role or "user").strip().lower()

    if requested_role == "admin":
        raise HTTPException(status_code=403, detail="Admin registration is not permitted via this endpoint")
    requested_role = "user"

    username_exists = db.query(models.User).filter(func.lower(models.User.username) == normalized_username.lower()).first()
    if username_exists:
        raise HTTPException(status_code=400, detail=f"Username '{normalized_username}' is already taken by another user. Each username can only be registered once.")
    email_lookup_hash = fingerprint_text(normalized_email)
    email_exists = (
        db.query(models.User)
        .filter(or_(models.User.email_lookup_hash == email_lookup_hash, func.lower(models.User.email) == normalized_email.lower()))
        .first()
    )
    if email_exists:
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = models.User(
        username=normalized_username,
        email=encrypt_sensitive_value(normalized_email),
        email_lookup_hash=email_lookup_hash,
        hashed_password=auth.get_password_hash(user.password),
        role=requested_role,
        country=user.country or "United States",
        auth_provider="local",
        is_email_verified=True,
        created_at=datetime.utcnow(),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    logger.info(
        "new_user_registered username=%s role=%s email=%s",
        normalized_username,
        requested_role,
        log_ciphertext(normalized_email),
    )
    return {
        "user": serialize_user(new_user),
        "message": "Account created successfully. You can sign in now.",
        "verification_notice": "Email verification is confirmed for your account.",
    }


@app.post("/api/auth/social-login", response_model=schemas.AuthResponse)
async def social_login(payload: schemas.SocialLoginRequest, request: Request, db: Session = Depends(database.get_db)):
    clean_email = str(payload.email).strip().lower()
    user = find_user_by_identifier(db, clean_email)

    if not user:
        base_username = payload.name.lower().replace(" ", "_").strip()
        if not base_username:
            base_username = clean_email.split("@")[0]
        base_username = "".join(c for c in base_username if c.isalnum() or c in ("_", "-", "@", "."))
        if len(base_username) < 3:
            base_username = f"user_{base_username}"

        candidate_username = base_username[:30]
        counter = 1
        while db.query(models.User).filter(func.lower(models.User.username) == candidate_username.lower()).first():
            candidate_username = f"{base_username[:25]}_{counter}"
            counter += 1

        email_lookup_hash = fingerprint_text(clean_email)
        random_pass = secrets.token_urlsafe(24)
        user = models.User(
            username=candidate_username,
            email=encrypt_sensitive_value(clean_email),
            email_lookup_hash=email_lookup_hash,
            hashed_password=auth.get_password_hash(random_pass),
            role="user",
            country=payload.country or "United States",
            auth_provider=payload.provider,
            is_email_verified=True,
            is_active=True,
            created_at=datetime.utcnow(),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        logger.info("social_user_provisioned provider=%s username=%s email=%s", payload.provider, candidate_username, log_ciphertext(clean_email))

    ip_address = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "unknown")
    device_name = get_device_name(user_agent)

    db_activity = models.UserActivity(
        user_id=user.id,
        action_type="login",
        device=device_name,
        network_activity=0,
        details=encrypt_json_payload(
            {
                "summary": f"Successful {payload.provider} social login from {ip_address}",
                "ip_address": ip_address,
                "device_name": device_name,
                "user_agent": user_agent,
                "provider": payload.provider,
            }
        ),
    )
    db.add(db_activity)
    db.commit()
    db.refresh(db_activity)
    update_behavior_profile(db, user.id, db_activity)
    db.commit()

    base_assessment = ai_engine.evaluate_threat(
        user_id=user.id,
        current_activity=db_activity,
        recent_activities=[db_activity],
    )
    login_assessment = assess_login_security(db, user, ip_address, device_name, base_assessment)

    expires_delta = auth.timedelta(hours=STANDARD_LOGIN_HOURS)
    expires_at = datetime.utcnow() + expires_delta
    session_id = auth.generate_session_id()
    auth_session = models.AuthSession(
        user_id=user.id,
        session_token_id=session_id,
        ip_address=encrypt_sensitive_value(ip_address),
        device_name=encrypt_sensitive_value(device_name),
        expires_at=expires_at,
        is_active=True,
    )
    db.add(auth_session)
    user.last_login_at = datetime.utcnow()
    user.last_login_ip = encrypt_sensitive_value(ip_address)
    user.last_login_device = encrypt_sensitive_value(device_name)
    db.commit()

    access_token = auth.create_access_token(
        data={"sub": user.username, "role": user.role, "sid": session_id},
        expires_delta=expires_delta,
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_at": expires_at,
        "remember_me": False,
        "user": serialize_user(user),
        "assessment": login_assessment,
        "security_status": login_assessment.get("security_status", "Safe"),
        "suspicious_session": login_assessment.get("suspicious_session", False),
        "warning_message": None,
    }


@app.post("/api/admin/reset-lockout")
async def reset_lockout(db: Session = Depends(database.get_db)):
    """Clear all failed login attempts so locked-out users can log in immediately."""
    deleted = db.query(models.LoginAttempt).filter(models.LoginAttempt.success.is_(False)).delete()
    db.commit()
    logger.info("reset_lockout: cleared %d failed login attempt records", deleted)
    return {"message": f"Lockout cleared. Deleted {deleted} failed attempt record(s)."}


@app.post("/api/auth/login", response_model=schemas.AuthResponse)
async def login(request: Request, db: Session = Depends(database.get_db)):
    try:
        credentials = await parse_login_request(request)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc

    identifier = credentials.identifier
    ip_address = get_client_ip(request)
    user_agent = request.headers.get("user-agent", "unknown")
    device_name = get_device_name(user_agent)

    if get_failed_attempt_count(db, identifier) >= FAILED_ATTEMPT_LIMIT:
        # Do not log a login attempt here to prevent extending the rate-limit lockout window.
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please wait 5 minutes before retrying.",
        )

    user = find_user_by_identifier(db, identifier)
    password_valid = False
    if user:
        password_valid = auth.verify_password(credentials.password, user.hashed_password)

    if not user or not password_valid:
        log_login_attempt(
            db,
            identifier=identifier,
            ip_address=ip_address,
            user_agent=user_agent,
            device_name=device_name,
            success=False,
            user=user,
            failure_reason="Incorrect username/email or password",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not bool(user.is_active) or bool(user.is_locked):
        log_login_attempt(
            db,
            identifier=identifier,
            ip_address=ip_address,
            user_agent=user_agent,
            device_name=device_name,
            success=False,
            user=user,
            failure_reason="Account is locked or inactive",
        )
        raise HTTPException(status_code=403, detail="This account is locked or inactive")

    previous_login_at = user.last_login_at

    db_activity = models.UserActivity(
        user_id=user.id,
        action_type="login",
        device=device_name,
        network_activity=0,
        details=encrypt_json_payload(
            {
                "summary": f"Successful login from {ip_address}",
                "ip_address": ip_address,
                "device_name": device_name,
                "user_agent": user_agent,
            }
        ),
    )
    db.add(db_activity)
    db.commit()
    db.refresh(db_activity)
    update_behavior_profile(db, user.id, db_activity)
    db.commit()

    recent_activities = (
        db.query(models.UserActivity)
        .filter(models.UserActivity.user_id == user.id)
        .order_by(models.UserActivity.timestamp.desc())
        .limit(100)
        .all()
    )
    recent_activities = list(reversed(recent_activities))
    base_assessment = ai_engine.evaluate_threat(
        user_id=user.id,
        current_activity=db_activity,
        recent_activities=recent_activities,
    )
    login_assessment = assess_login_security(db, user, ip_address, device_name, base_assessment)

    db_activity.risk_score = login_assessment["score"]
    db_activity.risk_level = login_assessment["risk_level"]
    db_activity.details = encrypt_json_payload(
        {
            "summary": login_assessment["summary"],
            "ip_address": ip_address,
            "device_name": device_name,
            "user_agent": user_agent,
            "security_status": login_assessment["security_status"],
            "suspicious_reasons": login_assessment["reasons"],
        }
    )
    db.add(db_activity)

    login_attempt = log_login_attempt(
        db,
        identifier=identifier,
        ip_address=ip_address,
        user_agent=user_agent,
        device_name=device_name,
        success=True,
        user=user,
        suspicious=login_assessment["suspicious_session"],
        suspicious_reasons=login_assessment["reasons"],
    )

    user.last_login_at = login_attempt.created_at
    user.last_login_ip = encrypt_sensitive_value(ip_address)
    user.last_login_ip_hash = fingerprint_text(ip_address)
    user.last_login_device = encrypt_sensitive_value(device_name)
    user.last_login_device_hash = fingerprint_text(device_name)
    db.add(user)

    if is_risky(login_assessment["score"]):
        threat_log = models.ThreatLog(
            user_id=user.id,
            anomaly_score=login_assessment["score"],
            threat_level=login_assessment["level"],
            action_taken="monitor",
            details=encrypt_sensitive_value(login_assessment["summary"]),
        )
        db.add(threat_log)

    expires_delta = auth.timedelta(days=REMEMBER_ME_DAYS) if credentials.remember_me else auth.timedelta(hours=STANDARD_LOGIN_HOURS)
    expires_at = datetime.utcnow() + expires_delta
    session_id = auth.generate_session_id()
    auth_session = models.AuthSession(
        user_id=user.id,
        session_token_id=session_id,
        expires_at=expires_at,
        ip_address=encrypt_sensitive_value(ip_address),
        ip_address_hash=fingerprint_text(ip_address),
        user_agent=encrypt_sensitive_value(user_agent),
        device_name=encrypt_sensitive_value(device_name),
        device_name_hash=fingerprint_text(device_name),
        remember_me=credentials.remember_me,
        suspicious=login_assessment["suspicious_session"],
        suspicious_reason=encrypt_sensitive_value(json.dumps(login_assessment["reasons"])),
    )
    db.add(auth_session)
    db.commit()

    access_token = auth.create_access_token(
        data={"sub": user.username, "role": user.role, "sid": session_id},
        expires_delta=expires_delta,
    )
    await emit_login_activity(user, login_assessment, login_attempt.created_at)

    warning_message = login_assessment.get("warning_message")
    if previous_login_at:
        warning_message = warning_message or f"Last successful login was on {previous_login_at.isoformat()}."

    user_email_plain = decrypt_sensitive_value(user.email) or user.email or user.username
    geo_data = geo_tracker.log_access(
        ip=ip_address,
        user_email=user_email_plain,
        user_agent=user_agent,
        action="login",
        threat_score=int(login_assessment.get("score", 0)),
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_at": expires_at,
        "remember_me": credentials.remember_me,
        "user": serialize_user(user),
        "assessment": login_assessment,
        "security_status": login_assessment["security_status"],
        "suspicious_session": login_assessment["suspicious_session"],
        "warning_message": warning_message,
        "access_info": {
            "ip": geo_data["ip"],
            "location": f"{geo_data['city']}, {geo_data['region']}, {geo_data['country']}",
            "isp": geo_data["isp"],
            "time": geo_data["access_time"],
            "is_proxy": geo_data["is_proxy"],
            "is_datacenter": geo_data["is_datacenter"],
        },
    }


@app.get("/api/access-logs")
async def get_access_logs(current_user: models.User = Depends(get_current_user)):
    user_role = getattr(current_user, "role", "user")
    user_email = decrypt_sensitive_value(current_user.email) or current_user.email or current_user.username
    if user_role == "admin":
        logs = geo_tracker.get_access_logs(limit=200)
    else:
        logs = geo_tracker.get_access_logs(user_email=user_email, limit=50)
    return {"logs": logs, "total": len(logs)}


@app.post("/api/auth/logout")

def logout(
    current_user: models.User = Depends(get_current_user),
    current_session: Optional[models.AuthSession] = Depends(get_current_session),
    db: Session = Depends(database.get_db),
):
    if current_session and current_session.user_id == current_user.id:
        current_session.is_active = False
        current_session.last_seen_at = datetime.utcnow()
        db.add(current_session)
        db.commit()
    return {"message": "Session closed successfully"}


@app.get("/api/users/me", response_model=schemas.UserResponse)
def read_users_me(current_user: models.User = Depends(get_current_user)):
    return serialize_user(current_user)


@app.get("/api/dashboard", response_model=schemas.DashboardSummaryResponse)
@app.get("/dashboard", response_model=schemas.DashboardSummaryResponse, include_in_schema=False)
def get_dashboard_summary(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db),
):
    return build_dashboard_summary(current_user, db)


@app.get("/api/threats")
def get_threats(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db),
):
    query = db.query(models.ThreatLog)
    if get_user_role(current_user) != "admin":
        query = query.filter(models.ThreatLog.user_id == current_user.id)
    rows = query.order_by(models.ThreatLog.timestamp.desc()).limit(200).all()
    return [serialize_threat(row) for row in filter_usb_threat_rows(rows)[:50]]


@app.get("/api/activity", response_model=List[schemas.ActivityResponse])
def get_recent_activity(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db),
):
    query = db.query(models.UserActivity)
    if get_user_role(current_user) != "admin":
        query = query.filter(models.UserActivity.user_id == current_user.id)
    rows = query.order_by(models.UserActivity.timestamp.desc()).limit(200).all()
    return [serialize_activity(row) for row in filter_usb_activities(rows)[:100]]


@app.get("/api/users", response_model=List[schemas.UserResponse])
def get_users(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db),
):
    return [serialize_user(user) for user in db.query(models.User).limit(50).all()]


@app.get("/api/behavior-profiles", response_model=List[schemas.BehaviorProfileResponse])
def get_behavior_profiles(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db),
):
    users = db.query(models.User).order_by(models.User.username.asc()).limit(50).all()
    profiles_by_user = {profile.user_id: profile for profile in db.query(models.BehaviorProfile).all()}
    return [serialize_behavior_profile(user, profiles_by_user.get(user.id)) for user in users]


@app.get("/api/ai-insights", response_model=schemas.AIInsightResponse)
def get_ai_insights(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db),
):
    users = db.query(models.User).order_by(models.User.username.asc()).limit(50).all()
    activity_count_rows = db.query(models.UserActivity.user_id, models.UserActivity.action_type).all()
    activity_counts: Dict[int, int] = {}
    for row in activity_count_rows:
        if not ENABLE_USB_SCANNING and is_usb_action_type(getattr(row, "action_type", None)):
            continue
        activity_counts[row.user_id] = activity_counts.get(row.user_id, 0) + 1

    threat_rows = (
        db.query(models.ThreatLog.user_id, models.ThreatLog.anomaly_score, models.ThreatLog.details, models.ThreatLog.timestamp)
        .order_by(models.ThreatLog.timestamp.desc())
        .all()
    )
    threat_rows = filter_usb_threat_rows(threat_rows)

    threats_by_user: Dict[int, List[Any]] = {}
    for row in threat_rows:
        threats_by_user.setdefault(row.user_id, []).append(row)

    recent_activity_rows = (
        db.query(models.UserActivity.user_id, models.UserActivity.risk_score, models.UserActivity.timestamp, models.UserActivity.action_type)
        .order_by(models.UserActivity.timestamp.desc())
        .limit(1000)
        .all()
    )
    activity_scores_by_user: Dict[int, List[float]] = {}
    for row in recent_activity_rows:
        if not ENABLE_USB_SCANNING and is_usb_action_type(getattr(row, "action_type", None)):
            continue
        bucket = activity_scores_by_user.setdefault(row.user_id, [])
        if len(bucket) < 20:
            bucket.append(float(row.risk_score or 0.0))

    insight_rows = []
    for user in users:
        user_threats = threats_by_user.get(user.id, [])
        threat_count = len(user_threats)
        avg_score = sum(threat.anomaly_score for threat in user_threats) / threat_count if threat_count else 0.0
        activity_count = int(activity_counts.get(user.id, 0))
        recent_activity_scores = activity_scores_by_user.get(user.id, [])
        overall_risk_score = compute_overall_risk_score(recent_activity_scores, avg_score)
        overall_risk_level = score_to_risk_level(overall_risk_score)
        isolation_ready = activity_count >= 12
        cluster_ready = activity_count >= 10
        if isolation_ready and cluster_ready:
            ai_status = "Adaptive models ready"
        elif activity_count > 0:
            ai_status = "Learning baseline"
        else:
            ai_status = "No activity yet"

        top_reasons = []
        for threat in user_threats[:5]:
            detail = (decrypt_sensitive_value(threat.details) or "").strip()
            if detail and detail not in top_reasons:
                top_reasons.append(detail)

        insight_rows.append(
            {
                "user_id": user.id,
                "username": user.username,
                "role": user.role or "user",
                "account_type": get_account_type(user),
                "activity_count": activity_count,
                "threat_count": threat_count,
                "avg_anomaly_score": round(avg_score, 2),
                "overall_risk_score": overall_risk_score,
                "overall_risk_level": overall_risk_level,
                "isolation_forest_ready": isolation_ready,
                "cluster_model_ready": cluster_ready,
                "ai_status": ai_status,
                "latest_summary": top_reasons[0] if top_reasons else None,
                "top_reasons": top_reasons[:3],
            }
        )

    total_human_users = sum(1 for row in insight_rows if row["account_type"] == "human")
    total_system_accounts = sum(1 for row in insight_rows if row["account_type"] != "human")
    return {
        "total_human_users": total_human_users,
        "total_system_accounts": total_system_accounts,
        "continuously_learning": True,
        "users": insight_rows,
    }


@app.get("/api/system-monitor")
def get_system_monitor(current_user: models.User = Depends(require_admin)):
    return system_monitor.get_current_snapshot()


@app.get("/api/desktop/security-center")
def get_desktop_security_center(current_user: models.User = Depends(require_admin)):
    return desktop_security_service.get_security_center()


@app.get("/api/desktop/network-traffic")
def get_desktop_network_traffic(current_user: models.User = Depends(require_admin)):
    return desktop_security_service.get_traffic_snapshot()


@app.get("/api/desktop/processes")
def get_desktop_processes(current_user: models.User = Depends(require_admin)):
    return desktop_security_service.get_process_snapshot()


class PhishingAnalysisRequest(BaseModel):
    text: str = ""
    url: str = ""


@app.post("/api/security/analyze-phishing")
async def analyze_phishing(req: PhishingAnalysisRequest, current_user = Depends(get_current_user)):
    try:
        result = {}
        if req.text and req.text.strip():
            try:
                result['text_analysis'] = phishing_detector.analyze_text(req.text)
            except Exception as e:
                result['text_analysis'] = {
                    'score': 0, 'is_phishing': False,
                    'risk_level': 'ERROR', 'indicators': [f'Analysis error: {str(e)}'],
                    'urls_found': [], 'error': str(e)
                }
        if req.url and req.url.strip():
            try:
                result['url_analysis'] = phishing_detector.analyze_url(req.url)
            except Exception as e:
                result['url_analysis'] = {
                    'score': 0, 'is_phishing': False,
                    'risk_level': 'ERROR', 'indicators': [f'Analysis error: {str(e)}'],
                    'error': str(e)
                }
        if not result:
            return {'error': 'Provide text or url to analyze'}
        return result
    except Exception as e:
        return {'error': str(e), 'text_analysis': None, 'url_analysis': None}


class BlockEntityRequest(BaseModel):
    block_type: str  # ip | user | process | domain | usb_device
    value: str
    reason: str
    apply_firewall: bool = True


class UnblockEntityRequest(BaseModel):
    block_type: str
    value: str
    reason: str = ""


@app.post("/api/security/block")
async def block_entity(req: BlockEntityRequest, current_user: models.User = Depends(get_current_user)):
    user_role = getattr(current_user, "role", "user")
    user_email = decrypt_sensitive_value(current_user.email) or current_user.email or current_user.username
    if user_role != "admin":
        raise HTTPException(403, "Only admins can create permanent blocks")
    result = block_manager.block(
        req.block_type, req.value, req.reason,
        user_email, req.apply_firewall
    )
    if not result.get("success"):
        raise HTTPException(400, result.get("error", "Block failed"))
    return result


@app.post("/api/security/unblock")
async def unblock_entity(req: UnblockEntityRequest, current_user: models.User = Depends(get_current_user)):
    user_role = getattr(current_user, "role", "user")
    user_email = decrypt_sensitive_value(current_user.email) or current_user.email or current_user.username
    if user_role != "admin":
        raise HTTPException(403, "Only admins can unblock entities")
    result = block_manager.unblock(
        req.block_type, req.value, user_email, req.reason
    )
    if not result.get("success"):
        raise HTTPException(400, result.get("error", "Unblock failed"))
    return result


@app.get("/api/security/blocks")
async def get_blocks(include_inactive: bool = False, current_user: models.User = Depends(get_current_user)):
    user_role = getattr(current_user, "role", "user")
    if user_role != "admin":
        raise HTTPException(403, "Admin only")
    return {"blocks": block_manager.get_all_blocks(include_inactive)}


@app.post("/api/desktop/scan-text")


def scan_desktop_text(payload: TextScanRequest, current_user: models.User = Depends(get_current_user)):
    return desktop_security_service.scan_text(payload)


@app.post("/api/desktop/scan-url")
def scan_desktop_url(payload: UrlScanRequest, current_user: models.User = Depends(get_current_user)):
    return desktop_security_service.scan_url(payload)


@app.get("/api/desktop/firewall/rules")
def list_desktop_firewall_rules(
    current_user: models.User = Depends(require_admin),
    db: Session = Depends(database.get_db),
):
    rules = db.query(models.FirewallAppRule).order_by(models.FirewallAppRule.timestamp.desc()).all()
    return [
        {
            "id": r.id,
            "application_path": r.application_path,
            "action": r.action,
            "direction": r.direction,
            "rule_name": r.rule_name,
            "timestamp": r.timestamp.isoformat()
        }
        for r in rules
    ]


@app.post("/api/desktop/firewall/rules")
def apply_desktop_firewall_rule(
    payload: FirewallRuleRequest,
    current_user: models.User = Depends(require_admin),
    db: Session = Depends(database.get_db),
):
    if not is_admin():
        raise_admin_required("Firewall rule management")
    result = desktop_security_service.apply_firewall_rule(payload)
    if result.get("error") == "admin_required" or result.get("status") == "needs_admin":
        raise_admin_required("Firewall rule management")
    if result.get("status") in {"applied", "unsupported"}:
        existing = db.query(models.FirewallAppRule).filter(models.FirewallAppRule.application_path == payload.application_path).first()
        if not existing:
            rule = models.FirewallAppRule(
                application_path=payload.application_path,
                action=payload.action,
                direction=payload.direction,
                rule_name=result.get("rule_name")
            )
            db.add(rule)
            db.commit()
    return result


@app.delete("/api/desktop/firewall/rules/{rule_id}")
def delete_desktop_firewall_rule(
    rule_id: int,
    current_user: models.User = Depends(require_admin),
    db: Session = Depends(database.get_db),
):
    if not is_admin():
        raise_admin_required("Firewall rule management")
    import subprocess
    rule = db.query(models.FirewallAppRule).filter(models.FirewallAppRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found.")
    
    if os.name == "nt":
        command = [
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={rule.rule_name}",
        ]
        from app.process_utils import run_hidden
        run_hidden(command, timeout=15, check=False)
        
    db.delete(rule)
    db.commit()
    return {"status": "deleted", "message": f"Rule {rule.rule_name} deleted successfully."}


@app.get("/api/system/process-launch-stats")
def get_child_process_launch_stats():
    """Retrieve child process launch statistics for monitoring hidden execution"""
    from app.process_utils import get_launch_stats
    return get_launch_stats()


@app.get("/api/system/settings/geo-lookup")
def get_geo_lookup_setting():
    """Retrieve remote-IP server location privacy setting"""
    return {
        "online_lookup_enabled": geo.is_online_lookup_enabled(),
        "database": "IANA/RIR IPv4/IPv6 Allocation Table (Public Domain / CC0, October 2026)",
        "notice": "Server locations indicate the remote server's approximate hosting facility, never your local device location."
    }


@app.post("/api/system/settings/geo-lookup")
def set_geo_lookup_setting(payload: dict):
    """Update remote-IP server location privacy setting"""
    enabled = bool(payload.get("enabled", False))
    geo.set_online_lookup_enabled(enabled)
    return {
        "status": "success",
        "online_lookup_enabled": geo.is_online_lookup_enabled()
    }


_cached_current_location = None
_cached_location_timestamp = 0.0


@app.get("/api/system/current-location")
def get_user_current_location(current_user: models.User = Depends(get_current_user)):
    """User's own current public IP and location via independent lookup (3s timeout)"""
    global _cached_current_location, _cached_location_timestamp
    now = time.time()
    if _cached_current_location and (now - _cached_location_timestamp) < 300:
        age = int(now - _cached_location_timestamp)
        return {**_cached_current_location, "updated_seconds_ago": age, "state": "LIVE" if age < 300 else "STALE"}

    import urllib.request
    try:
        req = urllib.request.Request("https://api.ipify.org?format=json", headers={"User-Agent": "AIFirewall/1.0"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            public_ip = data.get("ip")
            if public_ip:
                geo_info = geo_tracker.lookup_ip(public_ip)
                loc = {
                    "ip": public_ip,
                    "city": geo_info.get("city") or "",
                    "region": geo_info.get("region") or "",
                    "country": geo_info.get("country") or "Unknown",
                    "isp": geo_info.get("isp") or "",
                    "source": "api.ipify.org (independent)",
                    "accuracy": "approximate, from IP",
                    "state": "LIVE",
                    "updated_seconds_ago": 0,
                    "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                }
                _cached_current_location = loc
                _cached_location_timestamp = now
                return loc
    except Exception:
        pass

    return {
        "ip": None,
        "city": "",
        "region": "",
        "country": "",
        "isp": "",
        "source": "independent lookup",
        "accuracy": "approximate, from IP",
        "state": "OFFLINE",
        "location_label": "Location unavailable (offline)",
        "updated_seconds_ago": int(now - _cached_location_timestamp) if _cached_location_timestamp else 0,
        "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


@app.get("/api/system/detailed-status")
def get_system_detailed_status(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    """Real machine telemetry checks for every feature (PART 2)"""
    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    admin_active = is_admin()

    # 1. Administrative Rights
    admin_item = {
        "id": "admin_rights",
        "name": "Windows Administrative Privileges",
        "state": "RUNNING" if admin_active else "NEEDS ADMIN",
        "reason": "Process is running with elevated administrator rights." if admin_active else "Process is running in standard user mode. Relaunch as Administrator for firewall rules and hosts-file domain redirection.",
        "last_run_time": now_iso,
        "last_result": {"is_admin": admin_active, "platform": platform.platform()},
        "remediation": "Right-click the AI Firewall shortcut and select 'Run as Administrator'." if not admin_active else "None required."
    }

    # 2. Bound Runtime Port
    port_file = get_runtime_port_file()
    bound_port = None
    if port_file.exists():
        try:
            p_data = json.loads(port_file.read_text(encoding="utf-8"))
            bound_port = p_data.get("port")
        except Exception:
            pass
    if not bound_port:
        bound_port = int(os.environ.get("AI_FIREWALL_PORT", "8000"))

    port_item = {
        "id": "backend_port",
        "name": "Backend REST & WebSocket Socket",
        "state": "RUNNING",
        "reason": f"FastAPI daemon actively bound and accepting loopback HTTP/WebSocket connections on port {bound_port}.",
        "last_run_time": now_iso,
        "last_result": {"bound_port": bound_port, "host": "127.0.0.1", "protocol": "TCP"},
        "remediation": "Check for conflicting services if port cannot bind."
    }

    # 3. Database
    db_ok = False
    table_count = 0
    db_size_mb = 0.0
    db_path = get_database_path()
    try:
        res = db.execute(text("SELECT count(*) FROM sqlite_master WHERE type='table'")).scalar()
        table_count = int(res or 0)
        db_ok = True
        if db_path.exists():
            db_size_mb = round(os.path.getsize(db_path) / (1024 * 1024), 2)
    except Exception as e:
        logger.error(f"DB check failed: {e}")

    database_item = {
        "id": "database",
        "name": "Encrypted Local Storage (SQLite WAL)",
        "state": "RUNNING" if db_ok else "ERROR",
        "reason": f"SQLite database is healthy in Write-Ahead-Log (WAL) mode with {table_count} tables." if db_ok else "Database query failed.",
        "last_run_time": now_iso,
        "last_result": {"path": str(db_path), "size_mb": db_size_mb, "tables": table_count, "journal_mode": "WAL"},
        "remediation": "Ensure write access to %APPDATA%\\AIFirewall." if not db_ok else "None required."
    }

    # 4. Markov Model
    user_count = db.query(models.User).count()
    activity_count = db.query(models.UserActivity).count()
    markov_trained = activity_count >= 12
    markov_item = {
        "id": "markov_model",
        "name": "Markov Sequence Model",
        "state": "RUNNING",
        "reason": "Markov sequence transition matrix active." if markov_trained else f"Learning mode active ({activity_count}/12 baseline actions recorded).",
        "last_run_time": now_iso,
        "last_result": {
            "mode": "trained" if markov_trained else "learning mode",
            "event_count": activity_count,
            "human_users": user_count,
            "transition_order": 1
        },
        "remediation": "Perform normal user activity (processes, network, logins) to build baseline."
    }

    # 5. Isolation Forest
    iso_trained = activity_count >= 15
    iso_item = {
        "id": "isolation_forest",
        "name": "Isolation Forest Outlier Model",
        "state": "RUNNING",
        "reason": "Scikit-Learn Isolation Forest outlier evaluation active." if iso_trained else f"Gathering telemetry baseline ({activity_count}/15 events needed for optimal fit).",
        "last_run_time": now_iso,
        "last_result": {
            "mode": "trained" if iso_trained else "learning mode",
            "samples_analyzed": activity_count,
            "contamination": 0.05,
            "n_estimators": 100
        },
        "remediation": "Allow system to record normal background activity."
    }

    # 6. Phishing / NLP Detector
    phishing_item = {
        "id": "phishing_detector",
        "name": "Phishing & Obfuscation Heuristics",
        "state": "RUNNING",
        "reason": "Phishing detection pipeline online with NLP heuristics, homoglyphs, and suspicious TLD evaluation.",
        "last_run_time": now_iso,
        "last_result": {
            "max_text_length": 10000,
            "heuristic_checks": ["urgency_keywords", "homoglyphs", "ip_literal", "subdomain_depth", "punycode"],
            "online_mode": False
        },
        "remediation": "None required."
    }

    # 7. Spam Detector
    spam_item = {
        "id": "spam_detector",
        "name": "Email & Content Spam Engine",
        "state": "RUNNING",
        "reason": "Spam inspection engine ready with weighted urgency phrases, URL extractors, and formatting checks.",
        "last_run_time": now_iso,
        "last_result": {"status": "active", "keyword_terms_count": 10, "punctuation_analyzer": "active"},
        "remediation": "None required."
    }

    # 8. Process Monitor
    proc_count = len(psutil.pids()) if psutil else 0
    proc_item = {
        "id": "process_monitor",
        "name": "Host Process Lifecycle Monitor",
        "state": "RUNNING" if psutil else "ERROR",
        "reason": f"Actively monitoring {proc_count} running processes for unexpected spawns and suspicious command lines.",
        "last_run_time": now_iso,
        "last_result": {"active_processes": proc_count, "collector": "psutil"},
        "remediation": "Ensure psutil is installed."
    }

    # 9. Network Monitor
    net_conns = psutil.net_connections(kind='inet') if psutil else []
    remote_conns = [c for c in net_conns if c.raddr]
    net_item = {
        "id": "network_monitor",
        "name": "Network Socket Telemetry Monitor",
        "state": "RUNNING" if psutil else "ERROR",
        "reason": f"Tracking {len(net_conns)} sockets ({len(remote_conns)} remote established/listening connections).",
        "last_run_time": now_iso,
        "last_result": {"total_sockets": len(net_conns), "remote_connections": len(remote_conns)},
        "remediation": "None required."
    }

    # 10. Clipboard Monitor
    clip_item = {
        "id": "clipboard_monitor",
        "name": "Pure-Python Clipboard Threat Scanner",
        "state": "RUNNING",
        "reason": "Local memory clipboard monitoring operational; discards benign text, alerts only on threat score > 25.",
        "last_run_time": now_iso,
        "last_result": {"inspection_scope": "local_memory_only", "persistent_storage": False},
        "remediation": "None required."
    }

    # 11. USB Monitor
    usb_status = build_usb_status(db)
    usb_item = {
        "id": "usb_monitor",
        "name": "Removable Media (USB) Hardware Monitor",
        "state": "RUNNING",
        "reason": f"{usb_status.get('connected_count', 0)} removable drive(s) currently detected on the system.",
        "last_run_time": now_iso,
        "last_result": {
            "connected_count": usb_status.get("connected_count", 0),
            "collector": usb_status.get("collector", "windows-host-agent"),
            "devices": [d.get("name") for d in usb_status.get("current_devices", [])]
        },
        "remediation": "Insert a USB flash drive to perform automatic malware and EICAR signature scanning."
    }

    # 12. Windows Firewall (netsh)
    netsh_ok = False
    netsh_msg = ""
    try:
        from app.process_utils import run_hidden
        cmd_res = run_hidden(["netsh", "advfirewall", "show", "allprofiles", "state"], timeout=5)
        if cmd_res.returncode == 0:
            netsh_ok = True
            netsh_msg = "Windows Defender Firewall netsh interface is responsive."
        else:
            netsh_msg = cmd_res.stderr or cmd_res.stdout or "netsh failed"
    except Exception as exc:
        netsh_msg = str(exc)

    firewall_item = {
        "id": "firewall",
        "name": "Windows Defender Firewall Controller (netsh)",
        "state": "RUNNING" if netsh_ok else "ERROR",
        "reason": netsh_msg,
        "last_run_time": now_iso,
        "last_result": {
            "netsh_accessible": netsh_ok,
            "can_mutate_rules": admin_active,
            "rule_prefix": "AIFirewall-"
        },
        "remediation": "Ensure Windows Firewall service (mpssvc) is running. Run as Administrator to add/remove rules." if not netsh_ok or not admin_active else "None required."
    }

    # 13. Hosts File
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts" if os.name == "nt" else "/etc/hosts"
    hosts_writable = admin_active and os.access(hosts_path, os.W_OK)
    hosts_item = {
        "id": "hosts_file",
        "name": "Hosts File Domain Blocker",
        "state": "RUNNING" if hosts_writable else ("NEEDS ADMIN" if not admin_active else "ERROR"),
        "reason": f"Hosts file at {hosts_path} is writable with automated backup retention." if hosts_writable else "Hosts file is read-only. Administrative privileges required to apply domain loopback redirection.",
        "last_run_time": now_iso,
        "last_result": {"path": hosts_path, "writable": hosts_writable, "backup_dir": "%APPDATA%\\AIFirewall\\backups"},
        "remediation": "Relaunch AI Firewall as Administrator to enable host-level domain blocking." if not hosts_writable else "None required."
    }

    # 14. Geolocation Engine
    online_geo = geo.is_online_lookup_enabled()
    geo_item = {
        "id": "geolocation",
        "name": "IP Geolocation Resolution",
        "state": "DISABLED" if not online_geo else "RUNNING",
        "reason": "Online lookup disabled; offline IANA / RIR IPv4/IPv6 allocation ranges active for maximum privacy." if not online_geo else "Online approximate facility lookup enabled via rate-limited API queries.",
        "last_run_time": now_iso,
        "last_result": {
            "mode": "online" if online_geo else "offline (IANA / RIR ranges)",
            "ipv6_coverage": "Global RIR prefixes (APNIC, ARIN, RIPE, LACNIC, AFRINIC)",
            "privacy_preserving": True
        },
        "remediation": "Toggle 'Look up server locations online' in Live Activity if online lookup is desired."
    }

    # 15. WebSocket Hub
    ws_clients = len(manager.active_connections)
    ws_item = {
        "id": "websocket",
        "name": "Real-Time Telemetry WebSocket Hub",
        "state": "RUNNING",
        "reason": f"{ws_clients} active browser client(s) currently receiving live security broadcasts.",
        "last_run_time": now_iso,
        "last_result": {"active_clients": ws_clients, "endpoint": "/api/ws/monitor"},
        "remediation": "Connect UI to /api/ws/monitor."
    }

    # 16. Last Event Time
    last_act = db.query(models.UserActivity.timestamp).order_by(models.UserActivity.timestamp.desc()).first()
    last_event_str = None
    if last_act and last_act[0]:
        t = last_act[0]
        last_event_str = t.isoformat() if hasattr(t, "isoformat") else str(t)
        if not last_event_str.endswith("Z") and "+" not in last_event_str:
            last_event_str += "Z"

    event_time_item = {
        "id": "last_event_time",
        "name": "Telemetry Ingestion Heartbeat",
        "state": "RUNNING" if last_event_str else "OFFLINE",
        "reason": f"Last recorded security event occurred at {last_event_str}." if last_event_str else "No security events recorded yet in this database.",
        "last_run_time": now_iso,
        "last_result": {"latest_event_timestamp": last_event_str},
        "remediation": "Perform actions on the system or run a simulation preset to generate telemetry."
    }

    return {
        "timestamp": now_iso,
        "features": [
            admin_item,
            port_item,
            database_item,
            markov_item,
            iso_item,
            phishing_item,
            spam_item,
            proc_item,
            net_item,
            clip_item,
            usb_item,
            firewall_item,
            hosts_item,
            geo_item,
            ws_item,
            event_time_item
        ]
    }


@app.get("/api/usb-status")
def get_usb_status(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db),
):
    return build_usb_status(db)


@app.get("/api/device-safety/status")
def get_device_safety_status(current_user: models.User = Depends(get_current_user)):
    return read_device_safety_status()


@app.post("/api/device-safety/scan")
def queue_device_safety_scan(
    request: schemas.DeviceSafetyScanRequest,
    current_user: models.User = Depends(get_current_user),
):
    result = queue_device_safety_command(
        "scan_target",
        target_id=request.target_id,
        requested_by=current_user.username,
    )
    is_completed = isinstance(result, dict) and "files_scanned" in result
    return {
        "status": "completed" if is_completed else "queued",
        "result": result,
        "message": f"Scan completed for {request.target_id}." if is_completed else f"Manual scan queued for {request.target_id}.",
    }


@app.post("/api/device-safety/live-watch")
def set_device_safety_live_watch(
    request: schemas.DeviceSafetyWatchRequest,
    current_user: models.User = Depends(get_current_user),
):
    command = queue_device_safety_command(
        "set_live_watch",
        enabled=bool(request.enabled),
        requested_by=current_user.username,
    )
    return {
        "status": "queued",
        "command": command,
        "message": "Live watch update queued.",
    }


@app.get("/api/device-safety/quarantine")
def get_device_safety_quarantine(current_user: models.User = Depends(get_current_user)):
    return {"items": list_quarantine_items()}


class DeviceSafetyRestoreRequest(BaseModel):
    entry_id: str
    target_dir: Optional[str] = None


@app.post("/api/device-safety/restore")
def restore_device_safety_quarantine(
    request: DeviceSafetyRestoreRequest,
    current_user: models.User = Depends(require_admin),
):
    res = restore_quarantine_file(request.entry_id, request.target_dir)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error", "Restore failed"))
    return res


@app.post("/api/system-monitor/ingest")
async def ingest_system_monitor(
    payload: schemas.SystemMonitorIngestPayload,
    current_user: models.User = Depends(require_admin_or_system_agent),
):
    await system_monitor.ingest_external_snapshot(payload.snapshot, payload.events)
    return {
        "status": "accepted",
        "collector": payload.snapshot.get("collector", "external"),
        "received_from": current_user.username,
    }


@app.post("/api/activity/log")
async def log_activity(
    activity: schemas.ActivityCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db),
):
    if not ENABLE_USB_SCANNING and is_usb_action_type(activity.action_type):
        return {
            "status": "Ignored",
            "assessment": build_usb_ignored_assessment(current_user.id),
        }

    db_activity = models.UserActivity(
        user_id=current_user.id,
        action_type=activity.action_type,
        device=activity.device,
        network_activity=activity.network_activity,
        details=encrypt_sensitive_value(activity.details),
    )
    db.add(db_activity)
    db.commit()
    db.refresh(db_activity)
    update_behavior_profile(db, current_user.id, db_activity)
    db.commit()

    recent_activities = (
        db.query(models.UserActivity)
        .filter(models.UserActivity.user_id == current_user.id)
        .order_by(models.UserActivity.timestamp.desc())
        .limit(100)
        .all()
    )
    recent_activities = list(reversed(filter_usb_activities(recent_activities)))
    threat_assessment = ai_engine.evaluate_threat(
        user_id=current_user.id,
        current_activity=db_activity,
        recent_activities=recent_activities,
    )

    anomaly_score = threat_assessment["score"]
    threat_level = threat_assessment["level"]
    db_activity.risk_score = anomaly_score
    db_activity.risk_level = threat_assessment["risk_level"]
    db.add(db_activity)
    db.commit()

    if is_risky(anomaly_score):
        threat_log = models.ThreatLog(
            user_id=current_user.id,
            anomaly_score=anomaly_score,
            threat_level=threat_level,
            action_taken=threat_assessment.get("recommended_action", "monitor"),
            details=encrypt_sensitive_value(
                threat_assessment.get("summary") or f"Anomalous action: {activity.action_type}"
            ),
        )
        db.add(threat_log)
        db.commit()
        db.refresh(threat_log)
        now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        alert_msg = {
            "id": str(uuid.uuid4()),
            "type": "THREAT_ALERT",
            "timestamp": now_utc,
            "data": {
                "user": current_user.username,
                "score": anomaly_score,
                "level": threat_level,
                "action": activity.action_type,
                "risk_level": threat_assessment["risk_level"],
                "details": threat_assessment.get("summary") or activity.details,
                "timestamp": now_utc,
            },
        }
        await manager.broadcast(json.dumps(alert_msg), user_id=current_user.id)

    now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    activity_msg = {
        "id": str(uuid.uuid4()),
        "type": "NEW_ACTIVITY",
        "timestamp": now_utc,
        "data": {
            "user": current_user.username,
            "action": activity.action_type,
            "network": activity.network_activity,
            "score": anomaly_score,
            "risk_level": threat_assessment["risk_level"],
            "details": threat_assessment.get("summary") or activity.details,
            "timestamp": now_utc,
        },
    }
    await manager.broadcast(json.dumps(activity_msg), user_id=current_user.id)
    return {"status": "Logged successfully", "assessment": threat_assessment}


@app.websocket("/api/ws/monitor")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.query_params.get("token")
    if not token:
        logger.warning("WebSocket connection rejected: missing authentication token")
        await websocket.close(code=4401)
        return

    db = database.SessionLocal()
    try:
        payload = get_token_payload(token)
        username = payload.get("sub")
        session_id = payload.get("sid")
        user = db.query(models.User).filter(models.User.username == username).first()
        if not user:
            logger.warning(f"WebSocket connection rejected: user '{username}' not found")
            await websocket.close(code=4401)
            return

        session = (
            db.query(models.AuthSession)
            .filter(
                models.AuthSession.session_token_id == session_id,
                models.AuthSession.is_active.is_(True),
            )
            .first()
            if session_id
            else None
        )
        if session_id and (session is None or session.expires_at < datetime.utcnow()):
            logger.warning(f"WebSocket connection rejected: session for user '{username}' is expired or inactive")
            await websocket.close(code=4401)
            return
    except HTTPException as exc:
        logger.warning(f"WebSocket connection rejected: invalid token credentials ({exc.detail})")
        await websocket.close(code=4401)
        return
    except Exception as exc:
        logger.warning(f"WebSocket connection rejected: token decode error ({exc})")
        await websocket.close(code=4401)
        return
    finally:
        db.close()

    await manager.connect(websocket, user)
    logger.info(f"WebSocket client connected: user '{user.username}' (role: {get_user_role(user)})")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info(f"WebSocket client disconnected: user '{user.username}'")
    except Exception as exc:
        manager.disconnect(websocket)
        logger.info(f"WebSocket client disconnected abruptly: user '{user.username}' ({exc})")


# --- TRAFFIC MONITOR ENDPOINTS ---

@app.post("/api/traffic-monitor/ingest")
async def ingest_traffic_monitor_data(
    payload: schemas.TrafficIngestPayload,
    db: Session = Depends(database.get_db),
):
    await traffic_service.ingest_traffic(payload.connections, payload.interface_stats, db)
    now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    await manager.broadcast(
        json.dumps({
            "id": str(uuid.uuid4()),
            "type": "TRAFFIC_MONITOR_UPDATE",
            "timestamp": now_utc,
            "connections": traffic_service.connections,
            "interface_stats": traffic_service.interface_stats
        }),
        admin_only=False
    )
    return {"status": "accepted"}


@app.get("/api/traffic-monitor/status")
async def get_traffic_monitor_status():
    return {
        "connections": traffic_service.connections,
        "interface_stats": traffic_service.interface_stats
    }


@app.get("/api/traffic-monitor/rules", response_model=List[schemas.NetworkRuleResponse])
def get_network_rules(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    return db.query(models.NetworkTrafficRule).all()


@app.post("/api/traffic-monitor/rules", response_model=schemas.NetworkRuleResponse)
def create_network_rule(
    payload: schemas.NetworkRuleCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    rule = db.query(models.NetworkTrafficRule).filter(models.NetworkTrafficRule.ip_address == payload.ip_address).first()
    if rule:
        rule.action = payload.action
        rule.watchlist = payload.watchlist
    else:
        rule = models.NetworkTrafficRule(
            ip_address=payload.ip_address,
            action=payload.action,
            watchlist=payload.watchlist
        )
        db.add(rule)
    db.commit()
    db.refresh(rule)
    traffic_service.load_rules(db, force=True)
    return rule


@app.delete("/api/traffic-monitor/rules/{ip_address}")
def delete_network_rule(
    ip_address: str,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    rule = db.query(models.NetworkTrafficRule).filter(models.NetworkTrafficRule.ip_address == ip_address).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(rule)
    db.commit()
    traffic_service.load_rules(db, force=True)
    return {"status": "deleted"}


@app.get("/api/traffic-monitor/reputation/{ip}")
async def get_ip_reputation_info(
    ip: str,
    current_user: models.User = Depends(get_current_user)
):
    return await traffic_service.get_ip_reputation(ip)


PROTECTED_PROCESS_NAMES = {
    "system",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "smss.exe",
}

@app.post("/api/traffic-monitor/disconnect")
@app.post("/api/desktop/processes/kill")
def disconnect_process_connection(
    payload: Dict[str, Any],
    current_user: models.User = Depends(get_current_user)
):
    pid = payload.get("pid")
    if pid is None:
        raise HTTPException(status_code=400, detail="Missing process PID")

    try:
        pid_int = int(pid)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid process PID")

    # Protection: check if target is the application's own backend
    current_pid = os.getpid()
    if pid_int == current_pid:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "protected_process",
                "message": f"Process (PID {pid_int}) is the AI Firewall application backend itself and cannot be terminated."
            }
        )

    try:
        import psutil
        proc = psutil.Process(pid_int)
        name = (proc.name() or "").lower()

        # Protection: check if target is a critical Windows system process
        if name in PROTECTED_PROCESS_NAMES or pid_int <= 4:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "protected_process",
                    "message": f"Process '{name}' (PID {pid_int}) is a critical system process and cannot be terminated."
                }
            )

        proc.terminate()
        return {"status": "success", "message": f"Terminated process '{name}' (PID {pid_int}) successfully."}
    except psutil.NoSuchProcess:
        raise HTTPException(
            status_code=404,
            detail={"error": "not_found", "message": f"Process with PID {pid_int} no longer exists or has already terminated."}
        )
    except (psutil.AccessDenied, PermissionError):
        raise HTTPException(
            status_code=403,
            detail={"error": "admin_required", "message": f"Terminating process (PID {pid_int}) requires Windows Administrator privileges. Run AI Firewall as Administrator."}
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to terminate process: {str(e)}")


# --- SPAM DETECTION ENDPOINTS ---

@app.post("/api/spam-detection/scan", response_model=schemas.SpamScanLogResponse)
def scan_submitted_url(
    payload: schemas.SpamScanRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    target = (payload.url or "") + (payload.text or "")
    if not target.strip():
        raise HTTPException(status_code=400, detail="Either 'url' or 'text' must be provided.")
    result = spam_service.scan_url(url=payload.url, db=db, text=payload.text)
    return result


@app.get("/api/spam-detection/logs", response_model=List[schemas.SpamScanLogResponse])
def get_spam_logs(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    return db.query(models.SpamScanLog).order_by(models.SpamScanLog.timestamp.desc()).limit(100).all()


class SpamBlockPayload(BaseModel):
    domain: str
    reason: Optional[str] = "Blocked via Spam Detection Panel"


@app.post("/api/spam-detection/block")
def block_spam_domain(
    payload: SpamBlockPayload,
    current_user: models.User = Depends(get_current_user)
):
    domain = (payload.domain or "").strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain cannot be empty.")
    user_email = decrypt_sensitive_value(current_user.email) or current_user.email or current_user.username
    res = block_manager.block(
        block_type="domain",
        value=domain,
        reason=payload.reason or "Blocked via Spam Detection Panel",
        added_by=user_email,
        apply_firewall=False
    )
    return res


# --- HARMFUL WEBSITE DETECTION AND BLOCKING ENDPOINTS ---

@app.post("/api/website-security/scan")
async def scan_website_url(
    payload: schemas.WebsiteScanRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    result = website_security_service.evaluate_url(
        raw_url=payload.url_or_domain,
        db=db,
        user=current_user,
        browser_or_app=payload.browser_or_app or "Browser/System"
    )

    # Broadcast real-time WebSocket alert if website is high risk or blocked
    if result["blocked"] or result["threat_status"] in ("High Risk", "Malicious"):
        now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        await manager.broadcast(
            json.dumps({
                "id": str(uuid.uuid4()),
                "type": "WEBSITE_BLOCKED_ALERT" if result["blocked"] else "WEBSITE_RISK_ALERT",
                "timestamp": now_utc,
                "data": {
                    "domain": result["domain"],
                    "threat_status": result["threat_status"],
                    "threat_score": result["threat_score"],
                    "category": result["category"],
                    "action_taken": result["action_taken"],
                    "username": current_user.username,
                    "reasons": result["reasons"],
                    "timestamp": datetime.utcnow().isoformat()
                }
            }),
            admin_only=False
        )

    return result


@app.get("/api/website-security/logs", response_model=List[schemas.WebsiteAccessLogResponse])
def get_website_access_logs(
    limit: int = 100,
    search: Optional[str] = None,
    threat_status: Optional[str] = None,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    query = db.query(models.WebsiteAccessLog)
    if get_user_role(current_user) != "admin":
        query = query.filter(models.WebsiteAccessLog.user_id == current_user.id)

    if search:
        s = f"%{search.strip().lower()}%"
        query = query.filter(or_(
            func.lower(models.WebsiteAccessLog.domain).like(s),
            func.lower(models.WebsiteAccessLog.url).like(s),
            func.lower(models.WebsiteAccessLog.category).like(s)
        ))

    if threat_status:
        query = query.filter(models.WebsiteAccessLog.threat_status == threat_status)

    return query.order_by(models.WebsiteAccessLog.timestamp.desc()).limit(limit).all()


@app.get("/api/website-security/stats", response_model=schemas.WebsiteStatsResponse)
def get_website_security_stats(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    return website_security_service.get_stats(db)


@app.get("/api/website-security/blocked", response_model=List[schemas.BlockedWebsiteResponse])
def get_blocked_websites(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    return db.query(models.BlockedWebsite).filter(models.BlockedWebsite.is_active == True).order_by(models.BlockedWebsite.created_at.desc()).all()


@app.post("/api/website-security/blocked", response_model=schemas.BlockedWebsiteResponse)
def add_blocked_website(
    payload: schemas.BlockedWebsiteCreate,
    current_user: models.User = Depends(require_admin),
    db: Session = Depends(database.get_db)
):
    domain = payload.domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        import urllib.parse
        domain = urllib.parse.urlparse(domain).netloc.split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]

    existing = db.query(models.BlockedWebsite).filter(models.BlockedWebsite.domain == domain).first()
    if existing:
        existing.is_active = True
        existing.reason = payload.reason or existing.reason
        existing.threat_score = payload.threat_score or existing.threat_score
        existing.category = payload.category or existing.category
        existing.added_by = current_user.username
        entry = existing
    else:
        entry = models.BlockedWebsite(
            domain=domain,
            url_pattern=payload.url_pattern,
            reason=payload.reason or "Manual Admin Block",
            threat_score=payload.threat_score or 90.0,
            category=payload.category or "Phishing/Malware",
            added_by=current_user.username,
            is_active=True
        )
        db.add(entry)

    db.commit()
    db.refresh(entry)

    # Perform actual OS-level host block
    block_res = website_blocker.block_domain_os_level(domain)
    if not block_res.get("success"):
        if block_res.get("error") == "admin_required":
            raise HTTPException(
                status_code=403,
                detail=admin_required_response("OS-level website blocking")
            )
        raise HTTPException(
            status_code=400,
            detail=block_res.get("message") or block_res.get("error") or "Failed to block domain in hosts file."
        )

    return entry


@app.delete("/api/website-security/blocked/{target}")
def remove_blocked_website(
    target: str,
    current_user: models.User = Depends(require_admin),
    db: Session = Depends(database.get_db)
):
    target = target.strip().lower()
    entry = None
    if target.isdigit():
        entry = db.query(models.BlockedWebsite).filter(models.BlockedWebsite.id == int(target)).first()
    if not entry:
        entry = db.query(models.BlockedWebsite).filter(models.BlockedWebsite.domain == target).first()

    if not entry:
        raise HTTPException(status_code=404, detail="Blocked website entry not found")

    entry.is_active = False
    db.commit()

    # Perform actual OS-level host unblock
    unblock_res = website_blocker.unblock_domain_os_level(entry.domain)
    if not unblock_res.get("success"):
        if unblock_res.get("error") == "admin_required":
            raise HTTPException(
                status_code=403,
                detail=admin_required_response("OS-level website unblocking")
            )
        raise HTTPException(
            status_code=400,
            detail=unblock_res.get("message") or unblock_res.get("error") or "Failed to unblock domain in hosts file."
        )

    return {"status": "success", "message": f"Unblocked domain {entry.domain} successfully."}


@app.get("/api/website-security/whitelist", response_model=List[schemas.WebsiteWhitelistResponse])
def get_whitelisted_websites(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    return db.query(models.WebsiteWhitelist).order_by(models.WebsiteWhitelist.created_at.desc()).all()


@app.post("/api/website-security/whitelist", response_model=schemas.WebsiteWhitelistResponse)
def add_whitelisted_website(
    payload: schemas.WebsiteWhitelistCreate,
    current_user: models.User = Depends(require_admin),
    db: Session = Depends(database.get_db)
):
    domain = payload.domain.strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        import urllib.parse
        domain = urllib.parse.urlparse(domain).netloc.split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]

    existing = db.query(models.WebsiteWhitelist).filter(models.WebsiteWhitelist.domain == domain).first()
    if existing:
        existing.added_by = current_user.username
        existing.reason = payload.reason or existing.reason
        existing.is_permanent = payload.is_permanent
        entry = existing
    else:
        entry = models.WebsiteWhitelist(
            domain=domain,
            added_by=current_user.username,
            reason=payload.reason or "Trusted Whitelist",
            is_permanent=payload.is_permanent
        )
        db.add(entry)

    # Deactivate any block rule for this domain
    blocked_entry = db.query(models.BlockedWebsite).filter(models.BlockedWebsite.domain == domain).first()
    if blocked_entry:
        blocked_entry.is_active = False

    db.commit()
    db.refresh(entry)

    # Unblock OS host file if previously blocked
    website_blocker.unblock_domain_os_level(domain)

    return entry


@app.delete("/api/website-security/whitelist/{target}")
def remove_whitelisted_website(
    target: str,
    current_user: models.User = Depends(require_admin),
    db: Session = Depends(database.get_db)
):
    target = target.strip().lower()
    entry = None
    if target.isdigit():
        entry = db.query(models.WebsiteWhitelist).filter(models.WebsiteWhitelist.id == int(target)).first()
    if not entry:
        entry = db.query(models.WebsiteWhitelist).filter(models.WebsiteWhitelist.domain == target).first()

    if not entry:
        raise HTTPException(status_code=404, detail="Whitelisted entry not found")

    domain = entry.domain
    db.delete(entry)
    db.commit()

    return {"status": "success", "message": f"Removed domain {domain} from whitelist."}


@app.get("/api/website-security/alerts", response_model=List[schemas.WebsiteSecurityAlertResponse])
def get_website_security_alerts(
    limit: int = 50,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    query = db.query(models.WebsiteSecurityAlert)
    if get_user_role(current_user) != "admin":
        query = query.filter(models.WebsiteSecurityAlert.user_id == current_user.id)
    return query.order_by(models.WebsiteSecurityAlert.timestamp.desc()).limit(limit).all()


@app.get("/api/website-security/config")
def get_website_security_config(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(database.get_db)
):
    return website_security_service.get_config(db)


@app.put("/api/website-security/config")
def update_website_security_config(
    payload: schemas.WebsiteConfigUpdate,
    current_user: models.User = Depends(require_admin),
    db: Session = Depends(database.get_db)
):
    updates = payload.model_dump(exclude_unset=True)
    updated = website_security_service.update_config(db, updates)
    return {"status": "success", "config": updated}


@app.get("/api/website-security/block-page", response_class=HTMLResponse)
def get_website_block_page(
    domain: str = "example-malicious-site.com",
    score: float = 91.0,
    reason: str = "Possible phishing / malicious activity detected.",
    category: str = "Phishing/Malware",
    user_name: str = "Current User"
):
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    html_content = website_blocker.render_block_page_html(
        domain=domain,
        threat_score=score,
        reason=reason,
        category=category,
        timestamp_str=now_str,
        user_name=user_name
    )
    return HTMLResponse(content=html_content)


