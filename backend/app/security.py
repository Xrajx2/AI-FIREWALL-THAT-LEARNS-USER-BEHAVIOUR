import base64
import hashlib
import json
import logging
import os
import secrets
import shutil
import sqlite3
import subprocess
from datetime import datetime
from typing import Any, Dict, Optional

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger("ai_firewall.security")

ENCRYPTION_PREFIX = "enc::"


def _get_keys_dir() -> str:
    try:
        from app.paths import get_keys_dir
    except ImportError:
        from backend.app.paths import get_keys_dir
    return str(get_keys_dir())


def _restrict_file_permissions(file_path: str):
    """Restrict file permissions to the current Windows user"""
    if os.name == "nt":
        username = os.environ.get("USERNAME")
        if username:
            try:
                from app.process_utils import run_hidden
                run_hidden(
                    ["icacls", file_path, "/inheritance:r", f"/grant:r", f"{username}:(R,W)"],
                    timeout=5,
                    check=False,
                )
            except Exception:
                pass


def _check_and_backup_undecryptable_db(db_path: str):
    """If database has enc:: data and encryption key is missing/recreated, back up and recreate"""
    if not os.path.exists(db_path):
        return
    has_encrypted_data = False
    conn = None
    try:
        conn = sqlite3.connect(db_path, timeout=5)
        cur = conn.cursor()
        tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        for table in tables:
            if table.startswith("sqlite_"):
                continue
            cols = [col[1] for col in cur.execute(f"PRAGMA table_info({table})").fetchall()]
            for col in cols:
                try:
                    res = cur.execute(f"SELECT 1 FROM {table} WHERE {col} LIKE '{ENCRYPTION_PREFIX}%' LIMIT 1").fetchone()
                    if res:
                        has_encrypted_data = True
                        break
                except Exception:
                    continue
            if has_encrypted_data:
                break
    except Exception:
        pass
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

    if has_encrypted_data:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{db_path}.unreadable_key.{ts}.bak"
        try:
            shutil.copy2(db_path, backup_path)
            os.remove(db_path)
            logger.warning(
                f"Existing database had encrypted fields with missing key. Backed up to {backup_path} and reinitializing."
            )
        except Exception as e:
            logger.error(f"Failed to backup undecryptable database: {e}")


def _load_or_generate_key() -> str:
    env_key = os.getenv("DATA_ENCRYPTION_KEY")
    if env_key:
        return env_key

    keys_dir = _get_keys_dir()
    key_file = os.path.join(keys_dir, "secret.key")

    if os.path.exists(key_file):
        try:
            with open(key_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    return content
        except Exception as e:
            logger.error(f"Failed to read existing secret key: {e}")

    # First run or key missing: check if existing SQLite DB has unreadable encrypted data
    try:
        from app.paths import get_database_url
    except ImportError:
        from backend.app.paths import get_database_url
    db_url = os.getenv("DATABASE_URL") or get_database_url()
    if db_url.startswith("sqlite"):
        raw_path = db_url.replace("sqlite:///", "").replace("sqlite://", "").split("?")[0]
        if raw_path and raw_path != ":memory:":
            _check_and_backup_undecryptable_db(os.path.abspath(raw_path))

    # Generate new random Fernet key
    new_key = Fernet.generate_key().decode("utf-8")
    try:
        with open(key_file, "w", encoding="utf-8") as f:
            f.write(new_key)
        _restrict_file_permissions(key_file)
        logger.info(f"Generated new encryption key at {key_file}")
    except Exception as e:
        logger.error(f"Failed to persist encryption key: {e}")

    return new_key


def _load_or_generate_jwt_secret() -> str:
    env_secret = os.getenv("SECRET_KEY")
    if env_secret:
        return env_secret

    keys_dir = _get_keys_dir()
    jwt_file = os.path.join(keys_dir, "jwt_secret.key")

    if os.path.exists(jwt_file):
        try:
            with open(jwt_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    return content
        except Exception as e:
            logger.error(f"Failed to read existing JWT secret: {e}")

    # Generate cryptographically secure random secret
    new_secret = secrets.token_urlsafe(32)
    try:
        with open(jwt_file, "w", encoding="utf-8") as f:
            f.write(new_secret)
        _restrict_file_permissions(jwt_file)
        logger.info(f"Generated new JWT secret at {jwt_file}")
    except Exception as e:
        logger.error(f"Failed to persist JWT secret: {e}")

    return new_secret


def get_jwt_secret() -> str:
    return _load_or_generate_jwt_secret()


def _build_fernet() -> Fernet:
    key_str = _load_or_generate_key().encode("utf-8")
    # If key is already a valid base64 32-byte fernet key, use directly; otherwise hash it
    try:
        return Fernet(key_str)
    except Exception:
        digest = hashlib.sha256(key_str).digest()
        return Fernet(base64.urlsafe_b64encode(digest))


_fernet = _build_fernet()


def is_encrypted_value(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(ENCRYPTION_PREFIX)


def encrypt_sensitive_value(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value)
    if not text:
        return text
    if is_encrypted_value(text):
        return text
    token = _fernet.encrypt(text.encode("utf-8")).decode("utf-8")
    return f"{ENCRYPTION_PREFIX}{token}"


def decrypt_sensitive_value(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value)
    if not text:
        return text
    if not is_encrypted_value(text):
        return text
    token = text[len(ENCRYPTION_PREFIX) :]
    try:
        return _fernet.decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return text


def encrypt_json_value(payload: Dict[str, Any]) -> Optional[str]:
    if payload is None:
        return None
    return encrypt_sensitive_value(json.dumps(payload))


def decrypt_json_value(value: Any) -> Dict[str, Any]:
    decrypted = decrypt_sensitive_value(value)
    if not decrypted:
        return {}
    try:
        parsed = json.loads(decrypted)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def fingerprint_text(value: Any, *, normalize: bool = True) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if normalize:
        text = text.lower()
    secret = os.getenv("DATA_LOOKUP_KEY") or _load_or_generate_key()
    return hashlib.sha256(f"{secret}:{text}".encode("utf-8")).hexdigest()


def log_ciphertext(value: Any) -> str:
    encrypted = encrypt_sensitive_value(value)
    return encrypted or "-"


def maybe_encrypt_legacy_value(value: Any) -> Any:
    if value is None:
        return None
    if is_encrypted_value(value):
        return value
    text = str(value)
    if not text:
        return text
    return encrypt_sensitive_value(text)
