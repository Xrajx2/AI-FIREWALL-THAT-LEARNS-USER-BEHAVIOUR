import os
import shutil
import sqlite3
import logging
from datetime import datetime
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base

logger = logging.getLogger("ai_firewall.database")

try:
    from backend.app.paths import get_database_url
except ImportError:
    try:
        from app.paths import get_database_url
    except ImportError:
        def get_database_url():
            appdata = os.environ.get("APPDATA") or os.path.expanduser("~\\AppData\\Roaming")
            return f"sqlite:///{os.path.join(appdata, 'AIFirewall', 'aifirewall.db')}"

DATABASE_URL = get_database_url()

def check_and_recover_sqlite_db(db_url: str):
    if not db_url.startswith("sqlite"):
        return
    # Extract file path from sqlite URI
    raw_path = db_url.replace("sqlite:///", "").replace("sqlite://", "")
    # Handle query params if any
    clean_path = raw_path.split("?")[0]
    if not clean_path or clean_path == ":memory:":
        return
    clean_path = os.path.abspath(clean_path)
    if not os.path.exists(clean_path):
        # First run: directory check
        parent = os.path.dirname(clean_path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        return

    # Check database integrity
    is_corrupt = False
    error_msg = ""
    conn = None
    try:
        conn = sqlite3.connect(clean_path, timeout=5)
        cur = conn.cursor()
        cur.execute("PRAGMA integrity_check;")
        row = cur.fetchone()
        if not row or str(row[0]).lower() != "ok":
            is_corrupt = True
            error_msg = f"Integrity check failed: {row}"
    except Exception as e:
        is_corrupt = True
        error_msg = str(e)
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

    if is_corrupt:
        logger.error(f"Detected corrupt or unreadable database at {clean_path}: {error_msg}")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{clean_path}.corrupt.{ts}.bak"
        try:
            shutil.copy2(clean_path, backup_path)
            logger.info(f"Backed up corrupted database to {backup_path}")
            os.remove(clean_path)
            logger.info("Corrupted database removed. A clean database will be initialized.")
        except Exception as copy_err:
            logger.error(f"Failed to backup/remove corrupt database: {copy_err}")

check_and_recover_sqlite_db(DATABASE_URL)

engine_options = {}
if DATABASE_URL.startswith("sqlite"):
    engine_options["connect_args"] = {"check_same_thread": False, "timeout": 60}

engine = create_engine(DATABASE_URL, **engine_options)

if DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA busy_timeout=30000;")
        except Exception:
            pass
        finally:
            cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
