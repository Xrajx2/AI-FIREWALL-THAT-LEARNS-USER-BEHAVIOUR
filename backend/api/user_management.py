from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from datetime import datetime
import sqlite3
import secrets
import string
from typing import Optional

try:
    from backend.app.auth import get_current_user
except ImportError:
    try:
        from app.auth import get_current_user
    except ImportError:
        from ..app.auth import get_current_user

router = APIRouter(prefix="/api/admin/users", tags=["User Management"])
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class CreateUserRequest(BaseModel):
    email: str
    password: str
    full_name: str
    role: str = 'user'
    department: str = ''
    can_view_logs: bool = True
    can_manage_blocks: bool = False
    can_manage_rules: bool = False
    is_active: bool = True

class UpdateUserRequest(BaseModel):
    full_name: Optional[str] = None
    role: Optional[str] = None
    department: Optional[str] = None
    can_view_logs: Optional[bool] = None
    can_manage_blocks: Optional[bool] = None
    can_manage_rules: Optional[bool] = None
    is_active: Optional[bool] = None
    new_password: Optional[str] = None

def get_db():
    try:
        from app.paths import get_database_path
        db_path = str(get_database_path())
    except ImportError:
        try:
            from backend.app.paths import get_database_path
            db_path = str(get_database_path())
        except ImportError:
            import os
            db_path = os.path.join(os.environ.get("APPDATA", "."), "AIFirewall", "aifirewall.db")
    return sqlite3.connect(db_path)

def init_user_table():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS managed_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                department TEXT DEFAULT '',
                can_view_logs INTEGER DEFAULT 1,
                can_manage_blocks INTEGER DEFAULT 0,
                can_manage_rules INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_login TEXT,
                login_count INTEGER DEFAULT 0,
                force_password_change INTEGER DEFAULT 0
            )
        """)
        conn.commit()

init_user_table()

def get_user_role(user):
    return str(getattr(user, 'role', 'user')).lower()

def get_user_identifier(user):
    email = getattr(user, 'email', None)
    if email:
        try:
            from backend.app.main import decrypt_sensitive_value
            dec = decrypt_sensitive_value(email)
            if dec:
                return dec
        except Exception:
            pass
        return str(email)
    return getattr(user, 'username', 'admin')

@router.get("")
async def list_users(current_user = Depends(get_current_user)):
    if get_user_role(current_user) != 'admin':
        raise HTTPException(403, "Admin only")
    with get_db() as conn:
        rows = conn.execute("""
            SELECT id, email, full_name, role, department,
                   can_view_logs, can_manage_blocks, can_manage_rules,
                   is_active, created_by, created_at, last_login, login_count
            FROM managed_users ORDER BY created_at DESC
        """).fetchall()
    cols = ['id','email','full_name','role','department','can_view_logs',
            'can_manage_blocks','can_manage_rules','is_active','created_by',
            'created_at','last_login','login_count']
    return {'users': [dict(zip(cols, r)) for r in rows]}

@router.post("/create")
async def create_user(req: CreateUserRequest, current_user = Depends(get_current_user)):
    if get_user_role(current_user) != 'admin':
        raise HTTPException(403, "Admin only")
    try:
        password_hash = pwd_context.hash(req.password)
        creator = get_user_identifier(current_user)
        with get_db() as conn:
            conn.execute("""
                INSERT INTO managed_users
                (email, password_hash, full_name, role, department,
                 can_view_logs, can_manage_blocks, can_manage_rules,
                 is_active, created_by, created_at, force_password_change)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            """, (
                req.email, password_hash, req.full_name, req.role,
                req.department, 1 if req.can_view_logs else 0,
                1 if req.can_manage_blocks else 0,
                1 if req.can_manage_rules else 0,
                1 if req.is_active else 0,
                creator, datetime.now().isoformat()
            ))
            conn.commit()
        return {'success': True, 'email': req.email, 'role': req.role}
    except sqlite3.IntegrityError:
        raise HTTPException(400, f"User {req.email} already exists")
    except Exception as e:
        raise HTTPException(500, str(e))

@router.patch("/{user_id}")
async def update_user(user_id: int, req: UpdateUserRequest, current_user = Depends(get_current_user)):
    if get_user_role(current_user) != 'admin':
        raise HTTPException(403, "Admin only")
    updates = {}
    if req.full_name is not None: updates['full_name'] = req.full_name
    if req.role is not None: updates['role'] = req.role
    if req.department is not None: updates['department'] = req.department
    if req.can_view_logs is not None: updates['can_view_logs'] = 1 if req.can_view_logs else 0
    if req.can_manage_blocks is not None: updates['can_manage_blocks'] = 1 if req.can_manage_blocks else 0
    if req.can_manage_rules is not None: updates['can_manage_rules'] = 1 if req.can_manage_rules else 0
    if req.is_active is not None: updates['is_active'] = 1 if req.is_active else 0
    if req.new_password: updates['password_hash'] = pwd_context.hash(req.new_password)

    if not updates:
        raise HTTPException(400, "No updates provided")

    set_clause = ', '.join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [user_id]
    with get_db() as conn:
        conn.execute(f"UPDATE managed_users SET {set_clause} WHERE id = ?", values)
        conn.commit()
    return {'success': True, 'updated': list(updates.keys())}

@router.delete("/{user_id}")
async def delete_user(user_id: int, current_user = Depends(get_current_user)):
    if get_user_role(current_user) != 'admin':
        raise HTTPException(403, "Admin only")
    current_email = get_user_identifier(current_user)
    with get_db() as conn:
        user = conn.execute("SELECT email FROM managed_users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            raise HTTPException(404, "User not found")
        if user[0] == current_email:
            raise HTTPException(400, "Cannot delete your own account")
        conn.execute("DELETE FROM managed_users WHERE id = ?", (user_id,))
        conn.commit()
    return {'success': True}

@router.post("/{user_id}/reset-password")
async def reset_password(user_id: int, current_user = Depends(get_current_user)):
    if get_user_role(current_user) != 'admin':
        raise HTTPException(403, "Admin only")
    temp_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
    password_hash = pwd_context.hash(temp_password)
    with get_db() as conn:
        conn.execute(
            "UPDATE managed_users SET password_hash = ?, force_password_change = 1 WHERE id = ?",
            (password_hash, user_id)
        )
        conn.commit()
    return {'success': True, 'temp_password': temp_password, 'message': 'Share this password securely'}

@router.post("/{user_id}/toggle-active")
async def toggle_active(user_id: int, current_user = Depends(get_current_user)):
    if get_user_role(current_user) != 'admin':
        raise HTTPException(403, "Admin only")
    with get_db() as conn:
        conn.execute(
            "UPDATE managed_users SET is_active = NOT is_active WHERE id = ?",
            (user_id,)
        )
        conn.commit()
    return {'success': True}
