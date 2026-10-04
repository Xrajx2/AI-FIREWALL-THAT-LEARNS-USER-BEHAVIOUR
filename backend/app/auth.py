from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
import uuid

from backend.app.security import get_jwt_secret

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REMEMBER_ME_EXPIRE_MINUTES = 60 * 24 * 14

def get_secret_key() -> str:
    return get_jwt_secret()

# Backward compatibility module attribute
SECRET_KEY = get_secret_key()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def decode_access_token(token: str):
    return jwt.decode(token, get_secret_key(), algorithms=[ALGORITHM], options={"require_exp": True})

def generate_session_id() -> str:
    return str(uuid.uuid4())

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, get_secret_key(), algorithm=ALGORITHM)
    return encoded_jwt


from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

try:
    from backend.app import database, models
except ImportError:
    from . import database, models

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")


def credentials_exception() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_token_payload(token: str) -> dict:
    try:
        return decode_access_token(token)
    except Exception as exc:
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


