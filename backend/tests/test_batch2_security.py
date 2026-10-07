import os
import sys
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

# Ensure backend is on sys.path
backend_dir = str(Path(__file__).resolve().parent.parent)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.main import app, get_failed_attempt_count, FAILED_ATTEMPT_LIMIT
from app import database, models, auth, security
from app.database import engine, SessionLocal


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture(autouse=True)
def clean_test_state():
    """Ensure test users and attempts don't pollute across tests"""
    db = SessionLocal()
    try:
        db.query(models.LoginAttempt).delete()
        db.query(models.User).filter(models.User.username.like("b2_%")).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()
    yield
    db = SessionLocal()
    try:
        db.query(models.LoginAttempt).delete()
        db.query(models.User).filter(models.User.username.like("b2_%")).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def test_lockout_after_5_failed_logins_per_username(client):
    """5 failed logins in 5 minutes locks out the target username on the 6th attempt"""
    db = SessionLocal()
    try:
        # Create a test user
        user = models.User(
            username="b2_user1",
            email=security.encrypt_sensitive_value("b2_user1@test.local"),
            email_lookup_hash=security.fingerprint_text("b2_user1@test.local"),
            hashed_password=auth.get_password_hash("CorrectPassword123!"),
            role="user",
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        db.add(user)
        db.commit()
    finally:
        db.close()

    # 5 failed attempts with wrong password
    for i in range(5):
        r = client.post("/api/auth/login", json={"identifier": "b2_user1", "password": "WrongPassword!"})
        assert r.status_code == 401
        assert r.json()["detail"] == "Incorrect username/email or password"

    # 6th attempt must be 429 Too Many Requests (Lockout)
    r6 = client.post("/api/auth/login", json={"identifier": "b2_user1", "password": "WrongPassword!"})
    assert r6.status_code == 429
    assert "Too many failed login attempts. Please wait 5 minutes before retrying." in r6.json()["detail"]

    # Even with correct password, b2_user1 is locked out
    r_correct = client.post("/api/auth/login", json={"identifier": "b2_user1", "password": "CorrectPassword123!"})
    assert r_correct.status_code == 429


def test_lockout_per_username_does_not_block_other_users(client):
    """Locking out user1 from 127.0.0.1 must NOT block user2 from 127.0.0.1"""
    db = SessionLocal()
    try:
        user2 = models.User(
            username="b2_user2",
            email=security.encrypt_sensitive_value("b2_user2@test.local"),
            email_lookup_hash=security.fingerprint_text("b2_user2@test.local"),
            hashed_password=auth.get_password_hash("ValidPassword123!"),
            role="user",
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        db.add(user2)
        db.commit()
    finally:
        db.close()

    # b2_user1 is locked out from previous test or 5 failures
    for _ in range(5):
        client.post("/api/auth/login", json={"identifier": "b2_user1", "password": "Bad"})

    # b2_user2 should be able to log in successfully from the same client IP
    r = client.post("/api/auth/login", json={"identifier": "b2_user2", "password": "ValidPassword123!"})
    assert r.status_code == 200, f"user2 should not be locked out by user1's failures: {r.text}"
    assert "access_token" in r.json()


def test_lockout_applies_to_non_existent_usernames(client):
    """Lockout applies identically to usernames that do not exist"""
    fake_username = "b2_nonexistent_user"

    # 5 failed attempts for non-existent user
    for i in range(5):
        r = client.post("/api/auth/login", json={"identifier": fake_username, "password": "BadPassword1!"})
        assert r.status_code == 401
        assert r.json()["detail"] == "Incorrect username/email or password"

    # 6th attempt should be locked out (429)
    r6 = client.post("/api/auth/login", json={"identifier": fake_username, "password": "BadPassword1!"})
    assert r6.status_code == 429
    assert "Too many failed login attempts. Please wait 5 minutes before retrying." in r6.json()["detail"]


def test_identical_error_message_for_existent_and_non_existent_user(client):
    """Timing/credential enumeration protection: identical error messages"""
    db = SessionLocal()
    try:
        user = models.User(
            username="b2_existing",
            email=security.encrypt_sensitive_value("b2_existing@test.local"),
            email_lookup_hash=security.fingerprint_text("b2_existing@test.local"),
            hashed_password=auth.get_password_hash("SecretPassword99!"),
            role="user",
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        db.add(user)
        db.commit()
    finally:
        db.close()

    # Real user, bad password
    r_real = client.post("/api/auth/login", json={"identifier": "b2_existing", "password": "wrong"})
    # Fake user, bad password
    r_fake = client.post("/api/auth/login", json={"identifier": "b2_totally_fake", "password": "wrong"})

    assert r_real.status_code == 401
    assert r_fake.status_code == 401
    assert r_real.json()["detail"] == r_fake.json()["detail"] == "Incorrect username/email or password"


def test_lockout_expires_after_5_minutes(client):
    """Lockout is temporary (5 minutes), not permanent"""
    db = SessionLocal()
    try:
        # Insert 5 failed attempts with created_at 6 minutes ago
        six_mins_ago = datetime.utcnow() - timedelta(minutes=6)
        for i in range(5):
            attempt = models.LoginAttempt(
                attempt_identifier="b2_expiry_test",
                ip_address=security.encrypt_sensitive_value("127.0.0.1"),
                success=False,
                failure_reason=security.encrypt_sensitive_value("Incorrect password"),
                created_at=six_mins_ago,
            )
            db.add(attempt)
        db.commit()

        # Count within 5-minute window should be 0
        count = get_failed_attempt_count(db, "b2_expiry_test")
        assert count == 0, "Old failed attempts older than 5 minutes should not count toward lockout"
    finally:
        db.close()


def test_create_admin_endpoint_lifecycle(client):
    """create-admin endpoint:
    - enforces min password length of 10
    - works only when 0 admins exist
    - allows localhost only
    - returns 403 once an admin exists
    """
    db = SessionLocal()
    try:
        # Delete any existing admin accounts temporarily
        db.query(models.User).filter(models.User.role == "admin").delete()
        db.commit()
    finally:
        db.close()

    # 1. Admin status check
    r_status = client.get("/api/auth/admin-status")
    assert r_status.status_code == 200
    assert r_status.json()["has_admin"] is False

    # 2. Reject short password (<10 chars)
    r_short = client.post("/api/auth/create-admin", json={
        "username": "b2_admin1",
        "password": "short"
    })
    assert r_short.status_code == 400
    assert "at least 10 characters" in r_short.json()["detail"]

    # 3. Successful admin creation
    r_create = client.post("/api/auth/create-admin", json={
        "username": "b2_admin1",
        "password": "StrongAdminPassword123!",
        "email": "b2_admin1@local.test"
    })
    assert r_create.status_code == 200
    assert r_create.json()["user"]["role"] == "admin"
    assert r_create.json()["user"]["username"] == "b2_admin1"

    # 4. Admin status now True
    r_status2 = client.get("/api/auth/admin-status")
    assert r_status2.json()["has_admin"] is True

    # 5. Subsequent create-admin attempt must be rejected with 403
    r_second = client.post("/api/auth/create-admin", json={
        "username": "b2_admin2",
        "password": "AnotherStrongPassword123!",
    })
    assert r_second.status_code == 403
    assert "already exists" in r_second.json()["detail"].lower()


def test_standard_register_endpoint_cannot_create_admin(client):
    """The normal register / signup endpoint must NEVER allow creating an admin"""
    r = client.post("/api/auth/register", json={
        "username": "b2_hacker_admin",
        "password": "HackerPassword123!",
        "email": "hacker@example.com",
        "role": "admin"
    })
    assert r.status_code == 403
    assert "admin registration is not permitted" in r.json()["detail"].lower()

    # Verify no admin was created in DB
    db = SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.username == "b2_hacker_admin").first()
        assert user is None
    finally:
        db.close()


def test_keys_generated_in_appdata_and_accessible():
    """Verify keys are generated in %APPDATA%\\AIFirewall\\keys"""
    keys_dir = security._get_keys_dir()
    assert os.path.exists(keys_dir)
    assert os.path.exists(os.path.join(keys_dir, "secret.key"))
    assert os.path.exists(os.path.join(keys_dir, "jwt_secret.key"))

    jwt_secret = security.get_jwt_secret()
    assert jwt_secret and len(jwt_secret) >= 32


def test_jwt_token_requires_exp_claim():
    """Tokens without 'exp' claim must be rejected by auth.decode_access_token"""
    from jose import jwt as raw_jwt
    token_without_exp = raw_jwt.encode(
        {"sub": "test_user", "sid": "1234"},
        auth.get_secret_key(),
        algorithm="HS256"
    )
    with pytest.raises(auth.JWTError):
        auth.decode_access_token(token_without_exp)


def test_unreadable_encrypted_db_backed_up_and_recreated():
    """If encryption key is missing and DB has enc:: data, DB is backed up and recreated"""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_db_path = os.path.join(tmpdir, "test_legacy.db")
        conn = sqlite3.connect(test_db_path)
        cur = conn.cursor()
        cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT);")
        cur.execute("INSERT INTO users VALUES (1, 'enc::gAAAAABtestfakeciphertext');")
        conn.commit()
        conn.close()

        assert os.path.exists(test_db_path)
        # Call recovery check
        security._check_and_backup_undecryptable_db(test_db_path)

        # Original DB should be removed and backup created
        assert not os.path.exists(test_db_path)
        bak_files = [f for f in os.listdir(tmpdir) if f.startswith("test_legacy.db.unreadable_key.")]
        assert len(bak_files) == 1


def test_production_disables_docs_and_redoc(client):
    """In production mode (default), /docs, /redoc, and /openapi.json return 404"""
    r_docs = client.get("/docs")
    r_redoc = client.get("/redoc")
    r_openapi = client.get("/openapi.json")

    assert r_docs.status_code == 404
    assert r_redoc.status_code == 404
    assert r_openapi.status_code == 404


def test_cors_accepts_null_and_localhost(client):
    """CORS accepts Electron's null origin and localhost:5173 without wildcard *"""
    # Test localhost:5173 origin
    r1 = client.options(
        "/api/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET"
        }
    )
    assert r1.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert r1.headers.get("access-control-allow-credentials") == "true"

    # Test null origin (packaged Electron file://)
    r2 = client.options(
        "/api/health",
        headers={
            "Origin": "null",
            "Access-Control-Request-Method": "GET"
        }
    )
    assert r2.headers.get("access-control-allow-origin") == "null"
