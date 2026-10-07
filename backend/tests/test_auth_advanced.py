import os
import sys
from pathlib import Path

backend_dir = str(Path(__file__).resolve().parent.parent)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app import models

@pytest.fixture(scope="module")
def client():
    return TestClient(app)

@pytest.fixture(autouse=True)
def cleanup():
    db = SessionLocal()
    try:
        db.query(models.User).filter(models.User.username.in_(["varun@29", "varun@30", "testuser_otp", "social_google_user", "social_ms_user"])).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()
    yield
    db = SessionLocal()
    try:
        db.query(models.User).filter(models.User.username.in_(["varun@29", "varun@30", "testuser_otp", "social_google_user", "social_ms_user"])).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()

def test_unique_username_enforcement(client):
    # 1. First user registers varun@29
    r1 = client.post("/api/auth/register", json={
        "username": "varun@29",
        "email": "varun1@example.com",
        "password": "Password123!@#",
        "country": "India"
    })
    assert r1.status_code == 200, r1.text
    assert r1.json()["user"]["username"] == "varun@29"
    assert r1.json()["user"]["country"] == "India"

    # 2. Check username availability for varun@29
    chk1 = client.get("/api/auth/check-username?username=varun@29")
    assert chk1.status_code == 200
    assert chk1.json()["available"] is False
    assert "already taken" in chk1.json()["message"]

    # 3. Check username availability with different case Varun@29
    chk_case = client.get("/api/auth/check-username?username=Varun@29")
    assert chk_case.status_code == 200
    assert chk_case.json()["available"] is False

    # 4. Check available username
    chk2 = client.get("/api/auth/check-username?username=varun@30")
    assert chk2.status_code == 200
    assert chk2.json()["available"] is True

    # 5. Second user tries to register varun@29 -> MUST FAIL
    r2 = client.post("/api/auth/register", json={
        "username": "varun@29",
        "email": "another_varun@example.com",
        "password": "AnotherPassword123!",
        "country": "United States"
    })
    assert r2.status_code == 400
    assert "already taken by another user" in r2.json()["detail"]

    # 6. Case-insensitive duplicate attempt -> MUST FAIL
    r3 = client.post("/api/auth/register", json={
        "username": "Varun@29",
        "email": "varun_case@example.com",
        "password": "AnotherPassword123!",
        "country": "Canada"
    })
    assert r3.status_code == 400
    assert "already taken by another user" in r3.json()["detail"]

def test_email_otp_flow(client):
    # 1. Send OTP
    r_send = client.post("/api/auth/send-otp", json={
        "email": "otp_test@example.com",
        "purpose": "signup"
    })
    assert r_send.status_code == 200
    data = r_send.json()
    assert data["success"] is True
    assert "dev_otp" in data
    dev_otp = data["dev_otp"]
    assert len(dev_otp) == 6

    # 2. Verify with wrong OTP -> MUST FAIL
    r_wrong = client.post("/api/auth/verify-otp", json={
        "email": "otp_test@example.com",
        "otp": "000000" if dev_otp != "000000" else "111111"
    })
    assert r_wrong.status_code == 400
    assert "Invalid" in r_wrong.json()["detail"]

    # 3. Verify with correct OTP -> SUCCESS
    r_verify = client.post("/api/auth/verify-otp", json={
        "email": "otp_test@example.com",
        "otp": dev_otp
    })
    assert r_verify.status_code == 200
    assert r_verify.json()["verified"] is True

def test_social_login(client):
    # 1. Google social login
    r_google = client.post("/api/auth/social-login", json={
        "provider": "google",
        "email": "google_user@gmail.com",
        "name": "Social Google User",
        "country": "India"
    })
    assert r_google.status_code == 200
    g_data = r_google.json()
    assert "access_token" in g_data
    assert g_data["user"]["auth_provider"] == "google"
    assert g_data["user"]["country"] == "India"

    # 2. Microsoft social login
    r_ms = client.post("/api/auth/social-login", json={
        "provider": "microsoft",
        "email": "ms_user@outlook.com",
        "name": "Social MS User",
        "country": "United Kingdom"
    })
    assert r_ms.status_code == 200
    ms_data = r_ms.json()
    assert "access_token" in ms_data
    assert ms_data["user"]["auth_provider"] == "microsoft"
    assert ms_data["user"]["country"] == "United Kingdom"
