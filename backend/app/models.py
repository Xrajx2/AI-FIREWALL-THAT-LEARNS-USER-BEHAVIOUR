from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Boolean, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, nullable=True)
    email_lookup_hash = Column(String, unique=True, index=True, nullable=True)
    hashed_password = Column(String)
    role = Column(String, default="user")  # 'user' or 'admin'
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    is_locked = Column(Boolean, default=False)
    is_email_verified = Column(Boolean, default=True)
    last_login_at = Column(DateTime, nullable=True)
    last_login_ip = Column(String, nullable=True)
    last_login_ip_hash = Column(String, index=True, nullable=True)
    last_login_device = Column(String, nullable=True)
    last_login_device_hash = Column(String, index=True, nullable=True)
    
    activities = relationship("UserActivity", back_populates="user")
    threats = relationship("ThreatLog", back_populates="user")
    profile = relationship("BehaviorProfile", back_populates="user", uselist=False)
    login_attempts = relationship("LoginAttempt", back_populates="user")
    sessions = relationship("AuthSession", back_populates="user")

class UserActivity(Base):
    __tablename__ = "user_activity"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    timestamp = Column(DateTime, default=datetime.utcnow)
    action_type = Column(String)  # 'login', 'web_browsing', 'file_transfer', 'usb_insertion', etc.
    device = Column(String)       # device MAC or IP
    network_activity = Column(Float) # Size in MBs, for example
    details = Column(String, nullable=True) # Domain, filename, etc.
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String, default="Normal")

    user = relationship("User", back_populates="activities")

class ThreatLog(Base):
    __tablename__ = "threat_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    anomaly_score = Column(Float)     # 0 to 100
    threat_level = Column(String)     # Low, Medium, High, Critical
    action_taken = Column(String)     # e.g., 'blocked_ip', 'session_locked'
    timestamp = Column(DateTime, default=datetime.utcnow)
    details = Column(String, nullable=True)

    user = relationship("User", back_populates="threats")

class BehaviorProfile(Base):
    __tablename__ = "behavior_profiles"

    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    normal_login_time_start = Column(Integer)  # hour of day, e.g. 9
    normal_login_time_end = Column(Integer)    # hour of day, e.g. 18
    avg_data_transfer = Column(Float)          # expected average baseline
    frequent_devices = Column(String)          # JSON string of common devices
    login_hour_distribution = Column(Text, default="{}")
    frequent_applications = Column(Text, default="[]")
    file_directory_habits = Column(Text, default="[]")
    file_extension_habits = Column(Text, default="[]")
    recent_file_samples = Column(Text, default="[]")
    total_logins = Column(Integer, default=0)
    total_application_events = Column(Integer, default=0)
    total_file_events = Column(Integer, default=0)
    last_updated = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="profile")


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    attempt_identifier = Column(String, index=True)
    ip_address = Column(String, nullable=True)
    ip_address_hash = Column(String, nullable=True, index=True)
    user_agent = Column(Text, nullable=True)
    device_name = Column(String, nullable=True)
    device_name_hash = Column(String, nullable=True, index=True)
    success = Column(Boolean, default=False)
    failure_reason = Column(String, nullable=True)
    suspicious = Column(Boolean, default=False)
    suspicious_reasons = Column(Text, default="[]")
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    user = relationship("User", back_populates="login_attempts")


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    session_token_id = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_seen_at = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String, nullable=True)
    ip_address_hash = Column(String, nullable=True, index=True)
    user_agent = Column(Text, nullable=True)
    device_name = Column(String, nullable=True)
    device_name_hash = Column(String, nullable=True, index=True)
    remember_me = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    suspicious = Column(Boolean, default=False)
    suspicious_reason = Column(Text, nullable=True)

    user = relationship("User", back_populates="sessions")


class NetworkTrafficRule(Base):
    __tablename__ = "network_traffic_rules"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True)
    action = Column(String, default="block")  # 'block' or 'allow'
    watchlist = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow)


class SpamScanLog(Base):
    __tablename__ = "spam_scan_logs"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    domain = Column(String, index=True)
    risk_score = Column(Float)
    threat_type = Column(String)  # 'Safe', 'Phishing', 'Spam', 'Malware', 'Typosquatting'
    action_taken = Column(String)  # 'blocked', 'allowed', 'reported'
    scan_report = Column(Text)  # JSON string containing WHOIS, SSL, VT, Google Safe Browsing results
    timestamp = Column(DateTime, default=datetime.utcnow)


class FirewallAppRule(Base):
    __tablename__ = "firewall_app_rules"

    id = Column(Integer, primary_key=True, index=True)
    application_path = Column(String, unique=True, index=True)
    action = Column(String, default="block")  # 'block' or 'allow'
    direction = Column(String, default="out")  # 'in' or 'out'
    rule_name = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)


class WebsiteAccessLog(Base):
    __tablename__ = "website_access_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    username = Column(String, default="System/Anonymous", index=True)
    domain = Column(String, index=True, nullable=False)
    url = Column(Text, nullable=False)
    browser_or_app = Column(String, default="Browser/System")
    threat_status = Column(String, default="Safe", index=True)  # 'Safe', 'Suspicious', 'High Risk', 'Malicious'
    threat_score = Column(Float, default=0.0)
    category = Column(String, default="General")  # 'Phishing', 'Malware', 'Typosquatting', 'Adult', 'Safe', 'Suspicious'
    action_taken = Column(String, default="allowed", index=True)  # 'allowed', 'blocked', 'monitored', 'whitelisted'
    details = Column(Text, nullable=True)  # Encrypted/JSON details
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


class BlockedWebsite(Base):
    __tablename__ = "blocked_websites"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True, nullable=False)
    url_pattern = Column(String, nullable=True)
    reason = Column(String, default="Malicious activity detected")
    threat_score = Column(Float, default=90.0)
    category = Column(String, default="Phishing/Malware")
    added_by = Column(String, default="System Admin")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class WebsiteThreat(Base):
    __tablename__ = "website_threats"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True, nullable=False)
    threat_category = Column(String, default="Phishing")
    risk_score = Column(Float, default=85.0)
    source = Column(String, default="Threat Intelligence Feed")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class WebsiteWhitelist(Base):
    __tablename__ = "website_whitelists"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True, nullable=False)
    added_by = Column(String, default="System Admin")
    reason = Column(String, default="Trusted Domain")
    is_permanent = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class WebsiteSecurityAlert(Base):
    __tablename__ = "website_security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    username = Column(String, default="System User", index=True)
    domain = Column(String, index=True)
    threat_score = Column(Float, default=85.0)
    threat_level = Column(String, default="High Risk")  # 'Suspicious', 'High Risk', 'Critical'
    category = Column(String, default="Phishing")
    action_taken = Column(String, default="Blocked")
    reason = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


class WebsiteConfig(Base):
    __tablename__ = "website_configs"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, index=True, nullable=False)
    value = Column(String, nullable=False)
    description = Column(String, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


