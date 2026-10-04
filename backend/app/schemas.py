from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class UserCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    username: str = Field(min_length=3, max_length=32)
    email: Optional[EmailStr] = None
    password: str = Field(min_length=8, max_length=128)
    role: str = Field(default="user", min_length=4, max_length=16)
    admin_invite_code: Optional[str] = Field(default=None, max_length=128)

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Username may only contain letters, numbers, dashes, and underscores")
        return cleaned

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        password = value or ""
        has_upper = any(char.isupper() for char in password)
        has_lower = any(char.islower() for char in password)
        has_digit = any(char.isdigit() for char in password)
        has_symbol = any(not char.isalnum() for char in password)
        if len(password) < 8 or not (has_upper and has_lower and has_digit and has_symbol):
            raise ValueError("Password must include uppercase, lowercase, number, and special character.")
        return password

    @field_validator("role")
    @classmethod
    def normalize_role(cls, value: str) -> str:
        normalized = (value or "user").strip().lower()
        if normalized not in {"admin", "user"}:
            raise ValueError("Role must be either admin or user.")
        return normalized


class AuthLoginRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    identifier: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=128)
    remember_me: bool = False


class UserResponse(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    role: str
    created_at: Optional[datetime] = None
    is_active: bool = True
    is_locked: bool = False
    is_email_verified: bool = True
    last_login_at: Optional[datetime] = None
    last_login_ip: Optional[str] = None
    last_login_device: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str


class AuthResponse(BaseModel):
    access_token: str
    token_type: str
    expires_at: datetime
    remember_me: bool
    user: UserResponse
    assessment: Dict[str, Any]
    security_status: str
    suspicious_session: bool
    warning_message: Optional[str] = None


class SignupResponse(BaseModel):
    user: UserResponse
    message: str
    verification_notice: Optional[str] = None


class LoginAttemptResponse(BaseModel):
    id: int
    created_at: datetime
    ip_address: Optional[str] = None
    device_name: Optional[str] = None
    success: bool
    suspicious: bool
    failure_reason: Optional[str] = None
    suspicious_reasons: List[str] = []

    model_config = ConfigDict(from_attributes=True)


class DashboardSummaryResponse(BaseModel):
    user: UserResponse
    welcome_message: str
    security_status: str
    last_login_at: Optional[datetime] = None
    current_login_at: Optional[datetime] = None
    current_login_ip: Optional[str] = None
    current_login_device: Optional[str] = None
    suspicious_reasons: List[str] = []
    active_sessions: int = 0
    recent_login_activity: List[LoginAttemptResponse] = []


class ActivityCreate(BaseModel):
    action_type: str
    device: str
    network_activity: float = 0.0
    details: Optional[str] = None


class ActivityResponse(BaseModel):
    id: int
    user_id: int
    timestamp: datetime
    action_type: str
    device: str
    network_activity: float
    details: Optional[str] = None
    risk_score: Optional[float] = 0.0
    risk_level: Optional[str] = "Normal"

    model_config = ConfigDict(from_attributes=True)


class ThreatResponse(BaseModel):
    id: int
    user_id: int
    anomaly_score: float
    threat_level: str
    action_taken: str
    timestamp: datetime
    details: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class BehaviorCountItem(BaseModel):
    count: int
    last_seen: Optional[str] = None
    name: Optional[str] = None
    path: Optional[str] = None
    extension: Optional[str] = None
    device: Optional[str] = None
    source: Optional[str] = None


class RecentFileItem(BaseModel):
    path: str
    last_seen: Optional[str] = None


class LoginHourItem(BaseModel):
    hour: int
    count: int


class LoginPatternResponse(BaseModel):
    login_count: int
    window_start: Optional[int] = None
    window_end: Optional[int] = None
    peak_hours: List[int]
    hour_distribution: List[LoginHourItem]


class FileAccessHabitsResponse(BaseModel):
    event_count: int
    directories: List[BehaviorCountItem]
    file_types: List[BehaviorCountItem]
    recent_files: List[RecentFileItem]


class BehaviorProfileResponse(BaseModel):
    user_id: int
    username: str
    last_updated: Optional[str] = None
    login_pattern: LoginPatternResponse
    frequent_applications: List[BehaviorCountItem]
    file_access_habits: FileAccessHabitsResponse
    device_habits: List[BehaviorCountItem]
    learning_mode: bool = False


class SystemMonitorIngestPayload(BaseModel):
    snapshot: Dict[str, Any]
    events: List[Dict[str, Any]] = []


class AIInsightUserResponse(BaseModel):
    user_id: int
    username: str
    role: str
    account_type: str
    activity_count: int
    threat_count: int
    avg_anomaly_score: float
    overall_risk_score: float
    overall_risk_level: str
    isolation_forest_ready: bool
    cluster_model_ready: bool
    ai_status: str
    latest_summary: Optional[str] = None
    top_reasons: List[str]


class AIInsightResponse(BaseModel):
    total_human_users: int
    total_system_accounts: int
    continuously_learning: bool
    users: List[AIInsightUserResponse]


class DeviceSafetyScanRequest(BaseModel):
    target_id: str = Field(default="quick_all", min_length=2, max_length=128)


class DeviceSafetyWatchRequest(BaseModel):
    enabled: bool


class NetworkRuleCreate(BaseModel):
    ip_address: str
    action: str = "block"  # 'block' or 'allow'
    watchlist: bool = False


class NetworkRuleResponse(BaseModel):
    id: int
    ip_address: str
    action: str
    watchlist: bool
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class SpamScanRequest(BaseModel):
    url: Optional[str] = None
    text: Optional[str] = None


class SpamScanLogResponse(BaseModel):
    id: int
    url: str
    domain: str
    risk_score: float
    threat_type: str
    action_taken: str
    scan_report: str
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class TrafficIngestPayload(BaseModel):
    connections: List[Dict[str, Any]]
    interface_stats: Dict[str, Any]


class WebsiteScanRequest(BaseModel):
    url_or_domain: str
    browser_or_app: Optional[str] = "Browser/System"


class WebsiteAccessLogResponse(BaseModel):
    id: int
    user_id: Optional[int] = None
    username: str
    domain: str
    url: str
    browser_or_app: str
    threat_status: str
    threat_score: float
    category: str
    action_taken: str
    details: Optional[str] = None
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class BlockedWebsiteCreate(BaseModel):
    domain: str
    url_pattern: Optional[str] = None
    reason: Optional[str] = "Malicious domain manual block"
    threat_score: float = 90.0
    category: Optional[str] = "Phishing/Malware"


class BlockedWebsiteResponse(BaseModel):
    id: int
    domain: str
    url_pattern: Optional[str] = None
    reason: str
    threat_score: float
    category: str
    added_by: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class WebsiteWhitelistCreate(BaseModel):
    domain: str
    reason: Optional[str] = "Trusted domain whitelist"
    is_permanent: bool = True


class WebsiteWhitelistResponse(BaseModel):
    id: int
    domain: str
    added_by: str
    reason: str
    is_permanent: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class WebsiteSecurityAlertResponse(BaseModel):
    id: int
    user_id: Optional[int] = None
    username: str
    domain: str
    threat_score: float
    threat_level: str
    category: str
    action_taken: str
    reason: str
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class WebsiteConfigUpdate(BaseModel):
    suspicious_threshold: Optional[float] = None
    high_risk_threshold: Optional[float] = None
    malicious_threshold: Optional[float] = None
    auto_block_threshold: Optional[float] = None
    ai_behavior_sensitivity: Optional[float] = None


class WebsiteStatsResponse(BaseModel):
    total_visited: int
    safe_count: int
    suspicious_count: int
    blocked_count: int
    high_risk_count: int
    average_threat_score: float
    top_blocked_domains: List[Dict[str, Any]]
    threat_categories: List[Dict[str, Any]]
    high_risk_domains: List[Dict[str, Any]]
    browsing_anomalies_count: int
    config: Dict[str, Any]


