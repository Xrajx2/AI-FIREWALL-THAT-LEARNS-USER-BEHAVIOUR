import re
import ssl
import socket
import logging
import urllib.parse
import datetime
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session

from . import models
from .website_blocker import website_blocker
from .ai.scoring_engine import engine as ai_engine

logger = logging.getLogger("ai_firewall.website_security")

KNOWN_SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".click", ".download", ".space", ".monster",
    ".cfd", ".rest", ".bid", ".cam", ".sbs", ".icu", ".quest", ".gq",
    ".ml", ".cf", ".ga", ".work", ".buzz", ".fit", ".surf"
}

HIGH_PROFILE_BRANDS = [
    "paypal", "chase", "bankofamerica", "wellsfargo", "facebook", "google",
    "amazon", "netflix", "binance", "coinbase", "apple", "microsoft",
    "instagram", "github", "twitter", "linkedin", "steampowered", "wikipedia"
]

DEFAULT_CONFIG = {
    "suspicious_threshold": 30.0,
    "high_risk_threshold": 60.0,
    "malicious_threshold": 80.0,
    "auto_block_threshold": 80.0,
    "ai_behavior_sensitivity": 0.2
}


def sanitize_url(raw_url: str) -> Tuple[str, str]:
    """
    Normalizes URL and strips sensitive query param values for privacy.
    Returns (domain, sanitized_url)
    """
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "http://" + raw_url

    parsed = urllib.parse.urlparse(raw_url)
    domain = parsed.netloc.split(":")[0].lower()
    if domain.startswith("www."):
        domain = domain[4:]

    # Sanitize query parameters (e.g. ?token=secret -> ?token=[REDACTED])
    if parsed.query:
        query_pairs = urllib.parse.parse_qsl(parsed.query)
        sanitized_pairs = []
        sensitive_keys = {"token", "pass", "password", "secret", "auth", "key", "api_key", "session", "code"}
        for k, v in query_pairs:
            if k.lower() in sensitive_keys:
                sanitized_pairs.append((k, "[REDACTED]"))
            else:
                sanitized_pairs.append((k, v))
        clean_query = urllib.parse.urlencode(sanitized_pairs, safe='[]')
        sanitized_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, clean_query, ""))
    else:
        sanitized_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

    return domain, sanitized_url


class WebsiteSecurityService:
    def __init__(self):
        pass

    def get_config(self, db: Session) -> Dict[str, float]:
        config = dict(DEFAULT_CONFIG)
        try:
            db_configs = db.query(models.WebsiteConfig).all()
            for item in db_configs:
                try:
                    config[item.key] = float(item.value)
                except ValueError:
                    pass
        except Exception as e:
            logger.error(f"Error reading WebsiteConfig from DB: {e}")
        return config

    def update_config(self, db: Session, updates: Dict[str, float]) -> Dict[str, float]:
        for k, v in updates.items():
            if v is not None:
                existing = db.query(models.WebsiteConfig).filter(models.WebsiteConfig.key == k).first()
                if existing:
                    existing.value = str(v)
                else:
                    db.add(models.WebsiteConfig(key=k, value=str(v), description=f"Config setting {k}"))
        db.commit()
        return self.get_config(db)

    def is_whitelisted(self, domain: str, db: Session) -> bool:
        entry = db.query(models.WebsiteWhitelist).filter(
            models.WebsiteWhitelist.domain == domain
        ).first()
        if not entry:
            return False
        if not entry.is_permanent and entry.expires_at and entry.expires_at < datetime.datetime.utcnow():
            return False
        return True

    def is_blacklisted(self, domain: str, db: Session) -> Optional[models.BlockedWebsite]:
        return db.query(models.BlockedWebsite).filter(
            models.BlockedWebsite.domain == domain,
            models.BlockedWebsite.is_active == True
        ).first()

    def evaluate_url(self, raw_url: str, db: Session, user: Optional[models.User] = None, browser_or_app: str = "Browser/System") -> Dict[str, Any]:
        domain, sanitized_url = sanitize_url(raw_url)
        config = self.get_config(db)
        username = user.username if user else "System User"
        user_id = user.id if user else None

        # 1. Whitelist Check
        if self.is_whitelisted(domain, db):
            log = models.WebsiteAccessLog(
                user_id=user_id,
                username=username,
                domain=domain,
                url=sanitized_url,
                browser_or_app=browser_or_app,
                threat_status="Safe",
                threat_score=0.0,
                category="Whitelisted",
                action_taken="allowed",
                details="Domain is explicitly whitelisted by Administrator."
            )
            db.add(log)
            db.commit()
            db.refresh(log)
            return {
                "id": log.id,
                "domain": domain,
                "url": sanitized_url,
                "threat_status": "Safe",
                "threat_score": 0.0,
                "category": "Whitelisted",
                "action_taken": "allowed",
                "reasons": ["Domain is explicitly whitelisted by Administrator."],
                "blocked": False
            }

        # 2. Blacklist / Threat Intel Check
        blacklisted = self.is_blacklisted(domain, db)
        threat_intel = db.query(models.WebsiteThreat).filter(
            models.WebsiteThreat.domain == domain,
            models.WebsiteThreat.is_active == True
        ).first()

        risk_score = 0.0
        reasons: List[str] = []
        category = "Safe"

        if blacklisted:
            risk_score = max(risk_score, blacklisted.threat_score or 90.0)
            reasons.append(f"Domain is present on active blocklist: {blacklisted.reason}")
            category = blacklisted.category or "Blocked Domain"

        if threat_intel:
            risk_score = max(risk_score, threat_intel.risk_score or 85.0)
            reasons.append(f"Threat Intelligence Feed flagged domain ({threat_intel.threat_category})")
            category = threat_intel.threat_category

        # 3. Rule-Based & Pattern Risk Analysis
        parsed = urllib.parse.urlparse(sanitized_url)

        # TLD Check
        tld = "." + domain.split(".")[-1] if "." in domain else ""
        if tld in KNOWN_SUSPICIOUS_TLDS:
            risk_score += 30.0
            reasons.append(f"Domain uses high-risk suspicious TLD ({tld})")
            category = "Suspicious TLD"

        # Typosquatting / Brand Imitation
        for brand in HIGH_PROFILE_BRANDS:
            if brand in domain and domain != f"{brand}.com" and domain != f"{brand}.org" and domain != f"{brand}.ac.in":
                # Check if it's an exact match or suspicious sub/hyphen domain like paypal-security.xyz
                risk_score += 45.0
                reasons.append(f"Possible typosquatting or phishing brand imitation target: '{brand}'")
                category = "Phishing"
                break

        # Excessive Subdomains Check
        subdomains = domain.split(".")
        if len(subdomains) > 4:
            risk_score += 20.0
            reasons.append(f"Excessive subdomain depth ({len(subdomains)} levels) detected")

        # IP Address Domain Check
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            risk_score += 25.0
            reasons.append("Direct IP address connection instead of domain name")
            category = "Suspicious Host"

        # Suspicious URL Keywords
        suspicious_keywords = ["login", "signin", "banking", "verify", "secure", "account-update", "credential", "wallet", "airdrop", "free-crypto"]
        path_lower = parsed.path.lower()
        matched_kw = [kw for kw in suspicious_keywords if kw in path_lower or kw in domain]
        if matched_kw:
            if risk_score > 20 or category in ("Phishing", "Suspicious TLD"):
                risk_score += 25.0
                reasons.append(f"Suspicious login/security keywords in URL path: {', '.join(matched_kw)}")

        # Unencrypted HTTP Check
        if parsed.scheme == "http" and domain not in ("localhost", "127.0.0.1"):
            risk_score += 15.0
            reasons.append("Unencrypted connection protocol (HTTP)")

        # 4. AI & User Behavioral Anomaly Scoring
        if user_id:
            # Check user browsing drift
            recent_logs = db.query(models.WebsiteAccessLog).filter(
                models.WebsiteAccessLog.user_id == user_id,
                models.WebsiteAccessLog.timestamp >= datetime.datetime.utcnow() - datetime.timedelta(minutes=15)
            ).all()

            high_risk_recent = [l for l in recent_logs if l.threat_score >= config["suspicious_threshold"]]
            if len(high_risk_recent) >= 3:
                risk_score += 30.0
                reasons.append(f"Behavioral Anomaly: User accessed {len(high_risk_recent)} suspicious/unusual domains within 15 minutes.")
                category = "Browsing Anomaly"

        risk_score = float(min(100.0, max(0.0, risk_score)))

        # Categorize Threat Status
        if risk_score >= config["malicious_threshold"]:
            threat_status = "Malicious"
            if category == "Safe": category = "Malicious"
        elif risk_score >= config["high_risk_threshold"]:
            threat_status = "High Risk"
            if category == "Safe": category = "High Risk"
        elif risk_score >= config["suspicious_threshold"]:
            threat_status = "Suspicious"
            if category == "Safe": category = "Suspicious"
        else:
            threat_status = "Safe"
            category = "Safe"

        # Determine Action (Block if score >= auto_block_threshold)
        should_block = risk_score >= config["auto_block_threshold"] or blacklisted is not None
        action_taken = "blocked" if should_block else ("monitored" if threat_status != "Safe" else "allowed")

        # 5. OS-Level Host Blocking Enforcement
        if should_block:
            website_blocker.block_domain_os_level(domain)

            # Create Security Alert in DB
            alert = models.WebsiteSecurityAlert(
                user_id=user_id,
                username=username,
                domain=domain,
                threat_score=risk_score,
                threat_level=threat_status,
                category=category,
                action_taken="Blocked",
                reason="; ".join(reasons) if reasons else "Harmful website threshold exceeded."
            )
            db.add(alert)

            # Also trigger main UserActivity Threat log if critical
            if user_id:
                user_act = models.UserActivity(
                    user_id=user_id,
                    action_type="harmful_website_blocked",
                    device="Host Endpoint",
                    network_activity=1.0,
                    details=f"Blocked domain '{domain}' with Threat Score {risk_score:.1f}. Reasons: {'; '.join(reasons[:2])}",
                    risk_score=risk_score,
                    risk_level=threat_status
                )
                db.add(user_act)

        # Log Access Event
        access_log = models.WebsiteAccessLog(
            user_id=user_id,
            username=username,
            domain=domain,
            url=sanitized_url,
            browser_or_app=browser_or_app,
            threat_status=threat_status,
            threat_score=risk_score,
            category=category,
            action_taken=action_taken,
            details="; ".join(reasons) if reasons else "Clean website access."
        )
        db.add(access_log)
        db.commit()
        db.refresh(access_log)

        return {
            "id": access_log.id,
            "domain": domain,
            "url": sanitized_url,
            "threat_status": threat_status,
            "threat_score": risk_score,
            "category": category,
            "action_taken": action_taken,
            "reasons": reasons,
            "blocked": should_block,
            "timestamp": access_log.timestamp
        }

    def get_stats(self, db: Session) -> Dict[str, Any]:
        logs = db.query(models.WebsiteAccessLog).all()
        config = self.get_config(db)

        total_visited = len(logs)
        safe_count = sum(1 for l in logs if l.threat_status == "Safe")
        suspicious_count = sum(1 for l in logs if l.threat_status == "Suspicious")
        high_risk_count = sum(1 for l in logs if l.threat_status == "High Risk")
        blocked_count = sum(1 for l in logs if l.action_taken == "blocked" or l.threat_status == "Malicious")

        avg_score = (sum(l.threat_score for l in logs) / total_visited) if total_visited > 0 else 0.0

        # Top blocked domains
        blocked_logs = [l for l in logs if l.action_taken == "blocked"]
        domain_counts = {}
        for l in blocked_logs:
            domain_counts[l.domain] = domain_counts.get(l.domain, 0) + 1
        top_blocked = [{"domain": k, "count": v} for k, v in sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:5]]

        # Category distribution
        cat_counts = {}
        for l in logs:
            cat_counts[l.category] = cat_counts.get(l.category, 0) + 1
        threat_cats = [{"category": k, "count": v} for k, v in cat_counts.items()]

        # High risk domains
        high_risk_list = db.query(models.WebsiteAccessLog).filter(
            models.WebsiteAccessLog.threat_score >= config["high_risk_threshold"]
        ).order_by(models.WebsiteAccessLog.timestamp.desc()).limit(10).all()

        high_risk_formatted = [
            {
                "domain": l.domain,
                "score": l.threat_score,
                "category": l.category,
                "username": l.username,
                "action": l.action_taken,
                "timestamp": l.timestamp.strftime("%H:%M:%S")
            }
            for l in high_risk_list
        ]

        anomalies_count = db.query(models.WebsiteSecurityAlert).filter(
            models.WebsiteSecurityAlert.category == "Browsing Anomaly"
        ).count()

        return {
            "total_visited": total_visited,
            "safe_count": safe_count,
            "suspicious_count": suspicious_count,
            "blocked_count": blocked_count,
            "high_risk_count": high_risk_count,
            "average_threat_score": round(avg_score, 1),
            "top_blocked_domains": top_blocked,
            "threat_categories": threat_cats,
            "high_risk_domains": high_risk_formatted,
            "browsing_anomalies_count": anomalies_count,
            "config": config
        }


website_security_service = WebsiteSecurityService()
