import hashlib
import ipaddress
import json
import logging
import os
import sqlite3
import time
from contextlib import closing
from datetime import datetime
from typing import Optional

try:
    from backend.app.security import encrypt_sensitive_value, decrypt_sensitive_value
except ImportError:
    try:
        from app.security import encrypt_sensitive_value, decrypt_sensitive_value
    except ImportError:
        def encrypt_sensitive_value(v):
            return v
        def decrypt_sensitive_value(v):
            return v

logger = logging.getLogger("ai_firewall.geo_tracker")


def hash_ip(ip: str) -> str:
    cleaned = (ip or "").strip().lower()
    return hashlib.sha256(cleaned.encode("utf-8")).hexdigest()


def is_private_or_local_ip(ip: str) -> bool:
    if not ip:
        return True
    cleaned = ip.strip().lower()
    if cleaned in ("127.0.0.1", "localhost", "::1", "testclient", "unknown"):
        return True
    try:
        obj = ipaddress.ip_address(cleaned)
        return (
            obj.is_private
            or obj.is_loopback
            or obj.is_link_local
            or obj.is_reserved
            or obj.is_multicast
        )
    except ValueError:
        return True


class GeoTracker:
    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            try:
                from app.paths import get_database_path
                self.db_path = str(get_database_path())
            except ImportError:
                try:
                    from backend.app.paths import get_database_path
                    self.db_path = str(get_database_path())
                except ImportError:
                    self.db_path = os.path.join(os.environ.get("APPDATA", "."), "AIFirewall", "aifirewall.db")
        else:
            self.db_path = db_path
        self._init_db()

    def _init_db(self):
        try:
            with closing(sqlite3.connect(self.db_path)) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS access_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_email TEXT,
                        ip_address TEXT NOT NULL,
                        city TEXT,
                        region TEXT,
                        country TEXT,
                        country_code TEXT,
                        latitude REAL,
                        longitude REAL,
                        isp TEXT,
                        timezone TEXT,
                        access_time TEXT NOT NULL,
                        user_agent TEXT,
                        action TEXT DEFAULT 'login',
                        threat_score INTEGER DEFAULT 0,
                        is_vpn INTEGER DEFAULT 0,
                        is_proxy INTEGER DEFAULT 0,
                        is_datacenter INTEGER DEFAULT 0
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS geo_cache (
                        ip TEXT PRIMARY KEY,
                        data_json TEXT NOT NULL,
                        cached_at REAL NOT NULL
                    )
                """)
                conn.commit()
        except Exception as exc:
            logger.warning(f"GeoTracker DB initialization warning: {exc}")

    def lookup_ip(self, ip: str) -> dict:
        default = {
            "ip": ip,
            "city": "Unknown",
            "region": "Unknown",
            "country": "Unknown",
            "country_code": "UN",
            "latitude": 0.0,
            "longitude": 0.0,
            "isp": "Unknown",
            "timezone": "Unknown",
            "is_vpn": False,
            "is_proxy": False,
            "is_datacenter": False,
        }

        # 1. Skip private / local IPs without any network lookup
        if is_private_or_local_ip(ip):
            cleaned = (ip or "").strip().lower()
            is_loopback = cleaned in ("127.0.0.1", "localhost", "::1", "testclient")
            return {
                **default,
                "city": "Local" if is_loopback else "Private Network",
                "region": "Local",
                "country": "Local Network",
                "country_code": "LOC",
                "isp": "Local Loopback/Private",
                "timezone": "UTC",
            }

        # 2. Check SQLite cache (keep for 24 hours = 86400 seconds)
        try:
            ip_key = hash_ip(ip)
            with closing(sqlite3.connect(self.db_path)) as conn:
                row = conn.execute(
                    "SELECT data_json, cached_at FROM geo_cache WHERE ip = ?", (ip_key,)
                ).fetchone()
                if not row:
                    row = conn.execute(
                        "SELECT data_json, cached_at FROM geo_cache WHERE ip = ?", (ip,)
                    ).fetchone()
                if row:
                    data_json, cached_at = row
                    if (time.time() - float(cached_at)) < 86400:
                        decrypted = decrypt_sensitive_value(data_json) or data_json
                        cached_geo = json.loads(decrypted)
                        if isinstance(cached_geo, dict):
                            return cached_geo
        except Exception as exc:
            logger.debug(f"Geo cache read error: {exc}")

        # 3. HTTP lookup with 3-second timeout and fallback on offline/rate-limiting
        try:
            import requests

            res = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp,timezone,proxy,hosting",
                timeout=3.0,
            )
            if res.status_code == 200:
                data = res.json()
                if data.get("status") == "success":
                    geo = {
                        "ip": ip,
                        "city": data.get("city") or "Unknown",
                        "region": data.get("regionName") or "Unknown",
                        "country": data.get("country") or "Unknown",
                        "country_code": data.get("countryCode") or "UN",
                        "latitude": float(data.get("lat") or 0.0),
                        "longitude": float(data.get("lon") or 0.0),
                        "isp": data.get("isp") or "Unknown",
                        "timezone": data.get("timezone") or "Unknown",
                        "is_vpn": False,
                        "is_proxy": bool(data.get("proxy")),
                        "is_datacenter": bool(data.get("hosting")),
                    }
                    # Save to SQLite cache with hashed IP key and encrypted payload (24 hours)
                    try:
                        ip_key = hash_ip(ip)
                        encrypted_data = encrypt_sensitive_value(json.dumps(geo)) or json.dumps(geo)
                        with closing(sqlite3.connect(self.db_path)) as conn:
                            conn.execute(
                                "INSERT OR REPLACE INTO geo_cache (ip, data_json, cached_at) VALUES (?, ?, ?)",
                                (ip_key, encrypted_data, time.time()),
                            )
                            conn.commit()
                    except Exception as cache_exc:
                        logger.debug(f"Geo cache write error: {cache_exc}")
                    return geo
        except Exception as exc:
            logger.debug(f"Geo lookup network exception: {exc}")

        return default

    def log_access(
        self,
        ip: str,
        user_email: str = None,
        user_agent: str = None,
        action: str = "login",
        threat_score: int = 0,
    ) -> dict:
        """Log an access event with full geo data (never blocks or raises)"""
        try:
            geo = self.lookup_ip(ip)
        except Exception as exc:
            logger.warning(f"lookup_ip failed safely: {exc}")
            geo = {
                "ip": ip,
                "city": "Unknown",
                "region": "Unknown",
                "country": "Unknown",
                "country_code": "UN",
                "latitude": 0.0,
                "longitude": 0.0,
                "isp": "Unknown",
                "timezone": "Unknown",
                "is_vpn": False,
                "is_proxy": False,
                "is_datacenter": False,
            }

        now = datetime.now().isoformat()

        stored_ip = encrypt_sensitive_value(ip) or ip
        stored_email = encrypt_sensitive_value(user_email) if user_email else user_email

        try:
            with closing(sqlite3.connect(self.db_path)) as conn:
                conn.execute(
                    """
                    INSERT INTO access_logs
                    (user_email, ip_address, city, region, country, country_code,
                     latitude, longitude, isp, timezone, access_time, user_agent,
                     action, threat_score, is_vpn, is_proxy, is_datacenter)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        stored_email,
                        stored_ip,
                        geo["city"],
                        geo["region"],
                        geo["country"],
                        geo["country_code"],
                        geo["latitude"],
                        geo["longitude"],
                        geo["isp"],
                        geo["timezone"],
                        now,
                        user_agent,
                        action,
                        threat_score,
                        1 if geo["is_vpn"] else 0,
                        1 if geo["is_proxy"] else 0,
                        1 if geo["is_datacenter"] else 0,
                    ),
                )
                conn.commit()
        except Exception as exc:
            logger.warning(f"Failed to record access log in SQLite: {exc}")

        return {
            **geo,
            "access_time": now,
            "user_email": user_email,
            "action": action,
            "threat_score": threat_score,
        }

    def get_access_logs(self, user_email: str = None, limit: int = 100) -> list:
        try:
            with closing(sqlite3.connect(self.db_path)) as conn:
                rows = conn.execute(
                    "SELECT * FROM access_logs ORDER BY access_time DESC LIMIT ?",
                    (max(limit, 200),),
                ).fetchall()
            cols = [
                "id",
                "user_email",
                "ip_address",
                "city",
                "region",
                "country",
                "country_code",
                "latitude",
                "longitude",
                "isp",
                "timezone",
                "access_time",
                "user_agent",
                "action",
                "threat_score",
                "is_vpn",
                "is_proxy",
                "is_datacenter",
            ]
            results = []
            for row in rows:
                item = dict(zip(cols, row))
                item["ip_address"] = decrypt_sensitive_value(item["ip_address"]) or item["ip_address"]
                if item["user_email"]:
                    item["user_email"] = decrypt_sensitive_value(item["user_email"]) or item["user_email"]
                if user_email and item["user_email"] != user_email:
                    continue
                results.append(item)
                if len(results) >= limit:
                    break
            return results
        except Exception as exc:
            logger.warning(f"get_access_logs error: {exc}")
            return []
