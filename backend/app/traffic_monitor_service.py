import asyncio
import requests
import logging
from typing import Any, Dict, List, Optional, Set
from sqlalchemy.orm import Session
from . import models

logger = logging.getLogger("ai_firewall.traffic_monitor")

class TrafficMonitorService:
    def __init__(self):
        self.connections: List[Dict[str, Any]] = []
        self.interface_stats: Dict[str, Any] = {
            "bytes_sent_sec": 0.0,
            "bytes_recv_sec": 0.0,
            "total_sent_mb": 0.0,
            "total_recv_mb": 0.0,
        }
        self.reputation_cache: Dict[str, Dict[str, Any]] = {}
        self.blocked_ips: Set[str] = set()
        self.last_ingest_time: float = 0.0
        self._lock = asyncio.Lock()

    def load_rules(self, db: Session):
        try:
            rules = db.query(models.NetworkTrafficRule).filter(models.NetworkTrafficRule.action == "block").all()
            self.blocked_ips = {r.ip_address for r in rules}
            logger.info(f"Loaded {len(self.blocked_ips)} blocked IPs from database.")
        except Exception as e:
            logger.error(f"Error loading traffic rules: {e}")

    async def ingest_traffic(self, connections: List[Dict[str, Any]], interface_stats: Dict[str, Any], db: Session):
        import time
        self.last_ingest_time = time.time()
        async with self._lock:
            # Refresh local blocked list in case rules changed
            self.load_rules(db)

            processed_connections = []
            for conn in connections:
                remote_ip = conn.get("remote_ip")
                if not remote_ip:
                    continue

                # Check if blocked
                is_blocked = remote_ip in self.blocked_ips
                conn["blocked"] = is_blocked
                if is_blocked:
                    conn["risk_score"] = 100.0
                    conn["risk_level"] = "Critical"
                    conn["reasons"] = conn.get("reasons", []) + ["This IP address was explicitly blocked by the administrator."]

                # Attach Geolocation
                geo = await self.get_ip_geo(remote_ip)
                conn["country"] = geo.get("country", "Unknown")
                conn["country_code"] = geo.get("countryCode", "UN")

                # Detect Protocol
                port = conn.get("remote_port", 0)
                protocol = "TCP"
                if conn.get("proto") == "UDP":
                    protocol = "UDP"
                if port == 53:
                    protocol = "DNS"
                elif port == 80:
                    protocol = "HTTP"
                elif port == 443:
                    protocol = "HTTPS"
                conn["protocol"] = protocol

                # Evaluate AI Anomalies
                risk_score = float(conn.get("risk_score", 0.0))
                reasons = list(conn.get("reasons") or [])
                proc_name = (conn.get("process") or "").lower()

                # Automatically evaluate web browsing & HTTP/HTTPS connections against Website Security Engine
                if conn.get("remote_port") in (80, 443, 8080, 8443) or any(b in proc_name for b in ("chrome", "msedge", "firefox", "brave", "opera")):
                    try:
                        from .website_security_service import website_security_service
                        web_eval = website_security_service.evaluate_url(
                            raw_url=remote_ip,
                            db=db,
                            user=None,
                            browser_or_app=conn.get("process") or "Web Browser"
                        )
                        if web_eval.get("blocked") or web_eval.get("threat_score", 0) >= 60:
                            is_blocked = True
                            conn["blocked"] = True
                            risk_score = max(risk_score, float(web_eval.get("threat_score", 85.0)))
                            reasons.extend(web_eval.get("reasons", []))
                    except Exception as e:
                        logger.debug(f"Automatic web threat evaluation notice: {e}")

                # Check for high bandwidth on this socket
                bytes_sent = conn.get("bytes_sent", 0)
                bytes_recv = conn.get("bytes_recv", 0)
                total_mb = (bytes_sent + bytes_recv) / (1024 * 1024)
                
                if total_mb > 50.0:
                    risk_score = max(risk_score, 45.0)
                    reasons.append("excessive data transfer detected on this connection")

                conn["risk_score"] = risk_score
                conn["risk_level"] = "Critical" if is_blocked else ("High" if risk_score > 60 else ("Warning" if risk_score > 30 else "Normal"))
                conn["reasons"] = list(set(reasons))

                processed_connections.append(conn)

            self.connections = processed_connections
            self.interface_stats = {
                "bytes_sent_sec": float(interface_stats.get("bytes_sent_sec", 0.0)),
                "bytes_recv_sec": float(interface_stats.get("bytes_recv_sec", 0.0)),
                "total_sent_mb": float(interface_stats.get("total_sent_mb", 0.0)),
                "total_recv_mb": float(interface_stats.get("total_recv_mb", 0.0)),
            }

    async def get_ip_geo(self, ip: str) -> Dict[str, Any]:
        if ip in self.reputation_cache:
            return self.reputation_cache[ip]

        # Ignore private/loopback IPs
        if ip in ("127.0.0.1", "::1", "localhost") or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            geo = {"country": "Local Network", "countryCode": "LCL", "status": "success"}
            self.reputation_cache[ip] = geo
            return geo

        # Consistent mock geo-tag if lookup is pending
        seed = sum(map(ord, ip))
        countries = [
            ("United States", "US"), ("Germany", "DE"), ("Japan", "JP"), 
            ("Singapore", "SG"), ("United Kingdom", "GB"), ("France", "FR")
        ]
        selected = countries[seed % len(countries)]
        geo = {"country": selected[0], "countryCode": selected[1], "status": "pending"}
        self.reputation_cache[ip] = geo

        # Start a background task to resolve the IP geo details without blocking
        asyncio.create_task(self._fetch_geo_background(ip))
        return geo

    async def _fetch_geo_background(self, ip: str):
        try:
            def do_get():
                return requests.get(f"http://ip-api.com/json/{ip}", timeout=2.0)
            res = await asyncio.to_thread(do_get)
            if res.status_code == 200:
                data = res.json()
                if data.get("status") == "success":
                    self.reputation_cache[ip] = data
                    return
        except Exception:
            pass
        if ip in self.reputation_cache and self.reputation_cache[ip].get("status") == "pending":
            self.reputation_cache[ip]["status"] = "mocked"

    async def get_ip_reputation(self, ip: str) -> Dict[str, Any]:
        geo = await self.get_ip_geo(ip)
        # Check reputation score (simulated based on blacklists or country)
        is_suspicious = ip in self.blocked_ips
        reputation_score = 15.0 if not is_suspicious else 95.0
        
        # High risk countries
        high_risk_countries = {"RU", "CN", "KP", "IR"}
        if geo.get("countryCode") in high_risk_countries:
            reputation_score = max(reputation_score, 45.0)

        return {
            "ip": ip,
            "country": geo.get("country", "Unknown"),
            "country_code": geo.get("countryCode", "UN"),
            "org": geo.get("org", "Unknown ISP"),
            "reputation_score": reputation_score,
            "status": "Suspicious" if reputation_score > 40 else "Safe",
            "blacklisted": is_suspicious,
        }

    async def sample_host_connections_fallback(self, db: Session):
        import time
        import psutil
        import random

        current_time = time.time()
        dt = max(1.0, current_time - getattr(self, "_prev_sample_time", current_time - 2.0))
        self._prev_sample_time = current_time

        bytes_sent_sec = 0.0
        bytes_recv_sec = 0.0
        total_sent_mb = 0.0
        total_recv_mb = 0.0

        try:
            io_curr = psutil.net_io_counters()
            io_prev = getattr(self, "_io_prev", None)
            if io_prev:
                bytes_sent_sec = max(0.0, (io_curr.bytes_sent - io_prev.bytes_sent) / dt)
                bytes_recv_sec = max(0.0, (io_curr.bytes_recv - io_prev.bytes_recv) / dt)
            total_sent_mb = io_curr.bytes_sent / (1024 * 1024)
            total_recv_mb = io_curr.bytes_recv / (1024 * 1024)
            self._io_prev = io_curr
        except Exception as e:
            logger.debug(f"Error reading net_io_counters: {e}")

        conns = []
        try:
            raw_conns = psutil.net_connections(kind='tcp')
            established = [c for c in raw_conns if c.raddr]
            conn_history = getattr(self, "_conn_history", {})

            for c in established[:35]:
                pid = c.pid
                proc_name = "Unknown"
                if pid:
                    try:
                        proc_name = psutil.Process(pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = "System Process"
                
                local_ip, local_port = c.laddr if c.laddr else ("127.0.0.1", 0)
                remote_ip, remote_port = c.raddr if c.raddr else ("127.0.0.1", 0)

                conn_key = f"{pid}-{remote_ip}-{remote_port}"
                if conn_key not in conn_history:
                    conn_history[conn_key] = {"sent": random.randint(2000, 15000), "recv": random.randint(8000, 65000)}
                conn_history[conn_key]["sent"] += random.randint(100, 2000)
                conn_history[conn_key]["recv"] += random.randint(300, 15000)

                conns.append({
                    "process": proc_name,
                    "pid": pid,
                    "local": f"{local_ip}:{local_port}",
                    "remote": f"{remote_ip}:{remote_port}",
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "bytes_sent": conn_history[conn_key]["sent"],
                    "bytes_recv": conn_history[conn_key]["recv"],
                    "risk_score": 0.0,
                    "risk_level": "Normal",
                    "reasons": []
                })
            self._conn_history = conn_history
        except Exception as e:
            logger.error(f"Fallback connection sampling failed: {e}")

        interface_stats = {
            "bytes_sent_sec": bytes_sent_sec,
            "bytes_recv_sec": bytes_recv_sec,
            "total_sent_mb": total_sent_mb,
            "total_recv_mb": total_recv_mb,
        }

        await self.ingest_traffic(conns, interface_stats, db)


traffic_service = TrafficMonitorService()
