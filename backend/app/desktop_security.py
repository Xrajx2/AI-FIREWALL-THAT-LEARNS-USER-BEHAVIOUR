import ipaddress
import os
import platform
import re
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is an optional runtime dependency in some deployments.
    psutil = None

from pydantic import BaseModel, Field

from .admin_utils import is_admin, admin_required_response
from .risk import score_to_recommended_action, score_to_risk_level


class TextScanRequest(BaseModel):
    source: str = Field(default="clipboard", min_length=2, max_length=32)
    text: str = Field(min_length=1, max_length=20000)


class UrlScanRequest(BaseModel):
    url: str = Field(min_length=3, max_length=4096)


class FirewallRuleRequest(BaseModel):
    application_path: str = Field(min_length=2, max_length=1024)
    action: str = Field(default="block", pattern="^(allow|block)$")
    direction: str = Field(default="out", pattern="^(in|out)$")
    rule_name: Optional[str] = Field(default=None, max_length=180)


class DesktopSecurityService:
    def __init__(self):
        self._last_net_io: Dict[str, Any] = {}

    def get_security_center(self) -> Dict[str, Any]:
        process_snapshot = self.get_process_snapshot()
        traffic_snapshot = self.get_traffic_snapshot()
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": platform.node() or "localhost",
            "platform": platform.platform(),
            "startup": {
                "managed_by": "electron",
                "enabled_hint": "Electron enables Windows login startup with app.setLoginItemSettings.",
            },
            "processes": process_snapshot,
            "traffic": traffic_snapshot,
            "threat_history": self._build_threat_history(process_snapshot, traffic_snapshot),
            "resource_mode": {
                "poll_interval_seconds": 3,
                "collector": "psutil-and-windows-netsh",
                "low_resource_notes": [
                    "Snapshots are computed on demand for dashboard polling.",
                    "Electron starts hidden to tray and reuses the FastAPI service.",
                    "Heavy packet capture is avoided unless a future driver integration is added.",
                ],
            },
        }

    def get_process_snapshot(self) -> Dict[str, Any]:
        if psutil is None:
            return {
                "count": 0,
                "top": [],
                "suspicious": [],
                "errors": ["psutil is not installed, so process telemetry is unavailable."],
            }

        rows: List[Dict[str, Any]] = []
        suspicious: List[Dict[str, Any]] = []
        for proc in psutil.process_iter(["pid", "name", "exe", "username", "cpu_percent", "memory_info", "cmdline"]):
            try:
                info = proc.info
                name = info.get("name") or "unknown"
                memory_mb = round((info.get("memory_info").rss if info.get("memory_info") else 0) / 1024 / 1024, 2)
                row = {
                    "pid": info.get("pid"),
                    "name": name,
                    "path": info.get("exe") or "",
                    "user": info.get("username") or "",
                    "cpu": round(float(info.get("cpu_percent") or 0.0), 2),
                    "memory_mb": memory_mb,
                    "risk": self._score_process(name, info.get("exe") or "", info.get("cmdline") or []),
                }
                rows.append(row)
                if row["risk"]["score"] >= 45:
                    suspicious.append(row)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        rows.sort(key=lambda item: (item["cpu"], item["memory_mb"]), reverse=True)
        suspicious.sort(key=lambda item: item["risk"]["score"], reverse=True)
        return {
            "count": len(rows),
            "top": rows[:15],
            "suspicious": suspicious[:10],
            "errors": [],
        }

    def get_traffic_snapshot(self) -> Dict[str, Any]:
        connections, is_limited = self._collect_connections()
        now = datetime.now(timezone.utc)
        aggregate = self._collect_net_speed(now)
        process_counter = Counter(item.get("process") or "Unknown" for item in connections)
        app_rows = []
        for process_name, count in process_counter.most_common(12):
            app_connections = [item for item in connections if item.get("process") == process_name]
            highest_risk = max((item["risk"]["score"] for item in app_connections), default=0.0)
            app_rows.append(
                {
                    "application": process_name,
                    "connection_count": count,
                    "remote_ips": sorted({item["remote_ip"] for item in app_connections if item.get("remote_ip")})[:8],
                    "remote_ports": sorted({item["remote_port"] for item in app_connections if item.get("remote_port")})[:8],
                    "upload_kbps": aggregate["upload_kbps"],
                    "download_kbps": aggregate["download_kbps"],
                    "bandwidth_kbps": aggregate["upload_kbps"] + aggregate["download_kbps"],
                    "risk_score": highest_risk,
                    "risk_level": score_to_risk_level(highest_risk),
                }
            )

        suspicious = [item for item in connections if item["risk"]["score"] >= 45]
        suspicious.sort(key=lambda item: item["risk"]["score"], reverse=True)
        return {
            "timestamp": now.isoformat(),
            "connection_count": len(connections),
            "applications": app_rows,
            "connections": connections[:50],
            "suspicious_connections": suspicious[:12],
            "aggregate": aggregate,
            "is_limited_view": is_limited,
            "view_mode": "limited view (run as Administrator)" if is_limited else "full",
            "message": "limited view (run as Administrator)" if is_limited else None,
            "errors": ["limited view (run as Administrator)"] if is_limited else [],
        }

    def scan_text(self, payload: TextScanRequest) -> Dict[str, Any]:
        text = payload.text.strip()
        lowered = text.lower()
        score = 0.0
        reasons: List[str] = []
        spam_terms = {
            "urgent": 8,
            "verify your account": 18,
            "password expires": 14,
            "gift card": 12,
            "wire transfer": 15,
            "crypto wallet": 12,
            "lottery": 18,
            "limited time": 8,
            "click here": 10,
            "invoice attached": 8,
        }
        for term, weight in spam_terms.items():
            if term in lowered:
                score += weight
                reasons.append(f"Contains spam/phishing phrase: {term}")

        urls = re.findall(r"https?://[^\s)>\"]+", text)
        for url in urls[:5]:
            url_result = self.scan_url(UrlScanRequest(url=url))
            if url_result["score"] >= 45:
                score += 24
                reasons.append(f"Suspicious URL detected: {url_result['host']}")

        if len(re.findall(r"[A-Z]{5,}", text)) >= 3:
            score += 8
            reasons.append("Contains repeated all-caps emphasis.")
        if len(re.findall(r"[!?]", text)) >= 5:
            score += 7
            reasons.append("Uses excessive urgency punctuation.")

        normalized_score = round(min(100.0, score), 2)
        return {
            "source": payload.source,
            "score": normalized_score,
            "risk_level": score_to_risk_level(normalized_score),
            "recommended_action": score_to_recommended_action(normalized_score),
            "is_spam": normalized_score >= 45,
            "reasons": reasons[:8] or ["No obvious spam or phishing indicators found."],
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }

    def scan_url(self, payload: UrlScanRequest) -> Dict[str, Any]:
        raw_url = payload.url.strip()
        parsed = urlparse(raw_url if "://" in raw_url else f"https://{raw_url}")
        host = (parsed.hostname or "").lower()
        path = parsed.path or ""
        score = 0.0
        reasons: List[str] = []

        if not host:
            score += 40
            reasons.append("URL does not contain a valid hostname.")
        if parsed.scheme not in {"https", "http"}:
            score += 20
            reasons.append("URL uses an uncommon scheme.")
        if parsed.scheme == "http":
            score += 12
            reasons.append("URL does not use HTTPS.")
        if self._is_ip_literal(host):
            score += 25
            reasons.append("Hostname is a raw IP address.")
        if len(host.split(".")) >= 5:
            score += 12
            reasons.append("Hostname uses many subdomains.")
        if "@" in raw_url:
            score += 18
            reasons.append("URL contains @ redirection syntax.")
        if any(token in host for token in ("xn--", "login-", "secure-", "verify-", "account-")):
            score += 15
            reasons.append("Hostname uses suspicious account/security wording.")
        if any(token in path.lower() for token in ("login", "verify", "password", "wallet", "invoice")):
            score += 8
            reasons.append("Path asks for credential or payment context.")

        normalized_score = round(min(100.0, score), 2)
        return {
            "url": raw_url,
            "host": host,
            "score": normalized_score,
            "risk_level": score_to_risk_level(normalized_score),
            "recommended_action": score_to_recommended_action(normalized_score),
            "is_malicious": normalized_score >= 55,
            "reasons": reasons[:8] or ["No obvious phishing indicators found."],
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }

    def apply_firewall_rule(self, payload: FirewallRuleRequest) -> Dict[str, Any]:
        app_path = str(Path(payload.application_path).expanduser())
        base_name = payload.rule_name or f"AIFirewall-{payload.action.title()}-{Path(app_path).name}"
        rule_name = base_name if base_name.startswith("AIFirewall-") else f"AIFirewall-{base_name}"
        if os.name != "nt":
            return {
                "status": "unsupported",
                "message": "Windows firewall rules can only be applied on Windows.",
                "rule_name": rule_name,
            }

        if not is_admin():
            return {
                "status": "needs_admin",
                "error": "admin_required",
                "message": "Windows firewall rules require Administrator privileges. Run AI Firewall as Administrator to apply rules.",
                "rule_name": rule_name,
            }

        netsh_action = "block" if payload.action == "block" else "allow"
        command = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            f"dir={payload.direction}",
            f"action={netsh_action}",
            f"program={app_path}",
            "enable=yes",
        ]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
        return {
            "status": "applied" if completed.returncode == 0 else "failed",
            "rule_name": rule_name,
            "application_path": app_path,
            "action": payload.action,
            "direction": payload.direction,
            "stdout": (completed.stdout or "").strip(),
            "stderr": (completed.stderr or "").strip(),
        }

    def _collect_connections(self) -> tuple[List[Dict[str, Any]], bool]:
        if psutil is None:
            return [], False

        pid_to_name: Dict[int, str] = {}
        connections: List[Dict[str, Any]] = []
        is_limited = False
        raw_conns: List[tuple[Any, Optional[int]]] = []

        try:
            net_connections = psutil.net_connections(kind="inet")
            for conn in net_connections:
                raw_conns.append((conn, conn.pid))
        except (psutil.AccessDenied, PermissionError):
            is_limited = True
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    pconns = proc.connections(kind="inet") if hasattr(proc, "connections") else proc.net_connections(kind="inet")
                    for conn in pconns:
                        raw_conns.append((conn, proc.info.get("pid")))
                        if proc.info.get("pid"):
                            pid_to_name[proc.info["pid"]] = proc.info.get("name") or f"PID {proc.info['pid']}"
                except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
                    continue
        except Exception:
            return [], False

        for conn, pid in raw_conns:
            if not getattr(conn, "raddr", None):
                continue
            if pid and pid not in pid_to_name:
                try:
                    pid_to_name[pid] = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pid_to_name[pid] = f"PID {pid}"
            process = pid_to_name.get(pid or -1, "System")
            remote_ip = conn.raddr.ip
            remote_port = int(conn.raddr.port)
            risk = self._score_connection(process, remote_ip, remote_port)
            connections.append(
                {
                    "pid": pid,
                    "process": process,
                    "status": conn.status,
                    "local_ip": conn.laddr.ip if conn.laddr else "",
                    "local_port": int(conn.laddr.port) if conn.laddr else 0,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "risk": risk,
                    "risk_score": risk["score"],
                    "risk_level": risk["level"],
                    "reasons": risk["reasons"],
                }
            )
        connections.sort(key=lambda item: item["risk_score"], reverse=True)
        return connections, is_limited

    def _collect_net_speed(self, now: datetime) -> Dict[str, Any]:
        if psutil is None:
            return {"upload_kbps": 0.0, "download_kbps": 0.0, "bytes_sent": 0, "bytes_recv": 0}

        counters = psutil.net_io_counters()
        previous = self._last_net_io
        self._last_net_io = {
            "timestamp": now,
            "bytes_sent": counters.bytes_sent,
            "bytes_recv": counters.bytes_recv,
        }
        if not previous:
            return {
                "upload_kbps": 0.0,
                "download_kbps": 0.0,
                "bytes_sent": counters.bytes_sent,
                "bytes_recv": counters.bytes_recv,
            }

        elapsed = max(1.0, (now - previous["timestamp"]).total_seconds())
        upload_kbps = max(0.0, counters.bytes_sent - previous["bytes_sent"]) * 8 / elapsed / 1000
        download_kbps = max(0.0, counters.bytes_recv - previous["bytes_recv"]) * 8 / elapsed / 1000
        return {
            "upload_kbps": round(upload_kbps, 2),
            "download_kbps": round(download_kbps, 2),
            "bytes_sent": counters.bytes_sent,
            "bytes_recv": counters.bytes_recv,
        }

    def _score_process(self, name: str, exe: str, cmdline: List[str]) -> Dict[str, Any]:
        score = 0.0
        reasons: List[str] = []
        process_name = (name or "").lower()
        command_text = " ".join(cmdline).lower()
        suspicious_names = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}
        if process_name in suspicious_names:
            score += 22
            reasons.append("Administrative or script-capable process.")
        if any(token in command_text for token in ("encodedcommand", "downloadstring", "bypass", "hidden", "invoke-webrequest")):
            score += 38
            reasons.append("Command line contains suspicious execution flags.")
        if exe and "\\temp\\" in exe.lower():
            score += 18
            reasons.append("Executable is running from a temporary directory.")
        normalized = round(min(100.0, score), 2)
        return {
            "score": normalized,
            "level": score_to_risk_level(normalized),
            "recommended_action": score_to_recommended_action(normalized),
            "reasons": reasons or ["No suspicious process indicators found."],
        }

    def _score_connection(self, process: str, remote_ip: str, remote_port: int) -> Dict[str, Any]:
        score = 0.0
        reasons: List[str] = []
        scope = self._classify_ip(remote_ip)
        process_key = (process or "").lower()
        if scope == "public":
            score += 14
            reasons.append("Connection goes to a public IP.")
        if remote_port not in {53, 80, 123, 443, 853}:
            score += 10
            reasons.append("Connection uses a less common remote port.")
        if remote_port in {21, 23, 25, 135, 139, 445, 1433, 3389, 4444, 5555, 6667}:
            score += 25
            reasons.append("Connection uses a high-risk remote port.")
        if process_key in {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "python.exe"}:
            score += 24
            reasons.append("Connection originates from a script-capable process.")
        normalized = round(min(100.0, score), 2)
        return {
            "score": normalized,
            "level": score_to_risk_level(normalized),
            "recommended_action": score_to_recommended_action(normalized),
            "ip_scope": scope,
            "reasons": reasons or ["Connection matches expected network behavior."],
        }

    def _build_threat_history(self, process_snapshot: Dict[str, Any], traffic_snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
        rows = []
        for proc in process_snapshot.get("suspicious", [])[:5]:
            rows.append(
                {
                    "type": "process",
                    "title": proc["name"],
                    "score": proc["risk"]["score"],
                    "risk_level": proc["risk"]["level"],
                    "summary": proc["risk"]["reasons"][0],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
        for conn in traffic_snapshot.get("suspicious_connections", [])[:5]:
            rows.append(
                {
                    "type": "network",
                    "title": f"{conn['process']} -> {conn['remote_ip']}:{conn['remote_port']}",
                    "score": conn["risk_score"],
                    "risk_level": conn["risk_level"],
                    "summary": conn["reasons"][0],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
        rows.sort(key=lambda item: item["score"], reverse=True)
        return rows[:10]

    @staticmethod
    def _is_ip_literal(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    @staticmethod
    def _classify_ip(value: str) -> str:
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            return "unknown"
        if parsed.is_loopback:
            return "loopback"
        if parsed.is_private:
            return "private"
        if parsed.is_link_local:
            return "link_local"
        if parsed.is_reserved:
            return "reserved"
        return "public"


desktop_security_service = DesktopSecurityService()
