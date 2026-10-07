import asyncio
import psutil
import re
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Callable, Dict, Set, Optional

def format_endpoint(ip: str, port: int) -> str:
    ip_str = str(ip or "")
    if ":" in ip_str and not (ip_str.startswith("[") and ip_str.endswith("]")):
        return f"[{ip_str}]:{port}"
    return f"{ip_str}:{port}"

def normalize_connection_key(l_ip: str, l_port: int, r_ip: str, r_port: int, proto: str = "tcp") -> str:
    ep1 = (str(l_ip), int(l_port))
    ep2 = (str(r_ip), int(r_port))
    if ep1 > ep2:
        ep1, ep2 = ep2, ep1
    return f"{proto}:{format_endpoint(ep1[0], ep1[1])}<->{format_endpoint(ep2[0], ep2[1])}"

def get_app_pids() -> Set[int]:
    pids = {os.getpid()}
    try:
        parent_pid = int(os.environ.get("AI_FIREWALL_PARENT_PID", "0"))
        if parent_pid > 4:
            pids.add(parent_pid)
        ppid = psutil.Process().ppid()
        if ppid > 4:
            pids.add(ppid)
    except Exception:
        pass
    return pids

_current_dir = os.path.dirname(os.path.abspath(__file__))
_backend_dir = os.path.abspath(os.path.join(_current_dir, ".."))
_root_dir = os.path.abspath(os.path.join(_backend_dir, ".."))
for _p in [_backend_dir, _current_dir, _root_dir]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from ai.phishing_detector import PhishingDetector
except ImportError:
    try:
        from backend.ai.phishing_detector import PhishingDetector
    except ImportError:
        from ..ai.phishing_detector import PhishingDetector

try:
    from security.block_manager import block_manager
except ImportError:
    try:
        from backend.security.block_manager import block_manager
    except ImportError:
        from .block_manager import block_manager

try:
    from security.geo_tracker import GeoTracker
except ImportError:
    try:
        from backend.security.geo_tracker import GeoTracker
    except ImportError:
        from .geo_tracker import GeoTracker

detector = PhishingDetector()
geo = GeoTracker()

class LiveMonitor:
    def __init__(self):
        self.running = False
        self.callbacks = []
        self.known_connections: Dict[str, dict] = {}
        self.known_processes: Set[int] = set()
        self.process_info_cache: Dict[int, dict] = {}
        self.clipboard_last = ''
        self._last_net_time: Optional[float] = None
        self._last_net_bytes_recv: Optional[int] = None
        self._last_net_bytes_sent: Optional[int] = None

    def add_callback(self, fn: Callable):
        self.callbacks.append(fn)

    def emit(self, event_type: str, data: dict):
        now_utc = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        event = {
            'id': str(uuid.uuid4()),
            'type': event_type,
            'data': data,
            'timestamp': now_utc
        }
        for cb in self.callbacks:
            try:
                res = cb(event)
                if asyncio.iscoroutine(res):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(res)
                    except RuntimeError:
                        asyncio.run(res)
            except Exception:
                pass

    async def monitor_connections(self):
        """Monitor network connections with 5-tuple normalization, loopback tagging, and no duplicates"""
        while self.running:
            try:
                conns = psutil.net_connections(kind='inet')
                current_cycle_keys = set()
                app_pids = get_app_pids()
                backend_port = int(os.environ.get("AI_FIREWALL_PORT", "8000"))

                for c in conns:
                    if c.status == 'ESTABLISHED' and c.raddr:
                        norm_key = normalize_connection_key(c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port, proto="tcp")
                        if norm_key in current_cycle_keys:
                            # Dual socket end of same connection in this polling sweep; deduplicate
                            continue
                        current_cycle_keys.add(norm_key)

                        if norm_key not in self.known_connections:
                            remote_ip = c.raddr.ip
                            remote_port = c.raddr.port
                            local_ip = c.laddr.ip
                            local_port = c.laddr.port

                            # Identify process
                            try:
                                proc = psutil.Process(c.pid) if c.pid else None
                                proc_name = proc.name() if proc else 'Unknown'
                            except Exception:
                                proc_name = 'Unknown'

                            # Detect loopback and app's own traffic
                            is_loopback = (local_ip in ("127.0.0.1", "::1", "localhost")) and (remote_ip in ("127.0.0.1", "::1", "localhost"))
                            is_backend_port = (local_port == backend_port or remote_port == backend_port)
                            is_app_proc = (c.pid in app_pids) or (proc_name.lower() in ("ai firewall.exe", "aifirewall-backend.exe"))
                            is_app_traffic = (is_loopback and (is_backend_port or is_app_proc)) or is_app_proc

                            is_blocked = block_manager.is_blocked('ip', remote_ip)
                            geo_data = geo.lookup_ip(remote_ip)

                            conn_payload = {
                                'local': format_endpoint(local_ip, local_port),
                                'remote': format_endpoint(remote_ip, remote_port),
                                'local_ip': local_ip,
                                'local_port': local_port,
                                'remote_ip': remote_ip,
                                'remote_port': remote_port,
                                'normalized_key': norm_key,
                                'process': proc_name,
                                'pid': c.pid,
                                'city': geo_data.get('city', ''),
                                'country': geo_data.get('country', ''),
                                'isp': geo_data.get('isp', ''),
                                'is_blocked': is_blocked,
                                'is_proxy': geo_data.get('is_proxy', False),
                                'is_datacenter': geo_data.get('is_datacenter', False),
                                'is_app_traffic': is_app_traffic,
                                'is_loopback': is_loopback,
                                'threat_level': 'HIGH' if is_blocked else 'LOW'
                            }
                            self.known_connections[norm_key] = conn_payload
                            self.emit('new_connection', conn_payload)

                # Connections that closed (key present previously but not in current_cycle_keys)
                closed_keys = set(self.known_connections.keys()) - current_cycle_keys
                for key in closed_keys:
                    conn_data = self.known_connections.pop(key, {})
                    self.emit('connection_closed', {
                        'connection': key,
                        'normalized_key': key,
                        'local': conn_data.get('local', ''),
                        'remote': conn_data.get('remote', ''),
                        'process': conn_data.get('process', 'Unknown'),
                        'is_app_traffic': conn_data.get('is_app_traffic', False),
                        'is_loopback': conn_data.get('is_loopback', False),
                    })
            except Exception:
                pass
            await asyncio.sleep(2)

    async def monitor_processes(self):
        """Monitor new processes starting and ending"""
        while self.running:
            try:
                current = {}
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'cpu_percent', 'memory_percent', 'create_time']):
                    try:
                        current[proc.pid] = proc.info
                    except Exception:
                        pass

                current_pids = set(current.keys())

                if self.known_processes:
                    # New processes
                    new_pids = current_pids - self.known_processes
                    for pid in new_pids:
                        info = current.get(pid, {})
                        name = info.get('name', 'Unknown') or 'Unknown'
                        c_time = info.get('create_time')
                        if c_time:
                            start_time_str = datetime.fromtimestamp(c_time, timezone.utc).strftime('%H:%M:%S')
                        else:
                            start_time_str = datetime.now(timezone.utc).strftime('%H:%M:%S')

                        proc_info = {
                            'pid': pid,
                            'name': name,
                            'exe': info.get('exe', '') or '',
                            'username': info.get('username', '') or '',
                            'start_time': start_time_str,
                        }
                        self.process_info_cache[pid] = proc_info

                        # Check if process is suspicious
                        suspicious_names = [
                            'mimikatz', 'netcat', 'nc.exe', 'nmap', 'wireshark',
                            'keylogger', 'rat', 'backdoor', 'msfconsole'
                        ]
                        is_suspicious = any(s in name.lower() for s in suspicious_names)

                        self.emit('new_process', {
                            'pid': pid,
                            'name': name,
                            'exe': proc_info['exe'],
                            'username': proc_info['username'],
                            'start_time': start_time_str,
                            'cpu': info.get('cpu_percent', 0) or 0,
                            'memory': info.get('memory_percent', 0) or 0,
                            'is_suspicious': is_suspicious,
                            'threat_level': 'CRITICAL' if is_suspicious else 'LOW'
                        })

                    # Closed processes
                    closed_pids = self.known_processes - current_pids
                    for pid in closed_pids:
                        info = self.process_info_cache.pop(pid, {})
                        name = info.get('name', 'Unknown')
                        start_time_str = info.get('start_time', 'Unknown')
                        self.emit('process_closed', {
                            'pid': pid,
                            'name': name,
                            'start_time': start_time_str,
                            'threat_level': 'LOW'
                        })
                else:
                    # Initial process inventory
                    for pid, info in current.items():
                        c_time = info.get('create_time')
                        s_time = datetime.fromtimestamp(c_time, timezone.utc).strftime('%H:%M:%S') if c_time else 'boot'
                        self.process_info_cache[pid] = {
                            'pid': pid,
                            'name': info.get('name', 'Unknown') or 'Unknown',
                            'exe': info.get('exe', '') or '',
                            'username': info.get('username', '') or '',
                            'start_time': s_time,
                        }

                self.known_processes = current_pids
            except Exception:
                pass
            await asyncio.sleep(2)

    def _get_clipboard_text(self) -> str:
        """Retrieve clipboard text using pure Python Windows ctypes API with no child processes."""
        if os.name != "nt":
            return ""
        try:
            import ctypes
            from ctypes import wintypes
            CF_UNICODETEXT = 13
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32

            user32.OpenClipboard.argtypes = [wintypes.HWND]
            user32.OpenClipboard.restype = wintypes.BOOL
            user32.CloseClipboard.argtypes = []
            user32.CloseClipboard.restype = wintypes.BOOL
            user32.GetClipboardData.argtypes = [wintypes.UINT]
            user32.GetClipboardData.restype = wintypes.HANDLE
            user32.IsClipboardFormatAvailable.argtypes = [wintypes.UINT]
            user32.IsClipboardFormatAvailable.restype = wintypes.BOOL

            kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
            kernel32.GlobalLock.restype = wintypes.LPVOID
            kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
            kernel32.GlobalUnlock.restype = wintypes.BOOL

            if not user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
                return ""
            if not user32.OpenClipboard(None):
                return ""
            try:
                h_data = user32.GetClipboardData(CF_UNICODETEXT)
                if not h_data:
                    return ""
                p_data = kernel32.GlobalLock(h_data)
                if not p_data:
                    return ""
                try:
                    return ctypes.wstring_at(p_data)
                finally:
                    kernel32.GlobalUnlock(h_data)
            finally:
                user32.CloseClipboard()
        except Exception:
            try:
                from app.process_utils import run_hidden
            except ImportError:
                from backend.app.process_utils import run_hidden
            res = run_hidden(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', 'Get-Clipboard'], timeout=3)
            return res.stdout.strip() if res.stdout else ""
        return ""

    async def monitor_clipboard(self):
        """Monitor clipboard for phishing URLs and suspicious content using pure Python."""
        while self.running:
            try:
                content = self._get_clipboard_text().strip()
                if content and content != self.clipboard_last and len(content) > 10:
                    self.clipboard_last = content
                    has_url = re.search(r'https?://', content)
                    if has_url or len(content) > 50:
                        analysis = detector.analyze_text(content)
                        if analysis.get('score', 0) > 25:
                            self.emit('clipboard_threat', {
                                'content_preview': content[:100] + '...' if len(content) > 100 else content,
                                'score': analysis.get('score', 0),
                                'risk_level': analysis.get('risk_level', 'MEDIUM'),
                                'indicators': analysis.get('indicators', []),
                                'is_phishing': analysis.get('is_phishing', False),
                                'auto_detected': True
                            })
            except Exception:
                pass
            await asyncio.sleep(2)

    async def monitor_system_stats(self):
        """Push system stats and live network rates every 5 seconds"""
        while self.running:
            try:
                import time
                cpu = psutil.cpu_percent(interval=1)
                ram = psutil.virtual_memory()
                # On Windows, '/' can be checked as 'C:\\' or root partition
                root_path = 'C:\\' if os.name == 'nt' else '/'
                disk = psutil.disk_usage(root_path)
                net = psutil.net_io_counters()

                now = time.time()
                if self._last_net_time is not None and self._last_net_bytes_recv is not None:
                    interval = max(0.1, now - self._last_net_time)
                    recv_diff = max(0, net.bytes_recv - self._last_net_bytes_recv)
                    sent_diff = max(0, net.bytes_sent - self._last_net_bytes_sent)
                    net_recv_rate_mb_s = round((recv_diff / (1024 * 1024)) / interval, 2)
                    net_sent_rate_mb_s = round((sent_diff / (1024 * 1024)) / interval, 2)
                    sample_interval = round(interval, 1)
                else:
                    net_recv_rate_mb_s = 0.0
                    net_sent_rate_mb_s = 0.0
                    sample_interval = 5.0

                self._last_net_time = now
                self._last_net_bytes_recv = net.bytes_recv
                self._last_net_bytes_sent = net.bytes_sent

                self.emit('system_stats', {
                    'cpu_percent': cpu,
                    'ram_percent': ram.percent,
                    'ram_used_gb': round(ram.used / (1024**3), 2),
                    'ram_total_gb': round(ram.total / (1024**3), 2),
                    'disk_percent': disk.percent,
                    'net_bytes_sent': net.bytes_sent,
                    'net_bytes_recv': net.bytes_recv,
                    'net_recv_rate_mb_s': net_recv_rate_mb_s,
                    'net_sent_rate_mb_s': net_sent_rate_mb_s,
                    'sample_interval_sec': sample_interval,
                    'net_total_recv_mb': round(net.bytes_recv / (1024 * 1024), 1),
                })
            except Exception:
                pass
            await asyncio.sleep(5)

    async def start(self):
        self.running = True
        await asyncio.gather(
            self.monitor_connections(),
            self.monitor_processes(),
            self.monitor_clipboard(),
            self.monitor_system_stats()
        )

    def stop(self):
        self.running = False

live_monitor = LiveMonitor()
