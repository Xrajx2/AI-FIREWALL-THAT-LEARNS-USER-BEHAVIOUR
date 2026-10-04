import asyncio
import psutil
import re
import os
import sys
from datetime import datetime
from typing import Callable

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
        self.known_connections = set()
        self.known_processes = set()
        self.clipboard_last = ''

    def add_callback(self, fn: Callable):
        self.callbacks.append(fn)

    def emit(self, event_type: str, data: dict):
        event = {
            'type': event_type,
            'data': data,
            'timestamp': datetime.now().isoformat()
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
        """Monitor new network connections in real time"""
        while self.running:
            try:
                conns = psutil.net_connections(kind='inet')
                current = set()
                for c in conns:
                    if c.status == 'ESTABLISHED' and c.raddr:
                        key = f"{c.laddr.ip}:{c.laddr.port}->{c.raddr.ip}:{c.raddr.port}"
                        current.add(key)
                        if key not in self.known_connections:
                            # New connection detected
                            remote_ip = c.raddr.ip
                            is_blocked = block_manager.is_blocked('ip', remote_ip)
                            geo_data = geo.lookup_ip(remote_ip)

                            # Get process name
                            try:
                                proc = psutil.Process(c.pid) if c.pid else None
                                proc_name = proc.name() if proc else 'Unknown'
                            except Exception:
                                proc_name = 'Unknown'

                            self.emit('new_connection', {
                                'local': f"{c.laddr.ip}:{c.laddr.port}",
                                'remote_ip': remote_ip,
                                'remote_port': c.raddr.port,
                                'process': proc_name,
                                'pid': c.pid,
                                'city': geo_data.get('city', 'Unknown'),
                                'country': geo_data.get('country', 'Unknown'),
                                'isp': geo_data.get('isp', 'Unknown'),
                                'is_blocked': is_blocked,
                                'is_proxy': geo_data.get('is_proxy', False),
                                'is_datacenter': geo_data.get('is_datacenter', False),
                                'threat_level': 'HIGH' if is_blocked else 'LOW'
                            })

                # Connections that closed
                closed = self.known_connections - current
                for key in closed:
                    self.emit('connection_closed', {'connection': key})

                self.known_connections = current
            except Exception:
                pass
            await asyncio.sleep(2)

    async def monitor_processes(self):
        """Monitor new processes starting"""
        while self.running:
            try:
                current = {}
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'cpu_percent', 'memory_percent']):
                    try:
                        current[proc.pid] = proc.info
                    except Exception:
                        pass

                current_pids = set(current.keys())
                new_pids = current_pids - self.known_processes

                for pid in new_pids:
                    info = current.get(pid, {})
                    name = info.get('name', 'Unknown') or 'Unknown'

                    # Check if process is suspicious
                    suspicious_names = [
                        'mimikatz', 'netcat', 'nc.exe', 'nmap', 'wireshark',
                        'keylogger', 'rat', 'backdoor', 'msfconsole'
                    ]
                    is_suspicious = any(s in name.lower() for s in suspicious_names)

                    self.emit('new_process', {
                        'pid': pid,
                        'name': name,
                        'exe': info.get('exe', '') or '',
                        'username': info.get('username', '') or '',
                        'cpu': info.get('cpu_percent', 0) or 0,
                        'memory': info.get('memory_percent', 0) or 0,
                        'is_suspicious': is_suspicious,
                        'threat_level': 'CRITICAL' if is_suspicious else 'LOW'
                    })

                self.known_processes = current_pids
            except Exception:
                pass
            await asyncio.sleep(3)

    async def monitor_clipboard(self):
        """Monitor clipboard for phishing URLs and suspicious content"""
        while self.running:
            try:
                import subprocess
                result = subprocess.run(
                    ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', 'Get-Clipboard'],
                    capture_output=True, text=True, timeout=3
                )
                content = result.stdout.strip() if result.stdout else ''
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
            await asyncio.sleep(1)

    async def monitor_system_stats(self):
        """Push system stats every 5 seconds"""
        while self.running:
            try:
                cpu = psutil.cpu_percent(interval=1)
                ram = psutil.virtual_memory()
                # On Windows, '/' can be checked as 'C:\\' or root partition
                root_path = 'C:\\' if os.name == 'nt' else '/'
                disk = psutil.disk_usage(root_path)
                net = psutil.net_io_counters()

                self.emit('system_stats', {
                    'cpu_percent': cpu,
                    'ram_percent': ram.percent,
                    'ram_used_gb': round(ram.used / (1024**3), 2),
                    'ram_total_gb': round(ram.total / (1024**3), 2),
                    'disk_percent': disk.percent,
                    'net_bytes_sent': net.bytes_sent,
                    'net_bytes_recv': net.bytes_recv,
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
