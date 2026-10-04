import sqlite3
import subprocess
import os
import threading
from datetime import datetime
from typing import Optional, Dict

class BlockManager:
    def __init__(self, db_path: Optional[str] = None, **kwargs):
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
        self._cache: Dict[str, str] = {}
        self._lock = threading.Lock()
        self.use_redis = False
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS permanent_blocks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    block_type TEXT NOT NULL,
                    value TEXT NOT NULL UNIQUE,
                    reason TEXT NOT NULL,
                    blocked_by TEXT NOT NULL,
                    blocked_at TEXT NOT NULL,
                    is_active INTEGER DEFAULT 1,
                    unblocked_by TEXT,
                    unblocked_at TEXT,
                    unblock_reason TEXT,
                    attempt_count INTEGER DEFAULT 0,
                    last_attempt TEXT
                )
            """)
            conn.commit()
        self._load_active_blocks_to_cache()

    def _load_active_blocks_to_cache(self):
        """Load all active blocks from DB into thread-safe in-memory cache on startup"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    "SELECT block_type, value FROM permanent_blocks WHERE is_active = 1"
                ).fetchall()
            with self._lock:
                self._cache.clear()
                for block_type, value in rows:
                    self._cache[f"block:{block_type}:{value}"] = "1"
        except Exception:
            pass

    def block(self, block_type: str, value: str, reason: str,
              blocked_by: str, apply_firewall: bool = True) -> dict:
        """
        block_type: 'ip' | 'user' | 'process' | 'domain' | 'usb_device'
        """
        now = datetime.now().isoformat()
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO permanent_blocks
                    (block_type, value, reason, blocked_by, blocked_at, is_active, unblocked_by, unblocked_at, unblock_reason)
                    VALUES (?, ?, ?, ?, ?, 1, NULL, NULL, NULL)
                """, (block_type, value, reason, blocked_by, now))
                conn.commit()

            # Cache in in-memory cache
            with self._lock:
                self._cache[f"block:{block_type}:{value}"] = "1"

            # Apply OS-level block for IPs
            if block_type == 'ip' and apply_firewall:
                self._block_ip_firewall(value, reason)

            # Block domain via hosts file
            if block_type == 'domain' and apply_firewall:
                self._block_domain(value)

            return {'success': True, 'blocked': value, 'type': block_type}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def unblock(self, block_type: str, value: str,
                unblocked_by: str, reason: str = '') -> dict:
        """Unblock — only callable by admin"""
        now = datetime.now().isoformat()
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE permanent_blocks
                    SET is_active = 0, unblocked_by = ?, unblocked_at = ?, unblock_reason = ?
                    WHERE block_type = ? AND value = ? AND is_active = 1
                """, (unblocked_by, now, reason, block_type, value))
                conn.commit()

            # Remove from in-memory cache
            with self._lock:
                self._cache.pop(f"block:{block_type}:{value}", None)

            # Remove OS-level block for IPs
            if block_type == 'ip':
                self._unblock_ip_firewall(value)

            # Remove domain block
            if block_type == 'domain':
                self._unblock_domain(value)

            return {'success': True, 'unblocked': value, 'type': block_type}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def is_blocked(self, block_type: str, value: str) -> bool:
        with self._lock:
            if f"block:{block_type}:{value}" in self._cache:
                return True
        # Fall back to DB if cache missed
        try:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT id FROM permanent_blocks WHERE block_type=? AND value=? AND is_active=1",
                    (block_type, value)
                ).fetchone()
            return bool(row)
        except Exception:
            return False

    def record_attempt(self, block_type: str, value: str):
        """Log that a blocked entity tried to access again"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE permanent_blocks
                    SET attempt_count = attempt_count + 1, last_attempt = ?
                    WHERE block_type = ? AND value = ? AND is_active = 1
                """, (datetime.now().isoformat(), block_type, value))
                conn.commit()
        except Exception:
            pass

    def get_all_blocks(self, include_inactive: bool = False) -> list:
        with sqlite3.connect(self.db_path) as conn:
            if include_inactive:
                rows = conn.execute("SELECT * FROM permanent_blocks ORDER BY blocked_at DESC").fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM permanent_blocks WHERE is_active=1 ORDER BY blocked_at DESC"
                ).fetchall()
        cols = ['id','block_type','value','reason','blocked_by','blocked_at',
                'is_active','unblocked_by','unblocked_at','unblock_reason',
                'attempt_count','last_attempt']
        return [dict(zip(cols, row)) for row in rows]

    def _block_ip_firewall(self, ip: str, reason: str):
        name = f"AIFirewall_BLOCK_{ip.replace('.','_')}"
        for d in ['in', 'out']:
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={name}_{d}', f'dir={d}', 'action=block',
                f'remoteip={ip}', 'enable=yes'
            ], capture_output=True, timeout=10)

    def _unblock_ip_firewall(self, ip: str):
        name = f"AIFirewall_BLOCK_{ip.replace('.','_')}"
        for d in ['in', 'out']:
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={name}_{d}'
            ], capture_output=True, timeout=10)

    def _block_domain(self, domain: str):
        hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
        entry = f"\n127.0.0.1 {domain}  # AIFirewall_BLOCK\n"
        try:
            with open(hosts_path, 'a') as f:
                f.write(entry)
        except Exception:
            subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
                f'Add-Content -Path "{hosts_path}" -Value "127.0.0.1 {domain}  # AIFirewall_BLOCK"'
            ], capture_output=True)

    def _unblock_domain(self, domain: str):
        hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
        try:
            with open(hosts_path, 'r') as f:
                lines = f.readlines()
            with open(hosts_path, 'w') as f:
                f.writelines(l for l in lines if domain not in l)
        except Exception:
            pass

block_manager = BlockManager()
