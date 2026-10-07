import ctypes
import sqlite3
import subprocess
import os
from datetime import datetime
from typing import Literal, Optional

try:
    from backend.app.admin_utils import is_admin
except ImportError:
    try:
        from app.admin_utils import is_admin
    except ImportError:
        def is_admin() -> bool:
            try:
                if os.name != 'nt':
                    return True
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False

def is_admin_user() -> bool:
    return is_admin()

class TrafficController:
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
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS firewall_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT NOT NULL UNIQUE,
                    direction TEXT NOT NULL,
                    action TEXT NOT NULL,
                    protocol TEXT DEFAULT 'any',
                    local_port TEXT DEFAULT 'any',
                    remote_ip TEXT DEFAULT 'any',
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    is_active INTEGER DEFAULT 1,
                    is_admin_locked INTEGER DEFAULT 0,
                    notes TEXT
                )
            """)
            conn.commit()

    def add_rule(self, rule_name: str, direction: Literal['in','out','both'],
                 action: Literal['allow','block'], protocol: str = 'any',
                 local_port: str = 'any', remote_ip: str = 'any',
                 created_by: str = 'admin', admin_locked: bool = True,
                 notes: str = '') -> dict:
        """Add firewall rule — admin_locked=True means users cannot modify"""
        if not is_admin():
            return {
                'success': False,
                'error': 'admin_required',
                'message': 'Managing Windows firewall rules requires Administrator privileges. Run AI Firewall as Administrator.'
            }
        try:
            directions = ['in', 'out'] if direction == 'both' else [direction]
            for d in directions:
                name = f"AIFirewall-{rule_name}-{d.upper()}"
                cmd = [
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={name}',
                    f'dir={d}',
                    f'action={action}',
                ]
                if protocol != 'any':
                    cmd.append(f'protocol={protocol}')
                if local_port != 'any' and protocol in ['tcp', 'udp']:
                    cmd.append(f'localport={local_port}')
                if remote_ip != 'any':
                    cmd.append(f'remoteip={remote_ip}')
                try:
                    from app.process_utils import run_hidden
                except ImportError:
                    from backend.app.process_utils import run_hidden
                result = run_hidden(cmd, timeout=10)
                if result.returncode != 0:
                    err = (result.stderr or result.stdout or '').lower()
                    if 'requires elevation' in err or 'access is denied' in err or 'run as administrator' in err:
                        return {
                            'success': False,
                            'error': 'admin_required',
                            'message': 'Managing Windows firewall rules requires Administrator privileges. Run AI Firewall as Administrator.'
                        }

            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO firewall_rules
                    (rule_name, direction, action, protocol, local_port, remote_ip,
                     created_by, created_at, is_active, is_admin_locked, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """, (rule_name, direction, action, protocol, local_port, remote_ip,
                      created_by, datetime.now().isoformat(),
                      1 if admin_locked else 0, notes))
                conn.commit()

            return {'success': True, 'rule': rule_name, 'direction': direction, 'action': action}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def remove_rule(self, rule_name: str, requested_by: str = 'admin', is_admin_flag: bool = False) -> dict:
        if not is_admin():
            return {
                'success': False,
                'error': 'admin_required',
                'message': 'Managing Windows firewall rules requires Administrator privileges. Run AI Firewall as Administrator.'
            }
        try:
            with sqlite3.connect(self.db_path) as conn:
                rule = conn.execute(
                    "SELECT rule_name, is_admin_locked FROM firewall_rules WHERE rule_name = ?",
                    (rule_name,)
                ).fetchone()

            if not rule:
                return {'success': False, 'error': 'Rule not found'}

            if rule[1] == 1 and not is_admin_flag:
                return {'success': False, 'error': 'This rule is admin-locked. Contact your administrator.'}

            try:
                from app.process_utils import run_hidden
            except ImportError:
                from backend.app.process_utils import run_hidden

            for d in ['IN', 'OUT']:
                name = f"AIFirewall-{rule_name}-{d}"
                result = run_hidden(
                    ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={name}'],
                    timeout=10
                )
                if result.returncode != 0:
                    err = (result.stderr or result.stdout or '').lower()
                    if 'requires elevation' in err or 'access is denied' in err or 'run as administrator' in err:
                        return {
                            'success': False,
                            'error': 'admin_required',
                            'message': 'Managing Windows firewall rules requires Administrator privileges. Run AI Firewall as Administrator.'
                        }

            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM firewall_rules WHERE rule_name = ?", (rule_name,))
                conn.commit()

            return {'success': True, 'removed': rule_name}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_all_rules(self) -> list:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM firewall_rules ORDER BY created_at DESC").fetchall()
        return [{'id':r[0],'rule_name':r[1],'direction':r[2],'action':r[3],
                 'protocol':r[4],'local_port':r[5],'remote_ip':r[6],
                 'created_by':r[7],'created_at':r[8],'is_active':r[9],
                 'is_admin_locked':r[10],'notes':r[11]} for r in rows]

    def check_user_can_modify(self, rule_name: str, is_admin: bool) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            rule = conn.execute(
                "SELECT is_admin_locked FROM firewall_rules WHERE rule_name = ?", (rule_name,)
            ).fetchone()
        if not rule:
            return True
        if rule[0] == 1 and not is_admin:
            return False
        return True