import ipaddress
import logging
import os
import platform
import re
import shutil
import subprocess
import tempfile
import urllib.parse
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("ai_firewall.website_blocker")

HOSTS_PATH_WINDOWS = r"C:\Windows\System32\drivers\etc\hosts"
HOSTS_PATH_POSIX = "/etc/hosts"
BLOCK_MARKER_OLD = "# AI-FIREWALL-BLOCK:"
BLOCK_MARKER_NEW = "# AIFirewall-Block:"
BLOCK_MARKERS = (
    "# AI-FIREWALL-BLOCK:",
    "# AIFirewall-Block:",
    "# AI-FIREWALL-BLOCK",
    "# AIFirewall-Block",
)
BLOCK_MARKER = BLOCK_MARKER_NEW


def validate_block_domain(domain: str) -> Tuple[bool, Optional[str]]:
    """
    Validate domain input to prevent hosts-file injection.
    Disallows spaces, newlines, tabs, carriage returns, '#', and raw IP strings.
    """
    if not domain or not isinstance(domain, str):
        return False, "Domain name cannot be empty."

    domain_clean = domain.strip().lower()
    if not domain_clean:
        return False, "Domain name cannot be empty."

    # Prevent hosts file injection via delimiter or comment characters
    if any(ch in domain_clean for ch in (" ", "\t", "\n", "\r", "#")):
        return False, "Invalid domain: spaces, tabs, newlines, and '#' characters are not allowed."

    # Prevent raw IP strings
    try:
        ipaddress.ip_address(domain_clean)
        return False, "Invalid domain: IP addresses cannot be blocked via hosts file."
    except ValueError:
        pass

    # Basic RFC domain label validation
    label_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    if not re.match(label_pattern, domain_clean):
        return False, "Invalid domain format: Domain must consist of valid alphanumeric labels."

    return True, None


class BlockResult(dict):
    """Dictionary result that evaluates to boolean True/False based on success key."""
    def __bool__(self) -> bool:
        return bool(self.get("success"))


class WebsiteBlockerEngine:
    def __init__(self, hosts_path: Optional[str] = None):
        self.os_type = platform.system().lower()
        if hosts_path:
            self.hosts_path = hosts_path
        else:
            self.hosts_path = HOSTS_PATH_WINDOWS if "win" in self.os_type else HOSTS_PATH_POSIX

    def _get_backup_dir(self) -> str:
        appdata = os.environ.get("APPDATA") or os.path.expanduser("~\\AppData\\Roaming")
        backup_dir = os.path.join(appdata, "AIFirewall", "backups")
        os.makedirs(backup_dir, exist_ok=True)
        return backup_dir

    def _backup_hosts_file(self) -> Optional[str]:
        """Keep the last 5 backups in %APPDATA%\\AIFirewall\\backups."""
        if not os.path.exists(self.hosts_path):
            return None

        backup_dir = self._get_backup_dir()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        backup_file = os.path.join(backup_dir, f"hosts.bak.{ts}")

        try:
            shutil.copy2(self.hosts_path, backup_file)
            # Maintain only last 5 backups
            all_backups = sorted(
                [os.path.join(backup_dir, f) for f in os.listdir(backup_dir) if f.startswith("hosts.bak.")],
                key=os.path.getmtime,
            )
            while len(all_backups) > 5:
                oldest = all_backups.pop(0)
                try:
                    os.remove(oldest)
                except Exception:
                    pass
            return backup_file
        except Exception as e:
            logger.warning(f"Could not back up hosts file: {e}")
            return None

    def _safe_write_hosts(self, lines: List[str]) -> Tuple[bool, Optional[str]]:
        """Write safely: write to a temp file, then replace. Never leave a half-written hosts file."""
        self._backup_hosts_file()

        hosts_dir = os.path.dirname(os.path.abspath(self.hosts_path))
        temp_file = None
        try:
            # Write to temporary file in the same directory to allow atomic replace across same filesystem
            temp_file = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=hosts_dir, delete=False)
            temp_file.writelines(lines)
            temp_file.flush()
            temp_file.close()

            # Atomic replace
            os.replace(temp_file.name, self.hosts_path)
            return True, None
        except PermissionError as e:
            logger.warning(f"Permission denied modifying hosts file at {self.hosts_path}: {e}")
            return False, "admin_required"
        except Exception as e:
            logger.error(f"Error replacing hosts file: {e}")
            return False, str(e)
        finally:
            if temp_file and os.path.exists(temp_file.name):
                try:
                    os.remove(temp_file.name)
                except Exception:
                    pass

    def get_active_hosts_blocks(self) -> List[str]:
        if not os.path.exists(self.hosts_path):
            return []
        try:
            with open(self.hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            blocked_domains = []
            for line in content.splitlines():
                line = line.strip()
                for marker in BLOCK_MARKERS:
                    if marker in line:
                        parts = line.split(marker)
                        if len(parts) >= 2:
                            val = parts[1].strip()
                            if val.startswith(":"):
                                val = val[1:].strip()
                            if val:
                                blocked_domains.append(val)
                        break
            return list(set(blocked_domains))
        except Exception as e:
            logger.error(f"Failed to read hosts file at {self.hosts_path}: {e}")
            return []

    def block_domain_os_level(self, domain: str) -> BlockResult:
        """
        Adds domain to OS Hosts file pointing to 127.0.0.1 and flushes DNS cache.
        """
        raw_domain = domain.strip().lower()
        if raw_domain.startswith(("http://", "https://")):
            parsed = urllib.parse.urlparse(raw_domain)
            raw_domain = parsed.netloc.split(":")[0]
        if raw_domain.startswith("www."):
            raw_domain = raw_domain[4:]

        valid, err_msg = validate_block_domain(raw_domain)
        if not valid:
            return BlockResult(success=False, error="invalid_domain", message=err_msg)

        if not os.path.exists(self.hosts_path):
            return BlockResult(success=False, error="not_found", message=f"Hosts file not found at {self.hosts_path}")

        try:
            with open(self.hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            # Check if domain is already blocked with our marker
            already_blocked = any(any(m in l for m in BLOCK_MARKERS) and raw_domain in l for l in lines)
            if not already_blocked:
                host_entry_1 = f"127.0.0.1 {raw_domain} {BLOCK_MARKER} {raw_domain}\n"
                host_entry_2 = f"127.0.0.1 www.{raw_domain} {BLOCK_MARKER} {raw_domain}\n"
                new_lines = list(lines)
                if new_lines and not new_lines[-1].endswith("\n"):
                    new_lines[-1] = new_lines[-1] + "\n"
                new_lines.append(host_entry_1)
                new_lines.append(host_entry_2)

                ok, err = self._safe_write_hosts(new_lines)
                if not ok:
                    if err == "admin_required":
                        return BlockResult(
                            success=False,
                            error="admin_required",
                            message="Permission denied modifying hosts file. Run AI Firewall as Administrator."
                        )
                    return BlockResult(
                        success=False,
                        error="write_failed",
                        message=f"Failed to modify hosts file: {err}"
                    )
                logger.info(f"Successfully added OS hosts block entry for {raw_domain}")

            self._flush_dns_cache()
            self._add_netsh_firewall_rule(raw_domain)
            return BlockResult(success=True, domain=raw_domain)
        except PermissionError:
            return BlockResult(
                success=False,
                error="admin_required",
                message="Permission denied modifying hosts file. Run AI Firewall as Administrator."
            )
        except Exception as e:
            logger.error(f"Error blocking domain {raw_domain} in hosts file: {e}")
            return BlockResult(success=False, error=str(e), message=f"Failed to block domain: {str(e)}")

    def unblock_domain_os_level(self, domain: str) -> BlockResult:
        """
        Removes domain from OS Hosts file and flushes DNS cache.
        Removes ONLY lines with the AI-FIREWALL-BLOCK marker!
        """
        raw_domain = domain.strip().lower()
        if raw_domain.startswith("www."):
            raw_domain = raw_domain[4:]

        valid, err_msg = validate_block_domain(raw_domain)
        if not valid:
            return BlockResult(success=False, error="invalid_domain", message=err_msg)

        if not os.path.exists(self.hosts_path):
            return BlockResult(success=False, error="not_found", message=f"Hosts file not found at {self.hosts_path}")

        try:
            with open(self.hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            # Remove ONLY lines with either AI-FIREWALL-BLOCK or AIFirewall-Block marker for this domain
            new_lines = []
            for line in lines:
                is_marked = any(m in line for m in BLOCK_MARKERS)
                if is_marked and (
                    f" {raw_domain} " in line
                    or f" www.{raw_domain} " in line
                    or any(line.rstrip().endswith(f"{m} {raw_domain}") for m in BLOCK_MARKERS)
                    or any(line.rstrip().endswith(f"{m}:{raw_domain}") for m in BLOCK_MARKERS)
                ):
                    continue
                new_lines.append(line)

            if len(new_lines) != len(lines):
                ok, err = self._safe_write_hosts(new_lines)
                if not ok:
                    if err == "admin_required":
                        return BlockResult(
                            success=False,
                            error="admin_required",
                            message="Permission denied modifying hosts file. Run AI Firewall as Administrator."
                        )
                    return BlockResult(
                        success=False,
                        error="write_failed",
                        message=f"Failed to modify hosts file: {err}"
                    )
                logger.info(f"Removed OS hosts block entry for {raw_domain}")

            self._flush_dns_cache()
            self._remove_netsh_firewall_rule(raw_domain)
            return BlockResult(success=True, domain=raw_domain)
        except PermissionError:
            return BlockResult(
                success=False,
                error="admin_required",
                message="Permission denied modifying hosts file. Run AI Firewall as Administrator."
            )
        except Exception as e:
            logger.error(f"Error unblocking domain {raw_domain} in hosts file: {e}")
            return BlockResult(success=False, error=str(e), message=f"Failed to unblock domain: {str(e)}")

    def cleanup_all_managed_blocks(self) -> BlockResult:
        """Removes all blocks created by AI Firewall (both old and new markers)."""
        if not os.path.exists(self.hosts_path):
            return BlockResult(success=True, message="Hosts file does not exist")
        try:
            with open(self.hosts_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            new_lines = [l for l in lines if not any(m in l for m in BLOCK_MARKERS)]
            if len(new_lines) != len(lines):
                ok, err = self._safe_write_hosts(new_lines)
                if not ok:
                    return BlockResult(success=False, error=err or "write_failed")
            self._flush_dns_cache()
            return BlockResult(success=True)
        except PermissionError:
            return BlockResult(success=False, error="admin_required")
        except Exception as e:
            return BlockResult(success=False, error=str(e))

    def sync_all_blocked_domains(self, blocked_domains: List[str]):
        """
        Syncs list of active blocked domains to OS Hosts file.
        """
        for domain in blocked_domains:
            self.block_domain_os_level(domain)

    def _flush_dns_cache(self):
        try:
            if "win" in self.os_type:
                subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True, check=False)
            elif "darwin" in self.os_type:
                subprocess.run(["killall", "-HUP", "mDNSResponder"], capture_output=True, check=False)
            else:
                subprocess.run(["systemd-resolve", "--flush-caches"], capture_output=True, check=False)
        except Exception as e:
            logger.warning(f"DNS cache flush notice (non-fatal): {e}")

    def _add_netsh_firewall_rule(self, domain: str):
        if "win" not in self.os_type:
            return
        rule_name = f"AIFirewall-BlockDomain-{domain.replace('.', '-')}"
        try:
            cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={domain}'
            subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
        except Exception:
            pass

    def _remove_netsh_firewall_rule(self, domain: str):
        if "win" not in self.os_type:
            return
        rule_name = f"AIFirewall-BlockDomain-{domain.replace('.', '-')}"
        try:
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
        except Exception:
            pass

    def render_block_page_html(
        self,
        domain: str,
        threat_score: float,
        reason: str,
        category: str,
        timestamp_str: str,
        user_name: str = "Current User"
    ) -> str:
        score_color = "#ef4444" if threat_score >= 80 else "#f59e0b"
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Website Blocked - AI Firewall Security Alert</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }}
        body {{ background-color: #0b0f19; color: #f3f4f6; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }}
        .card {{ background: #111827; border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 20px; padding: 40px; max-width: 600px; width: 100%; box-shadow: 0 25px 50px -12px rgba(239, 68, 68, 0.25); text-align: center; position: relative; overflow: hidden; }}
        .card::before {{ content: ''; position: absolute; top: 0; left: 0; right: 0; height: 6px; background: linear-gradient(90deg, #ef4444, #f59e0b); }}
        .icon-box {{ width: 80px; height: 80px; background: rgba(239, 68, 68, 0.1); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 24px; color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.2); }}
        .icon-box svg {{ width: 44px; height: 44px; stroke-width: 2; }}
        h1 {{ font-size: 28px; font-weight: 800; color: #ffffff; margin-bottom: 8px; letter-spacing: -0.5px; }}
        .subtitle {{ font-size: 14px; color: #9ca3af; margin-bottom: 28px; text-transform: uppercase; letter-spacing: 2px; font-weight: 600; }}
        .domain-badge {{ background: #1f2937; border: 1px solid #374151; padding: 12px 20px; border-radius: 12px; font-size: 18px; font-weight: 700; color: #60a5fa; word-break: break-all; margin-bottom: 24px; display: inline-block; width: 100%; }}
        .meta-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 28px; text-align: left; }}
        .meta-item {{ background: #1f2937; padding: 14px; border-radius: 10px; border: 1px solid rgba(255,255,255,0.05); }}
        .meta-label {{ font-size: 11px; text-transform: uppercase; color: #6b7280; margin-bottom: 4px; font-weight: 600; letter-spacing: 1px; }}
        .meta-value {{ font-size: 15px; font-weight: 700; color: #f3f4f6; }}
        .score-value {{ color: {score_color}; font-size: 20px; }}
        .reason-box {{ background: rgba(239, 68, 68, 0.08); border-left: 4px solid #ef4444; padding: 16px; border-radius: 0 10px 10px 0; text-align: left; margin-bottom: 28px; font-size: 14px; color: #fca5a5; line-height: 1.5; }}
        .footer-note {{ font-size: 12px; color: #6b7280; border-t: 1px solid #1f2937; pt: 16px; margin-top: 16px; }}
        .btn {{ display: inline-block; background: #374151; color: white; padding: 12px 24px; border-radius: 10px; text-decoration: none; font-weight: 600; font-size: 14px; transition: background 0.2s; border: none; cursor: pointer; }}
        .btn:hover {{ background: #4b5563; }}
    </style>
</head>
<body>
    <div class="card">
        <div class="icon-box">
            <svg fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
            </svg>
        </div>
        <h1>Harmful Website Access Blocked</h1>
        <div class="subtitle">AI Firewall Threat Prevention</div>

        <div class="domain-badge">{domain}</div>

        <div class="reason-box">
            <strong>Security Warning:</strong> {reason}
        </div>

        <div class="meta-grid">
            <div class="meta-item">
                <div class="meta-label">Threat Risk Score</div>
                <div class="meta-value score-value">{threat_score:.1f} / 100</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Threat Category</div>
                <div class="meta-value">{category}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Assigned User</div>
                <div class="meta-value">{user_name}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Time of Detection</div>
                <div class="meta-value">{timestamp_str}</div>
            </div>
        </div>

        <button onclick="window.history.back()" class="btn">Return to Safety</button>

        <div class="footer-note">
            Protected by AI Firewall that Learns User Behavior &bull; Contact Security Administrator if you believe this is a false positive.
        </div>
    </div>
</body>
</html>
"""


website_blocker = WebsiteBlockerEngine()
