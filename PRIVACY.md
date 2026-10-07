# Privacy Policy & Data Handling

AI Firewall is designed with a strict **local-first privacy architecture**. All activity logging, process inspections, machine-learning baselines, configuration parameters, and threat analysis remain on your local computer.

---

## 1. What Data Leaves Your Machine?

AI Firewall operates with an offline-first privacy model. **By default, no network requests are sent outside your local machine.**

### Remote IP Geolocation (Optional, Disabled by Default)
- **Default State:** **OFF** (the "Look up server locations online" toggle on the Live Activity page is unchecked by default).
- **What is Sent:** If and only if the user explicitly enables the "Look up server locations online" toggle, the remote public IP addresses of active established external network connections are queried against `http://ip-api.com/json/{ip}`.
- **Purpose & Display:** Lookups resolve the **approximate hosting location of the remote server** (e.g., city and country of the remote endpoint). The UI explicitly identifies this as the remote server's approximate facility location, never your local device location.
- **Offline Fallback & Bundled Database:** When online lookups are disabled (or when the computer is offline), AI Firewall queries a small bundled offline IP range table derived from public IANA and Regional Internet Registry (RIR) allocations (Public Domain / CC0 license, October 2026). If an IP is not found in the offline table, only the raw remote IP is displayed without any location label.
- **Rate-Limiting & Caching:** Online queries are rate-limited to a minimum interval of 1 second between requests and run asynchronously so the live activity feed is never blocked or stalled. Responses are cached locally in SQLite for 24 hours to prevent repeated external lookups.
- **Exclusions:** Private and loopback IP addresses (`127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `::1`) are **never** queried online.

**No other telemetry, usage analytics, personal data, crash reports, browsing history, or logs are transmitted to any third party or remote server.**

---

## 2. What Data Is Stored Locally?

All persistent application data is stored solely inside your Windows user profile at:
`%APPDATA%\AIFirewall\` (e.g., `C:\Users\<Username>\AppData\Roaming\AIFirewall\`)

This directory contains:
- **`aifirewall.db`**: Local SQLite database storing user accounts, password hashes (bcrypt), hashed IP logs, traffic rules, blocked domains, and security logs.
- **`keys/`**: Cryptographic keys (Fernet database encryption key, JWT secret). These keys are encrypted on disk using the **Windows Data Protection API (DPAPI)**, tying decryption strictly to your Windows user logon credentials.
- **`logs/`**: Local diagnostic application logs.
- **`backups/`**: Up to 5 timestamped backups of your Windows `hosts` file (`%WINDIR%\System32\drivers\etc\hosts`), captured prior to applying domain-blocking rules.
- **`quarantine/`**: Isolated files detected during removable drive (USB) scans.
- **`runtime_port.json`**: Temporary JSON file recording the dynamic localhost port chosen by the backend for inter-process communication with the Electron UI.

---

## 3. Clipboard & Background Checks

Clipboard content is inspected locally in memory using pure-Python Windows APIs solely to detect potential phishing URLs or suspicious manipulation patterns. Raw clipboard text is never stored in the database, never written to disk or diagnostic logs, and never sent off your PC. If and only if a severe phishing indicator is identified (threat score > 25), a short truncated preview (up to 100 characters) is temporarily dispatched to the local Live Activity dashboard over a localhost WebSocket. If no threat is found, the content is discarded immediately in memory. Periodic system and behavioral checks operate continuously in the background every 30 seconds.

---

## 4. Data Deletion & Uninstallation

- During standard uninstallation via the Windows Control Panel or Settings app, you are prompted whether you wish to delete `%APPDATA%\AIFirewall\`.
- If confirmed, all database records, cryptographic keys, quarantine files, and logs are permanently removed from your computer.
- Uninstallation automatically restores your Windows `hosts` file and removes any firewall rules created by AI Firewall (`AIFirewall-*`).
