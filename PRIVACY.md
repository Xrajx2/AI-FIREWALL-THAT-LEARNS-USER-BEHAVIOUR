# Privacy Policy & Data Handling

AI Firewall is designed with a strict **local-first privacy architecture**. All activity logging, process inspections, machine-learning baselines, configuration parameters, and threat analysis remain on your local computer.

---

## 1. What Data Leaves Your Machine?

**The only outbound network request initiated by the application is for public IP geolocation lookups:**
- **Service Used:** `http://ip-api.com/json/{ip}`
- **Condition:** Occurs only when external, public IP addresses are observed in active network connections or logged security events.
- **Exclusions:**
  - Private and loopback IP addresses (`127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are **never** queried and are skipped immediately.
  - Lookups are strictly limited by a **3-second timeout**. If the network is unavailable or the lookup times out, the application falls back safely to `"unknown"` without blocking execution.
- **Local Caching:** IP geolocation responses are cached locally in the SQLite database for 24 hours. The IP addresses are hashed/encrypted prior to storage, preventing plain-text IP retention. Repeated observations of the same IP do not trigger new external network requests.

**No other telemetry, usage analytics, personal data, crash reports, or logs are transmitted to any third party or remote server.**

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

## 3. Data Deletion & Uninstallation

- During standard uninstallation via the Windows Control Panel or Settings app, you are prompted whether you wish to delete `%APPDATA%\AIFirewall\`.
- If confirmed, all database records, cryptographic keys, quarantine files, and logs are permanently removed from your computer.
- Uninstallation automatically restores your Windows `hosts` file and removes any firewall rules created by AI Firewall (`AIFirewall-*`).
