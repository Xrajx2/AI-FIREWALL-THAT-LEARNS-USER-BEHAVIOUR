# Changelog

All notable changes to the AI Firewall project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-10-04

### Added
- **First-Run Provisioning Wizard**: Detects absence of administrative accounts on launch and prompts for initial admin creation (minimum 10-character password required, restricted to localhost).
- **Dynamic Port Negotiation**: Backend binds to an available ephemeral localhost port and registers it in `%APPDATA%\AIFirewall\runtime_port.json`.
- **Per-Username Authentication Lockout**: Automatically locks login for a specific username after 5 failed attempts within 5 minutes for a 5-minute cooling window, returning uniform errors to prevent username enumeration.
- **Windows DPAPI Key Protection**: Generates random Fernet encryption keys and JWT secrets, encrypted using Windows Data Protection API (`win32crypt.CryptProtectData`) in `%APPDATA%\AIFirewall\keys\`.
- **Protected System Process Guard**: Prevents termination of essential Windows OS services (`System`, `csrss.exe`, `wininit.exe`, `services.exe`, `lsass.exe`, `smss.exe`) and the application's own backend process.
- **Windows Firewall Integration (`netsh`)**: Manages inbound/outbound rules prefixed with `AIFirewall-` for clean identification and automated uninstallation.
- **Safe Hosts File Blocker**: Rotates up to 5 backups in `%APPDATA%\AIFirewall\backups\`, employs atomic write operations, and removes entries tagged with `# AIFirewall-Block` or legacy `# AI-FIREWALL-BLOCK`.
- **USB Malware Scanner & Quarantine**: Native Python scanner with EICAR signature recognition, drive removal tolerance, and quarantine folder isolation at `%APPDATA%\AIFirewall\quarantine\`.
- **IP Geolocation Caching**: 3-second timeout lookup with offline fallback; caches public IP lookups in SQLite with encryption for 24 hours.
- **Spam & Phishing Analysis**: Analyzes raw text payloads and URLs with offline SSL probing fallback.
- **Zero-CPU Windows Kernel Watchdog**: Uses kernel-level process monitoring (`OpenProcess` with `SYNCHRONIZE` + `WaitForSingleObject`) to guarantee instant, zero-CPU backend termination whenever the Electron UI closes.
- **NSIS Desktop Installer**: Self-contained x64 installer requiring Administrator elevation, creating Start Menu and Desktop shortcuts, with a custom uninstaller that restores hosts files and cleans firewall rules.

### Changed
- Migrated all runtime data, database files, keys, and backups strictly to `%APPDATA%\AIFirewall\`.
- Replaced hardcoded default encryption seeds and seeded credentials with dynamic, secure generation.
- Consolidated WebSocket communication to unified endpoints with exponential backoff auto-reconnect.
- Rewritten API documentation and project specifications.

### Removed
- Removed legacy container, background queue services, and cloud configuration files.
- Removed legacy test and demo scripts (`start_demo_day.cmd`, `demo_status_report.ps1`, `fix_demo_status.cmd`, etc.).
- Purged hardcoded default database `aifirewall.db` from repository root.
