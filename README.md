# AI Firewall that Learns User Behavior

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20x64-blue.svg)](https://microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Release-v1.0.0-green.svg)](CHANGELOG.md)

An open-source, local-first Windows desktop cybersecurity application that combines behavioral anomaly scoring with host-level defensive controls. It monitors user action sequences, flags anomalous behavior transitions, detects phishing and spam, scans removable media, and provides native Windows traffic control.

---

## Technical Overview & How It Works

AI Firewall takes an honest, practical approach to anomaly detection without inflated claims of "deep learning" or "military grade" intelligence:

1. **Markov Sequence Modeling**:
   User actions (file operations, process executions, network requests, logins) are modeled as sequential states. A first-order Markov chain tracks transition probabilities between consecutive events, calculating likelihood scores to detect unusual activity sequences.
2. **Isolation Forest & Statistical Scoring**:
   Numerical telemetry metrics (data transfer volumes, request frequencies, execution counts) are evaluated using an Isolation Forest to score statistical outliers against a localized baseline.
3. **Spam & Phishing Heuristics**:
   Analyzes raw text payloads and URLs for suspicious keyword density, homoglyphs, obfuscated domain structures, and risky TLDs. Operates reliably online and offline (skips live SSL probing with graceful fallbacks when offline).
4. **Removable Media (USB) Scanner**:
   Pure-Python scanner inspecting file headers, entropy, double extensions, suspicious script patterns, and standard test signatures (EICAR). Automatically quarantines flagged files into `%APPDATA%\AIFirewall\quarantine\`.
5. **Windows Host Traffic Control**:
   Directly manages Windows Defender Firewall inbound and outbound rules using `netsh advfirewall`, tagging all rules with the `AIFirewall-` prefix. Enforces domain blocking by adding loopback entries (`127.0.0.1`) to the Windows `hosts` file with automatic backups and DNS cache flushing.

---

## Tech Stack & Architecture

- **Desktop Shell**: Electron 39 (Windows x64)
- **User Interface**: React 19 + Tailwind CSS + Vite 8
- **Backend API**: Python 3.14 + FastAPI (bundled into a self-contained one-folder binary via PyInstaller)
- **Local Storage**: SQLite with WAL mode, encrypted fields via cryptography / Fernet, and zero external daemons (no Docker, no Redis, no Celery, no PostgreSQL)
- **Secret Protection**: Fernet database keys and JWT secrets are generated locally and encrypted using the **Windows Data Protection API (DPAPI)**
- **Process Lifecycle**: Managed via a zero-CPU Windows kernel watchdog (`OpenProcess` with `SYNCHRONIZE` + `WaitForSingleObject`) that terminates the backend immediately if the UI process closes

---

## System Requirements

- **Operating System**: Windows 10 (64-bit) or Windows 11 (64-bit)
- **Privileges**: Local **Administrator** rights
  - *Why?* Inspecting running system processes, modifying Windows Defender Firewall rules via `netsh`, and writing to `%SystemRoot%\System32\drivers\etc\hosts` require administrative elevation. If UAC elevation is declined, the application cannot open.
- **Hardware**: Minimum 4 GB RAM, 500 MB free disk space

---

## Installation & Setup

1. Download `AI-Firewall-Setup-1.0.0.exe` from the latest release.
2. Run the installer. When the Windows User Account Control (UAC) prompt appears, click **Yes** to allow elevation.
3. The installer installs the program to:
   ```
   %LOCALAPPDATA%\Programs\AI Firewall
   ```
   and creates shortcuts in your Start Menu and Desktop.
4. Launch **AI Firewall**.
5. **First-Run Wizard**: On initial launch, because no administrative account exists, the app prompts you to create your initial administrator credentials (minimum 10 characters). Once submitted, the setup endpoint permanently closes (HTTP 403).
6. Log in with your new administrator credentials.

---

## Windows SmartScreen Walkthrough

Because this open-source build is not signed with an expensive commercial Extended Validation (EV) certificate, Microsoft Defender SmartScreen may display an alert on first execution:

1. When the blue banner appears stating **"Windows protected your PC"** / *Microsoft Defender SmartScreen prevented an unrecognized app from starting*:
2. Click the **"More info"** hyperlink.
3. Click the **"Run anyway"** button that appears at the bottom.
4. Accept the Windows UAC elevation prompt (**"Do you want to allow this app to make changes to your device?"**).

---

## Antivirus False Positive Notice

Because AI Firewall interacts directly with core Windows security subsystems:
- Modifying the Windows `hosts` file to redirect malicious domains
- Invoking `netsh advfirewall` to add and remove firewall rules
- Inspecting running processes and terminating suspicious PIDs
- Quarantining malicious files from USB drives

Certain third-party antivirus suites may flag the installer or backend executable with generic heuristic classifications (e.g., `Heur.BZC`, `Riskware`, or `SuspiciousBehavior`).

**All source code is completely open and auditable.** If your antivirus produces an alert, you can verify the code, build the binaries directly from source, or add an exclusion for the installation folder.

---

## Building from Source

### Prerequisites
- Python 3.12, 3.13, or 3.14 (64-bit)
- Node.js 18+ and npm
- Windows PowerShell

### Exact 3-Step Build Process

1. **Build Backend Executable** (one-folder PyInstaller bundle):
   ```powershell
   py -3 -m PyInstaller aifirewall-backend.spec --clean --distpath frontend/build-resources/backend --workpath build
   ```

2. **Build Frontend Web Assets**:
   ```powershell
   npm --prefix frontend run build:frontend
   ```

3. **Package Electron Windows Installer**:
   ```powershell
   npm --prefix frontend run package:win
   ```

The packaged installer will be generated at:
```
frontend/release/AI-Firewall-Setup-1.0.0.exe
```

---

## Uninstallation

To cleanly remove AI Firewall:
1. Open **Windows Settings > Apps > Installed apps**, or run `Uninstall AI Firewall.exe` in the application directory.
2. The custom uninstaller will:
   - Terminate any running backend and UI processes.
   - Restore the Windows `hosts` file by removing all `# AIFirewall-Block` and legacy `# AI-FIREWALL-BLOCK` lines.
   - Remove all Windows Firewall rules prefixed with `AIFirewall-`.
   - Flush the Windows DNS resolver cache.
   - Ask whether you wish to retain or delete `%APPDATA%\AIFirewall\` (database, logs, and quarantine).

---

## Disclaimer

> [!WARNING]
> **Educational & Demonstration Project**: AI Firewall is developed as an academic project and engineering demonstration exploring host-level behavioral telemetry and automated defensive scripting. It is **not** a replacement for commercial enterprise firewalls, Next-Generation Firewalls (NGFW), or enterprise Endpoint Detection and Response (EDR) agents. Use responsibly and at your own risk.

---

## License

This project is open-source software licensed under the [MIT License](LICENSE).
