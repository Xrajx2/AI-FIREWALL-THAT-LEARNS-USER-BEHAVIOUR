# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

---

## Reporting a Vulnerability

We take the security and safety of AI Firewall seriously. If you discover a security vulnerability, please follow responsible disclosure guidelines.

### Reporting Process
- **Do not open a public GitHub issue** for undisclosed security vulnerabilities.
- Submit a detailed vulnerability report privately via GitHub Private Vulnerability Reporting or by contacting the project maintainers directly through their GitHub profiles.
- Please include in your report:
  1. A clear description of the vulnerability.
  2. Step-by-step instructions or proof-of-concept code to reproduce the issue.
  3. The environment used (Windows version, Python version, Electron version).
  4. Any potential impact or attack vectors.

### Response Timeline
- **Initial Acknowledgment:** Within 48 hours of receipt.
- **Assessment & Reproduction:** Within 5 business days.
- **Fix & Advisory:** A patch will be prepared and published alongside a coordinated disclosure advisory.

---

## Local Security Architecture

AI Firewall enforces several core defense-in-depth principles:
1. **Windows DPAPI Key Protection:** The cryptographic Fernet key and JWT secrets are encrypted using the Windows Data Protection API (`win32crypt.CryptProtectData`), restricting decryption to the local Windows user profile.
2. **Localhost-Only API:** The backend API binds strictly to `127.0.0.1` on a dynamically assigned port, mitigating port-squatting risks.
3. **Protected Process Guard:** Termination requests targeting critical Windows system processes (`System`, `csrss.exe`, `wininit.exe`, `services.exe`, `lsass.exe`, `smss.exe`) or AI Firewall's own runtime processes are rejected at the kernel/API boundary.
4. **Brute-Force Lockout:** Authentication locks out usernames after 5 consecutive failed attempts within 5 minutes for a 5-minute cooling window, returning identical error messages for valid and invalid usernames.
5. **Atomic Hosts File Operations:** Modifying the Windows `hosts` file creates automatic timestamped backups before applying alterations with distinct markers (`# AIFirewall-Block`).
