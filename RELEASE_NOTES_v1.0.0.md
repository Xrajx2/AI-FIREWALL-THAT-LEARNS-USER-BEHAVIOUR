# AI Firewall v1.0.0 Beta 2 Release Notes

**Release Date:** October 7, 2026  
**Tag:** `v1.0.0-beta.2`  
**Artifact:** [AI-Firewall-Setup-1.0.0.exe](https://github.com/Xrajx2/AI-FIREWALL-THAT-LEARNS-USER-BEHAVIOUR/releases/download/v1.0.0-beta.2/AI-Firewall-Setup-1.0.0.exe)  
**Target Platform:** Windows 10 / Windows 11 (64-bit)  
**SHA-256 Checksum:**  
```
D27886F3A187D4AC22EBE7954C454AFAFC4AAFAC228CC8CAC7D3C47D53043282
```

---

## Highlights & Features

- **Behavioral Sequence Modeling**: Evaluates user action transitions (processes, logins, file operations) using a first-order Markov model to detect unauthorized sequence anomalies.
- **Statistical Metric Anomaly Detection**: Employs an Isolation Forest to score quantitative deviations from user baseline behavior.
- **Native Windows Firewall Control**: Manages inbound and outbound rules using `netsh advfirewall`, tagging all rules with the `AIFirewall-` prefix.
- **Safe Hosts File Blocker**: Blocks malicious domains locally via loopback (`127.0.0.1`) redirection, keeping up to 5 rotating backups in `%APPDATA%\AIFirewall\backups\` and flushing the DNS resolver cache automatically.
- **Pure-Python USB Scanner & Quarantine**: Scans connected USB drives for suspicious script patterns, double extensions, and standard EICAR test strings, isolating threats into `%APPDATA%\AIFirewall\quarantine\`.
- **Spam & Phishing Analysis**: Detects malicious links and high-risk message payloads with offline resilience.
- **Zero-CPU Process Watchdog**: Windows kernel-level synchronization (`OpenProcess` with `SYNCHRONIZE` + `WaitForSingleObject`) guarantees the backend process cleanly self-terminates whenever the UI is closed.
- **DPAPI Key Storage**: Fernet database keys and JWT secrets are generated locally on first run and encrypted using the Windows Data Protection API (DPAPI).
- **First-Run Provisioning Wizard**: Automatically prompts for administrator account setup on first launch (minimum 10-character password required, restricted to localhost).

---

## Download & Installation

1. Download **`AI-Firewall-Setup-1.0.0.exe`** and the checksum file **`AI-Firewall-Setup-1.0.0.exe.sha256.txt`**.
2. Verify the SHA-256 checksum in PowerShell:
   ```powershell
   (Get-FileHash -Algorithm SHA256 .\AI-Firewall-Setup-1.0.0.exe).Hash -eq "D27886F3A187D4AC22EBE7954C454AFAFC4AAFAC228CC8CAC7D3C47D53043282"
   ```
3. Run `AI-Firewall-Setup-1.0.0.exe`.
4. Accept the Windows User Account Control (UAC) prompt to allow Administrator elevation.
5. If Windows Defender SmartScreen shows an unrecognized app warning:
   - Click **More info**
   - Click **Run anyway**
6. Complete the initial admin setup on first launch.

---

## Known Limitations & Considerations

1. **Administrator Rights Mandatory**: The desktop application requires Administrator privileges to interact with `netsh advfirewall`, edit the Windows `hosts` file, and terminate rogue processes. Declining UAC elevation will prevent the application from opening.
2. **Hosts File & Secure DNS Limitation**: Domain blocking maps hostnames to `127.0.0.1` in `%WINDIR%\System32\drivers\etc\hosts`. Browsers using Secure DNS (DNS over HTTPS / DoH) bypass the OS resolver, and accessing destination servers directly by IP address bypasses DNS resolution entirely.
3. **Windows Firewall Loopback Boundary**: The Windows Filtering Platform and Windows Defender Firewall do not filter local loopback (`127.0.0.1` / `::1`) traffic. Firewall rules apply strictly to external network interfaces.
4. **SmartScreen Notice**: Because this open-source build is not code-signed with a paid EV certificate, Windows Defender SmartScreen will display an initial warning on first execution.
5. **Antivirus Heuristic Detections**: Interacting with Windows firewall rules and the system `hosts` file can trigger heuristic alerts in certain third-party antivirus software. The source code is completely open for audit and verification.
6. **Offline IP Geolocation**: IP geolocation lookups enforce a 3-second timeout and cache responses for 24 hours. When offline, geolocation returns `"Unknown"` gracefully without interrupting login or protection routines.
7. **Academic Disclaimer**: AI Firewall is an educational and demonstration project exploring host-level behavioral telemetry and host defense scripting. It does not replace enterprise-grade commercial firewalls or EDR agents.
