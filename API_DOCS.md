# AI Firewall Desktop REST & WebSocket API Documentation

AI Firewall runs a local FastAPI backend bound to an ephemeral port on `127.0.0.1`. The chosen port is recorded at:
`%APPDATA%\AIFirewall\runtime_port.json`

Interactive OpenAPI / Swagger documentation is available at `http://127.0.0.1:<PORT>/docs` whenever the backend is running.

---

## 1. System & Health

### `GET /health` or `GET /api/health`
Verifies backend process readiness and runtime health.
- **Response**: `{"status": "ok", "app": "AI Firewall", "version": "1.0.0"}`

---

## 2. Authentication & First-Run Provisioning

### `GET /api/auth/admin-status`
Checks if an administrator account currently exists in the local database.
- **Response**: `{"admin_exists": true|false, "can_create_admin": true|false}`

### `POST /api/auth/create-admin`
Creates the initial administrative account during first launch.
- **Constraint**: Accessible **only** from localhost (`127.0.0.1`), and **only** when zero admin accounts exist. Returns HTTP `403 Forbidden` if an admin already exists or if called remotely.
- **Password Policy**: Minimum 10 characters required.
- **Body**: `{"username": "admin", "password": "StrongPassword123"}`

### `POST /api/auth/login`
Authenticates a user and returns a signed JWT access token.
- **Lockout Policy**: After 5 failed login attempts within 5 minutes for a given username, access for that username is temporarily locked for 5 minutes.
- **Uniform Error**: Returns `{"detail": "Invalid username or password"}` regardless of whether the username exists.
- **Body** (Form Data): `username`, `password`
- **Response**: `{"access_token": "<JWT_TOKEN>", "token_type": "bearer", "role": "admin"|"user"}`

### `POST /api/auth/logout`
Terminates the session and logs the logout event.

---

## 3. Dashboard, Activity & Anomaly Detection

### `GET /api/dashboard`
Returns a unified security status snapshot:
- Host health score
- Active threat counts
- Blocked domains and network connections
- Recent security events

### `GET /api/threats`
Retrieves recent threat logs and calculated anomaly scores.

### `POST /api/activity/log`
Ingests an activity record for adaptive behavior profiling.
- Evaluates event sequence transitions via Markov sequence model.
- Analyzes feature metrics using Isolation Forest.
- **Headers**: `Authorization: Bearer <TOKEN>`

### `GET /api/behavior-profiles`
Returns user behavior baselines, peak active hours, and baseline confidence metrics (`learning_mode: true|false`).

---

## 4. Traffic Control & Windows Firewall (`netsh`)

### `GET /api/traffic-monitor/rules`
Returns all active firewall rules managed by AI Firewall.

### `POST /api/traffic-monitor/rules`
Creates a new inbound/outbound Windows Firewall rule via `netsh advfirewall`.
- **Constraint**: Requires Administrator privileges. Rules are strictly prefixed with `AIFirewall-` for clean uninstallation.
- **Body**: `{"ip_address": "198.51.100.1", "action": "block", "direction": "out"}`

### `DELETE /api/traffic-monitor/rules/{ip_address}`
Removes an active firewall rule by IP address.

### `POST /api/traffic-monitor/disconnect`
Terminates active TCP connections associated with a suspicious process or IP.

---

## 5. Website Security & Hosts File Blocker

### `POST /api/website-security/blocked`
Blocks a target domain or IP.
- Automatically backs up `%WINDIR%\System32\drivers\etc\hosts` to `%APPDATA%\AIFirewall\backups\` (maintaining the last 5 backups).
- Adds redirection entry pointing to `127.0.0.1` flagged with `# AIFirewall-Block`.
- **Body**: `{"target": "malicious-domain.com", "reason": "phishing"}`

### `DELETE /api/website-security/blocked/{target}`
Unblocks a target domain.
- Safely removes lines matching `# AIFirewall-Block` or legacy `# AI-FIREWALL-BLOCK`.
- Automatically flushes DNS resolution cache.

### `GET /api/website-security/blocked`
Returns list of currently blocked websites and timestamped block entries.

---

## 6. Process Monitoring & Process Management

### `GET /api/desktop/processes`
Returns a list of running system processes, CPU/memory consumption, and network socket activity.

### `POST /api/desktop/processes/kill`
Terminates a runaway or suspicious process by PID.
- **Protected Processes**: Rejects termination of critical system processes (`System`, `csrss.exe`, `wininit.exe`, `services.exe`, `lsass.exe`, `smss.exe`) and AI Firewall's own backend process (`HTTP 403 Forbidden`).
- **Body**: `{"pid": 1234}`

---

## 7. Spam & Phishing Detection

### `POST /api/spam-detection/scan`
Analyzes raw email/message text or a suspicious URL for phishing patterns, high-risk keywords, obfuscated domains, and homoglyphs.
- Operates reliably both online and offline (skips live SSL probing with safe fallback when offline).
- **Body**: `{"text": "Suspicious payload content", "url": "http://suspicious-link.test"}`

---

## 8. USB Security & Antivirus Scanner

### `GET /api/usb-status` or `GET /api/device-safety/status`
Detects connected removable drives and reports scan status.

### `POST /api/device-safety/scan`
Initiates a deep file scan on removable media.
- Inspects file headers, entropy, script extensions, and known signatures (including EICAR standard test strings).
- Automatically isolates detected threats into `%APPDATA%\AIFirewall\quarantine\`.
- Gracefully handles drives disconnected mid-scan.

---

## 9. Real-Time Telemetry & WebSockets

### `WS /ws/live` and `WS /api/ws/monitor`
Provides continuous real-time telemetry streaming to the Electron desktop frontend:
- Live process updates
- Anomaly alerts and threat logs
- Firewall rule modifications
- Removable media events
- Supports automatic reconnect with exponential backoff
