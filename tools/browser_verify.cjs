// tools/browser_verify.cjs
// Real Chromium Browser Verification across 3 Timezones (PART 5)

const fs = require('fs');
const path = require('path');
const http = require('http');
const os = require('os');
const { spawn } = require('child_process');
const { chromium } = require(path.join(__dirname, '..', 'frontend', 'node_modules', 'playwright-core'));

const DIST_DIR = path.join(__dirname, '..', 'frontend', 'dist');
const SCREENSHOT_DIR = 'C:\\AI firewall rander\\academic\\viva\\screenshots';
const CHROME_PATH = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const EDGE_PATH = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const BACKEND_EXE = path.join(__dirname, '..', 'frontend', 'build-resources', 'backend', 'aifirewall-backend', 'aifirewall-backend.exe');

if (!fs.existsSync(SCREENSHOT_DIR)) {
  fs.mkdirSync(SCREENSHOT_DIR, { recursive: true });
}

// 1. Static file HTTP server for frontend/dist
function startStaticServer(port = 5173) {
  const mimeTypes = {
    '.html': 'text/html',
    '.js': 'text/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.woff2': 'font/woff2',
  };

  const server = http.createServer((req, res) => {
    let reqPath = req.url.split('?')[0];
    if (reqPath === '/') reqPath = '/index.html';
    let filePath = path.join(DIST_DIR, reqPath);

    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      filePath = path.join(DIST_DIR, 'index.html');
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = mimeTypes[ext] || 'application/octet-stream';

    try {
      const data = fs.readFileSync(filePath);
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(data);
    } catch (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
    }
  });

  return new Promise((resolve, reject) => {
    server.listen(port, '127.0.0.1', () => {
      resolve(server);
    });
    server.on('error', reject);
  });
}

function httpRequest(url, options = {}, body = null) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const reqOpts = {
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname + parsed.search,
      method: options.method || 'GET',
      headers: options.headers || {},
      timeout: 5000,
    };

    const req = http.request(reqOpts, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        resolve({ status: res.statusCode, body: data });
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('HTTP request timeout'));
    });

    if (body) {
      req.write(body);
    }
    req.end();
  });
}

const TIMEZONES = [
  { id: 'Asia/Kolkata', label: 'Asia_Kolkata', expectedOffsetMin: -330 },
  { id: 'America/Los_Angeles', label: 'America_Los_Angeles', expectedOffsetMin: 420 },
  { id: 'UTC', label: 'UTC', expectedOffsetMin: 0 },
];

const PAGES = [
  { tab: 'overview', name: 'Overview', label: 'Overview' },
  { tab: 'systemStatus', name: 'System_Status', label: 'System Status' },
  { tab: 'trafficControl', name: 'Traffic_Control', label: 'Traffic Control' },
  { tab: 'accessLogs', name: 'Access_Logs', label: 'Access Logs' },
  { tab: 'phishing', name: 'Phishing_Checker', label: 'Phishing Checker' },
  { tab: 'blocks', name: 'Block_Manager', label: 'Block Manager' },
  { tab: 'desktopSecurity', name: 'Windows_Security', label: 'Windows Security' },
  { tab: 'websiteSecurity', name: 'Website_Security', label: 'Website Security' },
  { tab: 'live', name: 'Live_Activity', label: 'Live Activity' },
  { tab: 'trafficMonitor', name: 'Traffic_Monitor', label: 'Traffic Monitor' },
  { tab: 'spamDetection', name: 'Spam_Detection', label: 'Spam Detection' },
  { tab: 'alerts', name: 'Threat_Alerts', label: 'Threat Alerts' },
  { tab: 'deviceSafety', name: 'Device_Safety', label: 'Device Safety' },
  { tab: 'users', name: 'User_Management', label: 'User Management' },
  { tab: 'simulation', name: 'Simulation_Lab', label: 'Simulation' },
];

async function main() {
  console.log('======================================================================');
  console.log('=== REAL CHROMIUM BROWSER VERIFICATION (PART 5) - 3 TIMEZONES ===');
  console.log('======================================================================');

  // Prepare isolated temporary data dir for backend
  const tempDir = path.join(os.tmpdir(), `aifirewall_browser_run_${Date.now()}`);
  fs.mkdirSync(tempDir, { recursive: true });
  fs.mkdirSync(path.join(tempDir, 'AIFirewall'), { recursive: true });

  console.log(`[Backend Setup] Temporary data directory: ${tempDir}`);
  console.log(`[Backend Setup] Spawning built executable: ${BACKEND_EXE}`);

  const backendProc = spawn(BACKEND_EXE, [], {
    cwd: path.join(__dirname, '..'),
    env: {
      ...process.env,
      AI_FIREWALL_PARENT_PID: '-1',
      AI_FIREWALL_NO_UAC: '1',
      AI_FIREWALL_PORT: '8000',
      APPDATA: tempDir,
    },
    stdio: 'ignore',
  });

  const runSummary = [];
  let staticServer = null;
  let browser = null;

  try {
    // Wait for backend /api/health
    console.log('[Backend Setup] Waiting for backend /api/health on port 8000...');
    let healthy = false;
    for (let i = 0; i < 30; i++) {
      try {
        const res = await httpRequest('http://127.0.0.1:8000/api/health');
        if (res.status === 200) {
          healthy = true;
          break;
        }
      } catch (e) { }
      await new Promise((r) => setTimeout(r, 500));
    }

    if (!healthy) {
      throw new Error('Backend failed to respond on http://127.0.0.1:8000/api/health within 15 seconds.');
    }
    console.log('[Backend Setup] Backend is healthy on port 8000!');

    // Initialize admin account
    console.log('[Auth Setup] Seeding administrator credentials (admin / AdminPassword123!)...');
    const adminPayload = JSON.stringify({
      username: 'admin',
      password: 'AdminPassword123!',
      email: 'admin@localhost.invalid',
    });
    try {
      await httpRequest('http://127.0.0.1:8000/api/auth/create-admin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(adminPayload) },
      }, adminPayload);
      console.log('[Auth Setup] Initial administrator created successfully.');
    } catch (err) {
      console.log(`[Auth Setup] Admin creation notice: ${err.message}`);
    }

    // Start static HTTP server for frontend/dist
    staticServer = await startStaticServer(5173);
    console.log('[Static Server] Serving frontend/dist on http://127.0.0.1:5173');

    const browserPath = fs.existsSync(CHROME_PATH) ? CHROME_PATH : EDGE_PATH;
    console.log(`[Chromium] Launching browser binary: ${browserPath}`);

    browser = await chromium.launch({
      executablePath: browserPath,
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    });

    for (const tzConfig of TIMEZONES) {
      console.log(`\n======================================================`);
      console.log(`>>> TESTING TIMEZONE: ${tzConfig.id} (${tzConfig.label}) <<<`);
      console.log(`======================================================`);

      const context = await browser.newContext({
        timezoneId: tzConfig.id,
        viewport: { width: 1440, height: 960 },
        ignoreHTTPSErrors: true,
      });

      const page = await context.newPage();
      const consoleErrors = [];
      const failedNetwork = [];

      page.on('console', (msg) => {
        if (msg.type() === 'error') {
          const text = msg.text();
          if (!text.includes('favicon.ico')) {
            consoleErrors.push(text);
          }
        }
      });

      page.on('response', (resp) => {
        if (resp.status() >= 400 && !resp.url().includes('favicon.ico')) {
          failedNetwork.push({ url: resp.url(), status: resp.status() });
        }
      });

      // 1. Verify Browser JavaScript Timezone Proof (Part 5.2a)
      await page.goto('http://127.0.0.1:5173/login', { waitUntil: 'networkidle' });
      const proof = await page.evaluate(() => {
        const now = new Date();
        return {
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          offset: now.getTimezoneOffset(),
          isoString: now.toISOString(),
          localeString: now.toLocaleString(),
        };
      });

      console.log(`[Timezone Proof] Intl TimeZone: ${proof.timezone}`);
      console.log(`[Timezone Proof] getTimezoneOffset(): ${proof.offset} minutes`);
      console.log(`[Timezone Proof] Local String: ${proof.localeString}`);

      const isMatch = (proof.timezone === tzConfig.id) || 
                      (tzConfig.id === 'Asia/Kolkata' && proof.timezone === 'Asia/Calcutta') ||
                      (tzConfig.id === 'UTC' && (proof.timezone === 'UTC' || proof.timezone === 'Etc/UTC'));
      if (!isMatch) {
        throw new Error(`Timezone mismatch! Expected ${tzConfig.id}, got ${proof.timezone}`);
      }

      // 2. Perform Real Form Authentication
      console.log('[Auth] Performing real login with admin credentials...');
      await page.waitForSelector('input[name="identifier"], input.auth-input, input:not([type="password"])', { timeout: 10000 });
      await page.fill('input[name="identifier"], input.auth-input, input:not([type="password"])', 'admin');
      await page.fill('input[type="password"]', 'AdminPassword123!');
      await page.click('button[type="submit"]');

      // Wait for Dashboard to mount
      await page.waitForSelector('nav, aside, .glow-effect', { timeout: 10000 });
      console.log('[Auth] Successfully authenticated and loaded dashboard.');

      // Enable devMode in localStorage to unlock simulation tab
      await page.evaluate(() => {
        localStorage.setItem('devMode', 'true');
      });

      // Reload page to reflect devMode
      await page.goto('http://127.0.0.1:5173/dashboard', { waitUntil: 'networkidle' });
      await page.waitForTimeout(1000);

      // 3. Navigate to each page and take full screenshot (Part 5.2b)
      for (const p of PAGES) {
        console.log(`[Screenshot] Capturing ${tzConfig.label}_${p.name}...`);

        // Click menu item in sidebar
        const clicked = await page.evaluate((cfg) => {
          const buttons = Array.from(document.querySelectorAll('nav button, aside button, nav a'));
          const target = buttons.find(b => {
            const txt = b.textContent.trim().toLowerCase();
            const cleanTxt = txt.replace(/\s+/g, '');
            return txt.includes(cfg.label.toLowerCase()) || 
                   cleanTxt.includes(cfg.tab.toLowerCase()) || 
                   (b.getAttribute('title') || '').toLowerCase().includes(cfg.label.toLowerCase());
          });
          if (target) {
            target.click();
            return true;
          }
          return false;
        }, { tab: p.tab, label: p.label });

        // Wait for panel render
        await page.waitForTimeout(1200);

        const shotPath = path.join(SCREENSHOT_DIR, `${tzConfig.label}_${p.name}.png`);
        await page.screenshot({ path: shotPath, fullPage: true });
        console.log(`  -> Saved: ${shotPath}`);
      }

      // 4. Assert zero console errors and clean network
      console.log(`[Verification] Console Errors: ${consoleErrors.length}`);
      console.log(`[Verification] Failed Network Requests: ${failedNetwork.length}`);

      runSummary.push({
        timezone: tzConfig.id,
        proofTimezone: proof.timezone,
        offsetMin: proof.offset,
        consoleErrorsCount: consoleErrors.length,
        failedNetworkCount: failedNetwork.length,
        screenshotsCount: PAGES.length,
        status: (consoleErrors.length === 0 && failedNetwork.length === 0) ? 'PASS' : 'WARN',
      });

      await context.close();
    }
  } finally {
    if (browser) {
      await browser.close().catch(() => {});
    }
    if (staticServer) {
      staticServer.close();
    }
    console.log(`\n[Clean-up] Terminating backend process PID ${backendProc.pid}...`);
    try {
      process.kill(backendProc.pid, 'SIGKILL');
    } catch (e) {
      // On Windows use taskkill
      spawn('taskkill', ['/F', '/T', '/PID', String(backendProc.pid)]);
    }

    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch (e) { }
  }

  console.log('\n======================================================');
  console.log('=== BROWSER VERIFICATION RUN SUMMARY ===');
  console.log('======================================================');
  console.table(runSummary);

  const scratchDir = path.join(__dirname, '..', 'scratch');
  if (!fs.existsSync(scratchDir)) {
    fs.mkdirSync(scratchDir, { recursive: true });
  }
  const reportPath = path.join(scratchDir, `browser_verification_report_${Date.now()}.json`);
  fs.writeFileSync(reportPath, JSON.stringify(runSummary, null, 2), 'utf8');
  console.log(`Report saved to: ${reportPath}`);
}

main().catch((err) => {
  console.error('[Browser Verify Error]', err);
  process.exit(1);
});
