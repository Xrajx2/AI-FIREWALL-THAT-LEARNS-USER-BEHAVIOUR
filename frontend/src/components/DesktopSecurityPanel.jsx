import React, { useEffect, useMemo, useState } from 'react';
import {
  Ban,
  ClipboardCheck,
  Cpu,
  Globe,
  Network,
  Radar,
  ShieldCheck,
  ShieldQuestion,
  Trash2,
} from 'lucide-react';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { buildApiUrl, getAuthHeaders } from '../utils/auth';
import { getRiskTone, normalizeRiskLevel } from '../utils/risk';

const emptySecurityCenter = {
  processes: { count: 0, top: [], suspicious: [] },
  traffic: { applications: [], connections: [], suspicious_connections: [], aggregate: { upload_kbps: 0, download_kbps: 0 } },
  threat_history: [],
  resource_mode: { low_resource_notes: [] },
};

export default function DesktopSecurityPanel() {
  const [securityCenter, setSecurityCenter] = useState(emptySecurityCenter);
  const [trafficSeries, setTrafficSeries] = useState([]);
  const [scanText, setScanText] = useState('');
  const [scanSource, setScanSource] = useState('clipboard');
  const [textScanResult, setTextScanResult] = useState(null);
  const [url, setUrl] = useState('');
  const [urlScanResult, setUrlScanResult] = useState(null);
  const [firewallPath, setFirewallPath] = useState('');
  const [firewallResult, setFirewallResult] = useState(null);
  const [rules, setRules] = useState([]);
  const [warning, setWarning] = useState('');

  const fetchRules = async () => {
    try {
      const response = await fetch(buildApiUrl('/api/desktop/firewall/rules'), { headers: getAuthHeaders() });
      if (response.ok) {
        setRules(await response.json());
      }
    } catch (error) {
      console.error('Failed to load firewall rules', error);
    }
  };

  useEffect(() => {
    const fetchSecurityCenter = async () => {
      try {
        const response = await fetch(buildApiUrl('/api/desktop/security-center'), { headers: getAuthHeaders() });
        if (!response.ok) {
          setWarning(response.status === 401 ? 'Sign in again to refresh desktop security telemetry.' : 'Desktop security telemetry is temporarily unavailable.');
          return;
        }
        const data = await response.json();
        setSecurityCenter(data);
        setWarning('');
        const now = new Date();
        setTrafficSeries((current) => [
          ...current.slice(-19),
          {
            time: now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
            upload: Number(data.traffic?.aggregate?.upload_kbps || 0),
            download: Number(data.traffic?.aggregate?.download_kbps || 0),
          },
        ]);
      } catch (error) {
        console.error('Failed to load desktop security center', error);
        setWarning('Desktop security telemetry is temporarily unavailable.');
      }
    };

    fetchSecurityCenter();
    fetchRules();
    const interval = setInterval(fetchSecurityCenter, 3000);
    return () => clearInterval(interval);
  }, []);

  const highestRisk = useMemo(() => {
    const rows = [
      ...(securityCenter.processes?.suspicious || []).map((item) => item.risk?.score || 0),
      ...(securityCenter.traffic?.suspicious_connections || []).map((item) => item.risk_score || 0),
    ];
    return rows.length ? Math.max(...rows) : 0;
  }, [securityCenter]);

  const runTextScan = async () => {
    if (!scanText.trim()) return;
    try {
      const response = await fetch(buildApiUrl('/api/desktop/scan-text'), {
        method: 'POST',
        headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ source: scanSource, text: scanText }),
      });
      if (response.ok) {
        setTextScanResult(await response.json());
        window.showToast?.('Text safety analysis complete.', 'success');
      } else {
        window.showToast?.('Failed to complete text scan.', 'error');
      }
    } catch (e) {
      window.showToast?.('Connection error running text scan.', 'error');
    }
  };

  const runUrlScan = async () => {
    if (!url.trim()) return;
    try {
      const response = await fetch(buildApiUrl('/api/desktop/scan-url'), {
        method: 'POST',
        headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ url }),
      });
      if (response.ok) {
        setUrlScanResult(await response.json());
        window.showToast?.('URL reputation audit complete.', 'success');
      } else {
        window.showToast?.('Failed to complete URL scan.', 'error');
      }
    } catch (e) {
      window.showToast?.('Connection error running URL scan.', 'error');
    }
  };

  const applyFirewallRule = async (action) => {
    if (!firewallPath.trim()) return;
    try {
      const response = await fetch(buildApiUrl('/api/desktop/firewall/rules'), {
        method: 'POST',
        headers: getAuthHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ application_path: firewallPath, action }),
      });
      const data = await response.json();
      if (response.ok) {
        setFirewallResult(data);
        fetchRules();
        const baseName = firewallPath.split(/[\\/]/).pop() || 'application';
        window.showToast?.(`Rule successfully applied to ${action} ${baseName}!`, 'success');
        setFirewallPath('');
      } else {
        window.showToast?.(data.detail || 'Failed to apply firewall rule.', 'error');
      }
    } catch (e) {
      window.showToast?.('Connection error applying firewall rule.', 'error');
    }
  };

  const deleteFirewallRule = async (ruleId, ruleName) => {
    if (!window.confirm(`Are you sure you want to delete the firewall rule "${ruleName}"?`)) return;
    try {
      const response = await fetch(buildApiUrl(`/api/desktop/firewall/rules/${ruleId}`), {
        method: 'DELETE',
        headers: getAuthHeaders(),
      });
      if (response.ok) {
        fetchRules();
        window.showToast?.(`Rule "${ruleName}" successfully deleted.`, 'success');
      } else {
        window.showToast?.('Failed to delete rule.', 'error');
      }
    } catch (e) {
      window.showToast?.('Connection error deleting rule.', 'error');
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <header className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="text-3xl font-bold text-white">Windows Security Center</h2>
            <span className="rounded-md border border-success/20 bg-success/10 px-2.5 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-success">
              Desktop
            </span>
          </div>
          <p className="mt-2 text-gray-400">
            Background host protection, application traffic, AI content scanning, firewall controls, and behavior anomalies.
          </p>
        </div>
        <div className="rounded-md border border-gray-700/10 bg-gray-900/10 px-4 py-3 text-sm text-gray-300">
          {securityCenter.host || 'localhost'} | {securityCenter.startup?.managed_by || 'electron'} startup
        </div>
      </header>

      {warning && (
        <div className="rounded-md border border-warning/20 bg-warning/10 p-4 text-sm text-warning">
          {warning}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <MetricCard title="Processes" value={securityCenter.processes?.count || 0} detail={`${securityCenter.processes?.suspicious?.length || 0} suspicious`} icon={<Cpu />} />
        <MetricCard title="Connections" value={securityCenter.traffic?.connection_count || 0} detail={`${securityCenter.traffic?.applications?.length || 0} active apps`} icon={<Network />} />
        <MetricCard title="Risk Peak" value={normalizeRiskLevel(null, highestRisk)} detail={`Score ${highestRisk.toFixed(1)}`} icon={<Radar />} tone={getRiskTone(null, highestRisk).text} />
        <MetricCard title="AI Scanners" value={securityCenter.scanners?.status || 'Active'} detail={`${securityCenter.scanners?.active_count || 4} engines (Phish, Spam, Clip, Proc)`} icon={<ShieldCheck />} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <section className="xl:col-span-2 glass-panel p-5 shadow-sm">
          <div className="mb-4 flex items-center justify-between gap-4">
            <div className="flex items-center gap-2 text-gray-200">
              <Network size={18} />
              <h3 className="font-semibold">Live Application Bandwidth</h3>
            </div>
            <div className="text-xs text-gray-500">
              Up {securityCenter.traffic?.aggregate?.upload_kbps || 0} kbps | Down {securityCenter.traffic?.aggregate?.download_kbps || 0} kbps
            </div>
          </div>
          <div className="h-[260px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trafficSeries} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="desktopUpload" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#22c55e" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#22c55e" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="desktopDownload" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#38bdf8" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" vertical={false} />
                <XAxis dataKey="time" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#ffffff', border: '1px solid #cbd5e1', borderRadius: '8px', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                  itemStyle={{ color: '#1e293b' }}
                  labelStyle={{ color: '#64748b', fontWeight: 'bold' }}
                />
                <Area type="monotone" dataKey="download" stroke="#38bdf8" strokeWidth={2} fill="url(#desktopDownload)" />
                <Area type="monotone" dataKey="upload" stroke="#22c55e" strokeWidth={2} fill="url(#desktopUpload)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </section>

        <section className="glass-panel p-5 shadow-sm flex flex-col justify-between">
          <div>
            <div className="mb-4 flex items-center gap-2 text-gray-200">
              <Ban size={18} />
              <h3 className="font-semibold">Firewall Rule</h3>
            </div>
            <input
              value={firewallPath}
              onChange={(event) => setFirewallPath(event.target.value)}
              placeholder="C:\\Program Files\\App\\app.exe"
              className="w-full rounded-md border border-gray-700/10 bg-gray-900/10 px-3 py-2 text-sm text-white outline-none focus:border-primary/40"
            />
            <div className="mt-3 flex gap-2">
              <button onClick={() => applyFirewallRule('block')} className="inline-flex flex-1 items-center justify-center gap-2 rounded-md border border-danger/20 bg-danger/10 px-3 py-2 text-sm font-semibold text-danger">
                <Ban size={16} />
                Block
              </button>
              <button onClick={() => applyFirewallRule('allow')} className="inline-flex flex-1 items-center justify-center gap-2 rounded-md border border-success/20 bg-success/10 px-3 py-2 text-sm font-semibold text-success">
                <ShieldCheck size={16} />
                Allow
              </button>
            </div>
            {firewallResult && (
              <div className="mt-4 rounded-md border border-gray-700/10 bg-gray-900/10 p-3 text-xs text-gray-300">
                <div className="font-semibold text-white">{firewallResult.status}</div>
                <div className="mt-1 break-all">{firewallResult.rule_name}</div>
                {firewallResult.stderr && <div className="mt-2 text-danger">{firewallResult.stderr}</div>}
              </div>
            )}
          </div>

          <div className="mt-6 border-t border-gray-700/10 pt-4 flex-1">
            <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-3">Active Rules</h4>
            {rules.length === 0 ? (
              <div className="text-xs text-gray-500 italic py-2">No active rules recorded.</div>
            ) : (
              <div className="space-y-2 max-h-[180px] overflow-y-auto pr-1">
                {rules.map((rule) => (
                  <div key={rule.id} className="p-2.5 rounded-lg bg-gray-900/10 border border-gray-700/10 flex items-center justify-between gap-3 text-xs">
                    <div className="truncate flex-1">
                      <span className="font-mono text-[10px] text-gray-300 block truncate" title={rule.application_path}>
                        {rule.application_path.split(/[\\/]/).pop()}
                      </span>
                      <span className="text-[10px] text-gray-500 block">
                        {rule.direction.toUpperCase()} | {rule.action.toUpperCase()}
                      </span>
                    </div>
                    <button
                      onClick={() => deleteFirewallRule(rule.id, rule.rule_name)}
                      className="p-1 rounded text-rose-500 hover:bg-rose-500/10 transition-colors shrink-0"
                      title="Delete Rule"
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <ScanPanel
          title="AI Spam Scan"
          icon={<ClipboardCheck size={18} />}
          result={textScanResult}
          control={(
            <>
              <select value={scanSource} onChange={(event) => setScanSource(event.target.value)} className="rounded-md border border-gray-700/10 bg-gray-900/10 px-3 py-2 text-sm text-white outline-none">
                <option value="clipboard">Clipboard</option>
                <option value="email">Email</option>
                <option value="notification">Notification</option>
              </select>
              <button onClick={runTextScan} className="rounded-md border border-primary/20 bg-primary/10 px-4 py-2 text-sm font-semibold text-primary">
                Scan
              </button>
            </>
          )}
        >
          <textarea
            value={scanText}
            onChange={(event) => setScanText(event.target.value)}
            placeholder="Paste email, notification, or clipboard text..."
            className="h-32 w-full resize-none rounded-md border border-gray-700/10 bg-gray-900/10 px-3 py-2 text-sm text-white outline-none focus:border-primary/40"
          />
        </ScanPanel>

        <ScanPanel
          title="Phishing URL Scan"
          icon={<Globe size={18} />}
          result={urlScanResult}
          control={(
            <button onClick={runUrlScan} className="rounded-md border border-primary/20 bg-primary/10 px-4 py-2 text-sm font-semibold text-primary">
              Scan
            </button>
          )}
        >
          <input
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            placeholder="https://example.com/login"
            className="w-full rounded-md border border-gray-700/10 bg-gray-900/10 px-3 py-2 text-sm text-white outline-none focus:border-primary/40"
          />
        </ScanPanel>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <DataPanel title="Per-Application Traffic" icon={<Network size={18} />} rows={securityCenter.traffic?.applications || []} emptyText="No application traffic captured yet." renderRow={(item) => (
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="font-semibold text-white">{item.application}</div>
              <div className="mt-1 text-xs text-gray-500">{item.connection_count} connections | ports {(item.remote_ports || []).join(', ') || '-'}</div>
              <div className="mt-1 text-xs text-gray-400 break-all">{(item.remote_ips || []).join(', ') || 'No remote IPs'}</div>
            </div>
            <div className="text-right text-xs text-gray-300">
              <div>{Number(item.download_kbps || 0).toFixed(1)} down</div>
              <div>{Number(item.upload_kbps || 0).toFixed(1)} up</div>
            </div>
          </div>
        )} />

        <DataPanel title="Suspicious Processes" icon={<ShieldQuestion size={18} />} rows={securityCenter.processes?.suspicious || []} emptyText="No suspicious processes detected." renderRow={(item) => (
          <RiskRow title={`${item.name} (${item.pid})`} subtitle={`${item.memory_mb} MB | CPU ${item.cpu}`} risk={item.risk} />
        )} />

        <DataPanel title="Suspicious Connections" icon={<Radar size={18} />} rows={securityCenter.traffic?.suspicious_connections || []} emptyText="No suspicious connections flagged." renderRow={(item) => (
          <RiskRow title={`${item.process} -> ${item.remote_ip}:${item.remote_port}`} subtitle={(item.reasons || []).join(' | ')} risk={{ score: item.risk_score, level: item.risk_level }} />
        )} />

        <DataPanel title="Threat History" icon={<ShieldCheck size={18} />} rows={securityCenter.threat_history || []} emptyText="Threat history is clear." renderRow={(item) => (
          <RiskRow title={item.title} subtitle={item.summary} risk={{ score: item.score, level: item.risk_level }} />
        )} />
      </div>
    </div>
  );
}

function MetricCard({ title, value, detail, icon, tone = 'text-primary' }) {
  return (
    <div className="glass-panel p-5 shadow-sm">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-xs uppercase tracking-[0.18em] text-gray-500">{title}</div>
          <div className="mt-3 text-3xl font-bold text-white">{value}</div>
          <div className="mt-2 text-sm text-gray-400">{detail}</div>
        </div>
        <div className={`flex h-11 w-11 items-center justify-center rounded-md border border-gray-700/10 bg-gray-900/10 ${tone}`}>
          {React.cloneElement(icon, { size: 22 })}
        </div>
      </div>
    </div>
  );
}

function ScanPanel({ title, icon, result, control, children }) {
  const tone = getRiskTone(result?.risk_level, result?.score);
  return (
    <section className="glass-panel p-5 shadow-sm">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-gray-200">
          {icon}
          <h3 className="font-semibold">{title}</h3>
        </div>
        <div className="flex items-center gap-2">{control}</div>
      </div>
      {children}
      {result && (
        <div className="mt-4 rounded-md border border-gray-700/10 bg-gray-900/10 p-4">
          <div className="flex items-center justify-between gap-3">
            <span className={`rounded-md border px-2.5 py-1 text-xs font-semibold ${tone.badge}`}>
              {normalizeRiskLevel(result.risk_level, result.score)}
            </span>
            <span className={`font-mono text-sm ${tone.text}`}>{Number(result.score || 0).toFixed(1)}</span>
          </div>
          <div className="mt-3 space-y-1 text-sm text-gray-300">
            {(result.reasons || []).map((reason) => <div key={reason}>{reason}</div>)}
          </div>
        </div>
      )}
    </section>
  );
}

function DataPanel({ title, icon, rows, emptyText, renderRow }) {
  return (
    <section className="glass-panel p-5 shadow-sm">
      <div className="mb-4 flex items-center gap-2 text-gray-200">
        {icon}
        <h3 className="font-semibold">{title}</h3>
      </div>
      <div className="space-y-3">
        {rows.length ? rows.slice(0, 8).map((row, index) => (
          <div key={`${title}-${index}`} className="rounded-md border border-gray-700/10 bg-gray-900/10 p-4">
            {renderRow(row)}
          </div>
        )) : (
          <div className="rounded-md border border-gray-700/10 bg-gray-900/10 p-4 text-sm text-gray-500">{emptyText}</div>
        )}
      </div>
    </section>
  );
}

function RiskRow({ title, subtitle, risk }) {
  const tone = getRiskTone(risk?.level, risk?.score);
  return (
    <div className="flex items-start justify-between gap-4">
      <div>
        <div className="font-semibold text-white break-all">{title}</div>
        <div className="mt-1 text-xs text-gray-400 break-all">{subtitle}</div>
      </div>
      <div className="text-right">
        <span className={`rounded-md border px-2.5 py-1 text-xs font-semibold ${tone.badge}`}>
          {normalizeRiskLevel(risk?.level, risk?.score)}
        </span>
        <div className={`mt-2 font-mono text-xs ${tone.text}`}>{Number(risk?.score || 0).toFixed(1)}</div>
      </div>
    </div>
  );
}
