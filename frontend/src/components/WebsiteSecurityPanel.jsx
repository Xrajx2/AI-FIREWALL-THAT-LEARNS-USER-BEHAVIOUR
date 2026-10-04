import React, { useState, useEffect } from 'react';
import {
  Globe,
  ShieldAlert,
  ShieldCheck,
  Ban,
  AlertTriangle,
  Search,
  CheckCircle,
  Plus,
  Trash2,
  ExternalLink,
  RefreshCw,
  Sliders,
  Eye
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  CartesianGrid
} from 'recharts';
import { buildApiUrl, getAuthHeaders, getStoredUser, isAdminUser } from '../utils/auth';

const PIE_COLORS = ['#10b981', '#f59e0b', '#f97316', '#ef4444', '#8b5cf6'];

export default function WebsiteSecurityPanel() {
  const user = getStoredUser();
  const adminMode = isAdminUser(user);

  const [stats, setStats] = useState(null);
  const [logs, setLogs] = useState([]);
  const [blockedWebsites, setBlockedWebsites] = useState([]);
  const [whitelistedWebsites, setWhitelistedWebsites] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  const [activeSubTab, setActiveSubTab] = useState('logs'); // 'logs', 'blocked', 'whitelist', 'alerts', 'settings'
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  // Live Domain Scanner State
  const [scanUrlInput, setScanUrlInput] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [scanning, setScanning] = useState(false);

  // Add Domain Modal State
  const [showAddBlockModal, setShowAddBlockModal] = useState(false);
  const [newBlockDomain, setNewBlockDomain] = useState('');
  const [newBlockReason, setNewBlockReason] = useState('Manual Admin Security Block');
  const [newBlockCategory, setNewBlockCategory] = useState('Phishing/Malware');

  const [showAddWhitelistModal, setShowAddWhitelistModal] = useState(false);
  const [newWhitelistDomain, setNewWhitelistDomain] = useState('');
  const [newWhitelistReason, setNewWhitelistReason] = useState('Trusted Enterprise Domain');

  // Config State
  const [configData, setConfigData] = useState({
    suspicious_threshold: 30,
    high_risk_threshold: 60,
    malicious_threshold: 80,
    auto_block_threshold: 80
  });

  const fetchData = async () => {
    setLoading(true);
    try {
      const headers = getAuthHeaders();
      const [statsRes, logsRes, blockedRes, whiteRes, alertsRes, configRes] = await Promise.all([
        fetch(buildApiUrl('/api/website-security/stats'), { headers }),
        fetch(buildApiUrl(`/api/website-security/logs?limit=100${searchTerm ? `&search=${encodeURIComponent(searchTerm)}` : ''}${statusFilter ? `&threat_status=${encodeURIComponent(statusFilter)}` : ''}`), { headers }),
        fetch(buildApiUrl('/api/website-security/blocked'), { headers }),
        fetch(buildApiUrl('/api/website-security/whitelist'), { headers }),
        fetch(buildApiUrl('/api/website-security/alerts'), { headers }),
        fetch(buildApiUrl('/api/website-security/config'), { headers })
      ]);

      if (statsRes.ok) setStats(await statsRes.json());
      if (logsRes.ok) setLogs(await logsRes.json());
      if (blockedRes.ok) setBlockedWebsites(await blockedRes.json());
      if (whiteRes.ok) setWhitelistedWebsites(await whiteRes.json());
      if (alertsRes.ok) setAlerts(await alertsRes.json());
      if (configRes.ok) setConfigData(await configRes.json());
    } catch (err) {
      console.error('Error fetching Website Security data', err);
      window.showToast?.('Failed to fetch website security data', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [searchTerm, statusFilter]);

  const handleScanUrl = async (e) => {
    e.preventDefault();
    if (!scanUrlInput.trim()) return;
    setScanning(true);
    setScanResult(null);
    try {
      const res = await fetch(buildApiUrl('/api/website-security/scan'), {
        method: 'POST',
        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ url_or_domain: scanUrlInput })
      });
      const data = await res.json();
      if (res.ok) {
        setScanResult(data);
        fetchData();
        if (data.blocked) {
          window.showToast?.(`Website ${data.domain} BLOCKED! Threat Score: ${data.threat_score}`, 'error');
        } else {
          window.showToast?.(`Website ${data.domain} evaluated: ${data.threat_status}`, 'success');
        }
      } else {
        window.showToast?.(data.detail || 'Scan failed', 'error');
      }
    } catch {
      window.showToast?.('Failed to scan website', 'error');
    } finally {
      setScanning(false);
    }
  };

  const handleAddBlockedDomain = async (e) => {
    e.preventDefault();
    if (!newBlockDomain.trim()) return;
    try {
      const res = await fetch(buildApiUrl('/api/website-security/blocked'), {
        method: 'POST',
        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain: newBlockDomain,
          reason: newBlockReason,
          category: newBlockCategory,
          threat_score: 95.0
        })
      });
      if (res.ok) {
        window.showToast?.(`Domain ${newBlockDomain} blocked and hosts updated!`, 'success');
        setNewBlockDomain('');
        setShowAddBlockModal(false);
        fetchData();
      } else {
        const data = await res.json();
        window.showToast?.(data.detail || 'Failed to block domain', 'error');
      }
    } catch {
      window.showToast?.('Error blocking domain', 'error');
    }
  };

  const handleUnblockDomain = async (target) => {
    try {
      const res = await fetch(buildApiUrl(`/api/website-security/blocked/${encodeURIComponent(target)}`), {
        method: 'DELETE',
        headers: getAuthHeaders()
      });
      if (res.ok) {
        window.showToast?.(`Domain ${target} unblocked successfully!`, 'success');
        fetchData();
      } else {
        window.showToast?.('Failed to unblock domain', 'error');
      }
    } catch {
      window.showToast?.('Error unblocking domain', 'error');
    }
  };

  const handleAddWhitelistDomain = async (e) => {
    e.preventDefault();
    if (!newWhitelistDomain.trim()) return;
    try {
      const res = await fetch(buildApiUrl('/api/website-security/whitelist'), {
        method: 'POST',
        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain: newWhitelistDomain,
          reason: newWhitelistReason,
          is_permanent: true
        })
      });
      if (res.ok) {
        window.showToast?.(`Domain ${newWhitelistDomain} added to whitelist!`, 'success');
        setNewWhitelistDomain('');
        setShowAddWhitelistModal(false);
        fetchData();
      } else {
        window.showToast?.('Failed to whitelist domain', 'error');
      }
    } catch {
      window.showToast?.('Error whitelisting domain', 'error');
    }
  };

  const handleRemoveWhitelist = async (target) => {
    try {
      const res = await fetch(buildApiUrl(`/api/website-security/whitelist/${encodeURIComponent(target)}`), {
        method: 'DELETE',
        headers: getAuthHeaders()
      });
      if (res.ok) {
        window.showToast?.('Domain removed from whitelist', 'success');
        fetchData();
      }
    } catch {
      window.showToast?.('Error removing whitelist entry', 'error');
    }
  };

  const handleUpdateConfig = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(buildApiUrl('/api/website-security/config'), {
        method: 'PUT',
        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify(configData)
      });
      if (res.ok) {
        window.showToast?.('Website Security thresholds updated!', 'success');
        fetchData();
      }
    } catch {
      window.showToast?.('Failed to update thresholds', 'error');
    }
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <Globe className="w-7 h-7 text-primary" />
            Harmful Website Security & Blocking
          </h2>
          <p className="text-xs text-gray-400 mt-1">
            Real-time domain inspection, AI behavior anomaly scoring, and OS Hosts/Firewall blocking.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl border border-emerald-500/20 bg-emerald-500/10 text-emerald-400 text-xs font-semibold">
            <ShieldCheck size={14} /> OS Hosts Blocker Active
          </span>
          <button
            onClick={fetchData}
            className="p-2.5 rounded-xl border border-white/10 bg-secondary/50 hover:bg-white/10 text-gray-300 transition-colors"
            title="Refresh Data"
          >
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="p-5 rounded-2xl border border-white/5 bg-secondary/40 backdrop-blur-xl">
          <div className="text-xs uppercase tracking-wider text-gray-400 font-semibold mb-1">Total Visited</div>
          <div className="text-3xl font-extrabold text-white">{stats?.total_visited || 0}</div>
          <div className="text-[11px] text-gray-500 mt-1">Domains Inspected</div>
        </div>
        <div className="p-5 rounded-2xl border border-emerald-500/20 bg-emerald-500/5 backdrop-blur-xl">
          <div className="text-xs uppercase tracking-wider text-emerald-400 font-semibold mb-1">Safe Websites</div>
          <div className="text-3xl font-extrabold text-emerald-400">{stats?.safe_count || 0}</div>
          <div className="text-[11px] text-emerald-500/70 mt-1">Clean Connections</div>
        </div>
        <div className="p-5 rounded-2xl border border-amber-500/20 bg-amber-500/5 backdrop-blur-xl">
          <div className="text-xs uppercase tracking-wider text-amber-400 font-semibold mb-1">Suspicious</div>
          <div className="text-3xl font-extrabold text-amber-400">{stats?.suspicious_count || 0}</div>
          <div className="text-[11px] text-amber-500/70 mt-1">Monitored Anomalies</div>
        </div>
        <div className="p-5 rounded-2xl border border-rose-500/30 bg-rose-500/10 backdrop-blur-xl">
          <div className="text-xs uppercase tracking-wider text-rose-400 font-semibold mb-1">Blocked Harmful</div>
          <div className="text-3xl font-extrabold text-rose-400">{stats?.blocked_count || 0}</div>
          <div className="text-[11px] text-rose-400/80 mt-1">OS Hosts Blocked</div>
        </div>
        <div className="p-5 rounded-2xl border border-purple-500/20 bg-purple-500/5 backdrop-blur-xl">
          <div className="text-xs uppercase tracking-wider text-purple-400 font-semibold mb-1">Avg Threat Score</div>
          <div className="text-3xl font-extrabold text-purple-400">{stats?.average_threat_score || 0} / 100</div>
          <div className="text-[11px] text-purple-400/70 mt-1">Risk Evaluation</div>
        </div>
      </div>

      {/* Live Website Threat Inspector Tool */}
      <div className="p-6 rounded-2xl border border-primary/20 bg-primary/5 backdrop-blur-xl">
        <h3 className="text-base font-bold text-white mb-2 flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-primary" />
          Live Website Threat Inspector & Real-Time Block Tester
        </h3>
        <p className="text-xs text-gray-400 mb-4">
          Test any domain or URL (e.g. <code className="text-primary">paypal-security-login.xyz</code> or <code className="text-emerald-400">google.com</code>) to evaluate phishing risk, typosquatting, SSL status, AI browsing drift, and test OS blocking.
        </p>

        <form onSubmit={handleScanUrl} className="flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-3 w-4 h-4 text-gray-500" />
            <input
              type="text"
              value={scanUrlInput}
              onChange={(e) => setScanUrlInput(e.target.value)}
              placeholder="Enter URL or domain (e.g. http://chase-login-verify.xyz)"
              className="w-full pl-10 pr-4 py-2.5 rounded-xl border border-white/10 bg-secondary/80 text-white placeholder-gray-500 focus:outline-none focus:border-primary text-sm"
            />
          </div>
          <button
            type="submit"
            disabled={scanning}
            className="px-5 py-2.5 rounded-xl bg-primary hover:bg-primary/90 text-white font-semibold text-xs transition-colors flex items-center gap-2 disabled:opacity-50"
          >
            {scanning ? <RefreshCw className="animate-spin w-4 h-4" /> : <Globe className="w-4 h-4" />}
            Inspect & Test Block
          </button>
        </form>

        {scanResult && (
          <div className="mt-4 p-4 rounded-xl border border-white/10 bg-secondary/90 space-y-3 animate-in fade-in duration-200">
            <div className="flex items-center justify-between">
              <div className="font-bold text-white text-base">{scanResult.domain}</div>
              <span
                className={`px-3 py-1 rounded-full text-xs font-bold uppercase ${
                  scanResult.blocked || scanResult.threat_status === 'Malicious'
                    ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                    : scanResult.threat_status === 'High Risk'
                    ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                    : scanResult.threat_status === 'Suspicious'
                    ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                    : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                }`}
              >
                {scanResult.threat_status} (Score: {scanResult.threat_score}/100)
              </span>
            </div>

            <div className="text-xs text-gray-300">
              <strong>Action Taken:</strong>{' '}
              <span className={scanResult.blocked ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                {scanResult.action_taken.toUpperCase()}
              </span>{' '}
              {scanResult.blocked && '(Domain added to Windows Hosts File blocklist)'}
            </div>

            {scanResult.reasons && scanResult.reasons.length > 0 && (
              <div className="space-y-1">
                <div className="text-xs text-gray-400 font-semibold">Detection Signals:</div>
                <ul className="list-disc list-inside text-xs text-rose-300/90 space-y-0.5">
                  {scanResult.reasons.map((r, i) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Visual Recharts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Categories Pie Chart */}
        <div className="p-6 rounded-2xl border border-white/5 bg-secondary/40 backdrop-blur-xl">
          <h3 className="text-sm font-bold text-white mb-4">Threat Categories Distribution</h3>
          {stats?.threat_categories && stats.threat_categories.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={stats.threat_categories}
                    dataKey="count"
                    nameKey="category"
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    label={({ category, count }) => `${category} (${count})`}
                  >
                    {stats.threat_categories.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#1f2937', borderColor: '#374151', borderRadius: '8px', fontSize: '12px' }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-xs text-gray-500">No threat category data recorded yet.</div>
          )}
        </div>

        {/* High-Risk Domains Leaderboard */}
        <div className="p-6 rounded-2xl border border-white/5 bg-secondary/40 backdrop-blur-xl">
          <h3 className="text-sm font-bold text-white mb-4">Top Blocked & High Risk Domains</h3>
          {stats?.top_blocked_domains && stats.top_blocked_domains.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats.top_blocked_domains}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="domain" stroke="#9ca3af" fontSize={11} />
                  <YAxis stroke="#9ca3af" fontSize={11} />
                  <Tooltip contentStyle={{ backgroundColor: '#1f2937', borderColor: '#374151', borderRadius: '8px', fontSize: '12px' }} />
                  <Bar dataKey="count" fill="#ef4444" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-xs text-gray-500">No blocked domain statistics yet.</div>
          )}
        </div>
      </div>

      {/* Interactive Management Navigation Tabs */}
      <div className="border-b border-white/10 flex items-center gap-6 text-sm font-semibold">
        <button
          onClick={() => setActiveSubTab('logs')}
          className={`pb-3 transition-colors border-b-2 ${activeSubTab === 'logs' ? 'border-primary text-primary' : 'border-transparent text-gray-400 hover:text-white'}`}
        >
          Website Access Logs ({logs.length})
        </button>
        <button
          onClick={() => setActiveSubTab('blocked')}
          className={`pb-3 transition-colors border-b-2 flex items-center gap-1.5 ${activeSubTab === 'blocked' ? 'border-rose-500 text-rose-400' : 'border-transparent text-gray-400 hover:text-white'}`}
        >
          <Ban size={15} /> Blocked Blacklist ({blockedWebsites.length})
        </button>
        <button
          onClick={() => setActiveSubTab('whitelist')}
          className={`pb-3 transition-colors border-b-2 flex items-center gap-1.5 ${activeSubTab === 'whitelist' ? 'border-emerald-500 text-emerald-400' : 'border-transparent text-gray-400 hover:text-white'}`}
        >
          <CheckCircle size={15} /> Whitelisted ({whitelistedWebsites.length})
        </button>
        <button
          onClick={() => setActiveSubTab('alerts')}
          className={`pb-3 transition-colors border-b-2 flex items-center gap-1.5 ${activeSubTab === 'alerts' ? 'border-amber-500 text-amber-400' : 'border-transparent text-gray-400 hover:text-white'}`}
        >
          <AlertTriangle size={15} /> Security Alerts ({alerts.length})
        </button>
        {adminMode && (
          <button
            onClick={() => setActiveSubTab('settings')}
            className={`pb-3 transition-colors border-b-2 flex items-center gap-1.5 ${activeSubTab === 'settings' ? 'border-purple-500 text-purple-400' : 'border-transparent text-gray-400 hover:text-white'}`}
          >
            <Sliders size={15} /> Threshold Settings
          </button>
        )}
      </div>

      {/* Sub-Tab 1: Access Logs */}
      {activeSubTab === 'logs' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row gap-3 justify-between items-center">
            <div className="relative flex-1 w-full">
              <Search className="absolute left-3 top-2.5 w-4 h-4 text-gray-500" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search domain, URL, or category..."
                className="w-full pl-9 pr-4 py-2 rounded-xl border border-white/10 bg-secondary/40 text-white placeholder-gray-500 text-xs focus:outline-none focus:border-primary"
              />
            </div>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-3 py-2 rounded-xl border border-white/10 bg-secondary/40 text-white text-xs focus:outline-none"
            >
              <option value="">All Statuses</option>
              <option value="Safe">Safe</option>
              <option value="Suspicious">Suspicious</option>
              <option value="High Risk">High Risk</option>
              <option value="Malicious">Malicious</option>
            </select>
          </div>

          <div className="rounded-2xl border border-white/5 bg-secondary/40 overflow-hidden backdrop-blur-xl">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-gray-300">
                <thead className="bg-white/5 text-gray-400 font-semibold uppercase tracking-wider text-[10px] border-b border-white/5">
                  <tr>
                    <th className="px-4 py-3">Domain / URL</th>
                    <th className="px-4 py-3">User</th>
                    <th className="px-4 py-3">Threat Status</th>
                    <th className="px-4 py-3">Risk Score</th>
                    <th className="px-4 py-3">Category</th>
                    <th className="px-4 py-3">Action</th>
                    <th className="px-4 py-3">Timestamp</th>
                    {adminMode && <th className="px-4 py-3 text-right">Quick Control</th>}
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {logs.length > 0 ? (
                    logs.map((log) => (
                      <tr key={log.id} className="hover:bg-white/5 transition-colors">
                        <td className="px-4 py-3 font-semibold text-white max-w-xs truncate">
                          <div>{log.domain}</div>
                          <div className="text-[10px] text-gray-500 truncate">{log.url}</div>
                        </td>
                        <td className="px-4 py-3 text-gray-400">{log.username}</td>
                        <td className="px-4 py-3">
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                              log.threat_status === 'Malicious'
                                ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                                : log.threat_status === 'High Risk'
                                ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                                : log.threat_status === 'Suspicious'
                                ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                                : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                            }`}
                          >
                            {log.threat_status}
                          </span>
                        </td>
                        <td className="px-4 py-3 font-bold">{log.threat_score.toFixed(1)} / 100</td>
                        <td className="px-4 py-3 text-gray-400">{log.category}</td>
                        <td className="px-4 py-3 uppercase font-semibold text-[10px]">
                          <span className={log.action_taken === 'blocked' ? 'text-rose-400 font-bold' : 'text-emerald-400'}>
                            {log.action_taken}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-gray-500">{new Date(log.timestamp).toLocaleTimeString()}</td>
                        {adminMode && (
                          <td className="px-4 py-3 text-right">
                            <div className="flex items-center justify-end gap-2">
                              {log.action_taken === 'blocked' ? (
                                <button
                                  onClick={() => handleUnblockDomain(log.domain)}
                                  className="px-2 py-1 rounded bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 font-semibold text-[10px]"
                                >
                                  Unblock
                                </button>
                              ) : (
                                <button
                                  onClick={() => {
                                    setNewBlockDomain(log.domain);
                                    setShowAddBlockModal(true);
                                  }}
                                  className="px-2 py-1 rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-400 font-semibold text-[10px]"
                                >
                                  Block
                                </button>
                              )}
                            </div>
                          </td>
                        )}
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={8} className="px-4 py-8 text-center text-gray-500">
                        No website access logs found matching filters.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Sub-Tab 2: Blocked Blacklist */}
      {activeSubTab === 'blocked' && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-sm font-bold text-white">Active Blocked Domains (OS Hosts File Enforced)</h3>
            {adminMode && (
              <button
                onClick={() => setShowAddBlockModal(true)}
                className="px-3 py-1.5 rounded-xl bg-rose-500 hover:bg-rose-600 text-white font-semibold text-xs transition-colors flex items-center gap-1.5"
              >
                <Plus size={14} /> Add Domain Block
              </button>
            )}
          </div>

          <div className="rounded-2xl border border-white/5 bg-secondary/40 overflow-hidden backdrop-blur-xl">
            <table className="w-full text-left text-xs text-gray-300">
              <thead className="bg-white/5 text-gray-400 font-semibold uppercase tracking-wider text-[10px] border-b border-white/5">
                <tr>
                  <th className="px-4 py-3">Blocked Domain</th>
                  <th className="px-4 py-3">Reason</th>
                  <th className="px-4 py-3">Category</th>
                  <th className="px-4 py-3">Added By</th>
                  <th className="px-4 py-3">Created Date</th>
                  {adminMode && <th className="px-4 py-3 text-right">Action</th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {blockedWebsites.length > 0 ? (
                  blockedWebsites.map((b) => (
                    <tr key={b.id} className="hover:bg-white/5 transition-colors">
                      <td className="px-4 py-3 font-bold text-rose-400 flex items-center gap-2">
                        <Ban size={14} /> {b.domain}
                      </td>
                      <td className="px-4 py-3 text-gray-300">{b.reason}</td>
                      <td className="px-4 py-3 text-gray-400">{b.category}</td>
                      <td className="px-4 py-3 text-gray-400">{b.added_by}</td>
                      <td className="px-4 py-3 text-gray-500">{new Date(b.created_at).toLocaleDateString()}</td>
                      {adminMode && (
                        <td className="px-4 py-3 text-right">
                          <button
                            onClick={() => handleUnblockDomain(b.domain)}
                            className="p-1.5 rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 transition-colors"
                            title="Unblock Domain"
                          >
                            <Trash2 size={14} />
                          </button>
                        </td>
                      )}
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-gray-500">
                      No domains currently on active blocklist.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Sub-Tab 3: Whitelist */}
      {activeSubTab === 'whitelist' && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-sm font-bold text-white">Whitelisted Domains (Trusted Override)</h3>
            {adminMode && (
              <button
                onClick={() => setShowAddWhitelistModal(true)}
                className="px-3 py-1.5 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-white font-semibold text-xs transition-colors flex items-center gap-1.5"
              >
                <Plus size={14} /> Add Whitelist Rule
              </button>
            )}
          </div>

          <div className="rounded-2xl border border-white/5 bg-secondary/40 overflow-hidden backdrop-blur-xl">
            <table className="w-full text-left text-xs text-gray-300">
              <thead className="bg-white/5 text-gray-400 font-semibold uppercase tracking-wider text-[10px] border-b border-white/5">
                <tr>
                  <th className="px-4 py-3">Whitelisted Domain</th>
                  <th className="px-4 py-3">Reason</th>
                  <th className="px-4 py-3">Added By</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {whitelistedWebsites.length > 0 ? (
                  whitelistedWebsites.map((w) => (
                    <tr key={w.id} className="hover:bg-white/5 transition-colors">
                      <td className="px-4 py-3 font-bold text-emerald-400 flex items-center gap-2">
                        <CheckCircle size={14} /> {w.domain}
                      </td>
                      <td className="px-4 py-3 text-gray-300">{w.reason}</td>
                      <td className="px-4 py-3 text-gray-400">{w.added_by}</td>
                      <td className="px-4 py-3 text-gray-500">{w.is_permanent ? 'Permanent' : 'Temporary'}</td>
                      <td className="px-4 py-3 text-right">
                        {adminMode && (
                          <button
                            onClick={() => handleRemoveWhitelist(w.domain)}
                            className="p-1.5 rounded bg-white/5 hover:bg-white/10 text-gray-400 hover:text-white transition-colors"
                            title="Remove Whitelist"
                          >
                            <Trash2 size={14} />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={5} className="px-4 py-8 text-center text-gray-500">
                      No explicit whitelist domains defined.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Sub-Tab 4: Security Alerts */}
      {activeSubTab === 'alerts' && (
        <div className="space-y-4">
          <h3 className="text-sm font-bold text-white">Website Security Alerts</h3>
          <div className="space-y-3">
            {alerts.length > 0 ? (
              alerts.map((a) => (
                <div key={a.id} className="p-4 rounded-2xl border border-rose-500/20 bg-rose-500/5 backdrop-blur-xl flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <ShieldAlert className="w-5 h-5 text-rose-400" />
                      <span className="font-bold text-white text-sm">{a.domain}</span>
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                        {a.threat_level} ({a.threat_score}/100)
                      </span>
                    </div>
                    <div className="text-xs text-gray-300">{a.reason}</div>
                    <div className="text-[11px] text-gray-500 mt-1">
                      User: <strong>{a.username}</strong> &bull; Action: <strong className="text-rose-400">{a.action_taken}</strong> &bull; {new Date(a.timestamp).toLocaleString()}
                    </div>
                  </div>
                  <a
                    href={buildApiUrl(`/api/website-security/block-page?domain=${encodeURIComponent(a.domain)}&score=${a.threat_score}&reason=${encodeURIComponent(a.reason)}&category=${encodeURIComponent(a.category)}&user_name=${encodeURIComponent(a.username)}`)}
                    target="_blank"
                    rel="noreferrer"
                    className="px-3 py-1.5 rounded-xl border border-white/10 bg-white/5 hover:bg-white/10 text-xs font-semibold text-gray-300 flex items-center gap-1.5 shrink-0"
                  >
                    <Eye size={14} /> Preview Warning Page
                  </a>
                </div>
              ))
            ) : (
              <div className="p-8 text-center text-xs text-gray-500 rounded-2xl border border-white/5 bg-secondary/40">
                No high-risk website alerts recorded yet.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Sub-Tab 5: Threshold Settings */}
      {activeSubTab === 'settings' && adminMode && (
        <div className="p-6 rounded-2xl border border-white/5 bg-secondary/40 backdrop-blur-xl max-w-2xl">
          <h3 className="text-base font-bold text-white mb-4 flex items-center gap-2">
            <Sliders className="w-5 h-5 text-purple-400" />
            Website Risk Threshold & Auto-Block Settings
          </h3>
          <form onSubmit={handleUpdateConfig} className="space-y-5">
            <div>
              <label className="block text-xs font-semibold text-gray-300 mb-1">Suspicious Threshold (30-59)</label>
              <input
                type="number"
                value={configData.suspicious_threshold}
                onChange={(e) => setConfigData({ ...configData, suspicious_threshold: parseFloat(e.target.value) })}
                className="w-full px-3 py-2 rounded-xl border border-white/10 bg-secondary/80 text-white text-xs"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-gray-300 mb-1">High Risk Threshold (60-79)</label>
              <input
                type="number"
                value={configData.high_risk_threshold}
                onChange={(e) => setConfigData({ ...configData, high_risk_threshold: parseFloat(e.target.value) })}
                className="w-full px-3 py-2 rounded-xl border border-white/10 bg-secondary/80 text-white text-xs"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-gray-300 mb-1">Auto-Block Threshold (80-100)</label>
              <input
                type="number"
                value={configData.auto_block_threshold}
                onChange={(e) => setConfigData({ ...configData, auto_block_threshold: parseFloat(e.target.value) })}
                className="w-full px-3 py-2 rounded-xl border border-white/10 bg-secondary/80 text-white text-xs"
              />
            </div>
            <button
              type="submit"
              className="px-5 py-2.5 rounded-xl bg-purple-600 hover:bg-purple-700 text-white font-semibold text-xs transition-colors"
            >
              Save Configuration Settings
            </button>
          </form>
        </div>
      )}

      {/* Add Block Modal */}
      {showAddBlockModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-secondary/90 border border-white/10 rounded-2xl p-6 max-w-md w-full shadow-2xl space-y-4 animate-in zoom-in-95 duration-200">
            <h3 className="text-lg font-bold text-white">Add Domain Block (OS Level)</h3>
            <form onSubmit={handleAddBlockedDomain} className="space-y-4">
              <div>
                <label className="block text-xs text-gray-400 mb-1">Domain Name</label>
                <input
                  type="text"
                  value={newBlockDomain}
                  onChange={(e) => setNewBlockDomain(e.target.value)}
                  placeholder="e.g. malicious-phishing-site.com"
                  className="w-full px-3 py-2 rounded-xl border border-white/10 bg-secondary text-white text-xs focus:outline-none focus:border-rose-500"
                  required
                />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Reason for Blocking</label>
                <input
                  type="text"
                  value={newBlockReason}
                  onChange={(e) => setNewBlockReason(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl border border-white/10 bg-secondary text-white text-xs"
                />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Category</label>
                <select
                  value={newBlockCategory}
                  onChange={(e) => setNewBlockCategory(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl border border-white/10 bg-secondary text-white text-xs"
                >
                  <option value="Phishing/Malware">Phishing/Malware</option>
                  <option value="Typosquatting">Typosquatting</option>
                  <option value="Adult/Gambling">Adult/Gambling</option>
                  <option value="Security Violation">Security Violation</option>
                </select>
              </div>
              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddBlockModal(false)}
                  className="px-4 py-2 rounded-xl border border-white/10 text-gray-400 hover:text-white text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl bg-rose-500 hover:bg-rose-600 text-white font-semibold text-xs"
                >
                  Block Domain Now
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add Whitelist Modal */}
      {showAddWhitelistModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-secondary/90 border border-white/10 rounded-2xl p-6 max-w-md w-full shadow-2xl space-y-4 animate-in zoom-in-95 duration-200">
            <h3 className="text-lg font-bold text-white">Add Whitelist Domain</h3>
            <form onSubmit={handleAddWhitelistDomain} className="space-y-4">
              <div>
                <label className="block text-xs text-gray-400 mb-1">Domain Name</label>
                <input
                  type="text"
                  value={newWhitelistDomain}
                  onChange={(e) => setNewWhitelistDomain(e.target.value)}
                  placeholder="e.g. trusted-partner.com"
                  className="w-full px-3 py-2 rounded-xl border border-white/10 bg-secondary text-white text-xs focus:outline-none focus:border-emerald-500"
                  required
                />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Reason for Whitelisting</label>
                <input
                  type="text"
                  value={newWhitelistReason}
                  onChange={(e) => setNewWhitelistReason(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl border border-white/10 bg-secondary text-white text-xs"
                />
              </div>
              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddWhitelistModal(false)}
                  className="px-4 py-2 rounded-xl border border-white/10 text-gray-400 hover:text-white text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-600 text-white font-semibold text-xs"
                >
                  Whitelist Domain
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
