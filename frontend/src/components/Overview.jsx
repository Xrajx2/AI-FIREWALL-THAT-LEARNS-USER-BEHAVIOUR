import React, { useState, useEffect } from 'react';
import { Activity, ShieldAlert, ShieldBan, Cpu } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import AccountSecurityPanel from './AccountSecurityPanel';
import { getRiskTone, normalizeRiskLevel } from '../utils/risk';
import { buildApiUrl, getAuthHeaders, getStoredUser, isAdminUser } from '../utils/auth';

const isSystemAccount = (user) => {
  const username = String(user?.username || '').toLowerCase();
  return username.endsWith('-agent') || username.startsWith('system-') || username === 'usb-security-agent';
};

const buildChartSeries = (activity = [], threats = [], activeBase = 0) => {
  const sortedActivity = [...activity].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp)).slice(-24);

  const processedData = sortedActivity.map((act) => {
    const dateStr = act.timestamp + (act.timestamp.includes('Z') ? '' : 'Z');
    const date = new Date(dateStr);
    const timeStr = `${date.getHours().toString().padStart(2, '0')}:${date.getMinutes().toString().padStart(2, '0')}`;
    const matchedThreat = threats.find((threat) => {
      const threatTime = new Date(threat.timestamp).getTime();
      const activityTime = date.getTime();
      return threatTime - activityTime < 5000 && threatTime >= activityTime;
    });

    return {
      time: timeStr,
      score: matchedThreat ? matchedThreat.anomaly_score : Number(act.risk_score || 0),
      active: Math.max(1, activeBase),
    };
  });

  while (processedData.length < 10) {
    processedData.unshift({ time: '--:--', score: 0, active: 0 });
  }

  return processedData;
};

const formatLocalTimestamp = (value) => {
  if (!value) {
    return '-';
  }
  const hasTimezone = typeof value === 'string' && (value.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(value));
  const normalized = typeof value === 'string' && !hasTimezone ? `${value}Z` : value;
  const parsed = new Date(normalized);
  return Number.isNaN(parsed.getTime()) ? '-' : parsed.toLocaleString();
};

const buildUsbBadge = (usbStatus) => {
  if (!usbStatus) {
    return { label: 'Checking', className: 'bg-gray-800 text-gray-400 border border-gray-700' };
  }
  if (!usbStatus.enabled) {
    return { label: 'Disabled', className: 'bg-danger/10 text-danger border border-danger/20' };
  }
  if (usbStatus.collector === 'windows-host-agent' && usbStatus.snapshot_fresh) {
    return { label: 'Host Agent Live', className: 'bg-success/10 text-success border border-success/20' };
  }
  if (usbStatus.collector === 'windows-host-agent') {
    return { label: 'Host Agent Stale', className: 'bg-warning/10 text-warning border border-warning/20' };
  }
  return { label: 'Fallback Only', className: 'bg-warning/10 text-warning border border-warning/20' };
};

const formatUsbActionLabel = (actionType) => {
  const normalized = String(actionType || '').trim().toLowerCase();
  if (normalized === 'usb_live_activity') return 'Live Activity';
  if (normalized === 'usb_scan_complete') return 'Scan Complete';
  if (normalized === 'usb_insertion') return 'Drive Inserted';
  if (normalized === 'usb_removal') return 'Drive Removed';
  if (normalized === 'usb_threat_mitigated') return 'Threat Mitigated';
  return normalized.replaceAll('_', ' ') || 'USB Event';
};

const getUsbEventTone = (actionType) => {
  const normalized = String(actionType || '').trim().toLowerCase();
  if (normalized === 'usb_live_activity') {
    return 'bg-primary/10 border-primary/20 text-primary';
  }
  if (normalized === 'usb_scan_complete') {
    return 'bg-success/10 border-success/20 text-success';
  }
  if (normalized === 'usb_threat_mitigated') {
    return 'bg-danger/10 border-danger/20 text-danger';
  }
  if (normalized === 'usb_removal') {
    return 'bg-warning/10 border-warning/20 text-warning';
  }
  return 'bg-gray-800 border-gray-700 text-gray-300';
};

export default function Overview() {
  const currentUser = getStoredUser();
  const adminMode = isAdminUser(currentUser);
  const [stats, setStats] = useState({
    activeUsers: 0,
    threatsBlocked: 0,
    highestRiskScore: 0,
    highestRiskLevel: 'Normal',
    blockedConnections: 0,
    suspiciousConnections: 0,
  });
  
  const [chartData, setChartData] = useState([]);
  const [usbEnabled, setUsbEnabled] = useState(false);
  const [usbStatus, setUsbStatus] = useState(null);
  const [showUsbHistory, setShowUsbHistory] = useState(false);
  const [aiInsights, setAiInsights] = useState(null);
  const [dashboardSummary, setDashboardSummary] = useState(null);
  const [pageWarning, setPageWarning] = useState('');

  useEffect(() => {
    const fetchData = async () => {
      try {
        const headers = getAuthHeaders();
        setPageWarning('');

        if (adminMode) {
          const [usersRes, threatsRes, actRes, insightsRes, monitorRes, usbStatusRes, dashboardRes] = await Promise.all([
            fetch(buildApiUrl('/api/users'), { headers }),
            fetch(buildApiUrl('/api/threats'), { headers }),
            fetch(buildApiUrl('/api/activity'), { headers }),
            fetch(buildApiUrl('/api/ai-insights'), { headers }),
            fetch(buildApiUrl('/api/system-monitor'), { headers }),
            fetch(buildApiUrl('/api/usb-status'), { headers }),
            fetch(buildApiUrl('/api/dashboard'), { headers }),
          ]);

          if (usersRes.ok && threatsRes.ok && actRes.ok) {
            const users = await usersRes.json();
            const threats = await threatsRes.json();
            const activity = await actRes.json();
            const insights = insightsRes.ok ? await insightsRes.json() : null;
            const monitorSnapshot = monitorRes.ok ? await monitorRes.json() : null;
            const sharedUsbStatus = usbStatusRes.ok ? await usbStatusRes.json() : null;
            const usbScanningEnabled = sharedUsbStatus?.enabled ?? (monitorSnapshot?.usb?.enabled !== false);
            setUsbEnabled(usbScanningEnabled);
            setUsbStatus(sharedUsbStatus);
            setAiInsights(insights || null);
            setDashboardSummary(dashboardRes.ok ? await dashboardRes.json() : null);

            const activeUsers = users.filter((user) => !isSystemAccount(user) && !user.is_locked).length;
            const threatsBlocked = threats.length;
            const humanInsights = insights?.users?.filter((item) => item.account_type === 'human') || [];
            const highestRiskUser = [...humanInsights].sort((a, b) => (b.overall_risk_score || 0) - (a.overall_risk_score || 0))[0];

            setStats({
              activeUsers,
              threatsBlocked,
              highestRiskScore: Number(highestRiskUser?.overall_risk_score || 0).toFixed(1),
              highestRiskLevel: normalizeRiskLevel(highestRiskUser?.overall_risk_level, highestRiskUser?.overall_risk_score),
              blockedConnections: monitorSnapshot?.network?.blocked_connections?.length || 0,
              suspiciousConnections: monitorSnapshot?.network?.suspicious_connections?.length || 0,
            });

            setChartData(buildChartSeries(activity, threats, users.length));
          }
          return;
        }

        const [threatsRes, actRes, usbStatusRes, dashboardRes] = await Promise.all([
          fetch(buildApiUrl('/api/threats'), { headers }),
          fetch(buildApiUrl('/api/activity'), { headers }),
          fetch(buildApiUrl('/api/usb-status'), { headers }),
          fetch(buildApiUrl('/api/dashboard'), { headers }),
        ]);

        if (threatsRes.ok && actRes.ok) {
          const threats = await threatsRes.json();
          const activity = await actRes.json();
          const sharedUsbStatus = usbStatusRes.ok ? await usbStatusRes.json() : null;
          const summary = dashboardRes.ok ? await dashboardRes.json() : null;
          const highestThreat = [...threats].sort((a, b) => (b.anomaly_score || 0) - (a.anomaly_score || 0))[0];
          const highestActivity = [...activity].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))[0];
          const highestScore = Math.max(Number(highestThreat?.anomaly_score || 0), Number(highestActivity?.risk_score || 0));

          setDashboardSummary(summary);
          setAiInsights(null);
          setUsbStatus(sharedUsbStatus);
          setUsbEnabled(sharedUsbStatus?.enabled !== false);
          setStats({
            activeUsers: 1,
            threatsBlocked: threats.length,
            highestRiskScore: highestScore.toFixed(1),
            highestRiskLevel: normalizeRiskLevel(highestThreat?.threat_level || highestActivity?.risk_level, highestScore),
            blockedConnections: Number(summary?.active_sessions || 0),
            suspiciousConnections: activity.filter((item) => normalizeRiskLevel(item.risk_level, item.risk_score) !== 'Normal').length,
          });
          setChartData(buildChartSeries(activity, threats, 1));
        }
      } catch (error) {
        console.error('Failed to fetch overview stats', error);
        setPageWarning('Overview data is temporarily unavailable. Refresh or sign in again to reload the protected dashboard feeds.');
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, [adminMode]);

  const riskTone = getRiskTone(stats.highestRiskLevel, stats.highestRiskScore);
  const usbBadge = buildUsbBadge(usbStatus);
  const usbEvents = usbStatus?.recent_events || [];
  const visibleUsbEvents = showUsbHistory ? usbEvents : usbEvents.slice(0, 3);
  const hiddenUsbEventCount = Math.max(0, usbEvents.length - visibleUsbEvents.length);
  const metricCards = adminMode
    ? [
        { title: 'Active Human Users', value: stats.activeUsers, icon: <Activity />, color: 'text-primary', bg: 'bg-primary/20' },
        { title: 'Threats Prevented', value: stats.threatsBlocked, icon: <ShieldAlert />, color: 'text-danger', bg: 'bg-danger/20', isAlert: stats.threatsBlocked > 0 },
        { title: 'Highest User Risk', value: stats.highestRiskLevel, meta: `Score ${stats.highestRiskScore}`, icon: <Cpu />, color: riskTone.text, bg: 'bg-warning/20' },
        { title: 'Blocked Connections', value: stats.blockedConnections, meta: `${stats.suspiciousConnections} suspicious outbound`, icon: <ShieldBan />, color: 'text-danger', bg: 'bg-danger/20', isAlert: stats.blockedConnections > 0 },
      ]
    : [
        { title: 'Protected Accounts', value: stats.activeUsers, icon: <Activity />, color: 'text-primary', bg: 'bg-primary/20' },
        { title: 'Alerts On My Account', value: stats.threatsBlocked, icon: <ShieldAlert />, color: 'text-danger', bg: 'bg-danger/20', isAlert: stats.threatsBlocked > 0 },
        { title: 'Highest Recent Risk', value: stats.highestRiskLevel, meta: `Score ${stats.highestRiskScore}`, icon: <Cpu />, color: riskTone.text, bg: 'bg-warning/20' },
        { title: 'Active Sessions', value: stats.blockedConnections, meta: `${stats.suspiciousConnections} suspicious recent events`, icon: <ShieldBan />, color: 'text-primary', bg: 'bg-primary/20', isAlert: stats.suspiciousConnections > 0 },
      ];

  return (
    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500 relative">
      {/* Ambient background glow */}
      <div className="absolute top-0 left-1/4 w-[500px] h-[500px] bg-primary/5 rounded-full blur-[120px] pointer-events-none -z-10" />

      <AccountSecurityPanel summary={dashboardSummary} />
      
      <header className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-gray-800/60 pb-6">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <h2 className="text-3xl font-extrabold tracking-tight text-white">{adminMode ? 'System Overview' : 'My Security Overview'}</h2>
            <div className="flex items-center gap-2 px-2.5 py-1 rounded-full bg-success/10 border border-success/20">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-success opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-success"></span>
              </span>
              <span className="text-xs font-semibold text-success uppercase tracking-wider">Live</span>
            </div>
          </div>
          <p className="text-gray-400 font-medium">
            {adminMode
              ? 'Real-time status and threat analytics of the AI behavior firewall.'
              : 'Your authenticated session, recent detections, and behavior-based security signals.'}
          </p>
        </div>
      </header>

      {pageWarning && (
        <div className="rounded-2xl border border-warning/20 bg-warning/10 p-4 text-sm text-warning">
          {pageWarning}
        </div>
      )}

      {/* Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {metricCards.map((card) => (
          <MetricCard key={card.title} {...card} />
        ))}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mt-8">
        <div className="glass-panel p-6 shadow-sm">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-lg font-bold text-gray-200">Recent Threat Scores</h3>
            <span className="text-xs font-medium px-2 py-1 bg-gray-800 rounded text-gray-400 border border-gray-700">Past 24 Hours</span>
          </div>
          <div className="h-[320px]">
             <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#ef4444" stopOpacity={0.4}/>
                    <stop offset="100%" stopColor="#ef4444" stopOpacity={0.0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff08" vertical={false} />
                <XAxis dataKey="time" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} dy={10} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} dx={-10} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#ffffff', border: '1px solid #cbd5e1', borderRadius: '8px', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                  itemStyle={{ color: '#1e293b' }}
                  labelStyle={{ color: '#64748b', fontWeight: 'bold' }}
                />
                <Area type="monotone" dataKey="score" stroke="#ef4444" strokeWidth={3} fillOpacity={1} fill="url(#colorScore)" activeDot={{ r: 6, fill: '#ef4444', stroke: '#fff', strokeWidth: 2 }}/>
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass-panel p-6 shadow-sm">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-lg font-bold text-gray-200">Active Network Sessions</h3>
            <span className="text-xs font-medium px-2 py-1 bg-gray-800 rounded text-gray-400 border border-gray-700">Past 24 Hours</span>
          </div>
          <div className="h-[320px]">
             <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorActive" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.4}/>
                    <stop offset="100%" stopColor="#3b82f6" stopOpacity={0.0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff08" vertical={false} />
                <XAxis dataKey="time" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} dy={10} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} dx={-10} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#ffffff', border: '1px solid #cbd5e1', borderRadius: '8px', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                  itemStyle={{ color: '#1e293b' }}
                  labelStyle={{ color: '#64748b', fontWeight: 'bold' }}
                />
                <Area type="monotone" dataKey="active" stroke="#3b82f6" strokeWidth={3} fillOpacity={1} fill="url(#colorActive)" activeDot={{ r: 6, fill: '#3b82f6', stroke: '#fff', strokeWidth: 2 }}/>
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <section className="glass-panel p-6 shadow-sm">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-bold text-gray-200">{adminMode ? 'AI Learning Insights' : 'Role-Based Visibility'}</h3>
          <span className="text-xs font-medium px-2 py-1 bg-gray-800 rounded text-gray-400 border border-gray-700">
            {adminMode ? 'Isolation Forest + Clustering' : currentUser?.role || 'user'}
          </span>
        </div>

        {!adminMode ? (
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
            <InsightCard
              title="Current Role"
              value={String(currentUser?.role || 'user').toUpperCase()}
              detail="Your dashboard is scoped to your own login history, alerts, and activity feed."
            />
            <InsightCard
              title="Active Sessions"
              value={dashboardSummary?.active_sessions || 0}
              detail="Concurrent authenticated sessions tied to your account."
            />
            <InsightCard
              title="Session Status"
              value={dashboardSummary?.security_status || 'Loading'}
              detail="Admin-only telemetry stays protected unless you sign in with an admin role."
            />
          </div>
        ) : !aiInsights ? (
          <div className="rounded-2xl border border-white/5 bg-black/20 p-5 text-sm text-gray-500">
            AI learning telemetry is loading.
          </div>
        ) : (
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
            <InsightCard
              title="Human Users"
              value={aiInsights.total_human_users}
              detail="Visible human accounts that the model is learning from."
            />
            <InsightCard
              title="System Agents"
              value={aiInsights.total_system_accounts}
              detail="Internal service accounts for host telemetry and monitoring."
            />
            <InsightCard
              title="Continuous Learning"
              value={aiInsights.continuously_learning ? 'On' : 'Off'}
              detail="The backend retrains from new activity history as it grows."
            />
          </div>
        )}

        {adminMode && aiInsights?.users?.length > 0 && (
          <div className="mt-6 grid grid-cols-1 xl:grid-cols-2 gap-4">
            {aiInsights.users
              .filter((item) => item.account_type === 'human')
              .slice(0, 4)
              .map((item) => (
                <div key={item.user_id} className="rounded-2xl border border-gray-700/10 bg-gray-900/10 p-5">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <div className="text-white font-semibold">{item.username}</div>
                      <div className="text-sm text-gray-400 mt-1">{item.ai_status}</div>
                    </div>
                    <div className="text-right">
                      <div className="text-sm text-gray-500">Samples</div>
                      <div className="text-white font-semibold">{item.activity_count}</div>
                    </div>
                  </div>

                  <div className="text-xs text-gray-400 mt-3">
                    Isolation Forest: {item.isolation_forest_ready ? 'ready' : 'learning'} | Clustering: {item.cluster_model_ready ? 'ready' : 'learning'}
                  </div>

                  <div className="mt-3 flex items-center gap-2">
                    <span className={`px-2.5 py-1 rounded-full border text-xs font-medium ${getRiskTone(item.overall_risk_level, item.overall_risk_score).badge}`}>
                      {normalizeRiskLevel(item.overall_risk_level, item.overall_risk_score)}
                    </span>
                    <span className={`text-xs font-mono ${getRiskTone(item.overall_risk_level, item.overall_risk_score).text}`}>
                      {Number(item.overall_risk_score || 0).toFixed(1)}
                    </span>
                  </div>

                  <div className="mt-3 text-sm text-gray-300">
                    {item.latest_summary || 'No anomaly explanation recorded yet.'}
                  </div>
                </div>
              ))}
          </div>
        )}
      </section>

      <section className="glass-panel p-6 shadow-sm">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-bold text-gray-200">USB Scanner Status</h3>
          <span className={`text-xs font-medium px-2 py-1 rounded ${usbBadge.className}`}>
            {usbBadge.label}
          </span>
        </div>

        {!usbStatus ? (
          <div className="rounded-2xl border border-white/5 bg-black/20 p-5 text-sm text-gray-500">
            Checking the shared USB monitor state.
          </div>
        ) : (
          <div className="space-y-4">
            <div className={`rounded-2xl border p-5 ${
              usbStatus.connected_count > 0
                ? 'border-success/20 bg-success/10'
                : 'border-warning/20 bg-warning/10'
            }`}>
              <div className="text-xs uppercase tracking-[0.24em] text-gray-400">Pendrive State</div>
              <div className={`mt-2 text-3xl font-bold ${
                usbStatus.connected_count > 0 ? 'text-success' : 'text-warning'
              }`}>
                {usbStatus.connected_count > 0 ? 'Connected' : 'No Pendrive Detected'}
              </div>
              <div className="mt-2 text-sm text-gray-300">
                {usbStatus.connected_count > 0
                  ? `${usbStatus.connected_count} removable drive${usbStatus.connected_count === 1 ? '' : 's'} currently visible to the website.`
                  : 'The website does not currently see any removable drive on this PC.'}
              </div>
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-4 gap-4">
              <InsightCard
                title="Scanner State"
                value={usbStatus.status_label || 'Unknown'}
                detail={usbStatus.status_text || 'No USB status text available yet.'}
              />
              <InsightCard
                title="Pendrive State"
                value={usbStatus.connected_count > 0 ? 'Detected' : 'Not Detected'}
                detail={usbStatus.connected_count > 0 ? 'The website can currently see at least one removable drive.' : 'Plug the pendrive again after the Windows monitor starts if this should be connected.'}
              />
              <InsightCard
                title="Connected Drives"
                value={usbStatus.connected_count || 0}
                detail={usbStatus.current_devices?.length ? 'Live removable-drive list is shown below.' : 'No removable drives are visible right now.'}
              />
              <InsightCard
                title="Last Scan"
                value={usbStatus.last_scan_at ? 'Recorded' : 'None Yet'}
                detail={usbStatus.last_scan_at ? formatLocalTimestamp(usbStatus.last_scan_at) : 'A scan result will appear here after the next USB scan completes.'}
              />
            </div>

            <div className="rounded-2xl border border-gray-700/10 bg-gray-900/10 p-5 text-sm text-gray-300">
              <div className="font-semibold text-white">
                Source: {usbStatus.collector === 'windows-host-agent' ? 'Windows Host Agent' : 'Container Fallback'}
              </div>
              <div className="mt-2">{usbStatus.recommendation}</div>
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
              <div className="rounded-2xl border border-gray-700/10 bg-gray-900/10 p-5">
                <div className="flex items-center justify-between gap-4">
                  <div className="text-sm font-semibold text-white">Detected Removable Drives</div>
                  <div className="text-xs text-gray-500">
                    Updated {formatLocalTimestamp(usbStatus.snapshot_timestamp)}
                  </div>
                </div>
                <div className="mt-4 space-y-3">
                  {!usbStatus.current_devices?.length ? (
                    <div className="text-sm text-gray-500">No removable drives are currently visible to the backend.</div>
                  ) : (
                    usbStatus.current_devices.map((device) => (
                      <div key={device.id} className="rounded-xl border border-gray-700/10 bg-gray-900/20 p-4">
                        <div className="flex items-center justify-between gap-4">
                          <div>
                            <div className="font-semibold text-white">{device.name}</div>
                            <div className="mt-1 text-xs text-gray-500">{device.class} | {device.status}</div>
                          </div>
                          <div className="text-right text-xs text-gray-400">
                            {device.size_gb > 0 ? <div>{device.size_gb.toFixed(2)} GB total</div> : null}
                            {device.free_gb > 0 ? <div>{device.free_gb.toFixed(2)} GB free</div> : null}
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              <div className="rounded-2xl border border-gray-700/10 bg-gray-900/10 p-5">
                <div className="flex items-center justify-between gap-4">
                  <div className="text-sm font-semibold text-white">Live USB Activity</div>
                  <div className="flex items-center gap-3">
                    {usbEvents.length > 3 && (
                      <button
                        type="button"
                        onClick={() => setShowUsbHistory((current) => !current)}
                        className="rounded-full border border-gray-700/10 bg-gray-900/20 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-gray-300 transition hover:border-primary/30 hover:text-white"
                      >
                        {showUsbHistory ? 'Show Less' : `Show More +${usbEvents.length - 3}`}
                      </button>
                    )}
                    <div className="text-xs text-gray-500">
                      {usbStatus.snapshot_fresh ? 'Updates every few seconds' : 'Waiting for fresh update'}
                    </div>
                  </div>
                </div>
                <div className="mt-4 space-y-3">
                  {!usbEvents.length ? (
                    <div className="text-sm text-gray-500">No USB events have been recorded yet. Try copying a file or creating a folder on the pendrive.</div>
                  ) : (
                    visibleUsbEvents.map((event) => (
                      <div key={event.id} className="rounded-xl border border-gray-700/10 bg-gray-900/20 p-4">
                        <div className="flex items-start justify-between gap-4">
                          <div>
                            <div className="font-semibold text-white">{event.drive || event.device || 'USB'}</div>
                            <div className={`mt-2 inline-flex rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide ${getUsbEventTone(event.action_type)}`}>
                              {formatUsbActionLabel(event.action_type)}
                            </div>
                          </div>
                          <div className="text-xs text-gray-500">{formatLocalTimestamp(event.timestamp)}</div>
                        </div>
                        <div className="mt-2 text-sm text-gray-400">{event.summary}</div>
                        {(event.change_counts?.created_files || event.change_counts?.modified_files || event.change_counts?.deleted_files || event.change_counts?.created_directories || event.change_counts?.deleted_directories) ? (
                          <div className="mt-3 flex flex-wrap gap-2">
                            {event.change_counts.created_files > 0 && (
                              <span className="rounded-full border border-success/20 bg-success/10 px-3 py-1 text-xs text-success">
                                +{event.change_counts.created_files} file
                              </span>
                            )}
                            {event.change_counts.modified_files > 0 && (
                              <span className="rounded-full border border-primary/20 bg-primary/10 px-3 py-1 text-xs text-primary">
                                ~{event.change_counts.modified_files} modified
                              </span>
                            )}
                            {event.change_counts.deleted_files > 0 && (
                              <span className="rounded-full border border-danger/20 bg-danger/10 px-3 py-1 text-xs text-danger">
                                -{event.change_counts.deleted_files} deleted
                              </span>
                            )}
                            {event.change_counts.created_directories > 0 && (
                              <span className="rounded-full border border-warning/20 bg-warning/10 px-3 py-1 text-xs text-warning">
                                +{event.change_counts.created_directories} folder
                              </span>
                            )}
                            {event.change_counts.deleted_directories > 0 && (
                              <span className="rounded-full border border-warning/20 bg-warning/10 px-3 py-1 text-xs text-warning">
                                -{event.change_counts.deleted_directories} folder
                              </span>
                            )}
                          </div>
                        ) : null}
                        {!!event.items?.length && (
                          <div className="mt-3 space-y-2">
                            {event.items.slice(0, 4).map((item, index) => (
                              <div key={`${event.id}-item-${index}`} className="rounded-lg border border-gray-700/10 bg-gray-900/20 px-3 py-2 text-xs text-gray-300">
                                <div className="flex items-center justify-between gap-3">
                                  <span className="font-semibold text-white">{item.name || item.path || 'USB item'}</span>
                                  <span className="uppercase text-gray-500">{item.change_type} {item.entity_type}</span>
                                </div>
                                {item.path && <div className="mt-1 break-all text-gray-500">{item.path}</div>}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))
                  )}
                  {hiddenUsbEventCount > 0 && !showUsbHistory && (
                    <div className="rounded-xl border border-dashed border-gray-700/10 bg-gray-900/10 px-4 py-3 text-sm text-gray-400">
                      {hiddenUsbEventCount} older USB event{hiddenUsbEventCount === 1 ? '' : 's'} hidden. Use Show More to expand the full history.
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
      </section>

    </div>
  );
}

function InsightCard({ title, value, detail }) {
  return (
    <div className="rounded-2xl border border-gray-700/10 bg-gray-900/10 p-5">
      <div className="text-xs uppercase tracking-wide text-gray-500 mb-2">{title}</div>
      <div className="text-3xl font-bold text-white">{value}</div>
      <div className="text-sm text-gray-400 mt-2">{detail}</div>
    </div>
  );
}

function MetricCard({ title, value, icon, color, bg, isAlert, meta }) {
  return (
    <div className={`relative overflow-hidden glass-panel p-6 shadow-sm transition-all duration-300 hover:shadow-black/50 hover:-translate-y-1 ${isAlert ? 'border-danger/40 shadow-[0_0_30px_-5px_red]' : ''}`}>
      {/* Decorative gradient orb */}
      <div className={`absolute -right-6 -top-6 w-24 h-24 rounded-full blur-[40px] opacity-20 ${bg.replace('/20', '')}`} />
      
      <div className="flex items-center justify-between relative z-10">
        <div>
          <h4 className="text-gray-400 text-sm font-semibold tracking-wide uppercase mb-2">{title}</h4>
          <div className="text-4xl font-extrabold text-white tracking-tight">{value}</div>
          {meta && <div className="text-xs text-gray-400 mt-2">{meta}</div>}
        </div>
        <div className={`w-14 h-14 rounded-2xl flex items-center justify-center shadow-inner ${bg} ${color} border border-gray-700/10`}>
          {React.cloneElement(icon, { size: 28, strokeWidth: 2.5 })}
        </div>
      </div>
    </div>
  );
}
