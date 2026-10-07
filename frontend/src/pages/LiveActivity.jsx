import React, { useState, useEffect, useRef } from 'react';
import { buildWsUrl, buildApiUrl, getAuthToken } from '../utils/auth';

const SEVERITY_COLORS = {
  CRITICAL: { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500/30' },
  HIGH:     { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500/30' },
  MEDIUM:   { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500/30' },
  LOW:      { bg: 'bg-green-500/20', text: 'text-green-400', border: 'border-green-500/30' },
  NORMAL:   { bg: 'bg-blue-500/20', text: 'text-blue-400', border: 'border-blue-500/30' },
  ERROR:    { bg: 'bg-gray-500/20', text: 'text-gray-400', border: 'border-gray-500/30' },
};

const EVENT_META = {
  new_connection:    { icon: '🌐', label: 'New Connection' },
  connection_closed: { icon: '🔌', label: 'Connection Closed' },
  new_process:       { icon: '⚙️', label: 'New Process' },
  process_closed:    { icon: '🛑', label: 'Process Closed' },
  clipboard_threat:  { icon: '📋', label: 'Clipboard Threat' },
  NEW_ACTIVITY:      { icon: '📝', label: 'System Activity' },
  THREAT_ALERT:      { icon: '🚨', label: 'Threat Alert' },
};

const formatEndpoint = (ip, port) => {
  if (!ip) return '';
  const cleanIp = String(ip).trim();
  if (cleanIp.includes(':')) {
    return `[${cleanIp}]:${port}`;
  }
  return `${cleanIp}:${port}`;
};

export default function LiveActivity() {
  const [events, setEvents] = useState([]);
  const [filter, setFilter] = useState('all');
  const [stats, setStats] = useState(null);
  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);
  const [showAppTraffic, setShowAppTraffic] = useState(false);
  const [onlineGeo, setOnlineGeo] = useState(false);
  const [geoNotice, setGeoNotice] = useState("Place shown is the server's approximate location.");
  const [droppedCount, setDroppedCount] = useState(0);
  const [eventsPerMin, setEventsPerMin] = useState(0);
  const [lastEventTime, setLastEventTime] = useState(null);
  const [pcTimeStr, setPcTimeStr] = useState('');

  const wsRef = useRef(null);
  const feedRef = useRef(null);
  const pausedRef = useRef(false);
  const warnedTypesRef = useRef(new Set());
  const eventTimestampsRef = useRef([]);
  pausedRef.current = paused;

  // Header PC time and events per minute sliding window (PART 3.1 & 3.5)
  useEffect(() => {
    const updateHeader = () => {
      const now = new Date();
      const timeStr = now.toLocaleTimeString([], { hour12: false });
      const dateStr = now.toLocaleDateString([], { year: 'numeric', month: 'short', day: 'numeric' });
      const offsetMin = -now.getTimezoneOffset();
      const sign = offsetMin >= 0 ? '+' : '-';
      const absOffset = Math.abs(offsetMin);
      const hours = String(Math.floor(absOffset / 60)).padStart(2, '0');
      const mins = String(absOffset % 60).padStart(2, '0');
      const offsetStr = `UTC${sign}${hours}:${mins}`;
      const tzName = Intl.DateTimeFormat().resolvedOptions().timeZone || 'Local';
      setPcTimeStr(`${dateStr} ${timeStr} (${tzName}, ${offsetStr})`);

      const oneMinAgo = Date.now() - 60000;
      eventTimestampsRef.current = eventTimestampsRef.current.filter(t => t > oneMinAgo);
      setEventsPerMin(eventTimestampsRef.current.length);
    };

    updateHeader();
    const interval = setInterval(updateHeader, 1000);
    return () => clearInterval(interval);
  }, []);

  // Load geo lookup setting on mount
  useEffect(() => {
    const fetchGeoSetting = async () => {
      try {
        const token = getAuthToken() || localStorage.getItem('token') || sessionStorage.getItem('token') || '';
        const res = await fetch(buildApiUrl('/api/system/settings/geo-lookup'), {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        });
        if (res.ok) {
          const data = await res.json();
          setOnlineGeo(Boolean(data.online_lookup_enabled));
          if (data.notice) setGeoNotice(data.notice);
        }
      } catch (err) {
        console.debug('[LiveActivity] Could not fetch geo setting:', err);
      }
    };
    fetchGeoSetting();
  }, []);

  const handleToggleOnlineGeo = async (enabled) => {
    setOnlineGeo(enabled);
    try {
      const token = getAuthToken() || localStorage.getItem('token') || sessionStorage.getItem('token') || '';
      await fetch(buildApiUrl('/api/system/settings/geo-lookup'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ enabled }),
      });
    } catch (err) {
      console.error('[LiveActivity] Failed to update online geo lookup:', err);
    }
  };

  useEffect(() => {
    let ws;
    let reconnectTimer;
    let isMounted = true;
    let reconnectAttempts = 0;

    const connect = () => {
      if (!isMounted) return;
      const token = getAuthToken() || localStorage.getItem('token') || sessionStorage.getItem('token') || '';
      const wsUrl = `${buildWsUrl('/api/ws/monitor')}?token=${encodeURIComponent(token)}`;

      try {
        ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          if (isMounted) setConnected(true);
          reconnectAttempts = 0;
          console.log('[LiveActivity] WebSocket connected');
        };

        ws.onmessage = (e) => {
          try {
            const event = JSON.parse(e.data);

            // 1. Metric messages: update stats and NEVER display as feed rows
            if (event.type === 'system_stats') {
              setStats(event.data);
              return;
            }
            if (event.type === 'TRAFFIC_MONITOR_UPDATE' || event.type === 'SYSTEM_MONITOR_UPDATE') {
              // Pure metric update, skip event feed
              return;
            }

            // 2. Validate UTC ISO timestamp: if invalid or missing, warn once per type and drop
            const dt = event.timestamp ? new Date(event.timestamp) : null;
            if (!dt || isNaN(dt.getTime())) {
              if (!warnedTypesRef.current.has(event.type)) {
                console.warn(`[LiveActivity] Dropping event with invalid date (type: ${event.type}):`, event);
                warnedTypesRef.current.add(event.type);
              }
              return;
            }

            // 3. Skip if feed is paused
            if (pausedRef.current) return;

            eventTimestampsRef.current.push(Date.now());
            setLastEventTime(Date.now());

            setEvents(prev => {
              if (prev.length >= 300) {
                setDroppedCount(c => c + 1);
              }
              return [event, ...prev].slice(0, 300);
            });
            if (feedRef.current && feedRef.current.scrollTop < 100) {
              feedRef.current.scrollTop = 0;
            }
          } catch (err) {
            console.error('[LiveActivity] Error parsing ws payload', err);
          }
        };

        const scheduleReconnect = () => {
          if (!isMounted) return;
          setConnected(false);
          const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
          reconnectAttempts += 1;
          reconnectTimer = setTimeout(connect, delay);
        };

        ws.onclose = () => {
          scheduleReconnect();
        };

        ws.onerror = () => {
          if (ws) ws.close();
        };
      } catch (err) {
        if (isMounted) {
          setConnected(false);
          const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
          reconnectAttempts += 1;
          reconnectTimer = setTimeout(connect, delay);
        }
      }
    };

    connect();

    return () => {
      isMounted = false;
      clearTimeout(reconnectTimer);
      if (ws) ws.close();
    };
  }, []);

  // Filter out app's own and loopback traffic if toggle is off
  const isAppOrLoopback = (event) => {
    const d = event.data || {};
    if (d.is_app_traffic || d.is_loopback) return true;
    const proc = (d.process || d.name || '').toLowerCase();
    if (proc.includes('ai firewall') || proc.includes('aifirewall-backend')) return true;
    const remoteIp = String(d.remote_ip || '');
    const localIp = String(d.local_ip || '');
    if ((remoteIp === '127.0.0.1' || remoteIp === '::1' || remoteIp === 'localhost') &&
        (localIp === '127.0.0.1' || localIp === '::1' || localIp === 'localhost')) {
      return true;
    }
    return false;
  };

  const visibleEvents = events.filter(e => {
    if (!showAppTraffic && isAppOrLoopback(e)) {
      return false;
    }
    return true;
  });

  const matchesTab = (event, tabKey) => {
    if (tabKey === 'all') return true;
    if (tabKey === 'threat_alert') return event.type === 'THREAT_ALERT';
    if (tabKey === 'new_activity') return event.type === 'NEW_ACTIVITY';
    return event.type === tabKey;
  };

  const filtered = visibleEvents.filter(e => matchesTab(e, filter));

  const TABS = [
    { key: 'all', label: 'All Events', countsClose: false },
    { key: 'new_connection', label: 'New Connections', countsClose: false },
    { key: 'connection_closed', label: 'Connections Closed', countsClose: true },
    { key: 'new_process', label: 'New Processes', countsClose: false },
    { key: 'process_closed', label: 'Processes Closed', countsClose: true },
    { key: 'threat_alert', label: 'Threat Alerts', countsClose: false },
    { key: 'new_activity', label: 'System Activities', countsClose: false },
    { key: 'clipboard_threat', label: 'Clipboard Threats', countsClose: false },
  ];

  const getEventMeta = (type) => {
    if (EVENT_META[type]) return EVENT_META[type];
    const friendly = String(type).replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, c => c.toUpperCase());
    return { icon: '📡', label: friendly };
  };

  const isStale = connected && lastEventTime && (Date.now() - lastEventTime > 15000);

  return (
    <div className="p-6 h-full flex flex-col space-y-5">

      {/* Header */}
      <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-white">⚡ Live Activity Monitor</h1>
            {!connected ? (
              <div className="flex items-center gap-2 px-3 py-1 rounded-full text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/30">
                <div className="w-2 h-2 rounded-full bg-red-400" />
                DISCONNECTED
              </div>
            ) : isStale ? (
              <div className="flex items-center gap-2 px-3 py-1 rounded-full text-xs font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">
                <div className="w-2 h-2 rounded-full bg-amber-400" />
                STALE (No data &gt; 15s)
              </div>
            ) : (
              <div className="flex items-center gap-2 px-3 py-1 rounded-full text-xs font-bold bg-green-500/20 text-green-400 border border-green-500/30">
                <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                LIVE
              </div>
            )}
          </div>
          <div className="mt-1.5 text-xs text-gray-400">
            <strong className="text-gray-300">PC time:</strong> {pcTimeStr || 'Detecting...'}
          </div>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          <span className="px-2.5 py-1 rounded-lg bg-gray-900 border border-gray-800 text-gray-300 font-mono text-xs">
            Events/min: <strong className="text-cyan-400">{eventsPerMin}</strong>
          </span>
          <span className="px-2.5 py-1 rounded-lg bg-gray-900 border border-gray-800 text-gray-300 font-mono text-xs">
            Dropped cap: <strong className="text-amber-400">{droppedCount}</strong>
          </span>
          <span className="text-gray-400 text-xs font-mono">{filtered.length} showing / {visibleEvents.length} feed</span>
          <button
            onClick={() => setPaused(p => !p)}
            className={`px-3 py-1.5 rounded-xl text-xs font-medium transition-colors ${paused ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'}`}
          >
            {paused ? '▶ Resume' : '⏸ Pause'}
          </button>
          <button
            onClick={() => { setEvents([]); setDroppedCount(0); }}
            className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-xl text-xs transition-colors"
          >
            Clear
          </button>
        </div>
      </div>

      {/* Toggles bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-3 bg-gray-900/60 border border-gray-800 rounded-xl text-xs text-gray-300">
        <div className="flex items-center gap-6 flex-wrap">
          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={showAppTraffic}
              onChange={(e) => setShowAppTraffic(e.target.checked)}
              className="w-4 h-4 rounded text-blue-600 bg-gray-800 border-gray-700 focus:ring-0 focus:outline-none"
            />
            <span className="font-medium">Show app and loopback traffic</span>
          </label>

          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={onlineGeo}
              onChange={(e) => handleToggleOnlineGeo(e.target.checked)}
              className="w-4 h-4 rounded text-blue-600 bg-gray-800 border-gray-700 focus:ring-0 focus:outline-none"
            />
            <span className="font-medium">Look up server locations online</span>
          </label>
        </div>
        <div className="text-gray-500 text-[11px] italic">
          ℹ️ {geoNotice}
        </div>
      </div>

      {/* System stats bar with live network rate & total since boot */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-gray-900/80 border border-gray-700/80 rounded-2xl px-4 py-3 backdrop-blur-md">
            <div className="text-gray-400 text-xs font-semibold mb-1 uppercase tracking-wider">CPU Usage</div>
            <div className={`text-xl font-bold font-mono ${stats.cpu_percent > 80 ? 'text-red-400' : 'text-green-400'}`}>
              {stats.cpu_percent}%
            </div>
          </div>

          <div className="bg-gray-900/80 border border-gray-700/80 rounded-2xl px-4 py-3 backdrop-blur-md">
            <div className="text-gray-400 text-xs font-semibold mb-1 uppercase tracking-wider">RAM Usage</div>
            <div className={`text-xl font-bold font-mono ${stats.ram_percent > 85 ? 'text-red-400' : 'text-blue-400'}`}>
              {stats.ram_percent}%
              <span className="text-xs text-gray-400 font-normal ml-2">({stats.ram_used_gb} / {stats.ram_total_gb} GB)</span>
            </div>
          </div>

          <div className="bg-gray-900/80 border border-gray-700/80 rounded-2xl px-4 py-3 backdrop-blur-md">
            <div className="text-gray-400 text-xs font-semibold mb-1 uppercase tracking-wider">Disk Usage</div>
            <div className={`text-xl font-bold font-mono ${stats.disk_percent > 90 ? 'text-red-400' : 'text-purple-400'}`}>
              {stats.disk_percent}%
            </div>
          </div>

          <div className="bg-gray-900/80 border border-gray-700/80 rounded-2xl px-4 py-3 backdrop-blur-md">
            <div className="flex justify-between items-center mb-1">
              <div className="text-gray-400 text-xs font-semibold uppercase tracking-wider">Net Rate</div>
              <span className="text-[10px] text-gray-500 font-mono">({stats.sample_interval_sec || 5}s sample)</span>
            </div>
            <div className="text-xl font-bold font-mono text-cyan-400">
              {Number(stats.net_recv_rate_mb_s || 0).toFixed(2)} MB/s
            </div>
            <div className="text-[11px] text-gray-400 font-mono mt-0.5">
              {stats.net_total_recv_mb ? Number(stats.net_total_recv_mb).toFixed(1) : ((stats.net_bytes_recv || 0) / 1024 / 1024).toFixed(1)} MB since boot
            </div>
          </div>
        </div>
      )}

      {/* Filter tabs with precise counts and close distinction */}
      <div className="space-y-1">
        <div className="flex gap-2 flex-wrap">
          {TABS.map(tab => {
            const count = visibleEvents.filter(e => matchesTab(e, tab.key)).length;
            const isActive = filter === tab.key;
            return (
              <button
                key={tab.key}
                onClick={() => setFilter(tab.key)}
                className={`px-3 py-1.5 rounded-xl text-xs font-medium transition-all ${
                  isActive ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20' : 'bg-gray-800/80 text-gray-400 hover:bg-gray-700'
                }`}
              >
                {tab.label}
                <span className={`ml-1.5 font-mono ${isActive ? 'text-blue-200' : 'text-gray-500'}`}>
                  ({count})
                </span>
              </button>
            );
          })}
        </div>
        <div className="text-[11px] text-gray-500 px-1">
          ℹ️ Tab counters equal exact rows shown. <strong>Connections Closed</strong> and <strong>Processes Closed</strong> tabs count terminated resources.
        </div>
      </div>

      {/* Live event feed */}
      <div ref={feedRef} className="flex-1 min-h-[380px] max-h-[600px] overflow-y-auto bg-gray-950 rounded-2xl border border-gray-800 p-3 font-mono text-xs space-y-1.5 shadow-inner">
        {filtered.length === 0 ? (
          <div className="flex items-center justify-center h-48 text-gray-500">
            <div className="text-center">
              <div className="text-3xl mb-2">👁️</div>
              <div className="font-semibold text-sm">Monitoring System in Real Time...</div>
              <div className="text-xs text-gray-600 mt-1">Waiting for new network, process, or security activity</div>
            </div>
          </div>
        ) : (
          filtered.map((event, index) => {
            const meta = getEventMeta(event.type);
            const d = event.data || {};
            const threat = d.threat_level || (d.is_phishing ? 'HIGH' : d.is_suspicious ? 'CRITICAL' : d.risk_level === 'Dangerous' ? 'CRITICAL' : d.risk_level === 'Suspicious' ? 'HIGH' : 'LOW');
            const colors = SEVERITY_COLORS[threat] || SEVERITY_COLORS.LOW;

            const timeStr = event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : '';

            // Compute remote location label strictly (PART 3.3b, 3.3c)
            const isPrivateOrLoopback = d.is_loopback || d.is_private || ['127.0.0.1', '::1', 'localhost'].includes(String(d.remote_ip || ''));
            let locationStr = '';
            if (isPrivateOrLoopback) {
              locationStr = 'Local network';
            } else if (onlineGeo && d.city) {
              locationStr = `${d.city}, ${d.country || 'unknown'} (approximate)`;
            } else if (d.country) {
              locationStr = `Registered in: ${d.country} (approximate)`;
            } else {
              locationStr = 'Registered in: unknown';
            }

            return (
              <div key={event.id || `${event.type}-${event.timestamp}-${index}`} className={`flex items-center gap-3 p-2.5 rounded-xl border ${colors.border} ${colors.bg} hover:opacity-90 transition-opacity`}>
                <span className="flex-shrink-0 text-sm">{meta.icon}</span>
                <span className="text-gray-500 flex-shrink-0 text-[11px] font-mono">{timeStr}</span>
                <span className={`font-bold flex-shrink-0 ${colors.text}`}>{meta.label}</span>
                <span className="text-gray-200 flex-1 truncate">
                  {event.type === 'new_connection' && (
                    <>
                      {d.process || 'Process'} → {formatEndpoint(d.remote_ip, d.remote_port)}
                      {locationStr && <span className="text-gray-400 ml-1.5">({locationStr})</span>}
                    </>
                  )}
                  {event.type === 'connection_closed' && `Closed: ${d.process || 'Process'} (${d.connection})`}
                  {event.type === 'new_process' && `${d.name} [PID ${d.pid}] by ${d.username || 'system'}`}
                  {event.type === 'process_closed' && `Closed process: ${d.name} [PID ${d.pid}] (started ${d.start_time || 'unknown'})`}
                  {event.type === 'clipboard_threat' && `Score ${d.score} — ${d.indicators?.[0] || 'Suspicious clipboard content'}`}
                  {event.type === 'THREAT_ALERT' && `Threat Alert: ${d.action || 'Unknown'} — ${d.details || `Score ${d.score || 0}`}`}
                  {event.type === 'NEW_ACTIVITY' && `Activity: ${d.action || 'Unknown'} — ${d.details || `User: ${d.user || 'system'}`}`}
                  {!['new_connection', 'connection_closed', 'new_process', 'process_closed', 'clipboard_threat', 'THREAT_ALERT', 'NEW_ACTIVITY'].includes(event.type) && (
                    typeof d === 'string' ? d : JSON.stringify(d)
                  )}
                </span>
                {threat !== 'LOW' && (
                  <span className={`px-2 py-0.5 rounded-md text-[10px] font-bold uppercase flex-shrink-0 ${colors.bg} ${colors.text} border ${colors.border}`}>
                    {threat}
                  </span>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
