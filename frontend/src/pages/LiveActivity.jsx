import React, { useState, useEffect, useRef } from 'react';
import { buildWsUrl, getAuthToken } from '../utils/auth';

const SEVERITY_COLORS = {
  CRITICAL: { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500/30' },
  HIGH:     { bg: 'bg-orange-500/20', text: 'text-orange-400', border: 'border-orange-500/30' },
  MEDIUM:   { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500/30' },
  LOW:      { bg: 'bg-green-500/20', text: 'text-green-400', border: 'border-green-500/30' },
  ERROR:    { bg: 'bg-gray-500/20', text: 'text-gray-400', border: 'border-gray-500/30' },
};

export default function LiveActivity() {
  const [events, setEvents] = useState([]);
  const [filter, setFilter] = useState('all');
  const [stats, setStats] = useState(null);
  const [connected, setConnected] = useState(false);
  const [paused, setPaused] = useState(false);
  const wsRef = useRef(null);
  const feedRef = useRef(null);
  const pausedRef = useRef(false);
  pausedRef.current = paused;

  useEffect(() => {
    let ws;
    let reconnectTimer;
    let isMounted = true;

    const connect = () => {
      if (!isMounted) return;
      const token = getAuthToken() || localStorage.getItem('token') || '';
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
          if (pausedRef.current) return;
          try {
            const event = JSON.parse(e.data);
            if (event.type === 'system_stats') {
              setStats(event.data);
              return;
            }
            setEvents(prev => [event, ...prev].slice(0, 200));
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

    let reconnectAttempts = 0;
    connect();

    return () => {
      isMounted = false;
      clearTimeout(reconnectTimer);
      if (ws) ws.close();
    };
  }, []);

  const filtered = filter === 'all' ? events : events.filter(e => e.type === filter);

  const eventIcons = {
    new_connection:    { icon: '🌐', label: 'New Connection' },
    connection_closed: { icon: '❌', label: 'Connection Closed' },
    new_process:       { icon: '⚙️', label: 'New Process' },
    clipboard_threat:  { icon: '📋', label: 'Clipboard Threat' },
    system_stats:      { icon: '💻', label: 'System Stats' },
  };

  return (
    <div className="p-6 h-full flex flex-col space-y-6">

      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold text-white">⚡ Live Activity Monitor</h1>
          <div className={`flex items-center gap-2 px-3 py-1 rounded-full text-xs font-bold ${connected ? 'bg-green-500/20 text-green-400 border border-green-500/30' : 'bg-red-500/20 text-red-400 border border-red-500/30'}`}>
            <div className={`w-2 h-2 rounded-full ${connected ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`} />
            {connected ? 'LIVE' : 'DISCONNECTED'}
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-gray-500 text-sm font-mono">{events.length} events</span>
          <button
            onClick={() => setPaused(p => !p)}
            className={`px-3 py-1.5 rounded-xl text-sm font-medium transition-colors ${paused ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'}`}
          >
            {paused ? '▶ Resume' : '⏸ Pause'}
          </button>
          <button
            onClick={() => setEvents([])}
            className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-xl text-sm transition-colors"
          >
            Clear
          </button>
        </div>
      </div>

      {/* System stats bar */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'CPU Usage', value: `${stats.cpu_percent}%`, color: stats.cpu_percent > 80 ? 'text-red-400' : 'text-green-400' },
            { label: 'RAM Usage', value: `${stats.ram_percent}% (${stats.ram_used_gb} / ${stats.ram_total_gb} GB)`, color: stats.ram_percent > 85 ? 'text-red-400' : 'text-blue-400' },
            { label: 'Disk Usage', value: `${stats.disk_percent}%`, color: stats.disk_percent > 90 ? 'text-red-400' : 'text-purple-400' },
            { label: 'Net Received', value: `${(stats.net_bytes_recv / 1024 / 1024).toFixed(1)} MB`, color: 'text-cyan-400' },
          ].map(s => (
            <div key={s.label} className="bg-gray-900/80 border border-gray-700/80 rounded-2xl px-4 py-3 backdrop-blur-md">
              <div className="text-gray-400 text-xs font-semibold mb-1 uppercase tracking-wider">{s.label}</div>
              <div className={`text-xl font-bold font-mono ${s.color}`}>{s.value}</div>
            </div>
          ))}
        </div>
      )}

      {/* Filter tabs */}
      <div className="flex gap-2 flex-wrap">
        {['all', 'new_connection', 'new_process', 'clipboard_threat'].map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-3 py-1.5 rounded-xl text-xs font-medium transition-all ${
              filter === f ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20' : 'bg-gray-800/80 text-gray-400 hover:bg-gray-700'
            }`}
          >
            {f === 'all' ? 'All Events' : eventIcons[f]?.label || f}
            {f !== 'all' && <span className="ml-1 text-gray-400 font-mono">({events.filter(e => e.type === f).length})</span>}
          </button>
        ))}
      </div>

      {/* Live event feed */}
      <div ref={feedRef} className="flex-1 min-h-[380px] max-h-[600px] overflow-y-auto bg-gray-950 rounded-2xl border border-gray-800 p-3 font-mono text-xs space-y-1.5 shadow-inner">
        {filtered.length === 0 ? (
          <div className="flex items-center justify-center h-48 text-gray-500">
            <div className="text-center">
              <div className="text-3xl mb-2">👁️</div>
              <div className="font-semibold text-sm">Monitoring System in Real Time...</div>
              <div className="text-xs text-gray-600 mt-1">Waiting for new network, process, or clipboard activity</div>
            </div>
          </div>
        ) : (
          filtered.map((event, i) => {
            const meta = eventIcons[event.type] || { icon: '📡', label: event.type };
            const d = event.data || {};
            const threat = d.threat_level || (d.is_phishing ? 'HIGH' : d.is_suspicious ? 'CRITICAL' : 'LOW');
            const colors = SEVERITY_COLORS[threat] || SEVERITY_COLORS.LOW;

            return (
              <div key={i} className={`flex items-center gap-3 p-2.5 rounded-xl border ${colors.border} ${colors.bg} hover:opacity-90 transition-opacity`}>
                <span className="flex-shrink-0 text-sm">{meta.icon}</span>
                <span className="text-gray-500 flex-shrink-0 text-[11px]">{new Date(event.timestamp).toLocaleTimeString()}</span>
                <span className={`font-bold flex-shrink-0 ${colors.text}`}>{meta.label}</span>
                <span className="text-gray-200 flex-1 truncate">
                  {event.type === 'new_connection' && `${d.process} → ${d.remote_ip}:${d.remote_port} (${d.city || 'Unknown'}, ${d.country || 'Unknown'})`}
                  {event.type === 'new_process' && `${d.name} [PID ${d.pid}] by ${d.username || 'system'}`}
                  {event.type === 'clipboard_threat' && `Score ${d.score} — ${d.indicators?.[0] || 'Suspicious clipboard content'}`}
                  {event.type === 'connection_closed' && `Closed: ${d.connection}`}
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
