import React, { useEffect, useState, useMemo } from 'react';
import { 
  Network, 
  ArrowUp, 
  ArrowDown, 
  Database, 
  ShieldAlert, 
  ShieldX, 
  ShieldCheck, 
  Search, 
  Globe, 
  Plus, 
  Trash2,
  AlertTriangle,
  RefreshCw,
  SearchCode,
  Sparkles
} from 'lucide-react';
import { buildApiUrl, getAuthHeaders, getAuthToken, buildWsUrl } from '../utils/auth';

export default function TrafficMonitorPanel() {
  const [connections, setConnections] = useState([]);
  const [stats, setStats] = useState({
    bytes_sent_sec: 0,
    bytes_recv_sec: 0,
    total_sent_mb: 0,
    total_recv_mb: 0,
  });
  const [speedHistory, setSpeedHistory] = useState({
    upload: Array(15).fill(0),
    download: Array(15).fill(0)
  });
  const [rules, setRules] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [selectedIpInfo, setSelectedIpInfo] = useState(null);
  const [showReputationModal, setShowReputationModal] = useState(false);
  const [loadingReputation, setLoadingReputation] = useState(false);

  // Load blocklist rules
  const fetchRules = async () => {
    try {
      const res = await fetch(buildApiUrl('/api/traffic-monitor/rules'), {
        headers: getAuthHeaders()
      });
      if (res.ok) {
        const data = await res.json();
        setRules(data);
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchRules();

    const fetchStatus = async () => {
      try {
        const res = await fetch(buildApiUrl('/api/traffic-monitor/status'), {
          headers: getAuthHeaders()
        });
        if (res.ok) {
          const data = await res.json();
          setConnections(data.connections || []);
          const iStats = data.interface_stats || {};
          setStats(iStats);
          const up = iStats.bytes_sent_sec ? (iStats.bytes_sent_sec / 1024) : 0;
          const down = iStats.bytes_recv_sec ? (iStats.bytes_recv_sec / 1024) : 0;
          setSpeedHistory(prev => ({
            upload: [...prev.upload.slice(1), up],
            download: [...prev.download.slice(1), down]
          }));
        }
      } catch (e) {
        console.error('Traffic fetch failed', e);
      }
    };
    fetchStatus();

    // Poll every 2 seconds as robust fallback
    const pollInterval = setInterval(fetchStatus, 2000);

    // WebSocket with auto-reconnect (exponential backoff)
    let ws = null;
    let reconnectTimer = null;
    let reconnectAttempts = 0;
    let destroyed = false;

    const connect = () => {
      if (destroyed) return;
      const token = getAuthToken();
      ws = new WebSocket(buildWsUrl(`/api/ws/monitor?token=${encodeURIComponent(token || '')}`));

      ws.onopen = () => {
        reconnectAttempts = 0;
      };

      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.type === 'TRAFFIC_MONITOR_UPDATE') {
            setConnections(msg.connections || []);
            setStats(msg.interface_stats || {});
            const up = msg.interface_stats?.bytes_sent_sec ? (msg.interface_stats.bytes_sent_sec / 1024) : 0;
            const down = msg.interface_stats?.bytes_recv_sec ? (msg.interface_stats.bytes_recv_sec / 1024) : 0;
            setSpeedHistory(prev => ({
              upload: [...prev.upload.slice(1), up],
              download: [...prev.download.slice(1), down]
            }));
          }
        } catch (err) {
          console.error('WS parse error', err);
        }
      };

      ws.onclose = () => {
        if (!destroyed) {
          const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
          reconnectAttempts += 1;
          reconnectTimer = setTimeout(connect, delay);
        }
      };

      ws.onerror = () => {
        ws.close();
      };
    };

    connect();

    return () => {
      destroyed = true;
      clearInterval(pollInterval);
      clearTimeout(reconnectTimer);
      if (ws) ws.close();
    };
  }, []);

  // Format speed text
  const formatSpeed = (bytesPerSec) => {
    if (!bytesPerSec || bytesPerSec === 0) return '0.0 KB/s';
    const kb = bytesPerSec / 1024;
    if (kb > 1024) {
      return `${(kb / 1024).toFixed(1)} MB/s`;
    }
    return `${kb.toFixed(1)} KB/s`;
  };

  // Filter connections
  const filteredConns = useMemo(() => {
    return connections.filter(conn => {
      const matchesSearch = 
        conn.process?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        conn.remote_ip?.includes(searchQuery) ||
        String(conn.remote_port).includes(searchQuery);

      const matchesProto = protocolFilter === 'ALL' || conn.protocol === protocolFilter;
      const matchesStatus = statusFilter === 'ALL' || 
        (statusFilter === 'BLOCKED' && conn.blocked) || 
        (statusFilter === 'THREAT' && conn.risk_score > 30) ||
        (statusFilter === 'SAFE' && !conn.blocked && conn.risk_score <= 30);

      return matchesSearch && matchesProto && matchesStatus;
    });
  }, [connections, searchQuery, protocolFilter, statusFilter]);

  // Compute counters
  const totals = useMemo(() => {
    const active = connections.length;
    const threat = connections.filter(c => c.risk_score > 30).length;
    const blocked = connections.filter(c => c.blocked).length;
    const safe = connections.filter(c => !c.blocked && c.risk_score <= 30).length;
    return { active, threat, blocked, safe };
  }, [connections]);

  // Block/Allow IP actions
  const handleToggleBlock = async (ip, currentStatus) => {
    try {
      const headers = getAuthHeaders();
      if (currentStatus) {
        // Delete Rule
        const res = await fetch(buildApiUrl(`/api/traffic-monitor/rules/${ip}`), {
          method: 'DELETE',
          headers
        });
        if (res.ok) fetchRules();
      } else {
        // Add block rule
        const res = await fetch(buildApiUrl('/api/traffic-monitor/rules'), {
          method: 'POST',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip_address: ip, action: 'block' })
        });
        if (res.ok) fetchRules();
      }
    } catch (e) {
      console.error(e);
    }
  };

  // IP Reputation lookup
  const handleReputationLookup = async (ip) => {
    setLoadingReputation(true);
    setShowReputationModal(true);
    try {
      const res = await fetch(buildApiUrl(`/api/traffic-monitor/reputation/${ip}`), {
        headers: getAuthHeaders()
      });
      if (res.ok) {
        const data = await res.json();
        setSelectedIpInfo(data);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingReputation(false);
    }
  };

  // Disconnect process
  const handleDisconnect = async (pid) => {
    if (!window.confirm("Are you sure you want to terminate this application's sockets? This will close the program.")) return;
    try {
      const res = await fetch(buildApiUrl('/api/traffic-monitor/disconnect'), {
        method: 'POST',
        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid })
      });
      if (res.ok) {
        window.showToast?.("Process terminated successfully.", 'success');
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Render svg line graph
  const renderLineGraph = () => {
    const maxVal = Math.max(...speedHistory.download, ...speedHistory.upload, 1);
    
    const getPoints = (arr) => {
      return arr.map((val, idx) => {
        const x = (idx / (arr.length - 1)) * 100;
        const y = 35 - (val / maxVal) * 30; // padding from top/bottom
        return `${x},${y}`;
      }).join(' ');
    };

    const dlPoints = getPoints(speedHistory.download);
    const ulPoints = getPoints(speedHistory.upload);

    return (
      <div className="h-32 bg-black/40 rounded-2xl border border-white/5 p-4 relative flex flex-col justify-between overflow-hidden">
        <div className="flex items-center justify-between text-xs z-10">
          <span className="font-semibold text-white">Live Network Throughput Graph</span>
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1 text-blue-400 font-medium">
              <span className="w-2 h-2 rounded-full bg-blue-500"></span> Download
            </span>
            <span className="flex items-center gap-1 text-purple-400 font-medium">
              <span className="w-2 h-2 rounded-full bg-purple-500"></span> Upload
            </span>
          </div>
        </div>
        <div className="absolute inset-0 top-8 bottom-2 left-2 right-2">
          <svg className="w-full h-full" viewBox="0 0 100 35" preserveAspectRatio="none">
            {/* Download Curve */}
            <polyline
              fill="none"
              stroke="#3b82f6"
              strokeWidth="1.5"
              points={dlPoints}
            />
            {/* Upload Curve */}
            <polyline
              fill="none"
              stroke="#a855f7"
              strokeWidth="1.5"
              points={ulPoints}
            />
          </svg>
        </div>
        <div className="text-[9px] text-gray-500 font-mono z-10 flex justify-between mt-auto">
          <span>Max Peak: {maxVal.toFixed(1)} KB/s</span>
          <span>Live Metrics (2s intervals)</span>
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      
      {/* Header */}
      <header className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between border-b border-white/5 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="text-3xl font-extrabold text-white tracking-tight">Real-Time Traffic Monitor</h2>
            <span className="px-2 py-0.5 rounded bg-primary/10 border border-primary/20 text-[10px] font-semibold text-primary uppercase tracking-wide">
              Live Sockets
            </span>
          </div>
          <p className="text-gray-400 mt-2 max-w-2xl text-sm">
            Monitors packet throughput, socket bindings, geolocations, and flags DDoS-like activity or suspicious outbound network connections on your system.
          </p>
        </div>
        <button 
          onClick={fetchRules}
          className="flex items-center justify-center gap-2 px-4 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white hover:bg-white/10 transition-all font-medium self-start lg:self-auto"
        >
          <RefreshCw size={14} /> Refresh Rules
        </button>
      </header>

      {/* Cards Summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="glass-panel p-4 border border-white/10 rounded-2xl">
          <div className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Active Sockets</div>
          <div className="text-2xl font-black text-white mt-1">{totals.active}</div>
          <div className="text-[10px] text-gray-400 mt-0.5">Connections open</div>
        </div>
        <div className="glass-panel p-4 border border-white/10 rounded-2xl">
          <div className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Upload Speed</div>
          <div className="text-2xl font-black text-purple-400 mt-1 flex items-center gap-1.5">
            <ArrowUp size={16} />
            {formatSpeed(stats.bytes_sent_sec)}
          </div>
          <div className="text-[10px] text-gray-400 mt-0.5">Total Out: {stats.total_sent_mb?.toFixed(1)} MB</div>
        </div>
        <div className="glass-panel p-4 border border-white/10 rounded-2xl">
          <div className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Download Speed</div>
          <div className="text-2xl font-black text-blue-400 mt-1 flex items-center gap-1.5">
            <ArrowDown size={16} />
            {formatSpeed(stats.bytes_recv_sec)}
          </div>
          <div className="text-[10px] text-gray-400 mt-0.5">Total In: {stats.total_recv_mb?.toFixed(1)} MB</div>
        </div>
        <div className="glass-panel p-4 border border-white/10 rounded-2xl">
          <div className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Blocked IPs</div>
          <div className="text-2xl font-black text-rose-500 mt-1">{rules.length}</div>
          <div className="text-[10px] text-gray-400 mt-0.5">Outbound rules applied</div>
        </div>
      </div>

      {/* Speed Line Graph */}
      {renderLineGraph()}

      {/* Main Grid: Connection List & Filters */}
      <div className="glass-panel rounded-2xl border border-white/10 p-5 space-y-4">
        
        {/* Filter Bar */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-white/5 pb-4">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={15} />
            <input
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by Process name, IP address, Port..."
              className="w-full pl-10 pr-4 py-2 rounded-xl border border-white/10 bg-black/40 text-xs text-white outline-none focus:border-primary/50 transition-all font-medium"
            />
          </div>
          <div className="flex items-center gap-3">
            <select
              value={protocolFilter}
              onChange={(e) => setProtocolFilter(e.target.value)}
              className="px-3 py-2 rounded-xl border border-white/10 bg-black/50 text-xs text-gray-300 focus:border-primary/50 outline-none"
            >
              <option value="ALL">All Protocols</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="HTTPS">HTTPS (443)</option>
              <option value="HTTP">HTTP (80)</option>
              <option value="DNS">DNS (53)</option>
            </select>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-3 py-2 rounded-xl border border-white/10 bg-black/50 text-xs text-gray-300 focus:border-primary/50 outline-none"
            >
              <option value="ALL">All Sockets</option>
              <option value="SAFE">Safe</option>
              <option value="THREAT">Threat Anomalies</option>
              <option value="BLOCKED">Blocked IPs</option>
            </select>
          </div>
        </div>

        {/* Connection List Table */}
        <div className="overflow-x-auto rounded-xl border border-white/5 bg-black/20">
          <table className="w-full text-left border-collapse text-xs">
            <thead className="bg-white/[0.02] border-b border-white/10 text-gray-400 font-bold">
              <tr>
                <th className="p-3">Process</th>
                <th className="p-3">PID</th>
                <th className="p-3">Source Socket</th>
                <th className="p-3">Destination IP</th>
                <th className="p-3">Port</th>
                <th className="p-3">Proto</th>
                <th className="p-3">Traffic (Sent/Recv)</th>
                <th className="p-3">Country</th>
                <th className="p-3 text-center">Threat Status</th>
                <th className="p-3 text-center">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-gray-300 font-medium">
              {filteredConns.length === 0 ? (
                <tr>
                  <td colSpan="10" className="p-8 text-center text-gray-500 font-medium">
                    No active connections matching filters.
                  </td>
                </tr>
              ) : (
                filteredConns.map((conn, idx) => {
                  const isBlocked = rules.some(r => r.ip_address === conn.remote_ip);
                  const isSuspicious = conn.risk_score > 30;
                  
                  // Compute human-friendly size
                  const formatSize = (bytes) => {
                    if (bytes > 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
                    return `${(bytes / 1024).toFixed(0)} KB`;
                  };

                  return (
                    <tr key={`${conn.pid}-${conn.remote}-${idx}`} className="hover:bg-white/[0.01] transition-colors">
                      <td className="p-3 font-semibold text-white truncate max-w-[120px]">{conn.process}</td>
                      <td className="p-3 font-mono text-[10px] text-gray-500">{conn.pid || '-'}</td>
                      <td className="p-3 font-mono text-[10px] text-gray-400">{conn.local}</td>
                      <td className="p-3 font-mono text-[10px] text-gray-200">{conn.remote_ip}</td>
                      <td className="p-3 font-mono text-[10px] text-gray-400">{conn.remote_port}</td>
                      <td className="p-3">
                        <span className="px-1.5 py-0.5 rounded bg-white/[0.04] text-[9px] border border-white/10 font-bold uppercase">
                          {conn.protocol}
                        </span>
                      </td>
                      <td className="p-3 font-mono text-[10px] text-gray-400">
                        <span className="text-blue-400">↓ {formatSize(conn.bytes_recv)}</span>
                        <span className="mx-1">/</span>
                        <span className="text-purple-400">↑ {formatSize(conn.bytes_sent)}</span>
                      </td>
                      <td className="p-3">
                        <span className="inline-flex items-center gap-1.5">
                          <Globe size={11} className="text-gray-500" />
                          {conn.country || 'Local'}
                        </span>
                      </td>
                      <td className="p-3 text-center">
                        {isBlocked ? (
                          <span className="px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/20 text-[9px] font-bold text-rose-500 uppercase">
                            Blocked
                          </span>
                        ) : isSuspicious ? (
                          <span className="px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/20 text-[9px] font-bold text-amber-500 uppercase">
                            Suspicious
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20 text-[9px] font-bold text-emerald-500 uppercase">
                            Safe
                          </span>
                        )}
                      </td>
                      <td className="p-3">
                        <div className="flex items-center justify-center gap-2">
                          <button
                            onClick={() => handleReputationLookup(conn.remote_ip)}
                            title="Scan IP Reputation"
                            className="p-1 rounded bg-white/5 border border-white/10 text-gray-400 hover:text-white hover:bg-white/10 transition-colors"
                          >
                            <SearchCode size={13} />
                          </button>
                          <button
                            onClick={() => handleToggleBlock(conn.remote_ip, isBlocked)}
                            title={isBlocked ? "Unblock IP" : "Block IP"}
                            className={`p-1 rounded border transition-colors ${
                              isBlocked
                                ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-500 hover:bg-emerald-500/20'
                                : 'bg-rose-500/10 border-rose-500/20 text-rose-500 hover:bg-rose-500/20'
                            }`}
                          >
                            {isBlocked ? <ShieldCheck size={13} /> : <ShieldX size={13} />}
                          </button>
                          {conn.pid && (
                            <button
                              onClick={() => handleDisconnect(conn.pid)}
                              title="Disconnect Process Sockets"
                              className="p-1 rounded bg-white/5 border border-white/10 text-rose-400 hover:bg-rose-500/10 transition-colors"
                            >
                              <Trash2 size={13} />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* IP Reputation Lookup Modal */}
      {showReputationModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-in fade-in duration-300">
          <div className="glass-panel w-full max-w-md border border-white/15 rounded-2xl p-6 space-y-4 shadow-2xl relative">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Globe className="text-primary" size={18} />
              IP Reputation Scan Report
            </h3>
            
            {loadingReputation ? (
              <div className="py-8 flex flex-col items-center justify-center gap-3">
                <RefreshCw className="animate-spin text-primary" size={24} />
                <span className="text-xs text-gray-400">Analyzing host reputation and DNS databases...</span>
              </div>
            ) : selectedIpInfo ? (
              <div className="space-y-3.5 text-xs text-gray-300">
                <div className="p-3 bg-white/[0.02] border border-white/5 rounded-xl flex items-center justify-between">
                  <span className="font-semibold text-white">Target IP:</span>
                  <span className="font-mono text-white text-sm bg-black/40 px-2 py-0.5 rounded border border-white/5">{selectedIpInfo.ip}</span>
                </div>
                
                <div className="grid grid-cols-2 gap-3">
                  <div className="p-2.5 bg-white/[0.02] border border-white/5 rounded-xl">
                    <span className="text-[10px] text-gray-500 block">COUNTRY</span>
                    <span className="font-semibold text-white mt-0.5 block">{selectedIpInfo.country} ({selectedIpInfo.country_code})</span>
                  </div>
                  <div className="p-2.5 bg-white/[0.02] border border-white/5 rounded-xl">
                    <span className="text-[10px] text-gray-500 block">ISP/ORGANIZATION</span>
                    <span className="font-semibold text-white mt-0.5 block truncate">{selectedIpInfo.org}</span>
                  </div>
                </div>

                <div className="p-3 bg-white/[0.02] border border-white/5 rounded-xl space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-white">AI Reputation Score:</span>
                    <span className={`font-mono font-bold ${selectedIpInfo.reputation_score > 40 ? 'text-rose-500' : 'text-emerald-500'}`}>
                      {selectedIpInfo.reputation_score.toFixed(1)} / 100
                    </span>
                  </div>
                  <div className="w-full bg-white/5 h-1.5 rounded-full overflow-hidden">
                    <div 
                      className={`h-full rounded-full ${selectedIpInfo.reputation_score > 40 ? 'bg-rose-500' : 'bg-emerald-500'}`}
                      style={{ width: `${selectedIpInfo.reputation_score}%` }}
                    ></div>
                  </div>
                </div>

                <div className="p-3 bg-white/[0.02] border border-white/5 rounded-xl flex items-start gap-2.5">
                  <ShieldAlert className="text-warning mt-0.5 shrink-0" size={16} />
                  <div>
                    <span className="font-semibold text-white block">Security Assessment:</span>
                    <span className="text-gray-400 mt-1 block">
                      {selectedIpInfo.blacklisted 
                        ? "Explicitly blocked. Sockets are denied outbound connection permissions." 
                        : selectedIpInfo.reputation_score > 40 
                          ? "This IP address originates from a flagged country block or is spread across multiple concurrent process handles." 
                          : "This destination IP address is evaluated as clean and is permitted by firewall rules."
                      }
                    </span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-xs text-rose-400 text-center py-4">Failed to fetch reputation data.</div>
            )}

            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => {
                  setShowReputationModal(false);
                  setSelectedIpInfo(null);
                }}
                className="px-4 py-2 bg-white/5 border border-white/10 hover:bg-white/10 text-white rounded-xl text-xs font-semibold transition-colors"
              >
                Close Report
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
