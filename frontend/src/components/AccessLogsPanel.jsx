import React, { useState, useEffect } from 'react';
import { buildApiUrl, getAuthHeaders, isAdminUser, getStoredUser } from '../utils/auth';

export default function AccessLogsPanel() {
  const user = getStoredUser();
  const isAdmin = isAdminUser(user);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const res = await fetch(buildApiUrl('/api/access-logs'), { headers: getAuthHeaders() });
      if (res.ok) {
        const data = await res.json();
        setLogs(data.logs || []);
      }
    } catch (err) {
      console.error('Failed to load access logs', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <span>🌍</span> Access Logs
          </h1>
          <p className="text-xs text-gray-400 mt-1">
            Real-time geolocation telemetry and security flags on every login attempt.
          </p>
        </div>
        <button
          onClick={fetchLogs}
          className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-xl text-xs font-medium transition-colors"
        >
          Refresh Logs
        </button>
      </div>

      <div className="bg-gray-900/80 backdrop-blur-xl rounded-2xl border border-gray-800 overflow-hidden shadow-2xl">
        <table className="w-full text-left">
          <thead>
            <tr className="bg-gray-800/60 border-b border-gray-800">
              {['Time', 'User', 'IP Address', 'City', 'Region', 'Country', 'ISP', 'Threat', 'Flags'].map(h => (
                <th key={h} className="px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/50">
            {logs.length === 0 ? (
              <tr>
                <td colSpan="9" className="px-4 py-8 text-center text-sm text-gray-500">
                  {loading ? 'Loading access telemetry...' : 'No access logs recorded yet.'}
                </td>
              </tr>
            ) : (
              logs.map((log, i) => (
                <tr key={i} className="hover:bg-gray-800/40 transition-colors">
                  <td className="px-4 py-3 text-xs text-gray-400 font-mono">
                    {new Date(log.access_time).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-sm text-white font-medium">{log.user_email || 'Unknown'}</td>
                  <td className="px-4 py-3 text-sm text-blue-400 font-mono">{log.ip_address}</td>
                  <td className="px-4 py-3 text-sm text-gray-300">{log.city}</td>
                  <td className="px-4 py-3 text-sm text-gray-300">{log.region}</td>
                  <td className="px-4 py-3 text-sm text-gray-300">{log.country}</td>
                  <td className="px-4 py-3 text-sm text-gray-400">{log.isp}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                      log.threat_score > 70 ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                      log.threat_score > 40 ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' :
                      'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                    }`}>
                      {log.threat_score}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs">
                    <div className="flex gap-1.5 flex-wrap">
                      {log.is_proxy ? (
                        <span className="px-1.5 py-0.5 bg-red-500/20 text-red-400 rounded font-semibold text-[10px]">
                          PROXY
                        </span>
                      ) : null}
                      {log.is_datacenter ? (
                        <span className="px-1.5 py-0.5 bg-orange-500/20 text-orange-400 rounded font-semibold text-[10px]">
                          DC
                        </span>
                      ) : null}
                      {!log.is_proxy && !log.is_datacenter && (
                        <span className="text-gray-500 text-xs">-</span>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
