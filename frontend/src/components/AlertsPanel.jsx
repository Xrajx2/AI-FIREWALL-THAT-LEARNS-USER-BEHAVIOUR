import React, { useState, useEffect } from 'react';
import { AlertCircle, ShieldBan, Info } from 'lucide-react';
import { getRiskTone, normalizeRiskLevel } from '../utils/risk';
import { buildApiUrl, buildWsUrl, getAuthHeaders, getAuthToken } from '../utils/auth';

const formatThreatDetail = (details) => {
  if (!details) {
    return 'Unknown activity';
  }

  const normalized = details.replace(/^Anomalous action:\s*/i, '').trim();
  if (normalized.includes(' ')) {
    return normalized;
  }

  return normalized
    .split('_')
    .filter(Boolean)
    .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
    .join(' ');
};

const extractThreatTrigger = (details) => {
  if (!details) {
    return 'Behavior anomaly';
  }

  const normalized = details.replace(/^Anomalous action:\s*/i, '').trim();
  const summaryMatch = normalized.match(/flagged\s+(.+?)\s+because/i);
  if (summaryMatch?.[1]) {
    return summaryMatch[1]
      .split('_')
      .filter(Boolean)
      .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
      .join(' ');
  }

  return normalized
    .split('_')
    .filter(Boolean)
    .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
    .join(' ');
};

export default function AlertsPanel() {
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    const token = getAuthToken();
    fetch(buildApiUrl('/api/threats'), { headers: getAuthHeaders() })
      .then(res => res.json())
      .then(data => setAlerts(data))
      .catch(err => console.error("Error fetching threats:", err));

    const ws = new WebSocket(`${buildWsUrl('/api/ws/monitor')}?token=${encodeURIComponent(token || '')}`);

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type === 'THREAT_ALERT') {
        const dummyThreat = {
          id: Date.now(),
          timestamp: new Date().toISOString(),
          user_id: msg.data.user,
          threat_level: msg.data.level,
          anomaly_score: msg.data.score,
          details: msg.data.details || msg.data.action,
          action_taken: msg.data.level === 'Critical' ? 'session_locked' : 'alert_sent'
        };
        setAlerts(prev => [dummyThreat, ...prev]);
      }
    };

    return () => ws.close();
  }, []);

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <header className="mb-8">
        <h2 className="text-3xl font-bold text-white mb-2">Threat Alerts</h2>
        <p className="text-gray-400">This page lists detections that crossed the AI alert threshold. It does not mean every event is malware, but it does mean the behavior looked unusual enough to investigate.</p>
      </header>

      <div className="rounded-2xl border border-primary/20 bg-primary/10 p-5 text-sm text-gray-300">
        <div className="text-white font-semibold mb-2">What this page is showing</div>
        <p>
          When the anomaly score rises above the alert threshold, the system creates a threat card here. Each alert tells you what triggered the detection, how severe it looked, and what automatic response the firewall took.
        </p>
      </div>

      <div className="space-y-4">
        {alerts.length === 0 ? (
          <div className="glass-panel p-8 rounded-2xl text-center text-gray-500">
            No threats detected. The network is secure.
          </div>
        ) : (
          alerts.map((alert, i) => (
            <div key={alert.id || i} className={`glass-panel p-6 rounded-2xl flex items-start gap-4 border-l-4 ${
              normalizeRiskLevel(alert.threat_level, alert.anomaly_score) === 'Dangerous' ? 'border-l-danger bg-danger/5' :
              normalizeRiskLevel(alert.threat_level, alert.anomaly_score) === 'Suspicious' ? 'border-l-warning bg-warning/5' :
              'border-l-success bg-success/5'
            }`}>
              <div className={`mt-1 bg-white/10 p-2 rounded-full ${
                normalizeRiskLevel(alert.threat_level, alert.anomaly_score) === 'Dangerous' ? 'text-danger' :
                normalizeRiskLevel(alert.threat_level, alert.anomaly_score) === 'Suspicious' ? 'text-warning' :
                'text-success'
              }`}>
                {normalizeRiskLevel(alert.threat_level, alert.anomaly_score) === 'Dangerous' ? <ShieldBan size={24} /> :
                 normalizeRiskLevel(alert.threat_level, alert.anomaly_score) === 'Suspicious' ? <AlertCircle size={24} /> :
                 <Info size={24} />}
              </div>
              
              <div className="flex-1">
                <div className="flex justify-between items-start mb-2">
                  <h3 className="font-semibold text-lg flex items-center gap-2">
                    {normalizeRiskLevel(alert.threat_level, alert.anomaly_score)} Risk Alert
                    <span className="text-xs font-mono bg-white/10 px-2 py-1 rounded text-gray-400">
                      Score: {alert.anomaly_score?.toFixed(1) || alert.anomaly_score}
                    </span>
                  </h3>
                  <span className="text-sm text-gray-500 font-mono">
                    {new Date(alert.timestamp + (alert.timestamp.includes('Z') ? '' : 'Z')).toLocaleString()}
                  </span>
                </div>
                
                <p className="text-gray-300 mb-4">
                  <span className="text-gray-400">Model Summary:</span>{' '}
                  <span className="text-white">{formatThreatDetail(alert.details)}</span>
                </p>
                
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium text-gray-400">Trigger:</span>
                  <span className="text-xs px-2 py-1 rounded border border-white/10 bg-white/5 text-gray-300">
                    {extractThreatTrigger(alert.details)}
                  </span>
                  <span className={`text-xs px-2 py-1 rounded border font-medium ${getRiskTone(alert.threat_level, alert.anomaly_score).badge}`}>
                    {normalizeRiskLevel(alert.threat_level, alert.anomaly_score)}
                  </span>
                  <span className="text-sm font-medium text-gray-400 ml-2">Automated Action:</span>
                  <span className={`text-xs px-2 py-1 rounded border ${
                    alert.action_taken === 'block' || alert.action_taken === 'session_locked'
                      ? 'bg-danger/10 border-danger/30 text-danger' 
                      : 'bg-warning/10 border-warning/30 text-warning'
                  }`}>
                    {alert.action_taken.replace('_', ' ').toUpperCase()}
                  </span>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
