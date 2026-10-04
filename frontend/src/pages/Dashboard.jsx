import React, { useMemo, useState, useEffect } from 'react';
import Sidebar from '../components/Sidebar';
import Overview from '../components/Overview';
import TrafficControlPanel from '../components/TrafficControlPanel';
import AccessLogsPanel from '../components/AccessLogsPanel';
import AccessInfo from '../components/AccessInfo';
import PhishingCheckerPanel from '../components/PhishingCheckerPanel';
import BlockManagementPanel from '../components/BlockManagementPanel';
import LiveActivity from './LiveActivity';
import UserManagement from './UserManagement';
import TrafficMonitorPanel from '../components/TrafficMonitorPanel';
import SpamDetectionPanel from '../components/SpamDetectionPanel';
import AlertsPanel from '../components/AlertsPanel';
import DeviceSafetyPanel from '../components/DeviceSafetyPanel';
import DesktopSecurityPanel from '../components/DesktopSecurityPanel';
import WebsiteSecurityPanel from '../components/WebsiteSecurityPanel';
import UsersPanel from '../components/UsersPanel';
import SimulationPanel from '../components/SimulationPanel';
import { getStoredUser, isAdminUser, buildWsUrl, getAuthToken } from '../utils/auth';
import { normalizeRiskLevel } from '../utils/risk';

const ADMIN_TABS = ['overview', 'trafficControl', 'accessLogs', 'phishing', 'blocks', 'desktopSecurity', 'websiteSecurity', 'live', 'trafficMonitor', 'spamDetection', 'alerts', 'deviceSafety', 'users', 'simulation'];
const USER_TABS = ['overview', 'trafficControl', 'accessLogs', 'phishing', 'websiteSecurity', 'live', 'trafficMonitor', 'spamDetection', 'alerts', 'deviceSafety'];




export default function Dashboard({ defaultTab = 'overview' }) {
  const user = getStoredUser();
  const adminMode = isAdminUser(user);
  const availableTabs = useMemo(() => (adminMode ? ADMIN_TABS : USER_TABS), [adminMode]);
  const resolvedDefaultTab = availableTabs.includes(defaultTab) ? defaultTab : availableTabs[0];
  const [activeTab, setActiveTab] = useState(resolvedDefaultTab);
  const [toasts, setToasts] = useState([]);
  const [accessInfo, setAccessInfo] = useState(() => {
    try {
      const raw = sessionStorage.getItem('last_access_info');
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  });


  const visibleTab = availableTabs.includes(activeTab) ? activeTab : resolvedDefaultTab;
  const [notificationPermissionDenied, setNotificationPermissionDenied] = useState(false);

  // Request system notification permissions on mount
  React.useEffect(() => {
    if (typeof Notification !== 'undefined') {
      if (Notification.permission === 'denied') {
        setNotificationPermissionDenied(true);
      } else if (Notification.permission === 'default') {
        Notification.requestPermission().then((permission) => {
          if (permission === 'denied') {
            setNotificationPermissionDenied(true);
          }
        });
      }
    }
  }, []);

  // Listen for background threat alerts and send native OS toast notifications for Dangerous threats
  React.useEffect(() => {
    let ws = null;
    let reconnectTimer = null;
    let reconnectAttempts = 0;
    let isDisposed = false;

    const connectWs = () => {
      if (isDisposed) return;
      const token = getAuthToken();
      if (!token) return;

      try {
        ws = new WebSocket(`${buildWsUrl('/api/ws/monitor')}?token=${encodeURIComponent(token)}`);
        ws.onopen = () => {
          reconnectAttempts = 0;
        };
        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'THREAT_ALERT') {
              const risk = normalizeRiskLevel(msg.data.level, msg.data.score);
              if (risk === 'Dangerous') {
                if (typeof Notification !== 'undefined' && Notification.permission === 'granted') {
                  new Notification('AI Firewall - Dangerous Threat Blocked!', {
                    body: `Action: ${msg.data.details || msg.data.action || 'Critical anomaly detected.'}\nAnomaly Score: ${msg.data.score}`,
                    requireInteraction: true,
                  });
                }
              }
            }
          } catch (err) {
            console.error('Error parsing threat alert message', err);
          }
        };
        ws.onclose = () => {
          if (!isDisposed) {
            const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
            reconnectAttempts += 1;
            reconnectTimer = setTimeout(connectWs, delay);
          }
        };
        ws.onerror = () => {
          if (ws) ws.close();
        };
      } catch (err) {
        if (!isDisposed) {
          const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
          reconnectAttempts += 1;
          reconnectTimer = setTimeout(connectWs, delay);
        }
      }
    };

    connectWs();

    return () => {
      isDisposed = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (ws) ws.close();
    };
  }, [user]);

  React.useEffect(() => {
    window.showToast = (message, type = 'success') => {
      const id = Date.now();
      setToasts((prev) => [...prev, { id, message, type }]);
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id));
      }, 4000);
    };
    return () => {
      delete window.showToast;
    };
  }, []);

  return (
    <div className="flex h-screen bg-background text-gray-100 overflow-hidden relative">
      {/* Background decorations */}
      <div className="absolute top-[-10%] left-[20%] w-[500px] h-[500px] bg-primary/5 rounded-full blur-[150px] pointer-events-none"></div>
      <div className="absolute bottom-[-10%] right-[-5%] w-[400px] h-[400px] bg-accent/5 rounded-full blur-[150px] pointer-events-none"></div>

      <Sidebar activeTab={visibleTab} setActiveTab={setActiveTab} availableTabs={availableTabs} />
      
      <main className="flex-1 overflow-y-auto p-8 z-10">
        <div className="max-w-7xl mx-auto space-y-8">
          {notificationPermissionDenied && (
            <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg flex items-center justify-between text-amber-400 text-sm">
              <div className="flex items-center gap-2">
                <span>⚠️</span>
                <span>Desktop notification permission is denied. System notifications for dangerous threats will not appear on your desktop.</span>
              </div>
              <button
                onClick={() => setNotificationPermissionDenied(false)}
                className="text-gray-400 hover:text-white text-xs px-2 py-1 rounded"
              >
                Dismiss
              </button>
            </div>
          )}
          {accessInfo && <AccessInfo accessInfo={accessInfo} />}
          {visibleTab === 'overview' && <Overview />}
          {visibleTab === 'trafficControl' && <TrafficControlPanel />}
          {visibleTab === 'accessLogs' && <AccessLogsPanel />}
          {visibleTab === 'phishing' && <PhishingCheckerPanel />}
          {visibleTab === 'blocks' && adminMode && <BlockManagementPanel />}
          {visibleTab === 'desktopSecurity' && adminMode && <DesktopSecurityPanel />}



          {visibleTab === 'websiteSecurity' && <WebsiteSecurityPanel />}
          {visibleTab === 'live' && <LiveActivity />}
          {visibleTab === 'trafficMonitor' && <TrafficMonitorPanel />}
          {visibleTab === 'spamDetection' && <SpamDetectionPanel />}
          {visibleTab === 'alerts' && <AlertsPanel />}
          {visibleTab === 'deviceSafety' && <DeviceSafetyPanel />}
          {visibleTab === 'users' && adminMode && <UserManagement />}
          {visibleTab === 'simulation' && adminMode && <SimulationPanel />}
        </div>
      </main>

      {/* Premium Toast Notifications Floating Container */}
      <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-3 max-w-sm pointer-events-none">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className={`pointer-events-auto p-4 rounded-xl border shadow-xl flex items-center gap-3 animate-in slide-in-from-bottom-5 duration-300 ${
              toast.type === 'success'
                ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-600 font-semibold'
                : toast.type === 'error'
                  ? 'bg-rose-500/10 border-rose-500/20 text-rose-600 font-semibold'
                  : 'bg-amber-500/10 border-amber-500/20 text-amber-600 font-semibold'
            }`}
          >
            {toast.type === 'success' && (
              <svg className="w-5 h-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
              </svg>
            )}
            {toast.type === 'error' && (
              <svg className="w-5 h-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
              </svg>
            )}
            {toast.type === 'warning' && (
              <svg className="w-5 h-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            )}
            <div className="text-xs">{toast.message}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
