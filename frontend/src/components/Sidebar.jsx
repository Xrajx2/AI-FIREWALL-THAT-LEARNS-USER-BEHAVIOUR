import React, { useState } from 'react';
import { Shield, Activity, AlertTriangle, LayoutDashboard, LogOut, Users, Terminal, ScanSearch, MonitorCog, Network, ShieldAlert, Settings, Globe, ArrowLeftRight, MapPin, Fish, Lock } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { buildApiUrl, clearAuthSession, getAuthHeaders, getStoredUser, isAdminUser } from '../utils/auth';

const MENU_ITEMS = {
  overview: { id: 'overview', label: 'Overview', icon: <LayoutDashboard size={20} /> },
  trafficControl: { id: 'trafficControl', label: 'Traffic Control', icon: <ArrowLeftRight size={20} /> },
  accessLogs: { id: 'accessLogs', label: 'Access Logs', icon: <MapPin size={20} /> },
  phishing: { id: 'phishing', label: 'Phishing Checker', icon: <Fish size={20} /> },
  blocks: { id: 'blocks', label: 'Block Manager', icon: <Lock size={20} /> },
  desktopSecurity: { id: 'desktopSecurity', label: 'Windows Security', icon: <MonitorCog size={20} /> },
  websiteSecurity: { id: 'websiteSecurity', label: 'Website Security', icon: <Globe size={20} /> },
  live: { id: 'live', label: 'Live Activity', icon: <Activity size={20} /> },
  trafficMonitor: { id: 'trafficMonitor', label: 'Traffic Monitor', icon: <Network size={20} /> },
  spamDetection: { id: 'spamDetection', label: 'Spam Detection', icon: <ShieldAlert size={20} /> },
  alerts: { id: 'alerts', label: 'Threat Alerts', icon: <AlertTriangle size={20} /> },
  deviceSafety: { id: 'deviceSafety', label: 'Device Safety', icon: <ScanSearch size={20} /> },
  users: { id: 'users', label: 'User Management', icon: <Users size={20} /> },
  simulation: { id: 'simulation', label: 'Simulation', icon: <Terminal size={20} /> },
};





export default function Sidebar({ activeTab, setActiveTab, availableTabs = ['overview', 'alerts'] }) {
  const navigate = useNavigate();
  const user = getStoredUser();
  const adminMode = isAdminUser(user);
  const [devMode, setDevMode] = useState(() => localStorage.getItem('devMode') === 'true');

  const toggleDevMode = () => {
    const nextVal = !devMode;
    setDevMode(nextVal);
    localStorage.setItem('devMode', String(nextVal));
    window.showToast?.(
      nextVal ? 'Developer tools enabled. Simulation tab unlocked!' : 'Developer tools disabled.',
      'info'
    );
  };

  const handleLogout = async () => {
    try {
      await fetch(buildApiUrl('/api/auth/logout'), {
        method: 'POST',
        headers: getAuthHeaders(),
      });
    } catch {
      // We still clear local session state even if the API call fails.
    }
    clearAuthSession();
    navigate('/login');
  };

  const menuItems = availableTabs
    .map((tabId) => MENU_ITEMS[tabId])
    .filter(Boolean)
    .filter((item) => item.id !== 'simulation' || devMode);

  return (
    <div className="w-64 h-screen bg-secondary/50 border-r border-white/5 flex flex-col p-4 backdrop-blur-xl">
      <div className="flex items-center gap-3 mb-10 mt-4 px-2">
        <div className="w-10 h-10 bg-primary/20 rounded-xl flex items-center justify-center glow-effect">
          <Shield className="w-6 h-6 text-primary" />
        </div>
        <div>
          <h1 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-white to-gray-400">
            AI Firewall
          </h1>
          <div className="text-[11px] uppercase tracking-[0.24em] text-gray-500">Learns User Behavior</div>
        </div>
      </div>

      {user && (
        <div className="mb-4 rounded-2xl border border-gray-700/10 bg-gray-900/10 px-4 py-3 relative group">
          {adminMode && (
            <button
              onClick={toggleDevMode}
              className={`absolute top-3 right-3 p-1 rounded-lg border transition-colors ${
                devMode
                  ? 'border-primary/20 bg-primary/10 text-primary'
                  : 'border-transparent text-gray-500 hover:text-white hover:bg-white/5'
              }`}
              title="Toggle Simulation Mode"
            >
              <Settings size={14} />
            </button>
          )}
          <div className="text-xs uppercase tracking-[0.2em] text-gray-500">Signed In</div>
          <div className="mt-1 text-sm font-semibold text-white">{user.username}</div>
          <div className="text-xs text-gray-500 break-all">{user.email}</div>
          <div className="mt-2.5 inline-flex rounded-full border border-primary/20 bg-primary/10 px-2.5 py-1 text-[11px] uppercase tracking-[0.2em] text-primary">
            {adminMode ? 'Admin Role' : 'User Role'}
          </div>
        </div>
      )}

      <nav className="flex-1 space-y-1.5 overflow-y-auto pr-1">
        {menuItems.map((item) => (
          <button
            key={item.id}
            onClick={() => setActiveTab(item.id)}
            className={`w-full flex items-center gap-3 px-4 py-2.5 rounded-xl transition-all ${
              activeTab === item.id
                ? 'bg-primary/20 text-primary border border-primary/20'
                : 'text-gray-400 hover:bg-white/5 hover:text-white'
            }`}
          >
            {item.icon}
            <span className="font-medium text-xs">{item.label}</span>
          </button>
        ))}
      </nav>

      <div className="mt-auto border-t border-gray-700/10 pt-4">
        <button
          onClick={handleLogout}
          className="w-full flex items-center gap-3 px-4 py-2.5 rounded-xl text-gray-400 hover:bg-danger/10 hover:text-danger transition-colors"
        >
          <LogOut size={20} />
          <span className="font-medium text-xs">Logout</span>
        </button>
      </div>
    </div>
  );
}
