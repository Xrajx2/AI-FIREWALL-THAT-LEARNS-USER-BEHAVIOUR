import React, { useState, useEffect } from 'react';
import { BrowserRouter, HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import TitleBar from './components/TitleBar';
import { getAuthToken, getDefaultAppRoute, getStoredUser, hasRequiredRole, buildApiUrl } from './utils/auth';

function ProtectedRoute({ children, allowedRoles = [] }) {
  const token = getAuthToken();
  const user = getStoredUser();

  if (!token) {
    return <Navigate to="/login" replace />;
  }

  if (allowedRoles.length > 0 && !hasRequiredRole(allowedRoles, user)) {
    return <Navigate to={getDefaultAppRoute(user)} replace />;
  }

  return children;
}

function RootRedirect() {
  const token = getAuthToken();
  const user = getStoredUser();
  return <Navigate to={token ? getDefaultAppRoute(user) : '/login'} replace />;
}

function App() {
  const isElectron = typeof window !== 'undefined' && Boolean(window.electron?.isElectron || window.aiFirewallDesktop?.isElectron);
  const Router = isElectron ? HashRouter : BrowserRouter;

  const [backendReady, setBackendReady] = useState(false);
  const [retryCount, setRetryCount] = useState(0);

  useEffect(() => {
    let isMounted = true;
    let timer = null;

    const checkHealth = async () => {
      try {
        const res = await fetch(buildApiUrl('/api/health'), { signal: AbortSignal.timeout(2500) });
        if (res.ok) {
          if (isMounted) setBackendReady(true);
          return;
        }
      } catch (err) {
        // Backend not ready yet
      }

      if (isMounted) {
        setRetryCount((prev) => prev + 1);
        timer = setTimeout(checkHealth, 1500);
      }
    };

    checkHealth();

    return () => {
      isMounted = false;
      if (timer) clearTimeout(timer);
    };
  }, []);

  return (
    <div className={`min-h-screen bg-[#0a0a0f] text-gray-100 ${isElectron ? 'pt-[38px]' : ''}`}>
      <TitleBar />
      {!backendReady ? (
        <div className="flex flex-col items-center justify-center min-h-[80vh] px-4 text-center select-none">
          <div className="relative mb-6">
            <div className="w-16 h-16 border-4 border-cyan-500/20 border-t-cyan-500 rounded-full animate-spin"></div>
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="text-xl">🛡️</span>
            </div>
          </div>
          <h2 className="text-xl font-semibold text-white tracking-wide mb-2">
            Starting AI Firewall Security Engine...
          </h2>
          <p className="text-sm text-gray-400 max-w-sm mb-4">
            Initializing threat detection models, host telemetry, and secure database connections.
          </p>
          <div className="flex items-center space-x-2 text-xs text-cyan-400/80 bg-cyan-950/40 px-3 py-1.5 rounded-full border border-cyan-800/40">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
            <span>Connecting to backend services... {retryCount > 0 ? `(Attempt ${retryCount + 1})` : ''}</span>
          </div>
        </div>
      ) : (
      <Router>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/dashboard/*"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/admin/*"
            element={
              <ProtectedRoute allowedRoles={['admin']}>
                <Dashboard defaultTab="live" />
              </ProtectedRoute>
            } 
          />
          <Route
            path="/live-activity"
            element={
              <ProtectedRoute>
                <Dashboard defaultTab="live" />
              </ProtectedRoute>
            }
          />
          <Route
            path="/user-management"
            element={
              <ProtectedRoute allowedRoles={['admin']}>
                <Dashboard defaultTab="users" />
              </ProtectedRoute>
            }
          />
          <Route
            path="/phishing"
            element={
              <ProtectedRoute>
                <Dashboard defaultTab="phishing" />
              </ProtectedRoute>
            }
          />
          <Route
            path="/system-status"
            element={
              <ProtectedRoute>
                <Dashboard defaultTab="systemStatus" />
              </ProtectedRoute>
            }
          />
          <Route path="/" element={<RootRedirect />} />
        </Routes>
      </Router>
      )}
    </div>
  );
}

export default App;
