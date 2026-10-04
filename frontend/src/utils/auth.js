export const getApiBaseUrl = () => {
  if (import.meta.env.VITE_API_URL) {
    return import.meta.env.VITE_API_URL;
  }
  const dynamicPort = (typeof window !== 'undefined' && (window.AI_FIREWALL_PORT || window.electron?.port || sessionStorage.getItem('ai_firewall_port'))) || '8000';
  if (typeof window !== 'undefined' && window.location) {
    const hostname = window.location.hostname;
    if (hostname && hostname !== 'localhost' && hostname !== '127.0.0.1' && !window.location.protocol.startsWith('file')) {
      return `${window.location.protocol}//${hostname}:${dynamicPort}`;
    }
  }
  return `http://127.0.0.1:${dynamicPort}`;
};

export const API_BASE_URL = getApiBaseUrl();

const parseStoredJson = (value) => {
  if (!value) return null;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
};

export const buildApiUrl = (path) => `${getApiBaseUrl()}${path}`;

export const buildWsUrl = (path) => {
  const wsBase = getApiBaseUrl().replace(/^http/i, 'ws');
  return `${wsBase}${path}`;
};

const getStoredExpiry = () => localStorage.getItem('expires_at') || sessionStorage.getItem('expires_at');

export const normalizeRole = (role) => String(role || 'user').trim().toLowerCase();

export const isSessionExpired = () => {
  const expiresAt = getStoredExpiry();
  if (!expiresAt) return false;
  const parsed = new Date(expiresAt);
  if (Number.isNaN(parsed.getTime())) return false;
  return parsed.getTime() <= Date.now();
};

export const getAuthToken = () => {
  if (isSessionExpired()) {
    clearAuthSession();
    return null;
  }
  return localStorage.getItem('token') || sessionStorage.getItem('token');
};

export const getStoredUser = () => {
  if (isSessionExpired()) {
    clearAuthSession();
    return null;
  }
  return parseStoredJson(localStorage.getItem('user')) || parseStoredJson(sessionStorage.getItem('user'));
};

export const getUserRole = () => normalizeRole(getStoredUser()?.role);

export const isAdminUser = (user = getStoredUser()) => normalizeRole(user?.role) === 'admin';

export const hasRequiredRole = (allowedRoles = [], user = getStoredUser()) => {
  if (!allowedRoles?.length) return true;
  const normalized = normalizeRole(user?.role);
  return allowedRoles.map(normalizeRole).includes(normalized);
};

export const getDefaultAppRoute = (user = getStoredUser()) => (
  isAdminUser(user) ? '/admin' : '/dashboard'
);

export const getAuthHeaders = (headers = {}) => {
  const token = getAuthToken();
  return token ? { ...headers, Authorization: `Bearer ${token}` } : headers;
};

export const authHeaders = getAuthHeaders;


export const setAuthSession = (payload, rememberMe = false) => {
  const token = payload.access_token;
  const user = JSON.stringify(payload.user);
  const expiresAt = payload.expires_at || '';
  localStorage.removeItem('remembered_password');

  if (rememberMe) {
    // Persist across app restarts — store in localStorage
    localStorage.setItem('token', token);
    localStorage.setItem('user', user);
    localStorage.setItem('expires_at', expiresAt);
    // Clear sessionStorage to avoid duplicates
    sessionStorage.removeItem('token');
    sessionStorage.removeItem('user');
    sessionStorage.removeItem('expires_at');
  } else {
    // Session-only — cleared when app/window closes
    sessionStorage.setItem('token', token);
    sessionStorage.setItem('user', user);
    sessionStorage.setItem('expires_at', expiresAt);
    // Ensure no stale persistent token lingers
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('expires_at');
  }
};

export const clearAuthSession = () => {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
  localStorage.removeItem('expires_at');
  localStorage.removeItem('remembered_password');
  sessionStorage.removeItem('token');
  sessionStorage.removeItem('user');
  sessionStorage.removeItem('expires_at');
};

export const handleUnauthorizedResponse = (response) => {
  if (response?.status === 401) {
    clearAuthSession();
    if (typeof window !== 'undefined' && window.location.pathname !== '/login') {
      window.location.href = '#/login';
    }
  }
};
