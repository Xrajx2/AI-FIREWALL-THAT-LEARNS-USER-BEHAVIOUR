import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  Mail,
  Shield,
  ShieldAlert,
  Sparkles,
  UserCheck,
  UserRound,
} from 'lucide-react';
import { buildApiUrl, getAuthToken, getDefaultAppRoute, setAuthSession } from '../utils/auth';

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const scorePasswordStrength = (value) => {
  let score = 0;
  if (value.length >= 8) score += 1;
  if (value.length >= 10) score += 1;
  if (value.length >= 12) score += 1;
  if (/[A-Z]/.test(value)) score += 1;
  if (/[a-z]/.test(value)) score += 1;
  if (/\d/.test(value)) score += 1;
  if (/[^A-Za-z0-9]/.test(value)) score += 1;
  if (score >= 5) return { label: 'Strong', width: '100%', tone: 'bg-success' };
  if (score >= 3) return { label: 'Medium', width: '66%', tone: 'bg-warning' };
  return { label: 'Weak', width: '33%', tone: 'bg-danger' };
};

const initialLogin = { identifier: '', password: '', rememberMe: true };
const initialSignup = { username: '', email: '', password: '' };
const initialAdminCreate = { username: '', email: '', password: '', confirmPassword: '' };

const formatErrorMessage = (detail) => {
  if (!detail) return null;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((err) => {
        const field = err.loc ? err.loc.slice(1).join('.') : '';
        return `${field ? field + ': ' : ''}${err.msg}`;
      })
      .join('; ');
  }
  if (typeof detail === 'object') {
    if (detail.message) return detail.message;
    if (detail.detail) return formatErrorMessage(detail.detail);
    return JSON.stringify(detail);
  }
  return String(detail);
};

export default function Login() {
  const navigate = useNavigate();
  const [hasAdmin, setHasAdmin] = useState(true);
  const [checkingAdmin, setCheckingAdmin] = useState(true);
  const [mode, setMode] = useState('login'); // 'login' | 'signup' | 'create-admin'
  const [loginForm, setLoginForm] = useState({
    identifier: localStorage.getItem('remembered_identifier') || '',
    password: '',
    rememberMe: localStorage.getItem('remember_me_checked') !== 'false',
  });
  const [signupForm, setSignupForm] = useState(initialSignup);
  const [adminForm, setAdminForm] = useState(initialAdminCreate);

  const [showLoginPassword, setShowLoginPassword] = useState(false);
  const [showSignupPassword, setShowSignupPassword] = useState(false);
  const [showAdminPassword, setShowAdminPassword] = useState(false);

  const [fieldErrors, setFieldErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [banner, setBanner] = useState(null);

  useEffect(() => {
    localStorage.removeItem('remembered_password');
    if (getAuthToken()) {
      navigate(getDefaultAppRoute(), { replace: true });
      return;
    }

    const checkAdminStatus = async () => {
      try {
        const response = await fetch(buildApiUrl('/api/auth/admin-status'));
        if (response.ok) {
          const data = await response.json();
          const adminExists = Boolean(data.has_admin);
          setHasAdmin(adminExists);
          if (!adminExists) {
            setMode('create-admin');
          }
        }
      } catch (err) {
        console.error('Error querying admin status:', err);
      } finally {
        setCheckingAdmin(false);
      }
    };

    checkAdminStatus();
  }, [navigate]);

  const passwordStrength = useMemo(
    () => scorePasswordStrength(mode === 'create-admin' ? adminForm.password : signupForm.password || ''),
    [mode, adminForm.password, signupForm.password]
  );

  const validateLogin = () => {
    const nextErrors = {};
    if (!loginForm.identifier.trim()) nextErrors.identifier = 'Enter your username or email.';
    if (!loginForm.password) nextErrors.password = 'Enter your password.';
    return nextErrors;
  };

  const validateSignup = () => {
    const nextErrors = {};
    if (signupForm.username.trim().length < 3) nextErrors.username = 'Username must be at least 3 characters.';
    if (!emailPattern.test(signupForm.email.trim())) nextErrors.email = 'Enter a valid email address.';
    if (signupForm.password.length < 8 || passwordStrength.label === 'Weak') {
      nextErrors.password = 'Use 8+ characters with uppercase, lowercase, number, and symbol.';
    }
    return nextErrors;
  };

  const validateCreateAdmin = () => {
    const nextErrors = {};
    if (adminForm.username.trim().length < 3) nextErrors.username = 'Username must be at least 3 characters.';
    if (adminForm.email.trim() && !emailPattern.test(adminForm.email.trim())) {
      nextErrors.email = 'Enter a valid email address.';
    }
    if (adminForm.password.length < 10) {
      nextErrors.password = 'Administrator password must be at least 10 characters long.';
    }
    if (adminForm.password !== adminForm.confirmPassword) {
      nextErrors.confirmPassword = 'Passwords do not match.';
    }
    return nextErrors;
  };

  const handleLogin = async (event) => {
    event.preventDefault();
    const nextErrors = validateLogin();
    setFieldErrors(nextErrors);
    if (Object.keys(nextErrors).length) return;

    setLoading(true);
    setBanner(null);
    try {
      const response = await fetch(buildApiUrl('/api/auth/login'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identifier: loginForm.identifier.trim(),
          password: loginForm.password,
          remember_me: loginForm.rememberMe,
        }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(formatErrorMessage(data.detail) || 'Authentication failed.');
      }

      setAuthSession(data, true);
      if (data.access_info) {
        sessionStorage.setItem('last_access_info', JSON.stringify(data.access_info));
      }
      localStorage.setItem('remembered_identifier', loginForm.identifier.trim());
      localStorage.setItem('remember_me_checked', loginForm.rememberMe ? 'true' : 'false');
      localStorage.removeItem('remembered_password');

      const redirectPath = getDefaultAppRoute(data.user);
      setBanner({
        type: data.security_status === 'Suspicious' ? 'warning' : 'success',
        text: data.warning_message || 'Access granted! Opening AI Firewall dashboard...',
      });
      window.setTimeout(() => navigate(redirectPath, { replace: true }), 300);
    } catch (error) {
      setBanner({ type: 'error', text: error.message || 'Authentication failed.' });
    } finally {
      setLoading(false);
    }
  };

  const handleSignup = async (event) => {
    event.preventDefault();
    const nextErrors = validateSignup();
    setFieldErrors(nextErrors);
    if (Object.keys(nextErrors).length) return;

    setLoading(true);
    setBanner(null);
    try {
      const response = await fetch(buildApiUrl('/api/auth/signup'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: signupForm.username.trim(),
          email: signupForm.email.trim(),
          password: signupForm.password,
          role: 'user',
        }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(formatErrorMessage(data.detail) || 'Account creation failed.');
      }

      setBanner({
        type: 'success',
        text: `${data.message} ${data.verification_notice || ''}`.trim(),
      });
      setMode('login');
      setLoginForm((current) => ({
        ...current,
        identifier: signupForm.email.trim() || signupForm.username.trim(),
        password: '',
      }));
      setSignupForm(initialSignup);
      setFieldErrors({});
    } catch (error) {
      setBanner({ type: 'error', text: error.message || 'Account creation failed.' });
    } finally {
      setLoading(false);
    }
  };

  const handleCreateAdmin = async (event) => {
    event.preventDefault();
    const nextErrors = validateCreateAdmin();
    setFieldErrors(nextErrors);
    if (Object.keys(nextErrors).length) return;

    setLoading(true);
    setBanner(null);
    try {
      const response = await fetch(buildApiUrl('/api/auth/create-admin'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: adminForm.username.trim(),
          email: adminForm.email.trim() || null,
          password: adminForm.password,
        }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(formatErrorMessage(data.detail) || 'Failed to create administrator.');
      }

      setHasAdmin(true);
      setBanner({
        type: 'success',
        text: 'Administrator account created successfully! Please sign in with your master credentials.',
      });
      setMode('login');
      setLoginForm({
        identifier: adminForm.username.trim(),
        password: '',
        rememberMe: true,
      });
      setAdminForm(initialAdminCreate);
      setFieldErrors({});
    } catch (error) {
      setBanner({ type: 'error', text: error.message || 'Failed to create administrator.' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-shell min-h-screen flex items-center justify-center px-4 py-12 bg-gray-900 relative">
      {/* Background Glow */}
      <div className="absolute top-[10%] left-[10%] w-[350px] h-[350px] bg-primary/5 rounded-full blur-[100px] pointer-events-none"></div>
      <div className="absolute bottom-[10%] right-[10%] w-[350px] h-[350px] bg-accent/5 rounded-full blur-[100px] pointer-events-none"></div>

      <div className="relative z-10 w-full max-w-md">
        <section className="glass-panel p-6 md:p-10 shadow-2xl border border-gray-700/10 bg-black/95">
          <div className="mb-8 flex items-center justify-between gap-4">
            <div className="inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/10 px-3 py-1 text-xs uppercase tracking-[0.3em] text-primary">
              <Shield size={14} />
              AI Firewall
            </div>
            <div className="text-[11px] uppercase tracking-[0.24em] text-gray-500 font-semibold">
              {mode === 'create-admin' ? 'Initial Setup' : 'Secure Access'}
            </div>
          </div>

          {/* Mode Switcher when admin exists */}
          {hasAdmin && (
            <div className="mb-6 flex rounded-2xl border border-gray-700 bg-gray-800 p-1">
              {['login', 'signup'].map((tab) => (
                <button
                  key={tab}
                  type="button"
                  onClick={() => {
                    setMode(tab);
                    setFieldErrors({});
                    setBanner(null);
                  }}
                  className={`flex-1 rounded-xl px-4 py-2.5 text-xs font-semibold uppercase tracking-[0.22em] transition-all ${
                    mode === tab
                      ? 'bg-black text-white shadow-sm border border-gray-700'
                      : 'text-gray-500 hover:text-white'
                  }`}
                >
                  {tab === 'login' ? 'Login' : 'Sign Up'}
                </button>
              ))}
            </div>
          )}

          {banner && (
            <div
              className={`mb-5 rounded-2xl border px-4 py-3 text-xs animate-in fade-in zoom-in-95 ${
                banner.type === 'success'
                  ? 'border-success/20 bg-success/10 text-success'
                  : banner.type === 'warning'
                  ? 'border-warning/20 bg-warning/10 text-warning'
                  : 'border-danger/20 bg-danger/10 text-danger'
              }`}
            >
              {banner.text}
            </div>
          )}

          {mode === 'create-admin' ? (
            /* First Launch: Create Administrator View */
            <form onSubmit={handleCreateAdmin} className="space-y-5">
              <div className="rounded-2xl border border-primary/20 bg-primary/5 p-4 text-xs text-gray-300">
                <div className="flex items-center gap-2 text-primary font-bold mb-1">
                  <UserCheck size={16} />
                  <span>Create Master Administrator Account</span>
                </div>
                <p className="text-gray-400 text-[11px] leading-relaxed">
                  No administrator has been registered yet. Establish your master security credentials to initialize AI Firewall.
                </p>
              </div>

              <FloatingField
                icon={<UserRound size={18} />}
                label="Administrator Username"
                value={adminForm.username}
                error={fieldErrors.username}
              >
                <input
                  value={adminForm.username}
                  onChange={(e) => setAdminForm({ ...adminForm, username: e.target.value })}
                  className="auth-input text-white"
                  placeholder="admin"
                  autoFocus
                />
              </FloatingField>

              <FloatingField
                icon={<Mail size={18} />}
                label="Recovery Email (Optional)"
                value={adminForm.email}
                error={fieldErrors.email}
              >
                <input
                  value={adminForm.email}
                  onChange={(e) => setAdminForm({ ...adminForm, email: e.target.value })}
                  className="auth-input text-white"
                  placeholder="admin@example.local"
                />
              </FloatingField>

              <FloatingField
                icon={<KeyRound size={18} />}
                label="Admin Password (Min 10 chars)"
                value={adminForm.password}
                error={fieldErrors.password}
              >
                <input
                  type={showAdminPassword ? 'text' : 'password'}
                  value={adminForm.password}
                  onChange={(e) => setAdminForm({ ...adminForm, password: e.target.value })}
                  className="auth-input text-white pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowAdminPassword((current) => !current)}
                  className="auth-eye-button"
                >
                  {showAdminPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </FloatingField>

              <FloatingField
                icon={<KeyRound size={18} />}
                label="Confirm Password"
                value={adminForm.confirmPassword}
                error={fieldErrors.confirmPassword}
              >
                <input
                  type={showAdminPassword ? 'text' : 'password'}
                  value={adminForm.confirmPassword}
                  onChange={(e) => setAdminForm({ ...adminForm, confirmPassword: e.target.value })}
                  className="auth-input text-white pr-10"
                />
              </FloatingField>

              <div className="rounded-2xl border border-gray-700 bg-gray-800 p-4">
                <div className="flex items-center justify-between text-[10px] uppercase tracking-[0.24em] text-gray-500 font-semibold">
                  <span>Password Strength</span>
                  <span
                    className={
                      passwordStrength.label === 'Strong'
                        ? 'text-success font-bold'
                        : passwordStrength.label === 'Medium'
                        ? 'text-warning font-bold'
                        : 'text-danger font-bold'
                    }
                  >
                    {passwordStrength.label}
                  </span>
                </div>
                <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-gray-700">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${passwordStrength.tone}`}
                    style={{ width: passwordStrength.width }}
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full flex items-center justify-center gap-2.5 rounded-2xl py-3.5 font-semibold text-white bg-gradient-to-r from-primary to-indigo-600 hover:from-primary/95 hover:to-indigo-600/95 transition-all shadow-md hover:shadow-lg disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {loading ? <Loader2 size={18} className="animate-spin" /> : <Shield size={18} />}
                <span>{loading ? 'Creating Administrator...' : 'Create Administrator Account'}</span>
              </button>
            </form>
          ) : mode === 'login' ? (
            /* Login Form */
            <form onSubmit={handleLogin} className="space-y-5">
              <FloatingField
                icon={<Mail size={18} />}
                label="Username or Email"
                value={loginForm.identifier}
                error={fieldErrors.identifier}
              >
                <input
                  type="text"
                  name="identifier"
                  value={loginForm.identifier}
                  onChange={(e) => setLoginForm({ ...loginForm, identifier: e.target.value })}
                  className="auth-input text-white"
                  placeholder="Username or email"
                  autoFocus
                />
              </FloatingField>

              <FloatingField
                icon={<KeyRound size={18} />}
                label="Password"
                value={loginForm.password}
                error={fieldErrors.password}
              >
                <input
                  type={showLoginPassword ? 'text' : 'password'}
                  value={loginForm.password}
                  onChange={(e) => setLoginForm({ ...loginForm, password: e.target.value })}
                  className="auth-input text-white pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowLoginPassword((current) => !current)}
                  className="auth-eye-button"
                >
                  {showLoginPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </FloatingField>

              <div className="flex items-center justify-between text-xs">
                <label className="flex items-center gap-2.5 text-gray-500 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={loginForm.rememberMe}
                    onChange={(e) => setLoginForm({ ...loginForm, rememberMe: e.target.checked })}
                    className="h-4 w-4 rounded border-gray-700 bg-black text-primary focus:ring-primary"
                  />
                  Remember Me
                </label>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full flex items-center justify-center gap-2.5 rounded-2xl py-3.5 font-semibold text-white bg-gradient-to-r from-primary to-indigo-600 hover:from-primary/95 hover:to-indigo-600/95 transition-all shadow-md hover:shadow-lg disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {loading ? <Loader2 size={18} className="animate-spin" /> : <Shield size={18} />}
                <span>{loading ? 'Authenticating...' : 'Sign In'}</span>
              </button>
            </form>
          ) : (
            /* Signup Form (Standard User) */
            <form onSubmit={handleSignup} className="space-y-5">
              <FloatingField
                icon={<UserRound size={18} />}
                label="Username"
                value={signupForm.username}
                error={fieldErrors.username}
              >
                <input
                  value={signupForm.username}
                  onChange={(e) => setSignupForm({ ...signupForm, username: e.target.value })}
                  className="auth-input text-white"
                  autoFocus
                />
              </FloatingField>

              <FloatingField
                icon={<Mail size={18} />}
                label="Email Address"
                value={signupForm.email}
                error={fieldErrors.email}
              >
                <input
                  value={signupForm.email}
                  onChange={(e) => setSignupForm({ ...signupForm, email: e.target.value })}
                  className="auth-input text-white"
                />
              </FloatingField>

              <FloatingField
                icon={<KeyRound size={18} />}
                label="Password"
                value={signupForm.password}
                error={fieldErrors.password}
              >
                <input
                  type={showSignupPassword ? 'text' : 'password'}
                  value={signupForm.password}
                  onChange={(e) => setSignupForm({ ...signupForm, password: e.target.value })}
                  className="auth-input text-white pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowSignupPassword((current) => !current)}
                  className="auth-eye-button"
                >
                  {showSignupPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </FloatingField>

              <div className="rounded-2xl border border-gray-700 bg-gray-800 p-4">
                <div className="flex items-center justify-between text-[10px] uppercase tracking-[0.24em] text-gray-500 font-semibold">
                  <span>Password Strength</span>
                  <span
                    className={
                      passwordStrength.label === 'Strong'
                        ? 'text-success font-bold'
                        : passwordStrength.label === 'Medium'
                        ? 'text-warning font-bold'
                        : 'text-danger font-bold'
                    }
                  >
                    {passwordStrength.label}
                  </span>
                </div>
                <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-gray-700">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${passwordStrength.tone}`}
                    style={{ width: passwordStrength.width }}
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full flex items-center justify-center gap-2.5 rounded-2xl py-3.5 font-semibold text-white bg-gradient-to-r from-primary to-indigo-600 hover:from-primary/95 hover:to-indigo-600/95 transition-all shadow-md hover:shadow-lg disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {loading ? <Loader2 size={18} className="animate-spin" /> : <Sparkles size={18} />}
                <span>{loading ? 'Creating Account...' : 'Create Account'}</span>
              </button>
            </form>
          )}
        </section>
      </div>
    </div>
  );
}

function FloatingField({ icon, label, error, children }) {
  return (
    <label
      className={`relative block rounded-2xl border bg-gray-900 px-4 pt-3 pb-2 transition-all ${
        error
          ? 'border-danger/40 shadow-[0_0_0_1px_rgba(255,0,60,0.15)]'
          : 'border-gray-700 focus-within:border-primary/40 focus-within:shadow-[0_0_0_1px_rgba(79,70,229,0.15)]'
      }`}
    >
      <span className="pointer-events-none block text-[10px] uppercase tracking-[0.22em] text-primary font-bold">
        {label}
      </span>
      <div className="relative mt-2 flex items-center">
        <span className="auth-field-icon pointer-events-none">{icon}</span>
        {children}
      </div>
      {error && <span className="mt-1 block text-[10px] text-danger">{error}</span>}
    </label>
  );
}
