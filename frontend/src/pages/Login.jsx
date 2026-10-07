import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertCircle,
  CheckCircle2,
  Clock,
  Eye,
  EyeOff,
  Globe,
  KeyRound,
  Loader2,
  Mail,
  RefreshCw,
  Shield,
  ShieldCheck,
  Sparkles,
  UserCheck,
  UserRound,
  X,
} from 'lucide-react';
import { buildApiUrl, getAuthToken, getDefaultAppRoute, setAuthSession } from '../utils/auth';

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const COUNTRIES = [
  'India',
  'United States',
  'United Kingdom',
  'Canada',
  'Australia',
  'Germany',
  'France',
  'Japan',
  'Brazil',
  'Singapore',
  'United Arab Emirates',
  'Netherlands',
  'South Korea',
  'Italy',
  'Spain',
  'Switzerland',
  'Sweden',
  'Poland',
  'Mexico',
  'South Africa',
  'New Zealand',
  'Ireland',
  'Norway',
  'Denmark',
  'Finland',
  'Austria',
  'Belgium',
  'Portugal',
  'Saudi Arabia',
  'Israel',
  'Turkey',
  'Indonesia',
  'Malaysia',
  'Philippines',
  'Vietnam',
  'Thailand',
  'Argentina',
  'Chile',
  'Colombia',
  'Egypt',
  'Greece',
  'Hong Kong',
  'Hungary',
  'Czech Republic',
  'Romania',
  'Ukraine',
  'Nigeria',
  'Kenya',
  'Pakistan',
  'Bangladesh',
];

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
const initialSignup = { username: '', email: '', password: '', country: 'India' };
const initialAdminCreate = { username: '', email: '', password: '', confirmPassword: '', country: 'United States' };

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

const GoogleIcon = () => (
  <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24">
    <path
      fill="#4285F4"
      d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.66-5.17 3.66-9.17z"
    />
    <path
      fill="#34A853"
      d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.25v3.15C3.26 21.36 7.33 24 12 24z"
    />
    <path
      fill="#FBBC05"
      d="M5.28 14.27c-.25-.72-.38-1.49-.38-2.27s.13-1.55.38-2.27V6.58H1.25C.45 8.18 0 9.98 0 12s.45 3.82 1.25 5.42l4.03-3.15z"
    />
    <path
      fill="#EA4335"
      d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.33 0 3.26 2.64 1.25 6.58l4.03 3.15c.95-2.83 3.6-4.98 6.72-4.98z"
    />
  </svg>
);

const MicrosoftIcon = () => (
  <svg className="w-4 h-4 shrink-0" viewBox="0 0 21 21">
    <rect x="1" y="1" width="9" height="9" fill="#f25022" />
    <rect x="11" y="1" width="9" height="9" fill="#7fba00" />
    <rect x="1" y="11" width="9" height="9" fill="#00a4ef" />
    <rect x="11" y="11" width="9" height="9" fill="#ffb900" />
  </svg>
);

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

  // Real-time unique username availability
  const [usernameCheck, setUsernameCheck] = useState({ checking: false, available: null, message: '' });
  const [adminUsernameCheck, setAdminUsernameCheck] = useState({ checking: false, available: null, message: '' });

  // Email OTP verification state
  const [otpState, setOtpState] = useState({
    sent: false,
    verified: false,
    loading: false,
    code: '',
    timer: 0,
    previewCode: '',
    error: '',
  });

  // Social Login Modal
  const [socialModal, setSocialModal] = useState({
    open: false,
    provider: null,
    email: '',
    name: '',
    country: 'India',
    loading: false,
    error: '',
  });

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

  // Debounced username availability check for signup
  useEffect(() => {
    const raw = signupForm.username.trim();
    if (!raw) {
      setUsernameCheck({ checking: false, available: null, message: '' });
      return;
    }
    if (raw.length < 3) {
      setUsernameCheck({
        checking: false,
        available: false,
        message: 'Username must be at least 3 characters long.',
      });
      return;
    }
    setUsernameCheck((prev) => ({ ...prev, checking: true, message: 'Checking username...' }));
    const timer = setTimeout(async () => {
      try {
        const res = await fetch(buildApiUrl(`/api/auth/check-username?username=${encodeURIComponent(raw)}`));
        if (res.ok) {
          const data = await res.json();
          setUsernameCheck({
            checking: false,
            available: data.available,
            message: data.message,
          });
        }
      } catch {
        setUsernameCheck({ checking: false, available: null, message: '' });
      }
    }, 350);
    return () => clearTimeout(timer);
  }, [signupForm.username]);

  // Debounced username availability check for admin create
  useEffect(() => {
    const raw = adminForm.username.trim();
    if (!raw) {
      setAdminUsernameCheck({ checking: false, available: null, message: '' });
      return;
    }
    if (raw.length < 3) {
      setAdminUsernameCheck({
        checking: false,
        available: false,
        message: 'Username must be at least 3 characters long.',
      });
      return;
    }
    setAdminUsernameCheck((prev) => ({ ...prev, checking: true, message: 'Checking username...' }));
    const timer = setTimeout(async () => {
      try {
        const res = await fetch(buildApiUrl(`/api/auth/check-username?username=${encodeURIComponent(raw)}`));
        if (res.ok) {
          const data = await res.json();
          setAdminUsernameCheck({
            checking: false,
            available: data.available,
            message: data.message,
          });
        }
      } catch {
        setAdminUsernameCheck({ checking: false, available: null, message: '' });
      }
    }, 350);
    return () => clearTimeout(timer);
  }, [adminForm.username]);

  // OTP Countdown Timer
  useEffect(() => {
    if (otpState.timer <= 0) return;
    const interval = setInterval(() => {
      setOtpState((prev) => ({
        ...prev,
        timer: prev.timer > 1 ? prev.timer - 1 : 0,
      }));
    }, 1000);
    return () => clearInterval(interval);
  }, [otpState.timer]);

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
    const uname = signupForm.username.trim();
    if (uname.length < 3) {
      nextErrors.username = 'Username must be at least 3 characters.';
    } else if (usernameCheck.available === false) {
      nextErrors.username = usernameCheck.message || 'This username is already taken by another user.';
    }

    if (!emailPattern.test(signupForm.email.trim())) {
      nextErrors.email = 'Enter a valid email address.';
    } else if (!otpState.verified) {
      nextErrors.email = 'Please verify your email address using the 6-digit OTP code before proceeding.';
    }

    if (signupForm.password.length < 8 || passwordStrength.label === 'Weak') {
      nextErrors.password = 'Use 8+ characters with uppercase, lowercase, number, and symbol.';
    }
    return nextErrors;
  };

  const validateCreateAdmin = () => {
    const nextErrors = {};
    const uname = adminForm.username.trim();
    if (uname.length < 3) {
      nextErrors.username = 'Username must be at least 3 characters.';
    } else if (adminUsernameCheck.available === false) {
      nextErrors.username = adminUsernameCheck.message || 'This username is already taken.';
    }
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

  const handleSendOtp = async () => {
    const cleanEmail = signupForm.email.trim();
    if (!cleanEmail || !emailPattern.test(cleanEmail)) {
      setFieldErrors((prev) => ({ ...prev, email: 'Enter a valid email address to receive the verification OTP.' }));
      return;
    }
    setFieldErrors((prev) => ({ ...prev, email: undefined }));
    setOtpState((prev) => ({ ...prev, loading: true, error: '' }));
    try {
      const response = await fetch(buildApiUrl('/api/auth/send-otp'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: cleanEmail, purpose: 'signup' }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(formatErrorMessage(data.detail) || 'Failed to dispatch verification code.');
      }
      setOtpState((prev) => ({
        ...prev,
        sent: true,
        loading: false,
        timer: 60,
        previewCode: data.dev_otp || '',
        error: '',
      }));
      setBanner({
        type: 'success',
        text: data.dev_otp
          ? `Verification OTP sent to ${cleanEmail}. (Code: ${data.dev_otp})`
          : `Verification code sent to ${cleanEmail}. Please check your inbox.`,
      });
    } catch (err) {
      setOtpState((prev) => ({ ...prev, loading: false, error: err.message }));
      setBanner({ type: 'error', text: err.message || 'Failed to send OTP.' });
    }
  };

  const handleVerifyOtp = async () => {
    const cleanEmail = signupForm.email.trim();
    const cleanCode = otpState.code.trim();
    if (!cleanCode || cleanCode.length !== 6) {
      setOtpState((prev) => ({ ...prev, error: 'Please enter all 6 digits of the OTP code.' }));
      return;
    }
    setOtpState((prev) => ({ ...prev, loading: true, error: '' }));
    try {
      const response = await fetch(buildApiUrl('/api/auth/verify-otp'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: cleanEmail, otp: cleanCode }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(formatErrorMessage(data.detail) || 'Invalid or expired OTP code.');
      }
      setOtpState((prev) => ({
        ...prev,
        verified: true,
        loading: false,
        error: '',
      }));
      setBanner({ type: 'success', text: 'Email verified successfully! You can now finish account registration.' });
    } catch (err) {
      setOtpState((prev) => ({ ...prev, loading: false, error: err.message }));
    }
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
          country: signupForm.country || 'India',
          role: 'user',
        }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(formatErrorMessage(data.detail) || 'Account creation failed.');
      }

      setBanner({
        type: 'success',
        text: `${data.message} Welcome! Sign in with your registered credentials.`,
      });
      setMode('login');
      setLoginForm((current) => ({
        ...current,
        identifier: signupForm.username.trim(),
        password: '',
      }));
      setSignupForm(initialSignup);
      setOtpState({ sent: false, verified: false, loading: false, code: '', timer: 0, previewCode: '', error: '' });
      setUsernameCheck({ checking: false, available: null, message: '' });
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
          country: adminForm.country || 'United States',
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

  const openSocialLoginModal = (provider) => {
    const defaultEmail =
      signupForm.email.trim() ||
      (provider === 'google' ? 'security.operator@gmail.com' : 'security.operator@outlook.com');
    const defaultName = signupForm.username.trim() || 'AI Firewall Operator';
    setSocialModal({
      open: true,
      provider,
      email: defaultEmail,
      name: defaultName,
      country: signupForm.country || 'India',
      loading: false,
      error: '',
    });
  };

  const handleSocialAuthSubmit = async (e) => {
    e.preventDefault();
    if (!socialModal.email.trim() || !emailPattern.test(socialModal.email.trim())) {
      setSocialModal((prev) => ({ ...prev, error: 'Please enter a valid email address.' }));
      return;
    }
    setSocialModal((prev) => ({ ...prev, loading: true, error: '' }));
    try {
      const response = await fetch(buildApiUrl('/api/auth/social-login'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: socialModal.provider,
          email: socialModal.email.trim(),
          name: socialModal.name.trim() || 'Operator',
          country: socialModal.country || 'India',
        }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(formatErrorMessage(data.detail) || 'Social authentication failed.');
      }

      setAuthSession(data, true);
      setSocialModal((prev) => ({ ...prev, open: false, loading: false }));
      const providerName = socialModal.provider === 'google' ? 'Google' : 'Microsoft';
      setBanner({
        type: 'success',
        text: `Connected with ${providerName}! Opening AI Firewall dashboard...`,
      });
      const redirectPath = getDefaultAppRoute(data.user);
      window.setTimeout(() => navigate(redirectPath, { replace: true }), 350);
    } catch (err) {
      setSocialModal((prev) => ({ ...prev, loading: false, error: err.message }));
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

          {/* Social Logins on Login & Sign Up views */}
          {mode !== 'create-admin' && (
            <div className="mb-5">
              <div className="grid grid-cols-2 gap-3">
                <button
                  type="button"
                  onClick={() => openSocialLoginModal('google')}
                  className="flex items-center justify-center gap-2.5 py-2.5 px-3 rounded-2xl border border-gray-700 bg-gray-800/80 hover:bg-gray-700/80 text-white text-xs font-semibold transition-all hover:border-gray-500 shadow-sm"
                >
                  <GoogleIcon />
                  <span>Google</span>
                </button>
                <button
                  type="button"
                  onClick={() => openSocialLoginModal('microsoft')}
                  className="flex items-center justify-center gap-2.5 py-2.5 px-3 rounded-2xl border border-gray-700 bg-gray-800/80 hover:bg-gray-700/80 text-white text-xs font-semibold transition-all hover:border-gray-500 shadow-sm"
                >
                  <MicrosoftIcon />
                  <span>Microsoft</span>
                </button>
              </div>

              <div className="relative my-5 flex items-center justify-center">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-gray-800" />
                </div>
                <span className="relative bg-black px-3 text-[10px] uppercase tracking-wider text-gray-500 font-semibold">
                  Or continue with credentials
                </span>
              </div>
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

              <div>
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
                    placeholder="admin (unique)"
                    autoFocus
                  />
                </FloatingField>
                {/* Real-time username availability indicator */}
                {adminForm.username.trim().length >= 3 && (
                  <div className="mt-1.5 px-2 flex items-center gap-1.5 text-[11px]">
                    {adminUsernameCheck.checking ? (
                      <span className="text-gray-400 flex items-center gap-1">
                        <Loader2 size={12} className="animate-spin text-primary" />
                        Checking availability...
                      </span>
                    ) : adminUsernameCheck.available === true ? (
                      <span className="text-success flex items-center gap-1 font-medium">
                        <CheckCircle2 size={12} />
                        {adminUsernameCheck.message}
                      </span>
                    ) : adminUsernameCheck.available === false ? (
                      <span className="text-danger flex items-center gap-1 font-medium">
                        <AlertCircle size={12} />
                        {adminUsernameCheck.message}
                      </span>
                    ) : null}
                  </div>
                )}
              </div>

              <FloatingField
                icon={<Globe size={18} />}
                label="Country / Region"
                value={adminForm.country}
              >
                <select
                  value={adminForm.country}
                  onChange={(e) => setAdminForm({ ...adminForm, country: e.target.value })}
                  className="auth-input text-white bg-transparent outline-none cursor-pointer"
                >
                  {COUNTRIES.map((country) => (
                    <option key={country} value={country} className="bg-gray-900 text-white">
                      {country}
                    </option>
                  ))}
                </select>
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
                disabled={loading || adminUsernameCheck.available === false}
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
                  placeholder="e.g. varun@29 or email"
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
              {/* Username with Live Uniqueness Check */}
              <div>
                <FloatingField
                  icon={<UserRound size={18} />}
                  label="Unique Username"
                  value={signupForm.username}
                  error={fieldErrors.username}
                >
                  <input
                    value={signupForm.username}
                    onChange={(e) => setSignupForm({ ...signupForm, username: e.target.value })}
                    className="auth-input text-white"
                    placeholder="e.g. varun@29"
                    autoFocus
                  />
                </FloatingField>
                {/* Real-time username availability badge */}
                {signupForm.username.trim().length >= 3 && (
                  <div className="mt-1.5 px-2 flex items-center gap-1.5 text-[11px]">
                    {usernameCheck.checking ? (
                      <span className="text-gray-400 flex items-center gap-1">
                        <Loader2 size={12} className="animate-spin text-primary" />
                        Checking availability...
                      </span>
                    ) : usernameCheck.available === true ? (
                      <span className="text-success flex items-center gap-1 font-medium">
                        <CheckCircle2 size={12} />
                        {usernameCheck.message}
                      </span>
                    ) : usernameCheck.available === false ? (
                      <span className="text-danger flex items-center gap-1 font-medium">
                        <AlertCircle size={12} />
                        {usernameCheck.message}
                      </span>
                    ) : null}
                  </div>
                )}
                <div className="mt-1 px-2 text-[10px] text-gray-500">
                  Each username can only be registered once. Allowed: letters, numbers, @, ., _, -
                </div>
              </div>

              {/* Country Selection */}
              <FloatingField
                icon={<Globe size={18} />}
                label="Country / Region"
                value={signupForm.country}
              >
                <select
                  value={signupForm.country}
                  onChange={(e) => setSignupForm({ ...signupForm, country: e.target.value })}
                  className="auth-input text-white bg-transparent outline-none cursor-pointer"
                >
                  {COUNTRIES.map((country) => (
                    <option key={country} value={country} className="bg-gray-900 text-white">
                      {country}
                    </option>
                  ))}
                </select>
              </FloatingField>

              {/* Email Address with OTP Trigger */}
              <div>
                <FloatingField
                  icon={<Mail size={18} />}
                  label="Email Address"
                  value={signupForm.email}
                  error={fieldErrors.email}
                >
                  <div className="flex items-center w-full gap-2">
                    <input
                      value={signupForm.email}
                      disabled={otpState.verified}
                      onChange={(e) => {
                        setSignupForm({ ...signupForm, email: e.target.value });
                        if (otpState.verified) {
                          setOtpState((prev) => ({ ...prev, verified: false, sent: false }));
                        }
                      }}
                      className="auth-input text-white flex-1"
                      placeholder="operator@company.com"
                    />
                    {otpState.verified ? (
                      <span className="inline-flex items-center gap-1 rounded-full bg-success/15 px-2.5 py-1 text-[11px] font-bold text-success">
                        <CheckCircle2 size={13} />
                        Verified
                      </span>
                    ) : (
                      <button
                        type="button"
                        onClick={handleSendOtp}
                        disabled={otpState.loading || otpState.timer > 0}
                        className="inline-flex items-center gap-1 rounded-xl bg-primary/20 hover:bg-primary/30 text-primary border border-primary/30 px-3 py-1.5 text-xs font-semibold whitespace-nowrap transition-all disabled:opacity-50"
                      >
                        {otpState.loading ? (
                          <Loader2 size={12} className="animate-spin" />
                        ) : (
                          <Mail size={12} />
                        )}
                        <span>
                          {otpState.timer > 0 ? `Resend (${otpState.timer}s)` : otpState.sent ? 'Resend OTP' : 'Send OTP'}
                        </span>
                      </button>
                    )}
                  </div>
                </FloatingField>

                {/* Inline OTP Verification Panel */}
                {otpState.sent && !otpState.verified && (
                  <div className="mt-2.5 rounded-2xl border border-primary/30 bg-primary/5 p-3.5 space-y-2.5 animate-in fade-in zoom-in-95">
                    <div className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-1.5 text-primary font-semibold">
                        <KeyRound size={14} />
                        <span>Enter 6-Digit Email OTP</span>
                      </div>
                      {otpState.previewCode && (
                        <span className="text-[10px] text-gray-400 bg-gray-800 px-2 py-0.5 rounded border border-gray-700">
                          Dev Code: <strong className="text-white">{otpState.previewCode}</strong>
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-2">
                      <input
                        type="text"
                        maxLength={6}
                        value={otpState.code}
                        onChange={(e) =>
                          setOtpState((prev) => ({
                            ...prev,
                            code: e.target.value.replace(/\D/g, '').slice(0, 6),
                          }))
                        }
                        placeholder="••••••"
                        className="w-36 rounded-xl border border-gray-700 bg-black px-3 py-2 text-center text-sm font-mono tracking-[0.3em] text-white focus:border-primary focus:outline-none"
                      />
                      <button
                        type="button"
                        onClick={handleVerifyOtp}
                        disabled={otpState.loading || otpState.code.length !== 6}
                        className="flex-1 flex items-center justify-center gap-1.5 rounded-xl bg-primary px-3 py-2 text-xs font-semibold text-white hover:bg-primary/90 transition-all disabled:opacity-50"
                      >
                        {otpState.loading ? <Loader2 size={13} className="animate-spin" /> : <ShieldCheck size={13} />}
                        <span>Verify OTP</span>
                      </button>
                    </div>

                    {otpState.error && (
                      <p className="text-[11px] text-danger flex items-center gap-1">
                        <AlertCircle size={12} />
                        {otpState.error}
                      </p>
                    )}
                  </div>
                )}
              </div>

              {/* Password */}
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
                disabled={loading || usernameCheck.available === false}
                className="w-full flex items-center justify-center gap-2.5 rounded-2xl py-3.5 font-semibold text-white bg-gradient-to-r from-primary to-indigo-600 hover:from-primary/95 hover:to-indigo-600/95 transition-all shadow-md hover:shadow-lg disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {loading ? <Loader2 size={18} className="animate-spin" /> : <Sparkles size={18} />}
                <span>{loading ? 'Creating Account...' : 'Create Account'}</span>
              </button>
            </form>
          )}
        </section>
      </div>

      {/* Social Login Modal */}
      {socialModal.open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-in fade-in duration-200">
          <div className="relative w-full max-w-sm rounded-3xl border border-gray-700 bg-gray-900 p-6 shadow-2xl">
            <button
              type="button"
              onClick={() => setSocialModal((prev) => ({ ...prev, open: false }))}
              className="absolute top-4 right-4 text-gray-400 hover:text-white"
            >
              <X size={18} />
            </button>

            <div className="flex items-center gap-3 mb-4">
              <div className="p-2.5 rounded-2xl bg-black border border-gray-700">
                {socialModal.provider === 'google' ? <GoogleIcon /> : <MicrosoftIcon />}
              </div>
              <div>
                <h3 className="text-sm font-bold text-white capitalize">
                  Sign in with {socialModal.provider}
                </h3>
                <p className="text-[11px] text-gray-400">
                  Quick security authentication & account provision
                </p>
              </div>
            </div>

            <form onSubmit={handleSocialAuthSubmit} className="space-y-3.5">
              <FloatingField icon={<Mail size={16} />} label="Account Email" value={socialModal.email}>
                <input
                  type="email"
                  value={socialModal.email}
                  onChange={(e) => setSocialModal({ ...socialModal, email: e.target.value })}
                  className="auth-input text-white text-xs"
                  placeholder="name@provider.com"
                  required
                />
              </FloatingField>

              <FloatingField icon={<UserRound size={16} />} label="Full Name / Display Name" value={socialModal.name}>
                <input
                  type="text"
                  value={socialModal.name}
                  onChange={(e) => setSocialModal({ ...socialModal, name: e.target.value })}
                  className="auth-input text-white text-xs"
                  placeholder="Your Name"
                />
              </FloatingField>

              <FloatingField icon={<Globe size={16} />} label="Country / Region" value={socialModal.country}>
                <select
                  value={socialModal.country}
                  onChange={(e) => setSocialModal({ ...socialModal, country: e.target.value })}
                  className="auth-input text-white bg-transparent outline-none cursor-pointer text-xs"
                >
                  {COUNTRIES.map((c) => (
                    <option key={c} value={c} className="bg-gray-900 text-white">
                      {c}
                    </option>
                  ))}
                </select>
              </FloatingField>

              {socialModal.error && (
                <div className="text-[11px] text-danger flex items-center gap-1.5 p-2 rounded-xl bg-danger/10 border border-danger/20">
                  <AlertCircle size={13} className="shrink-0" />
                  <span>{socialModal.error}</span>
                </div>
              )}

              <div className="flex items-center gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setSocialModal((prev) => ({ ...prev, open: false }))}
                  className="flex-1 py-2.5 rounded-xl border border-gray-700 bg-gray-800 text-xs font-semibold text-gray-300 hover:text-white transition-all"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={socialModal.loading}
                  className="flex-1 py-2.5 rounded-xl bg-gradient-to-r from-primary to-indigo-600 text-xs font-semibold text-white hover:opacity-95 transition-all shadow-md flex items-center justify-center gap-1.5 disabled:opacity-50"
                >
                  {socialModal.loading ? <Loader2 size={14} className="animate-spin" /> : <ShieldCheck size={14} />}
                  <span>Authorize & Sign In</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
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
