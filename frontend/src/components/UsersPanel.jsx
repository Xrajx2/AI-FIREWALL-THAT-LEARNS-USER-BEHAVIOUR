import React, { useState, useEffect } from 'react';
import { Bot, User, ShieldAlert, ShieldCheck, Lock, Unlock } from 'lucide-react';
import { getRiskTone, normalizeRiskLevel, scoreToRiskLevel } from '../utils/risk';
import { buildApiUrl, getAuthHeaders } from '../utils/auth';

const isSystemAccount = (user, insight) => {
  if (insight?.account_type) {
    return insight.account_type === 'system_agent';
  }
  const username = String(user?.username || '').toLowerCase();
  return username.endsWith('-agent') || username.startsWith('system-') || username === 'usb-security-agent';
};

export default function UsersPanel() {
  const [users, setUsers] = useState([]);
  const [threats, setThreats] = useState([]);
  const [behaviorProfiles, setBehaviorProfiles] = useState([]);
  const [aiInsights, setAiInsights] = useState([]);
  const [loading, setLoading] = useState(true);
  const [profileWarning, setProfileWarning] = useState('');
  const [pageError, setPageError] = useState('');

  useEffect(() => {
    const fetchData = async () => {
      try {
        const headers = getAuthHeaders();

        const [usersRes, threatsRes, profilesRes, insightsRes] = await Promise.all([
          fetch(buildApiUrl('/api/users'), { headers }),
          fetch(buildApiUrl('/api/threats'), { headers }),
          fetch(buildApiUrl('/api/behavior-profiles'), { headers }),
          fetch(buildApiUrl('/api/ai-insights'), { headers })
        ]);

        if (!usersRes.ok) {
          throw new Error('Unable to load users right now.');
        }

        setPageError('');
        setProfileWarning('');

        const usersData = await usersRes.json();
        setUsers(usersData);

        if (threatsRes.ok) {
          const threatsData = await threatsRes.json();
          setThreats(threatsData);
        } else {
          setThreats([]);
        }

        if (profilesRes.ok) {
          const profilesData = await profilesRes.json();
          setBehaviorProfiles(profilesData);
        } else {
          setBehaviorProfiles([]);
          if (profilesRes.status === 401) {
            setProfileWarning('Behavior profiles are protected data. Your saved session looks expired, so login patterns, app usage, and file habits are temporarily hidden. Log out and sign in again to reload them.');
          } else {
            setProfileWarning('Behavior profiles are temporarily unavailable. Core user records are still loading normally.');
          }
        }

        if (insightsRes.ok) {
          const insightsData = await insightsRes.json();
          setAiInsights(insightsData.users || []);
        } else {
          setAiInsights([]);
        }
      } catch (error) {
        console.error("Error fetching users data:", error);
        setPageError(error.message || 'Unable to load user data.');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  const getUserRisk = (userId) => {
    const insight = getAiInsight(userId);
    if (insight?.overall_risk_score !== undefined) {
      return {
        score: Number(insight.overall_risk_score || 0).toFixed(1),
        level: normalizeRiskLevel(insight.overall_risk_level, insight.overall_risk_score),
      };
    }

    const userThreats = threats.filter(t => t.user_id === userId);
    if (userThreats.length === 0) return { score: '0.0', level: 'Normal' };
    
    const avgScore = userThreats.reduce((acc, curr) => acc + curr.anomaly_score, 0) / userThreats.length;
    return { score: avgScore.toFixed(1), level: scoreToRiskLevel(avgScore) };
  };

  const toggleUserLock = (userId) => {
    // In a production app, this would hit an API endpoint to lock the account.
    // For now, we simulate the UI change.
    setUsers(users.map(u => {
      if (u.id === userId) {
        return { ...u, is_locked: !u.is_locked };
      }
      return u;
    }));
  };

  const getBehaviorProfile = (userId) => (
    behaviorProfiles.find((profile) => profile.user_id === userId) || null
  );

  const getAiInsight = (userId) => (
    aiInsights.find((item) => item.user_id === userId) || null
  );

  const formatHour = (hour) => {
    if (hour === null || hour === undefined) {
      return '-';
    }
    return `${String(hour).padStart(2, '0')}:00`;
  };

  const humanUsers = users.filter((user) => !isSystemAccount(user, getAiInsight(user.id)));
  const systemAccounts = users.filter((user) => isSystemAccount(user, getAiInsight(user.id)));

  if (loading) {
    return <div className="flex justify-center p-8 text-gray-400">Loading user data...</div>;
  }

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <header className="mb-8">
        <h2 className="text-3xl font-bold text-white mb-2">Network Users</h2>
        <p className="text-gray-400">Human users and internal system agents are shown separately so monitoring accounts do not look like extra devices.</p>
      </header>

      {pageError && (
        <div className="rounded-2xl border border-danger/20 bg-danger/10 p-4 text-sm text-danger">
          {pageError}
        </div>
      )}

      {profileWarning && (
        <div className="rounded-2xl border border-warning/20 bg-warning/10 p-4 text-sm text-warning">
          {profileWarning}
        </div>
      )}

      <div className="rounded-2xl border border-primary/20 bg-primary/10 p-4 text-sm text-gray-300">
        <span className="text-white font-semibold">Why you saw four entries:</span> this list contains backend accounts, not physical devices.
        <span className="block mt-1">`testuser` is your human account. `system-monitor` and `system-monitor-agent` are active host telemetry accounts, and `usb-security-agent` may remain as a legacy account from the older USB module.</span>
      </div>

      <div className="glass-panel overflow-hidden rounded-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-gray-800">
                <th className="p-4 text-gray-400 font-medium text-sm">Human User</th>
                <th className="p-4 text-gray-400 font-medium text-sm">Role</th>
                <th className="p-4 text-gray-400 font-medium text-sm">Overall User Risk</th>
                <th className="p-4 text-gray-400 font-medium text-sm">Status</th>
                <th className="p-4 text-gray-400 font-medium text-sm text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/50">
              {humanUsers.map((user) => {
                const risk = getUserRisk(user.id);
                const riskTone = getRiskTone(risk.level, risk.score);
                
                return (
                  <tr key={user.id} className="hover:bg-white/[0.02] transition-colors">
                    <td className="p-4">
                      <div className="flex items-center space-x-3">
                        <div className="w-10 h-10 rounded-full bg-primary/20 flex items-center justify-center text-primary">
                          <User size={20} />
                        </div>
                        <div>
                          <div className="font-medium text-gray-200">{user.username}</div>
                          <div className="text-xs text-gray-500">ID: {user.id}</div>
                        </div>
                      </div>
                    </td>
                    <td className="p-4 text-gray-400 capitalize">{user.role || 'user'}</td>
                    <td className="p-4">
                      <div className="flex items-center gap-3">
                        <span className={`font-mono ${riskTone.text}`}>
                          {risk.score}
                        </span>
                        <span className={`px-2.5 py-1 rounded-full border text-xs font-medium ${riskTone.badge}`}>
                          {risk.level}
                        </span>
                        {risk.level === 'Dangerous' && <ShieldAlert size={14} className="text-danger" />}
                        {risk.level === 'Normal' && <ShieldCheck size={14} className="text-success" />}
                      </div>
                    </td>
                    <td className="p-4">
                      <span className={`px-2.5 py-1 rounded-full text-xs font-medium border ${
                        user.is_locked 
                          ? 'bg-danger/10 text-danger border-danger/20' 
                          : 'bg-success/10 text-success border-success/20'
                      }`}>
                        {user.is_locked ? 'Locked' : 'Active'}
                      </span>
                    </td>
                    <td className="p-4 text-right">
                      <button 
                        onClick={() => toggleUserLock(user.id)}
                        className={`p-2 rounded-lg border transition-all ${
                          user.is_locked 
                            ? 'bg-success/10 text-success border-success/20 hover:bg-success/20' 
                            : 'bg-danger/10 text-danger border-danger/20 hover:bg-danger/20'
                        }`}
                        title={user.is_locked ? "Unlock User" : "Lock User"}
                      >
                        {user.is_locked ? <Unlock size={16} /> : <Lock size={16} />}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          
          {humanUsers.length === 0 && (
            <div className="p-8 text-center text-gray-500">
              No human user accounts found.
            </div>
          )}
        </div>
      </div>

      <section className="space-y-4">
        <div>
          <h3 className="text-xl font-semibold text-white mb-1">Internal Monitoring Accounts</h3>
          <p className="text-gray-400 text-sm">These are service accounts used by Windows host telemetry and any legacy monitoring integrations.</p>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          {systemAccounts.map((user) => {
            const insight = getAiInsight(user.id);
            const riskTone = getRiskTone(insight?.overall_risk_level, insight?.overall_risk_score);
            return (
              <div key={`system-${user.id}`} className="glass-panel p-5 rounded-2xl border border-white/10 space-y-3">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-full bg-white/5 flex items-center justify-center text-primary">
                    <Bot size={18} />
                  </div>
                  <div>
                    <div className="font-medium text-white">{user.username}</div>
                    <div className="text-xs text-gray-500">{insight?.ai_status || 'System account'}</div>
                  </div>
                </div>
                <div className="text-sm text-gray-400">Activity samples: {insight?.activity_count ?? 0}</div>
                <div className="flex items-center gap-2 text-sm">
                  <span className="text-gray-400">Overall risk:</span>
                  <span className={`px-2 py-1 rounded-full border text-xs font-medium ${riskTone.badge}`}>
                    {normalizeRiskLevel(insight?.overall_risk_level, insight?.overall_risk_score)}
                  </span>
                  <span className={`font-mono ${riskTone.text}`}>{Number(insight?.overall_risk_score ?? 0).toFixed(1)}</span>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      <section className="space-y-4">
        <div>
          <h3 className="text-xl font-semibold text-white mb-1">Behavior Profiles</h3>
          <p className="text-gray-400 text-sm">Tracked login windows, frequently used applications, and file access habits per user.</p>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          {humanUsers.map((user) => {
            const profile = getBehaviorProfile(user.id);
            const insight = getAiInsight(user.id);
            const riskTone = getRiskTone(insight?.overall_risk_level, insight?.overall_risk_score);
            const topApps = profile?.frequent_applications?.slice(0, 3) || [];
            const topDirs = profile?.file_access_habits?.directories?.slice(0, 3) || [];
            const topTypes = profile?.file_access_habits?.file_types?.slice(0, 3) || [];
            const loginPattern = profile?.login_pattern;

            return (
              <div key={`behavior-${user.id}`} className="glass-panel p-6 rounded-2xl border border-white/10 space-y-5">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <div className="text-lg font-semibold text-white">{user.username}</div>
                    <div className="text-xs text-gray-500">Profile updated: {profile?.last_updated ? new Date(profile.last_updated + (profile.last_updated.includes('Z') ? '' : 'Z')).toLocaleString() : 'No tracked behavior yet'}</div>
                  </div>
                  <span className="px-2.5 py-1 rounded-full text-xs font-medium border bg-primary/10 text-primary border-primary/20">
                    {user.role || 'user'}
                  </span>
                </div>

                <div className="rounded-xl border border-primary/10 bg-primary/5 p-4">
                  <div className="text-xs uppercase tracking-wide text-gray-500 mb-2">AI Learning Status</div>
                  <div className="text-sm text-white">{insight?.ai_status || 'Learning baseline'}</div>
                  <div className="flex items-center gap-2 mt-2">
                    <span className={`px-2 py-1 rounded-full border text-xs font-medium ${riskTone.badge}`}>
                      Overall Risk: {normalizeRiskLevel(insight?.overall_risk_level, insight?.overall_risk_score)}
                    </span>
                    <span className={`text-xs font-mono ${riskTone.text}`}>
                      {Number(insight?.overall_risk_score ?? 0).toFixed(1)}
                    </span>
                  </div>
                  <div className="text-xs text-gray-400 mt-2">
                    Activity samples: {insight?.activity_count ?? 0} | Isolation Forest: {insight?.isolation_forest_ready ? 'ready' : 'learning'} | Clustering: {insight?.cluster_model_ready ? 'ready' : 'learning'}
                  </div>
                  {insight?.latest_summary && (
                    <div className="text-xs text-gray-400 mt-2">{insight.latest_summary}</div>
                  )}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="rounded-xl border border-white/5 bg-white/[0.03] p-4">
                    <div className="text-xs uppercase tracking-wide text-gray-500 mb-2">Login Pattern</div>
                    <div className="text-sm text-white">
                      {loginPattern?.login_count > 0
                        ? `${formatHour(loginPattern.window_start)} - ${formatHour(loginPattern.window_end)}`
                        : 'No login baseline yet'}
                    </div>
                    <div className="text-xs text-gray-500 mt-2">
                      Peak hours: {loginPattern?.peak_hours?.length ? loginPattern.peak_hours.map(formatHour).join(', ') : '-'}
                    </div>
                  </div>

                  <div className="rounded-xl border border-white/5 bg-white/[0.03] p-4">
                    <div className="text-xs uppercase tracking-wide text-gray-500 mb-2">Frequent Apps</div>
                    <div className="space-y-2">
                      {topApps.length ? topApps.map((app) => (
                        <div key={`${user.id}-${app.name}`} className="text-sm text-gray-300">
                          <span className="text-white font-medium">{app.name}</span> x{app.count}
                        </div>
                      )) : (
                        <div className="text-sm text-gray-500">No application habits tracked yet.</div>
                      )}
                    </div>
                  </div>

                  <div className="rounded-xl border border-white/5 bg-white/[0.03] p-4">
                    <div className="text-xs uppercase tracking-wide text-gray-500 mb-2">File Habits</div>
                    <div className="space-y-2">
                      {topDirs.length ? topDirs.map((dir) => (
                        <div key={`${user.id}-${dir.path}`} className="text-sm text-gray-300 break-all">
                          <span className="text-white font-medium">{dir.path}</span> x{dir.count}
                        </div>
                      )) : (
                        <div className="text-sm text-gray-500">No file access habits tracked yet.</div>
                      )}
                    </div>
                  </div>
                </div>

                <div className="rounded-xl border border-white/5 bg-white/[0.03] p-4">
                  <div className="text-xs uppercase tracking-wide text-gray-500 mb-3">Common File Types</div>
                  <div className="flex flex-wrap gap-2">
                    {topTypes.length ? topTypes.map((item) => (
                      <span key={`${user.id}-${item.extension}`} className="px-3 py-1 rounded-full bg-white/5 border border-white/10 text-sm text-gray-300">
                        {item.extension} x{item.count}
                      </span>
                    )) : (
                      <span className="text-sm text-gray-500">No file type baseline yet.</span>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}
