import React from 'react';
import { Clock3, ShieldCheck, ShieldAlert, UserRound, Waypoints } from 'lucide-react';

const formatDateTime = (value) => {
  if (!value) return 'No previous login recorded yet';
  return new Date(String(value).includes('Z') ? value : `${value}Z`).toLocaleString();
};

export default function AccountSecurityPanel({ summary }) {
  if (!summary) {
    return (
      <section className="glass-panel p-6 shadow-sm">
        <div className="text-sm text-gray-400">Loading authenticated session details...</div>
      </section>
    );
  }

  const isSuspicious = summary.security_status === 'Suspicious';
  const badgeClass = isSuspicious
    ? 'border-warning/30 bg-warning/10 text-warning'
    : 'border-success/30 bg-success/10 text-success';

  return (
    <section className="glass-panel relative overflow-hidden p-6 md:p-8 shadow-sm">
      <div className="relative flex flex-col gap-6 xl:flex-row xl:items-start xl:justify-between">
        <div className="max-w-2xl">
          <div className="flex flex-wrap items-center gap-3 mb-4">
            <span className="inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.25em] text-primary">
              <UserRound size={14} />
              Authenticated Session
            </span>
            <span className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-[0.2em] ${badgeClass}`}>
              {isSuspicious ? <ShieldAlert size={14} /> : <ShieldCheck size={14} />}
              Security Status: {summary.security_status}
            </span>
          </div>

          <h3 className="text-2xl md:text-3xl font-bold text-white tracking-tight">
            {summary.welcome_message}
          </h3>
          <p className="mt-3 text-gray-300 max-w-xl">
            Monitor authenticated access patterns, see whether the firewall considers the session safe, and review the most recent login history for this account.
          </p>

          {summary.suspicious_reasons?.length > 0 && (
            <div className="mt-4 rounded-2xl border border-warning/20 bg-warning/10 p-4 text-sm text-warning">
              {summary.suspicious_reasons.join(' | ')}
            </div>
          )}
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 xl:min-w-[420px]">
          <InfoCard
            icon={<Clock3 size={18} />}
            label="Last Successful Login"
            value={formatDateTime(summary.last_login_at)}
          />
          <InfoCard
            icon={<Waypoints size={18} />}
            label="Current Login Origin"
            value={`${summary.current_login_ip || 'Unknown IP'} | ${summary.current_login_device || 'Unknown device'}`}
          />
          <InfoCard
            icon={<ShieldCheck size={18} />}
            label="Current Session Started"
            value={formatDateTime(summary.current_login_at)}
          />
          <InfoCard
            icon={<UserRound size={18} />}
            label="Active Sessions"
            value={String(summary.active_sessions || 0)}
          />
        </div>
      </div>

      <div className="relative mt-6">
        <div className="text-sm font-semibold text-gray-200 mb-3">Recent Login Activity</div>
        <div className="overflow-hidden rounded-2xl border border-gray-700/10 bg-gray-900/10">
          <div className="grid grid-cols-[1.4fr,1fr,0.9fr,1.2fr] gap-3 border-b border-gray-700/10 px-4 py-3 text-xs font-semibold uppercase tracking-[0.2em] text-gray-500">
            <span>Time</span>
            <span>Device</span>
            <span>Status</span>
            <span>Notes</span>
          </div>

          {summary.recent_login_activity?.length ? (
            summary.recent_login_activity.map((item) => {
              const rowTone = item.suspicious ? 'text-warning' : item.success ? 'text-success' : 'text-danger';
              const notes = item.suspicious
                ? (item.suspicious_reasons || []).join(', ')
                : item.failure_reason || 'Trusted login pattern';

              return (
                <div
                  key={item.id}
                  className="grid grid-cols-[1.4fr,1fr,0.9fr,1.2fr] gap-3 border-b border-gray-700/10 px-4 py-3 text-sm text-gray-300 last:border-b-0"
                >
                  <div>{formatDateTime(item.created_at)}</div>
                  <div className="text-gray-400">{item.device_name || 'Unknown device'}</div>
                  <div className={rowTone}>
                    {item.success ? (item.suspicious ? 'Suspicious' : 'Safe') : 'Failed'}
                  </div>
                  <div className="text-gray-400">{notes}</div>
                </div>
              );
            })
          ) : (
            <div className="px-4 py-5 text-sm text-gray-500">No login history recorded yet.</div>
          )}
        </div>
      </div>
    </section>
  );
}

function InfoCard({ icon, label, value }) {
  return (
    <div className="rounded-2xl border border-gray-700/10 bg-gray-900/10 p-4">
      <div className="flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-gray-500">
        <span className="text-primary">{icon}</span>
        <span>{label}</span>
      </div>
      <div className="mt-3 text-sm font-medium text-gray-100 leading-6">{value}</div>
    </div>
  );
}
