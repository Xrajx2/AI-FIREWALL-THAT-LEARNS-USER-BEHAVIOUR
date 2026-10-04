import React, { useEffect, useMemo, useState } from 'react';
import { ScanSearch, ShieldCheck, ShieldAlert, FolderSearch, RefreshCw, Radio } from 'lucide-react';
import { buildApiUrl, getAuthHeaders } from '../utils/auth';

const LIVE_EVENT_PREVIEW_COUNT = 2;
const SCAN_HISTORY_PREVIEW_COUNT = 2;
const FINDING_PREVIEW_COUNT = 4;

const formatLocalTimestamp = (value) => {
  if (!value) {
    return '-';
  }
  const hasTimezone = typeof value === 'string' && (value.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(value));
  const normalized = typeof value === 'string' && !hasTimezone ? `${value}Z` : value;
  const parsed = new Date(normalized);
  return Number.isNaN(parsed.getTime()) ? '-' : parsed.toLocaleString();
};

const isFreshHeartbeat = (value) => {
  if (!value) {
    return false;
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return false;
  }
  return Date.now() - parsed.getTime() <= 15000;
};

const getVerdictTone = (verdict) => {
  const normalized = String(verdict || '').toLowerCase();
  if (normalized === 'unsafe') return 'border-danger/20 bg-danger/10 text-danger';
  if (normalized === 'review') return 'border-warning/20 bg-warning/10 text-warning';
  if (normalized === 'safe') return 'border-success/20 bg-success/10 text-success';
  return 'border-primary/20 bg-primary/10 text-primary';
};

const formatEventActionLabel = (event) => {
  const action = String(event?.action || '').toLowerCase();
  const entityType = String(event?.entity_type || '').toLowerCase();
  if (action === 'manual_scan_complete') return 'Scan Complete';
  if (action === 'watch_started') return 'Live Watch Started';
  if (action === 'watch_stopped') return 'Live Watch Paused';
  if (action === 'deleted') return entityType === 'directory' ? 'Folder Removed' : 'File Removed';
  if (action === 'modified') return 'File Updated';
  if (action === 'created') return entityType === 'directory' ? 'New Folder' : 'New File';
  return action ? action.replaceAll('_', ' ') : 'Activity';
};

const buildCollapsedLivePreview = (events) => {
  const buckets = [
    events.filter((event) => event?.entity_type === 'file' && ['safe', 'review', 'unsafe'].includes(String(event?.verdict || '').toLowerCase())),
    events.filter((event) => event?.entity_type === 'file'),
    events.filter((event) => event?.entity_type === 'directory'),
    events.filter((event) => event?.entity_type === 'scan'),
    events.filter((event) => event?.entity_type === 'service'),
  ];

  const merged = [];
  const seenIds = new Set();
  buckets.forEach((bucket) => {
    bucket.forEach((event) => {
      if (!seenIds.has(event.id)) {
        seenIds.add(event.id);
        merged.push(event);
      }
    });
  });
  return merged;
};

const buildCollapsedFindingPreview = (findings) => {
  const dangerousFindings = findings.filter((finding) => String(finding?.severity || '').toLowerCase() === 'malicious');
  const suspiciousFindings = findings.filter((finding) => String(finding?.severity || '').toLowerCase() === 'suspicious');
  const preview = [...dangerousFindings];

  for (const finding of suspiciousFindings) {
    if (preview.length >= FINDING_PREVIEW_COUNT) {
      break;
    }
    preview.push(finding);
  }

  return preview.length ? preview : findings.slice(0, FINDING_PREVIEW_COUNT);
};

export default function DeviceSafetyPanel() {
  const [status, setStatus] = useState(null);
  const [pageError, setPageError] = useState('');
  const [actionBusy, setActionBusy] = useState('');
  const [showScanHistory, setShowScanHistory] = useState(false);
  const [showLiveHistory, setShowLiveHistory] = useState(false);
  const [expandedFindings, setExpandedFindings] = useState({});

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const response = await fetch(buildApiUrl('/api/device-safety/status'), { headers: getAuthHeaders() });
        if (!response.ok) {
          throw new Error('Failed to load device safety status.');
        }
        const payload = await response.json();
        setStatus(payload);
        setPageError('');
      } catch (error) {
        console.error('Failed to fetch device safety status', error);
        setPageError(error.message || 'Device safety status is unavailable right now.');
      }
    };

    fetchStatus();
    const interval = setInterval(fetchStatus, 3000);
    return () => clearInterval(interval);
  }, []);

  const queueAction = async (path, body, busyKey) => {
    setActionBusy(busyKey);
    try {
      const response = await fetch(buildApiUrl(path), {
        method: 'POST',
        headers: {
          ...getAuthHeaders(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.detail || payload.message || 'Action failed.');
      }
      const refreshed = await fetch(buildApiUrl('/api/device-safety/status'), { headers: getAuthHeaders() });
      if (refreshed.ok) {
        setStatus(await refreshed.json());
      }
      setPageError('');
    } catch (error) {
      setPageError(error.message || 'Action failed.');
    } finally {
      setActionBusy('');
    }
  };

  const scannerState = status?.scanner?.state || 'idle';
  const liveWatchEnabled = !!status?.scanner?.live_watch_enabled;
  const agentOnline = status?.agent?.online !== undefined ? status.agent.online : isFreshHeartbeat(status?.agent?.last_heartbeat_at);
  const scanHistory = status?.scan_history || [];
  const liveEvents = status?.recent_live_events || [];
  const collapsedLivePreview = useMemo(() => buildCollapsedLivePreview(liveEvents), [liveEvents]);
  const visibleScanHistory = showScanHistory ? scanHistory : scanHistory.slice(0, SCAN_HISTORY_PREVIEW_COUNT);
  const visibleLiveEvents = showLiveHistory ? liveEvents : collapsedLivePreview.slice(0, LIVE_EVENT_PREVIEW_COUNT);
  const hiddenScanCount = Math.max(0, scanHistory.length - visibleScanHistory.length);
  const hiddenLiveCount = Math.max(0, liveEvents.length - visibleLiveEvents.length);
  const targets = useMemo(() => status?.targets || [], [status]);

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <header className="mb-8">
        <h2 className="text-3xl font-bold text-white mb-2">Device Safety</h2>
        <p className="text-gray-400">
          Manual scan controls for your PC folders and removable drives. Heavy scans only start when you press scan, while live watch can be turned on separately for newly added or downloaded files.
        </p>
      </header>

      {pageError && (
        <div className="rounded-2xl border border-warning/20 bg-warning/10 p-4 text-sm text-warning">
          {pageError}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-4 gap-4">
        <StatusCard
          title="Safety Agent"
          value={agentOnline ? 'Online' : 'Offline'}
          detail={agentOnline ? `Heartbeat ${formatLocalTimestamp(status?.agent?.last_heartbeat_at)}` : 'The Windows safety agent is not responding right now.'}
          tone={agentOnline ? 'success' : 'danger'}
        />
        <StatusCard
          title="Live Watch"
          value={liveWatchEnabled ? 'Active' : 'Paused'}
          detail={liveWatchEnabled ? 'New and changed files are being checked automatically.' : 'Nothing heavy runs until you enable watch or start a scan.'}
          tone={liveWatchEnabled ? 'primary' : 'warning'}
        />
        <StatusCard
          title="Current Job"
          value={scannerState === 'scanning' ? 'Scanning' : scannerState === 'watching' ? 'Watching' : 'Idle'}
          detail={status?.scanner?.current_job?.label || 'No manual scan running right now.'}
          tone={scannerState === 'scanning' ? 'primary' : 'neutral'}
        />
        <StatusCard
          title="Last Scan Verdict"
          value={status?.last_scan?.verdict ? String(status.last_scan.verdict).toUpperCase() : 'NONE'}
          detail={status?.last_scan?.completed_at ? formatLocalTimestamp(status.last_scan.completed_at) : 'Run a manual scan to generate the first result.'}
          tone={status?.last_scan?.verdict === 'unsafe' ? 'danger' : status?.last_scan?.verdict === 'review' ? 'warning' : 'success'}
        />
      </div>

      <section className="glass-panel p-5 shadow-sm">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="text-lg font-semibold text-white">Scan Controls</div>
            <div className="mt-1 text-sm text-gray-400">
              Start a fast scan only when you want it. Live watch is optional and can stay paused until demo time.
            </div>
          </div>
          <div className="flex flex-wrap gap-3">
            <button
              type="button"
              onClick={() => queueAction('/api/device-safety/scan', { target_id: 'quick_all' }, 'quick-scan')}
              disabled={actionBusy === 'quick-scan' || scannerState === 'scanning'}
              className="inline-flex items-center gap-2 rounded-xl border border-primary/20 bg-primary/10 px-4 py-3 text-sm font-semibold text-primary transition hover:bg-primary/20 disabled:opacity-60"
            >
              {actionBusy === 'quick-scan' ? <RefreshCw size={16} className="animate-spin" /> : <ScanSearch size={16} />}
              Fast Safety Scan
            </button>
            <button
              type="button"
              onClick={() => queueAction('/api/device-safety/live-watch', { enabled: !liveWatchEnabled }, 'toggle-watch')}
              disabled={actionBusy === 'toggle-watch'}
              className="inline-flex items-center gap-2 rounded-xl border border-gray-700/10 bg-gray-900/10 px-4 py-3 text-sm font-semibold text-white transition hover:border-primary/30 disabled:opacity-60"
            >
              <Radio size={16} />
              {liveWatchEnabled ? 'Stop Live Watch' : 'Start Live Watch'}
            </button>
          </div>
        </div>
      </section>

      <section className="glass-panel p-5 shadow-sm">
        <div className="flex items-center justify-between gap-4 mb-4">
          <div>
            <div className="text-lg font-semibold text-white">Targets</div>
            <div className="text-sm text-gray-400">Choose what to scan. Removable drives appear here automatically when connected.</div>
          </div>
          <div className="text-xs uppercase tracking-[0.18em] text-gray-500">{targets.length} visible</div>
        </div>
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          {targets.length === 0 ? (
            <div className="rounded-xl border border-gray-700/10 bg-gray-900/10 p-4 text-sm text-gray-500">
              No scan targets are visible yet.
            </div>
          ) : (
            targets.map((target) => (
              <div key={target.id} className="rounded-xl border border-gray-700/10 bg-gray-900/10 p-4 flex items-center justify-between gap-4">
                <div>
                  <div className="font-semibold text-white">{target.label}</div>
                  <div className="mt-1 text-xs text-gray-500">{target.kind.replaceAll('_', ' ')} | {target.path}</div>
                </div>
                <button
                  type="button"
                  onClick={() => queueAction('/api/device-safety/scan', { target_id: target.id }, `scan-${target.id}`)}
                  disabled={actionBusy === `scan-${target.id}` || scannerState === 'scanning'}
                  className="rounded-lg border border-gray-700/10 bg-gray-900/20 px-3 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-gray-200 transition hover:border-primary/30 hover:text-white disabled:opacity-60"
                >
                  {actionBusy === `scan-${target.id}` ? 'Queueing' : 'Scan'}
                </button>
              </div>
            ))
          )}
        </div>
      </section>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <section className="glass-panel p-5 shadow-sm">
          <div className="flex items-center justify-between gap-4 mb-4">
            <div>
              <div className="text-lg font-semibold text-white">New File Safety Feed</div>
              <div className="text-sm text-gray-400">Shows new, changed, downloaded, or removed items once live watch is active.</div>
            </div>
            <div className="flex items-center gap-3">
              {liveEvents.length > LIVE_EVENT_PREVIEW_COUNT && (
                <button
                  type="button"
                  onClick={() => setShowLiveHistory((current) => !current)}
                  className="rounded-full border border-gray-700/10 bg-gray-900/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-gray-300 transition hover:border-primary/30 hover:text-white"
                >
                  {showLiveHistory ? 'Show Less' : `Show More +${hiddenLiveCount}`}
                </button>
              )}
              <span className="text-xs text-gray-500">
                Showing {visibleLiveEvents.length} of {liveEvents.length} {liveWatchEnabled ? '| Live mode ready' : '| Watch paused'}
              </span>
            </div>
          </div>

          <div className="space-y-3">
            {!visibleLiveEvents.length ? (
              <div className="rounded-xl border border-gray-700/10 bg-gray-900/10 p-4 text-sm text-gray-500">
                No live file safety events yet. Turn on Live Watch, then download or add a file to see an instant verdict.
              </div>
            ) : (
              visibleLiveEvents.map((event) => (
                <div key={event.id} className="rounded-xl border border-gray-700/10 bg-gray-900/10 p-4">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <div className="font-semibold text-white">{event.name || event.target_label}</div>
                      <div className="mt-2 flex flex-wrap gap-2">
                        <div className="inline-flex rounded-full border border-gray-700/10 bg-gray-900/20 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-gray-200">
                          {formatEventActionLabel(event)}
                        </div>
                        <div className={`inline-flex rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] ${getVerdictTone(event.verdict)}`}>
                          {String(event.verdict || 'info').toUpperCase()}
                        </div>
                      </div>
                    </div>
                    <div className="text-xs text-gray-500">{formatLocalTimestamp(event.timestamp)}</div>
                  </div>
                  <div className="mt-2 text-sm text-gray-300">{event.summary}</div>
                  {event.path && <div className="mt-2 break-all text-xs text-gray-500">{event.path}</div>}
                  {!!event.reasons?.length && (
                    <div className="mt-3 flex flex-wrap gap-2">
                      {event.reasons.slice(0, 4).map((reason, index) => (
                        <span key={`${event.id}-reason-${index}`} className="rounded-full border border-gray-700/10 bg-gray-900/20 px-2.5 py-1 text-xs text-gray-300">
                          {reason}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))
            )}
            {hiddenLiveCount > 0 && !showLiveHistory && (
              <div className="rounded-xl border border-dashed border-gray-700/10 bg-gray-900/10 px-4 py-3 text-sm text-gray-400">
                {hiddenLiveCount} older live event{hiddenLiveCount === 1 ? '' : 's'} hidden.
              </div>
            )}
          </div>
        </section>

        <section className="glass-panel p-5 shadow-sm">
          <div className="flex items-center justify-between gap-4 mb-4">
            <div>
              <div className="text-lg font-semibold text-white">Scan History</div>
              <div className="text-sm text-gray-400">Manual scan results stay compact by default. Expand only when you need older runs.</div>
            </div>
            <div className="flex items-center gap-3">
              {scanHistory.length > SCAN_HISTORY_PREVIEW_COUNT && (
                <button
                  type="button"
                  onClick={() => setShowScanHistory((current) => !current)}
                  className="rounded-full border border-gray-700/10 bg-gray-900/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-gray-300 transition hover:border-primary/30 hover:text-white"
                >
                  {showScanHistory ? 'Show Less' : `Show More +${hiddenScanCount}`}
                </button>
              )}
              <span className="text-xs text-gray-500">Showing {visibleScanHistory.length} of {scanHistory.length}</span>
            </div>
          </div>

          <div className="space-y-3">
            {!visibleScanHistory.length ? (
              <div className="rounded-xl border border-gray-700/10 bg-gray-900/10 p-4 text-sm text-gray-500">
                No manual scan history yet. Press Fast Safety Scan when you want the first result.
              </div>
            ) : (
              visibleScanHistory.map((scan) => (
                <div key={scan.id} className="rounded-xl border border-gray-700/10 bg-gray-900/10 p-4">
                  {(() => {
                    const scanFindings = Array.isArray(scan.findings) ? scan.findings : [];
                    const findingsExpanded = !!expandedFindings[scan.id];
                    const visibleFindings = findingsExpanded ? scanFindings : buildCollapsedFindingPreview(scanFindings);
                    const hiddenFindingsCount = Math.max(0, scanFindings.length - visibleFindings.length);
                    return (
                      <>
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <div className="font-semibold text-white">{scan.label}</div>
                      <div className={`mt-2 inline-flex rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] ${getVerdictTone(scan.verdict)}`}>
                        {String(scan.verdict || 'safe').toUpperCase()}
                      </div>
                    </div>
                    <div className="text-xs text-gray-500">{formatLocalTimestamp(scan.completed_at)}</div>
                  </div>

                  <div className="mt-3 text-sm text-gray-300">{scan.summary}</div>

                  <div className="mt-3 flex flex-wrap gap-2">
                    <span className="rounded-full border border-success/20 bg-success/10 px-3 py-1 text-xs text-success">{scan.clean_count} safe</span>
                    <span className="rounded-full border border-warning/20 bg-warning/10 px-3 py-1 text-xs text-warning">{scan.suspicious_count} suspicious</span>
                    <span className="rounded-full border border-danger/20 bg-danger/10 px-3 py-1 text-xs text-danger">{scan.malicious_count} dangerous</span>
                    <span className="rounded-full border border-gray-700/10 bg-gray-900/20 px-3 py-1 text-xs text-gray-300">{scan.files_scanned} files checked</span>
                    {scan.truncated && (
                      <span className="rounded-full border border-primary/20 bg-primary/10 px-3 py-1 text-xs text-primary">fast scan limit reached</span>
                    )}
                  </div>

                  {!!scanFindings.length && (
                    <div className="mt-3">
                      <div className="mb-3 flex items-center justify-between gap-3">
                        <div className="text-xs uppercase tracking-[0.18em] text-gray-500">
                          {scan.malicious_count > 0 ? 'Dangerous files are shown first' : 'Top flagged files'}
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="text-xs text-gray-500">Showing {visibleFindings.length} of {scanFindings.length}</span>
                          {hiddenFindingsCount > 0 && (
                            <button
                              type="button"
                              onClick={() => setExpandedFindings((current) => ({ ...current, [scan.id]: !current[scan.id] }))}
                              className="rounded-full border border-gray-700/10 bg-gray-900/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-gray-300 transition hover:border-primary/30 hover:text-white"
                            >
                              {findingsExpanded ? 'Show Less' : `Show More Findings +${hiddenFindingsCount}`}
                            </button>
                          )}
                        </div>
                      </div>
                      <div className="space-y-2">
                      {visibleFindings.map((finding, index) => (
                        <div key={`${scan.id}-finding-${index}`} className="rounded-lg border border-gray-700/10 bg-gray-900/20 px-3 py-2">
                          <div className="flex items-center justify-between gap-3">
                            <span className="font-semibold text-white text-sm">{finding.name || finding.path}</span>
                            <span className={`rounded-full border px-2 py-1 text-[11px] font-semibold uppercase ${getVerdictTone(finding.severity === 'malicious' ? 'unsafe' : 'review')}`}>
                              {finding.severity}
                            </span>
                          </div>
                          {finding.path && <div className="mt-1 break-all text-xs text-gray-500">{finding.path}</div>}
                          {!!finding.signature_name && (
                            <div className="mt-2 text-xs text-danger">
                              Signature: {finding.signature_name}
                            </div>
                          )}
                          {!!finding.signature_description && (
                            <div className="mt-1 text-xs text-gray-400">{finding.signature_description}</div>
                          )}
                          {!!finding.reasons?.length && (
                            <div className="mt-2 flex flex-wrap gap-2">
                              {finding.reasons.slice(0, 5).map((reason, reasonIndex) => (
                                <span
                                  key={`${scan.id}-finding-${index}-reason-${reasonIndex}`}
                                  className="rounded-full border border-gray-700/10 bg-gray-900/20 px-2 py-1 text-[11px] text-gray-300"
                                >
                                  {reason}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                      </div>
                      {scan.hidden_finding_count > 0 && (
                        <div className="mt-3 text-xs text-gray-500">
                          {scan.hidden_finding_count} more flagged file{scan.hidden_finding_count === 1 ? '' : 's'} were kept out of memory to keep the app fast.
                        </div>
                      )}
                    </div>
                  )}
                      </>
                    );
                  })()}
                </div>
              ))
            )}
            {hiddenScanCount > 0 && !showScanHistory && (
              <div className="rounded-xl border border-dashed border-gray-700/10 bg-gray-900/10 px-4 py-3 text-sm text-gray-400">
                {hiddenScanCount} older scan result{hiddenScanCount === 1 ? '' : 's'} hidden.
              </div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}

function StatusCard({ title, value, detail, tone = 'neutral' }) {
  const toneClasses = {
    neutral: 'border-gray-700/10 bg-gray-900/10 text-white',
    success: 'border-success/20 bg-success/10 text-success',
    danger: 'border-danger/20 bg-danger/10 text-danger',
    warning: 'border-warning/20 bg-warning/10 text-warning',
    primary: 'border-primary/20 bg-primary/10 text-primary',
  };
  const icon = tone === 'danger'
    ? <ShieldAlert size={22} />
    : tone === 'success'
      ? <ShieldCheck size={22} />
      : tone === 'primary'
        ? <ScanSearch size={22} />
        : <FolderSearch size={22} />;

  return (
    <div className="rounded-2xl border border-gray-700/10 bg-gray-900/10 p-5">
      <div className="flex items-center justify-between gap-3">
        <div className="text-xs uppercase tracking-wide text-gray-500">{title}</div>
        <div className={`flex h-10 w-10 items-center justify-center rounded-xl border ${toneClasses[tone] || toneClasses.neutral}`}>
          {icon}
        </div>
      </div>
      <div className="mt-3 text-3xl font-bold text-white">{value}</div>
      <div className="mt-2 text-sm text-gray-400">{detail}</div>
    </div>
  );
}
