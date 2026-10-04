import React, { useEffect, useState, useMemo } from 'react';
import { 
  ShieldAlert, 
  Search, 
  RefreshCw, 
  Globe, 
  ShieldCheck, 
  ShieldX, 
  ExternalLink,
  History,
  Lock,
  LockKeyhole,
  FileSearch,
  Sparkles,
  ClipboardCopy,
  Info
} from 'lucide-react';
import { buildApiUrl, getAuthHeaders } from '../utils/auth';

export default function SpamDetectionPanel() {
  const [urlInput, setUrlInput] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [logs, setLogs] = useState([]);
  const [loadingScan, setLoadingScan] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('ALL');

  const fetchLogs = async () => {
    try {
      const res = await fetch(buildApiUrl('/api/spam-detection/logs'), {
        headers: getAuthHeaders()
      });
      if (res.ok) {
        const data = await res.json();
        setLogs(data);
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  const handleScan = async (e) => {
    e.preventDefault();
    if (!urlInput.trim()) return;
    setLoadingScan(true);
    try {
      const res = await fetch(buildApiUrl('/api/spam-detection/scan'), {
        method: 'POST',
        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlInput.trim() })
      });
      if (res.ok) {
        const data = await res.json();
        setScanResult(data);
        setUrlInput('');
        fetchLogs();
      }
    } catch (err) {
      console.error("URL scan failed", err);
    } finally {
      setLoadingScan(false);
    }
  };

  // Block Domain Action
  const handleBlockDomain = async (domain) => {
    try {
      const res = await fetch(buildApiUrl('/api/spam-detection/block'), {
        method: 'POST',
        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });
      if (res.ok) {
        window.showToast?.(`Blocked domain ${domain} successfully.`, 'success');
        fetchLogs();
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Copy scan report details to clipboard
  const handleCopyReport = (reportText) => {
    navigator.clipboard.writeText(reportText);
    window.showToast?.("Scan report copied to clipboard.", 'success');
  };

  // Parse report JSON string safely
  const parseReport = (reportStr) => {
    if (!reportStr) return {};
    try {
      // Python dictionary representation conversion to JSON string
      const jsonFriendly = reportStr
        .replace(/'/g, '"')
        .replace(/True/g, 'true')
        .replace(/False/g, 'false')
        .replace(/None/g, 'null');
      return JSON.parse(jsonFriendly);
    } catch (e) {
      return { raw: reportStr };
    }
  };

  // Filter logs
  const filteredLogs = useMemo(() => {
    return logs.filter(log => {
      const matchesSearch = 
        log.url.toLowerCase().includes(searchQuery.toLowerCase()) ||
        log.domain.toLowerCase().includes(searchQuery.toLowerCase());
      
      const matchesCategory = categoryFilter === 'ALL' || log.threat_type === categoryFilter;
      return matchesSearch && matchesCategory;
    });
  }, [logs, searchQuery, categoryFilter]);

  // Compute counters
  const counters = useMemo(() => {
    const total = logs.length;
    const spam = logs.filter(l => l.risk_score > 30).length;
    const malware = logs.filter(l => l.risk_score > 75).length;
    const safe = logs.filter(l => l.risk_score <= 30).length;
    return { total, spam, malware, safe };
  }, [logs]);

  // Get risk theme color class helper
  const getRiskColor = (score) => {
    if (score > 75) return { border: 'border-rose-500/20 bg-rose-500/5', text: 'text-rose-500', bar: 'bg-rose-500' };
    if (score > 50) return { border: 'border-orange-500/20 bg-orange-500/5', text: 'text-orange-400', bar: 'bg-orange-500' };
    if (score > 30) return { border: 'border-amber-500/20 bg-amber-500/5', text: 'text-amber-500', bar: 'bg-amber-500' };
    if (score > 10) return { border: 'border-yellow-400/20 bg-yellow-400/5', text: 'text-yellow-400', bar: 'bg-yellow-400' };
    return { border: 'border-emerald-500/20 bg-emerald-500/5', text: 'text-emerald-500', bar: 'bg-emerald-500' };
  };

  return (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      
      {/* Header */}
      <header className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between border-b border-white/5 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <h2 className="text-3xl font-extrabold text-white tracking-tight">AI Spam & URL Reputation</h2>
            <span className="px-2 py-0.5 rounded bg-primary/10 border border-primary/20 text-[10px] font-semibold text-primary uppercase tracking-wide">
              Phishing Blocker
            </span>
          </div>
          <p className="text-gray-400 mt-2 max-w-2xl text-sm">
            Audits websites, links, and domains. Leverages Levenshtein distance typosquatting checks, SSL verification, WHOIS registration age audits, and VirusTotal databases.
          </p>
        </div>
        <button 
          onClick={fetchLogs}
          className="flex items-center justify-center gap-2 px-4 py-2 bg-white/5 border border-white/10 rounded-xl text-xs text-white hover:bg-white/10 transition-all font-medium self-start lg:self-auto"
        >
          <RefreshCw size={14} /> Refresh Logs
        </button>
      </header>

      {/* Cards Summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="glass-panel p-4 border border-white/10 rounded-2xl">
          <div className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">URLs Audited</div>
          <div className="text-2xl font-black text-white mt-1">{counters.total}</div>
          <div className="text-[10px] text-gray-400 mt-0.5">Scan history total</div>
        </div>
        <div className="glass-panel p-4 border border-white/10 rounded-2xl">
          <div className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Spam Detected</div>
          <div className="text-2xl font-black text-amber-500 mt-1">{counters.spam}</div>
          <div className="text-[10px] text-gray-400 mt-0.5">High-risk warning URLs</div>
        </div>
        <div className="glass-panel p-4 border border-white/10 rounded-2xl">
          <div className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Phishing Blocked</div>
          <div className="text-2xl font-black text-rose-500 mt-1">{counters.malware}</div>
          <div className="text-[10px] text-gray-400 mt-0.5">Critical imitations intercepted</div>
        </div>
        <div className="glass-panel p-4 border border-white/10 rounded-2xl">
          <div className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Safe Websites</div>
          <div className="text-2xl font-black text-emerald-500 mt-1">{counters.safe}</div>
          <div className="text-[10px] text-gray-400 mt-0.5">Verified SSL domains</div>
        </div>
      </div>

      {/* URL Scan Bar */}
      <section className="glass-panel p-5 border border-white/10 rounded-2xl space-y-4">
        <h3 className="font-semibold text-white text-sm">Scan New Website Link</h3>
        <form onSubmit={handleScan} className="flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-500" size={16} />
            <input
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="Paste website address or link to scan (e.g. paypa1-verify-login.com)"
              className="w-full pl-11 pr-4 py-2.5 rounded-xl border border-white/10 bg-black/40 text-xs text-white outline-none focus:border-primary/50 transition-all font-medium"
            />
          </div>
          <button
            type="submit"
            disabled={loadingScan || !urlInput.trim()}
            className="px-5 py-2.5 bg-primary border border-primary/20 hover:bg-primary-hover disabled:opacity-50 text-white rounded-xl text-xs font-bold transition-all flex items-center justify-center gap-2"
          >
            {loadingScan ? <RefreshCw className="animate-spin" size={14} /> : "Scan Domain"}
          </button>
        </form>
      </section>

      {/* Active Scan Result Report */}
      {scanResult && (() => {
        const report = parseReport(scanResult.scan_report);
        const risk = getRiskColor(scanResult.risk_score);
        return (
          <div className={`p-5 rounded-2xl border ${risk.border} space-y-4 animate-in zoom-in-95 duration-300`}>
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/5 pb-3">
              <div>
                <span className="text-[10px] uppercase font-bold text-gray-500">AUDITED DOMAIN</span>
                <h4 className="text-base font-bold text-white font-mono mt-0.5 break-all">{scanResult.domain}</h4>
              </div>
              <div className="flex items-center gap-3">
                <div className="text-right">
                  <span className="text-[10px] uppercase font-bold text-gray-500 block">RISK LEVEL</span>
                  <span className={`font-mono text-sm font-bold block ${risk.text}`}>{scanResult.threat_type}</span>
                </div>
                <div className={`w-12 h-12 rounded-xl flex items-center justify-center font-black text-sm text-black ${risk.bar}`}>
                  {scanResult.risk_score.toFixed(0)}
                </div>
              </div>
            </div>

            {/* Heuristics Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
              
              {/* SSL Status */}
              <div className="p-3 bg-white/[0.02] border border-white/5 rounded-xl space-y-2">
                <div className="flex items-center justify-between text-gray-500 text-[10px] uppercase font-bold">
                  <span>SSL Certificate</span>
                  {report.ssl_valid ? <Lock size={12} className="text-emerald-400" /> : <ShieldX size={12} className="text-rose-400" />}
                </div>
                <div className="font-semibold text-white mt-1">
                  {report.ssl_issuer}
                </div>
                <div className="text-[10px] text-gray-400">
                  {report.ssl_valid ? `Valid connection` : `High-risk insecure traffic`}
                </div>
              </div>

              {/* WHOIS Age */}
              <div className="p-3 bg-white/[0.02] border border-white/5 rounded-xl space-y-2">
                <div className="flex items-center justify-between text-gray-500 text-[10px] uppercase font-bold">
                  <span>Domain Registration</span>
                  <Globe size={12} className="text-primary" />
                </div>
                <div className="font-semibold text-white mt-1">
                  Age: {report.domain_age_years} Years
                </div>
                <div className="text-[10px] text-gray-400">
                  Hosting Country: {report.hosting_country || 'US'}
                </div>
              </div>

              {/* API Database hits */}
              <div className="p-3 bg-white/[0.02] border border-white/5 rounded-xl space-y-2">
                <div className="flex items-center justify-between text-gray-500 text-[10px] uppercase font-bold">
                  <span>API Reputations</span>
                  <Sparkles size={12} className="text-violet-400" />
                </div>
                <div className="font-semibold text-white mt-1">
                  VirusTotal: {report.virustotal_positives} alerts
                </div>
                <div className="text-[10px] text-gray-400">
                  Google Safe Browsing: {report.google_safe_browsing}
                </div>
              </div>

            </div>

            {/* Assessment Details */}
            {report.reasons && report.reasons.length > 0 && (
              <div className="p-3 bg-black/30 border border-white/5 rounded-xl space-y-2 text-xs">
                <span className="font-bold text-gray-400 block">AI Assessment Findings:</span>
                <ul className="list-disc pl-4 space-y-1 text-gray-300">
                  {report.reasons.map((r, idx) => (
                    <li key={idx}>{r}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Action Buttons */}
            <div className="flex flex-wrap justify-between gap-3 pt-2">
              <div className="flex gap-2">
                <button
                  onClick={() => handleBlockDomain(scanResult.domain)}
                  className="px-4 py-2 bg-rose-500/10 border border-rose-500/20 hover:bg-rose-500/20 text-rose-500 rounded-xl text-xs font-semibold transition-colors"
                >
                  Block Domain
                </button>
                <button
                  onClick={() => handleCopyReport(scanResult.scan_report)}
                  className="px-4 py-2 bg-white/5 border border-white/10 hover:bg-white/10 text-white rounded-xl text-xs font-semibold transition-colors flex items-center gap-1.5"
                >
                  <ClipboardCopy size={13} /> Copy Report
                </button>
              </div>
              <button
                onClick={() => setScanResult(null)}
                className="px-4 py-2 bg-white/5 hover:bg-white/10 text-white rounded-xl text-xs font-semibold transition-colors"
              >
                Clear Result
              </button>
            </div>
          </div>
        );
      })()}

      {/* Spam History Logs */}
      <div className="glass-panel rounded-2xl border border-white/10 p-5 space-y-4">
        
        {/* Filter Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/5 pb-4">
          <div className="flex items-center gap-2">
            <History className="text-primary animate-pulse" size={16} />
            <h3 className="font-semibold text-white text-base">URL Scan Audit Logs</h3>
          </div>
          <div className="flex items-center gap-3">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-500" size={13} />
              <input
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter logs..."
                className="pl-8 pr-3 py-1.5 w-44 rounded-xl border border-white/10 bg-black/40 text-[11px] text-white outline-none focus:border-primary/50 transition-all"
              />
            </div>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="px-2 py-1.5 rounded-xl border border-white/10 bg-black/50 text-[11px] text-gray-300 focus:border-primary/50 outline-none"
            >
              <option value="ALL">All Categories</option>
              <option value="Safe">Safe</option>
              <option value="Low Risk">Low Risk</option>
              <option value="Medium Risk">Medium Risk</option>
              <option value="High Risk">High Risk</option>
              <option value="Critical">Critical</option>
            </select>
          </div>
        </div>

        {/* Scan Log Table */}
        <div className="overflow-x-auto rounded-xl border border-white/5 bg-black/20">
          <table className="w-full text-left border-collapse text-xs">
            <thead className="bg-white/[0.02] border-b border-white/10 text-gray-400 font-bold">
              <tr>
                <th className="p-3">Scanned URL</th>
                <th className="p-3">Domain</th>
                <th className="p-3">Risk Score</th>
                <th className="p-3">Threat Category</th>
                <th className="p-3">Action Status</th>
                <th className="p-3">Timestamp</th>
                <th className="p-3 text-center">Scan Report</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5 text-gray-300 font-medium">
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan="7" className="p-8 text-center text-gray-500 font-medium">
                    No scan logs matching filters.
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => {
                  const risk = getRiskColor(log.risk_score);
                  return (
                    <tr key={log.id} className="hover:bg-white/[0.01] transition-colors">
                      <td className="p-3 text-white truncate max-w-[200px]" title={log.url}>
                        <span className="flex items-center gap-1">
                          <ExternalLink size={10} className="text-gray-500 shrink-0" />
                          {log.url}
                        </span>
                      </td>
                      <td className="p-3 font-mono text-[10px] text-gray-400">{log.domain}</td>
                      <td className="p-3">
                        <span className={`font-bold font-mono ${risk.text}`}>
                          {log.risk_score.toFixed(0)}
                        </span>
                      </td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded border text-[9px] font-bold uppercase ${
                          log.threat_type === 'Critical' 
                            ? 'bg-rose-500/10 border-rose-500/20 text-rose-500' 
                            : log.threat_type === 'High Risk'
                              ? 'bg-orange-500/10 border-orange-500/20 text-orange-400'
                              : log.threat_type === 'Medium Risk'
                                ? 'bg-amber-500/10 border-amber-500/20 text-amber-500'
                                : log.threat_type === 'Low Risk'
                                  ? 'bg-yellow-400/10 border-yellow-400/20 text-yellow-400'
                                  : 'bg-emerald-500/10 border-emerald-500/20 text-emerald-500'
                        }`}>
                          {log.threat_type}
                        </span>
                      </td>
                      <td className="p-3">
                        <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
                          log.action_taken === 'blocked' ? 'text-rose-400 bg-rose-500/10' : 'text-emerald-400 bg-emerald-500/10'
                        }`}>
                          {log.action_taken}
                        </span>
                      </td>
                      <td className="p-3 text-gray-500 font-mono text-[10px]">
                        {new Date(log.timestamp + (log.timestamp?.includes('Z') ? '' : 'Z')).toLocaleString()}
                      </td>
                      <td className="p-3 text-center">
                        <button
                          onClick={() => {
                            setScanResult(log);
                          }}
                          className="p-1 rounded bg-white/5 border border-white/10 text-gray-400 hover:text-white hover:bg-white/10 transition-colors"
                          title="View Report"
                        >
                          <Info size={13} />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
