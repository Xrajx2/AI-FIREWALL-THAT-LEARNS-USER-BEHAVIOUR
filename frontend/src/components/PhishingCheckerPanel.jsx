import React, { Component, useState } from 'react';
import { buildApiUrl, getAuthHeaders } from '../utils/auth';

export class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  componentDidCatch(error, errorInfo) {
    console.error('Phishing component crashed:', error, errorInfo);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="p-6">
          <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
            <h2 className="text-red-400 font-bold text-lg mb-2">Detection Error</h2>
            <p className="text-gray-400 text-sm mb-4">
              Something went wrong during analysis. The page will not crash again.
            </p>
            <button
              onClick={() => this.setState({ hasError: false, error: null })}
              className="px-4 py-2 bg-red-600 text-white rounded text-sm hover:bg-red-500 transition-colors"
            >
              Try Again
            </button>
            <details className="mt-3">
              <summary className="text-gray-500 text-xs cursor-pointer">Error details</summary>
              <pre className="text-red-400 text-xs mt-2 overflow-auto bg-black/40 p-3 rounded-lg">{this.state.error?.toString()}</pre>
            </details>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

export function PhishingCheckerPanel() {
  const [input, setInput] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [mode, setMode] = useState('text');

  const analyze = async () => {
    if (!input.trim()) return;
    setLoading(true);
    try {
      const body = mode === 'text' ? { text: input } : { url: input };
      const res = await fetch(buildApiUrl('/api/security/analyze-phishing'), {
        method: 'POST',
        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const data = await res.json();
      setResult(data);
    } catch (err) {
      console.error('Phishing analysis failed', err);
      setResult({
        error: String(err),
        [mode === 'text' ? 'text_analysis' : 'url_analysis']: {
          score: 0,
          is_phishing: false,
          risk_level: 'ERROR',
          indicators: [`Network or analysis error: ${String(err)}`],
          urls_found: []
        }
      });
    } finally {
      setLoading(false);
    }
  };

  const analysis = result?.text_analysis || result?.url_analysis;
  const riskColors = {
    CRITICAL: { text: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/30', bar: 'bg-red-500' },
    HIGH: { text: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30', bar: 'bg-orange-500' },
    MEDIUM: { text: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', bar: 'bg-yellow-500' },
    LOW: { text: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', bar: 'bg-emerald-500' },
    ERROR: { text: 'text-gray-400', bg: 'bg-gray-500/10', border: 'border-gray-500/30', bar: 'bg-gray-500' }
  };
  const tone = riskColors[analysis?.risk_level] || riskColors.LOW;

  return (
    <div className="p-6 max-w-3xl">
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <span>Phishing & URL Detector</span>
        </h2>
        <p className="text-xs text-gray-400 mt-1">
          Deep NLP and heuristics engine analyzing urgency language, brand typosquatting, suspicious TLDs, and malicious links.
        </p>
      </div>

      <div className="flex gap-2 mb-4">
        {['text', 'url'].map(m => (
          <button
            key={m}
            onClick={() => { setMode(m); setResult(null); setInput(''); }}
            className={`px-4 py-2 rounded-xl text-xs font-semibold transition-all ${
              mode === m ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20' : 'bg-gray-800/80 text-gray-400 hover:bg-gray-700'
            }`}
          >
            {m === 'text' ? 'Analyze Message Text' : 'Analyze URL'}
          </button>
        ))}
      </div>

      <div className="mb-4">
        {mode === 'text' ? (
          <textarea
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder="Paste suspicious email, SMS, or notification message here..."
            rows={5}
            className="w-full bg-gray-900/80 border border-gray-700/80 rounded-2xl px-4 py-3 text-white text-sm resize-none focus:border-blue-500 outline-none backdrop-blur-md"
          />
        ) : (
          <input
            value={input}
            onChange={e => setInput(e.target.value)}
            placeholder="Paste suspicious URL (e.g. http://paypal-security-check.tk/verify)"
            className="w-full bg-gray-900/80 border border-gray-700/80 rounded-2xl px-4 py-3 text-white text-sm focus:border-blue-500 outline-none backdrop-blur-md"
          />
        )}
      </div>

      <button
        onClick={analyze}
        disabled={loading || !input.trim()}
        className="px-6 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-blue-600/20"
      >
        {loading ? 'Analyzing with AI heuristics...' : 'Analyze Now'}
      </button>

      {analysis && (
        <div className={`mt-6 p-5 rounded-2xl border backdrop-blur-md shadow-2xl ${tone.bg} ${tone.border}`}>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div>
                <div className={`font-bold text-lg ${tone.text}`}>
                  {analysis.is_phishing ? 'PHISHING THREAT DETECTED' : (analysis.risk_level === 'ERROR' ? 'ANALYSIS NOTICE' : 'APPEARS SAFE')}
                </div>
                <div className="text-gray-400 text-xs mt-0.5">Risk Level: <span className="font-semibold">{analysis.risk_level}</span></div>
              </div>
            </div>
            <div className={`text-4xl font-bold font-mono ${tone.text}`}>{analysis.score}</div>
          </div>

          <div className="bg-gray-800/80 rounded-full h-2.5 mb-5 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ${tone.bar}`}
              style={{ width: `${analysis.score}%` }}
            />
          </div>

          {analysis.indicators?.length > 0 && (
            <div className="mb-4">
              <div className="text-gray-400 text-xs uppercase font-semibold mb-2 tracking-wider">Threat Indicators</div>
              <div className="space-y-1.5">
                {analysis.indicators.map((ind, i) => (
                  <div key={i} className="flex items-start gap-2 bg-gray-900/60 p-2 rounded-lg border border-gray-800">
                    <span className="text-red-400 mt-0.5 flex-shrink-0 text-xs">!</span>
                    <span className="text-gray-300 text-xs">{ind}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {analysis.urls_found?.length > 0 && (
            <div className="mt-3">
              <div className="text-gray-400 text-xs uppercase font-semibold mb-2 tracking-wider">Embedded URLs Found</div>
              <div className="space-y-1">
                {analysis.urls_found.map((url, i) => (
                  <div key={i} className="text-blue-400 text-xs font-mono break-all bg-gray-900/40 p-2 rounded-lg border border-gray-800/60">
                    {url}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function PhishingCheckerWithBoundary() {
  return (
    <ErrorBoundary>
      <PhishingCheckerPanel />
    </ErrorBoundary>
  );
}
