import React, { useState, useEffect } from 'react';

export default function TitleBar() {
  const isElectron = typeof window !== 'undefined' && Boolean(window.electron?.isElectron || window.aiFirewallDesktop?.isElectron);
  const [version, setVersion] = useState('1.0.0');

  useEffect(() => {
    if (window.electron?.getVersion) {
      window.electron.getVersion().then(v => {
        if (v) setVersion(v);
      }).catch(() => {});
    }
  }, []);

  if (!isElectron) return null;

  return (
    <div style={{
      height: '38px',
      background: '#0a0a0f',
      borderBottom: '1px solid #1a1a2e',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 16px',
      WebkitAppRegion: 'drag',
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      zIndex: 9999,
      userSelect: 'none'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span style={{ fontSize: '14px' }}>🛡️</span>
        <span style={{ color: '#00d4ff', fontSize: '12px', fontWeight: 600, fontFamily: 'monospace' }}>
          AI Firewall v{version}
        </span>
      </div>
      <div style={{ display: 'flex', gap: '8px', WebkitAppRegion: 'no-drag' }}>
        {[
          { label: '—', fn: () => window.electron?.minimize?.(), color: '#ffd700', title: 'Minimize' },
          { label: '⬜', fn: () => window.electron?.maximize?.(), color: '#00d4ff', title: 'Maximize' },
          { label: '✕', fn: () => window.electron?.close?.(), color: '#ef4444', title: 'Close' },
        ].map(btn => (
          <button
            key={btn.label}
            onClick={btn.fn}
            title={btn.title}
            style={{
              width: '24px',
              height: '24px',
              borderRadius: '4px',
              border: 'none',
              background: 'transparent',
              color: btn.color,
              cursor: 'pointer',
              fontSize: '12px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'background 0.15s ease'
            }}
            onMouseEnter={e => e.target.style.background = '#1a1a2e'}
            onMouseLeave={e => e.target.style.background = 'transparent'}
          >
            {btn.label}
          </button>
        ))}
      </div>
    </div>
  );
}
