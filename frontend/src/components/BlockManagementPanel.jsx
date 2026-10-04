import React, { useState, useEffect } from 'react';
import { buildApiUrl, getAuthHeaders, isAdminUser, getStoredUser } from '../utils/auth';

export default function BlockManagementPanel() {
  const user = getStoredUser();
  const isAdmin = isAdminUser(user);
  const [blocks, setBlocks] = useState([]);
  const [showHistory, setShowHistory] = useState(false);
  const [form, setForm] = useState({ block_type: 'ip', value: '', reason: '', apply_firewall: true });
  const [unblockModal, setUnblockModal] = useState(null);
  const [unblockReason, setUnblockReason] = useState('');
  const [loading, setLoading] = useState(false);

  const loadBlocks = () => {
    fetch(buildApiUrl(`/api/security/blocks?include_inactive=${showHistory}`), { headers: getAuthHeaders() })
      .then(r => r.json())
      .then(d => setBlocks(d.blocks || []))
      .catch(err => console.error('Failed to load blocks', err));
  };

  useEffect(() => {
    loadBlocks();
  }, [showHistory]);

  const addBlock = async () => {
    if (!form.value || !form.reason) return;
    setLoading(true);
    try {
      const res = await fetch(buildApiUrl('/api/security/block'), {
        method: 'POST',
        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify(form)
      });
      const data = await res.json();
      if (res.ok && data.success) {
        loadBlocks();
        setForm({ block_type: 'ip', value: '', reason: '', apply_firewall: true });
        if (window.showToast) window.showToast(`Blocked ${form.value} permanently`, 'success');
      } else {
        alert(data.detail || data.error || 'Block failed');
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const unblock = async () => {
    if (!unblockModal || !unblockReason) return;
    setLoading(true);
    try {
      const res = await fetch(buildApiUrl('/api/security/unblock'), {
        method: 'POST',
        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({
          block_type: unblockModal.block_type,
          value: unblockModal.value,
          reason: unblockReason
        })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setUnblockModal(null);
        setUnblockReason('');
        loadBlocks();
        if (window.showToast) window.showToast(`Unblocked ${unblockModal.value}`, 'success');
      } else {
        alert(data.detail || data.error || 'Unblock failed');
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const typeColors = {
    ip: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    user: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
    process: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    domain: 'bg-red-500/20 text-red-400 border-red-500/30',
    usb_device: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
  };

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <span>Permanent Blocks</span>
          </h1>
          <p className="text-xs text-gray-400 mt-1">
            Global blacklist enforced at OS firewall, hosts file, and HTTP request middleware with audit logging.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-gray-400 text-xs cursor-pointer bg-gray-800/80 px-3 py-2 rounded-xl border border-gray-700">
            <input
              type="checkbox"
              checked={showHistory}
              onChange={e => setShowHistory(e.target.checked)}
              className="rounded bg-gray-900 border-gray-700 text-blue-600 focus:ring-blue-500"
            />
            Show unblock history
          </label>
        </div>
      </div>

      {isAdmin && (
        <div className="bg-gray-900/80 backdrop-blur-xl border border-gray-800 rounded-2xl p-5 mb-6 shadow-2xl">
          <h3 className="text-white font-semibold text-sm mb-3 flex items-center gap-2">
            <span>Add Permanent Blacklist Entry</span>
          </h3>
          <div className="flex gap-3 flex-wrap">
            <select
              value={form.block_type}
              onChange={e => setForm(p => ({ ...p, block_type: e.target.value }))}
              className="bg-gray-800 border border-gray-700 rounded-xl px-3 py-2 text-white text-xs font-semibold focus:border-blue-500 outline-none"
            >
              {['ip', 'user', 'process', 'domain', 'usb_device'].map(t => (
                <option key={t} value={t}>{t.toUpperCase()}</option>
              ))}
            </select>
            <input
              value={form.value}
              onChange={e => setForm(p => ({ ...p, value: e.target.value }))}
              placeholder="IP address, username, domain..."
              className="flex-1 bg-gray-800/80 border border-gray-700 rounded-xl px-3 py-2 text-white text-sm min-w-[180px] focus:border-blue-500 outline-none"
            />
            <input
              value={form.reason}
              onChange={e => setForm(p => ({ ...p, reason: e.target.value }))}
              placeholder="Reason for block"
              className="flex-1 bg-gray-800/80 border border-gray-700 rounded-xl px-3 py-2 text-white text-sm min-w-[180px] focus:border-blue-500 outline-none"
            />
            <label className="flex items-center gap-2 text-gray-300 text-xs px-2 cursor-pointer">
              <input
                type="checkbox"
                checked={form.apply_firewall}
                onChange={e => setForm(p => ({ ...p, apply_firewall: e.target.checked }))}
                className="rounded bg-gray-900 border-gray-700 text-blue-600 focus:ring-blue-500"
              />
              Apply to OS Firewall
            </label>
            <button
              onClick={addBlock}
              disabled={!form.value.trim() || !form.reason.trim() || loading}
              className="px-5 py-2 bg-red-600 hover:bg-red-500 text-white rounded-xl text-xs font-semibold disabled:opacity-50 transition-colors shadow-lg shadow-red-600/20"
            >
              Block Permanently
            </button>
          </div>
        </div>
      )}

      <div className="bg-gray-900/80 backdrop-blur-xl rounded-2xl border border-gray-800 overflow-hidden shadow-2xl">
        <table className="w-full text-left">
          <thead>
            <tr className="bg-gray-800/60 border-b border-gray-800">
              {['Type', 'Value', 'Reason', 'Blocked By', 'Blocked At', 'Attempts', 'Status', 'Action'].map(h => (
                <th key={h} className="px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/50">
            {blocks.length === 0 ? (
              <tr>
                <td colSpan="8" className="px-4 py-8 text-center text-sm text-gray-500">
                  No active permanent blocks.
                </td>
              </tr>
            ) : (
              blocks.map((block, i) => (
                <tr key={i} className={`hover:bg-gray-800/40 transition-colors ${!block.is_active ? 'opacity-50' : ''}`}>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-[11px] font-bold border ${typeColors[block.block_type] || 'bg-gray-700 text-gray-300'}`}>
                      {block.block_type.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-white font-mono font-medium">{block.value}</td>
                  <td className="px-4 py-3 text-sm text-gray-300 max-w-[200px] truncate" title={block.reason}>{block.reason}</td>
                  <td className="px-4 py-3 text-sm text-gray-400">{block.blocked_by}</td>
                  <td className="px-4 py-3 text-xs text-gray-400 font-mono">
                    {new Date(block.blocked_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-sm text-orange-400 font-mono font-bold">{block.attempt_count}</td>
                  <td className="px-4 py-3">
                    {block.is_active ? (
                      <span className="px-2 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 text-xs rounded-md font-bold">
                        BLOCKED
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 bg-gray-500/20 text-gray-400 text-xs rounded-md">
                        UNBLOCKED
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {block.is_active && isAdmin && (
                      <button
                        onClick={() => setUnblockModal(block)}
                        className="px-3 py-1 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-400 border border-emerald-500/30 rounded-lg text-xs font-semibold transition-colors"
                      >
                        Unblock
                      </button>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {unblockModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-700/80 rounded-2xl p-6 w-full max-w-md shadow-2xl">
            <h3 className="text-white font-bold text-lg mb-2 flex items-center gap-2">
              <span>Confirm Unblock</span>
            </h3>
            <p className="text-gray-300 text-xs mb-4">
              Unblock <span className="text-white font-mono font-bold">{unblockModal.value}</span>?
              This will remove all OS-level firewall and hosts entries for this entity.
            </p>
            <label className="text-gray-400 text-xs mb-1 block font-medium">Unblock Reason (Required)</label>
            <input
              value={unblockReason}
              onChange={e => setUnblockReason(e.target.value)}
              placeholder="e.g. Verified legitimate or false positive"
              className="w-full bg-gray-800 border border-gray-700 rounded-xl px-3 py-2 text-white text-sm mb-4 focus:border-emerald-500 outline-none"
            />
            <div className="flex gap-3">
              <button
                onClick={unblock}
                disabled={!unblockReason.trim() || loading}
                className="flex-1 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl font-semibold text-xs transition-colors disabled:opacity-50 shadow-lg shadow-emerald-600/20"
              >
                Confirm Unblock
              </button>
              <button
                onClick={() => { setUnblockModal(null); setUnblockReason(''); }}
                className="flex-1 py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-xl text-xs font-medium transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
