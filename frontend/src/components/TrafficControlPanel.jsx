import React, { useState, useEffect } from 'react';
import { buildApiUrl, getAuthHeaders, isAdminUser, getStoredUser } from '../utils/auth';

export default function TrafficControlPanel() {
  const user = getStoredUser();
  const isAdmin = isAdminUser(user);
  const [rules, setRules] = useState([]);
  const [directionFilter, setDirectionFilter] = useState('All');
  const [showAddForm, setShowAddForm] = useState(false);
  const [form, setForm] = useState({
    rule_name: '',
    direction: 'in',
    action: 'block',
    protocol: 'any',
    local_port: 'any',
    remote_ip: 'any',
    admin_locked: true,
    notes: ''
  });

  const loadRules = () => {
    fetch(buildApiUrl('/api/traffic/rules'), { headers: getAuthHeaders() })
      .then(r => r.json())
      .then(d => setRules(d.rules || []))
      .catch(err => console.error('Failed to load rules', err));
  };

  useEffect(() => {
    loadRules();
  }, []);

  const addRule = async () => {
    if (!form.rule_name.trim()) {
      alert('Please provide a rule name');
      return;
    }
    const res = await fetch(buildApiUrl('/api/traffic/rules/add'), {
      method: 'POST',
      headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify(form)
    });
    const data = await res.json();
    if (res.ok && data.success) {
      loadRules();
      setShowAddForm(false);
      setForm({
        rule_name: '',
        direction: 'in',
        action: 'block',
        protocol: 'any',
        local_port: 'any',
        remote_ip: 'any',
        admin_locked: true,
        notes: ''
      });
      if (window.showToast) window.showToast('Rule added successfully', 'success');
    } else {
      alert(data.detail || data.error || 'Failed to add rule');
    }
  };

  const removeRule = async (ruleName, isLocked) => {
    if (isLocked && !isAdmin) {
      alert('This rule is admin-locked. Contact your administrator.');
      return;
    }
    if (!window.confirm(`Are you sure you want to remove rule "${ruleName}"?`)) return;
    const res = await fetch(buildApiUrl(`/api/traffic/rules/${encodeURIComponent(ruleName)}`), {
      method: 'DELETE',
      headers: getAuthHeaders()
    });
    const data = await res.json();
    if (res.ok && data.success) {
      setRules(prev => prev.filter(r => r.rule_name !== ruleName));
      if (window.showToast) window.showToast(`Rule ${ruleName} removed`, 'success');
    } else {
      alert(data.detail || data.error || 'Failed to remove rule');
    }
  };

  const toggleLock = async (ruleName) => {
    if (!isAdmin) return;
    const res = await fetch(buildApiUrl(`/api/traffic/rules/toggle-lock/${encodeURIComponent(ruleName)}`), {
      method: 'POST',
      headers: getAuthHeaders()
    });
    const data = await res.json();
    if (res.ok && data.success) {
      loadRules();
      if (window.showToast) window.showToast('Lock status updated', 'success');
    }
  };

  const filteredRules = rules.filter(r => {
    if (directionFilter === 'All') return true;
    if (directionFilter === 'Inbound') return r.direction === 'in' || r.direction === 'both';
    if (directionFilter === 'Outbound') return r.direction === 'out' || r.direction === 'both';
    return true;
  });

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <span>Traffic Control</span>
          </h1>
          <p className="text-xs text-gray-400 mt-1">Manage network ingress and egress rules with admin privilege enforcement.</p>
        </div>
        {isAdmin && (
          <button
            onClick={() => setShowAddForm(true)}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-sm font-medium transition-colors shadow-lg shadow-blue-600/20"
          >
            + Add Rule
          </button>
        )}
      </div>

      <div className="flex gap-2 mb-4">
        {['All', 'Inbound', 'Outbound'].map(d => (
          <button
            key={d}
            onClick={() => setDirectionFilter(d)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${directionFilter === d ? 'bg-blue-600 text-white' : 'bg-gray-800/80 text-gray-300 hover:bg-gray-700'}`}
          >
            {d}
          </button>
        ))}
      </div>

      <div className="bg-gray-900/80 backdrop-blur-xl rounded-2xl border border-gray-800 overflow-hidden shadow-2xl">
        <table className="w-full text-left">
          <thead>
            <tr className="bg-gray-800/60 border-b border-gray-800">
              {['Rule Name', 'Direction', 'Action', 'Protocol', 'Port', 'Remote IP', 'Locked', 'Created By', 'Action'].map(h => (
                <th key={h} className="px-4 py-3 text-xs font-semibold text-gray-400 uppercase tracking-wider">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/50">
            {filteredRules.length === 0 ? (
              <tr>
                <td colSpan="9" className="px-4 py-8 text-center text-sm text-gray-500">
                  No traffic control rules configured.
                </td>
              </tr>
            ) : (
              filteredRules.map((rule, i) => (
                <tr key={i} className="hover:bg-gray-800/40 transition-colors">
                  <td className="px-4 py-3 text-sm text-white font-mono">{rule.rule_name}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded text-xs font-bold ${
                      rule.direction === 'in' ? 'bg-blue-500/20 text-blue-400' :
                      rule.direction === 'out' ? 'bg-purple-500/20 text-purple-400' :
                      'bg-teal-500/20 text-teal-400'
                    }`}>
                      {String(rule.direction || '').toUpperCase()}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded text-xs font-bold ${
                      rule.action === 'block' ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'
                    }`}>
                      {String(rule.action || '').toUpperCase()}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-300 font-mono">{rule.protocol}</td>
                  <td className="px-4 py-3 text-sm text-gray-300 font-mono">{rule.local_port}</td>
                  <td className="px-4 py-3 text-sm text-gray-300 font-mono">{rule.remote_ip}</td>
                  <td className="px-4 py-3">
                    {rule.is_admin_locked ? (
                      <button
                        onClick={() => toggleLock(rule.rule_name)}
                        disabled={!isAdmin}
                        className={`text-yellow-400 text-xs font-bold ${isAdmin ? 'hover:underline cursor-pointer' : 'cursor-default'}`}
                        title={isAdmin ? 'Click to toggle lock' : 'Admin-locked'}
                      >
                        [LOCKED]
                      </button>
                    ) : (
                      <button
                        onClick={() => toggleLock(rule.rule_name)}
                        disabled={!isAdmin}
                        className={`text-gray-500 text-xs ${isAdmin ? 'hover:text-gray-300 cursor-pointer' : 'cursor-default'}`}
                        title={isAdmin ? 'Click to lock rule' : 'Unlocked'}
                      >
                        Unlocked
                      </button>
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-400">{rule.created_by}</td>
                  <td className="px-4 py-3">
                    {(isAdmin || !rule.is_admin_locked) ? (
                      <button
                        onClick={() => removeRule(rule.rule_name, rule.is_admin_locked)}
                        className="px-3 py-1 bg-red-500/20 hover:bg-red-500/30 text-red-400 border border-red-500/30 rounded-lg text-xs font-medium transition-colors"
                      >
                        Remove
                      </button>
                    ) : (
                      <span className="text-gray-600 text-xs font-medium">Admin only</span>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {showAddForm && isAdmin && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 border border-gray-700/80 rounded-2xl p-6 w-full max-w-lg shadow-2xl">
            <h2 className="text-white font-bold text-lg mb-4">
              Add Firewall Rule
            </h2>
            <div className="flex flex-col gap-3">
              {[
                { label: 'Rule Name', key: 'rule_name', type: 'text', placeholder: 'e.g. BlockPort8080' },
                { label: 'Remote IP (optional)', key: 'remote_ip', type: 'text', placeholder: 'e.g. 192.168.1.50 or any' },
                { label: 'Port (optional)', key: 'local_port', type: 'text', placeholder: 'e.g. 8080 or any' },
                { label: 'Notes', key: 'notes', type: 'text', placeholder: 'Reason or context for this rule' },
              ].map(field => (
                <div key={field.key}>
                  <label className="text-gray-400 text-xs mb-1 block font-medium">{field.label}</label>
                  <input
                    value={form[field.key]}
                    onChange={e => setForm(p => ({ ...p, [field.key]: e.target.value }))}
                    placeholder={field.placeholder}
                    className="w-full bg-gray-800/80 border border-gray-700 rounded-xl px-3 py-2 text-white text-sm focus:border-blue-500 focus:outline-none"
                  />
                </div>
              ))}
              {[
                { label: 'Direction', key: 'direction', options: ['in', 'out', 'both'] },
                { label: 'Action', key: 'action', options: ['block', 'allow'] },
                { label: 'Protocol', key: 'protocol', options: ['any', 'tcp', 'udp', 'icmp'] },
              ].map(field => (
                <div key={field.key}>
                  <label className="text-gray-400 text-xs mb-1 block font-medium">{field.label}</label>
                  <select
                    value={form[field.key]}
                    onChange={e => setForm(p => ({ ...p, [field.key]: e.target.value }))}
                    className="w-full bg-gray-800/80 border border-gray-700 rounded-xl px-3 py-2 text-white text-sm focus:border-blue-500 focus:outline-none"
                  >
                    {field.options.map(o => (
                      <option key={o} value={o}>{o.toUpperCase()}</option>
                    ))}
                  </select>
                </div>
              ))}
              <div className="flex items-center gap-2 pt-2">
                <input
                  type="checkbox"
                  id="admin_locked"
                  checked={form.admin_locked}
                  onChange={e => setForm(p => ({ ...p, admin_locked: e.target.checked }))}
                  className="rounded bg-gray-800 border-gray-700 text-blue-600 focus:ring-blue-500"
                />
                <label htmlFor="admin_locked" className="text-gray-300 text-xs cursor-pointer">
                  Admin-locked (regular users cannot remove or modify)
                </label>
              </div>
            </div>
            <div className="flex gap-3 mt-6">
              <button
                onClick={addRule}
                className="flex-1 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-medium text-sm transition-colors shadow-lg shadow-blue-600/20"
              >
                Add Rule
              </button>
              <button
                onClick={() => setShowAddForm(false)}
                className="flex-1 py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-xl text-sm font-medium transition-colors"
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
