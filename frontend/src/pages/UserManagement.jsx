import React, { useState, useEffect } from 'react';
import { buildApiUrl, getAuthHeaders } from '../utils/auth';

export default function UserManagement() {
  const [users, setUsers] = useState([]);
  const [showCreate, setShowCreate] = useState(false);
  const [resetResult, setResetResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [form, setForm] = useState({
    email: '',
    password: '',
    full_name: '',
    role: 'user',
    department: '',
    can_view_logs: true,
    can_manage_blocks: false,
    can_manage_rules: false
  });

  const loadUsers = async () => {
    setLoading(true);
    try {
      const res = await fetch(buildApiUrl('/api/admin/users'), { headers: getAuthHeaders() });
      if (res.ok) {
        const d = await res.json();
        setUsers(d.users || []);
      } else {
        const d = await res.json();
        console.error('Failed to load users', d);
      }
    } catch (err) {
      console.error('Error fetching users', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadUsers();
  }, []);

  const createUser = async () => {
    try {
      const res = await fetch(buildApiUrl('/api/admin/users/create'), {
        method: 'POST',
        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify(form)
      });
      const data = await res.json();
      if (data.success) {
        setShowCreate(false);
        loadUsers();
        setForm({
          email: '',
          password: '',
          full_name: '',
          role: 'user',
          department: '',
          can_view_logs: true,
          can_manage_blocks: false,
          can_manage_rules: false
        });
        window.showToast?.(`User ${data.email} created successfully!`, 'success');
      } else {
        alert(data.detail || data.error || 'Failed to create user');
      }
    } catch (err) {
      alert('Error creating user: ' + String(err));
    }
  };

  const toggleActive = async (userId) => {
    try {
      const res = await fetch(buildApiUrl(`/api/admin/users/${userId}/toggle-active`), {
        method: 'POST',
        headers: getAuthHeaders()
      });
      if (res.ok) {
        loadUsers();
        window.showToast?.('User active status toggled.', 'success');
      }
    } catch (err) {
      console.error(err);
    }
  };

  const deleteUser = async (userId, email) => {
    if (!confirm(`Delete user ${email}? This cannot be undone.`)) return;
    try {
      const res = await fetch(buildApiUrl(`/api/admin/users/${userId}`), {
        method: 'DELETE',
        headers: getAuthHeaders()
      });
      const data = await res.json();
      if (res.ok && data.success) {
        loadUsers();
        window.showToast?.(`User ${email} deleted.`, 'success');
      } else {
        alert(data.detail || data.error || 'Failed to delete user');
      }
    } catch (err) {
      console.error(err);
    }
  };

  const resetPassword = async (userId) => {
    try {
      const res = await fetch(buildApiUrl(`/api/admin/users/${userId}/reset-password`), {
        method: 'POST',
        headers: getAuthHeaders()
      });
      const data = await res.json();
      if (data.success) {
        setResetResult(data);
      } else {
        alert(data.detail || data.error || 'Failed to reset password');
      }
    } catch (err) {
      console.error(err);
    }
  };

  const PERMISSIONS = [
    { key: 'can_view_logs', label: 'View Logs' },
    { key: 'can_manage_blocks', label: 'Manage Blocks' },
    { key: 'can_manage_rules', label: 'Manage Rules' },
  ];

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <span>👥 User Management</span>
          </h1>
          <p className="text-xs text-gray-400 mt-1">
            Create, manage enterprise roles, fine-grained access permissions, and account passwords.
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="px-4 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-sm font-medium transition-colors shadow-lg shadow-blue-600/20 flex items-center gap-2"
        >
          <span>+ Create User</span>
        </button>
      </div>

      {/* Users table */}
      <div className="bg-gray-900/80 rounded-2xl border border-gray-700/80 overflow-hidden backdrop-blur-md shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="bg-gray-800/80 border-b border-gray-700">
                {['Name', 'Email', 'Role', 'Department', 'Permissions', 'Status', 'Last Login', 'Actions'].map(h => (
                  <th key={h} className="px-4 py-3.5 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {users.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-xs text-gray-500">
                    {loading ? 'Loading user registry...' : 'No managed users found. Create the first user above.'}
                  </td>
                </tr>
              ) : (
                users.map((user, i) => (
                  <tr key={user.id || i} className={`hover:bg-gray-800/30 transition-colors ${!user.is_active ? 'opacity-50' : ''}`}>
                    <td className="px-4 py-3 text-sm text-white font-medium">{user.full_name}</td>
                    <td className="px-4 py-3 text-sm text-blue-400 font-mono">{user.email}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2.5 py-1 rounded-full text-xs font-bold uppercase ${
                        user.role === 'admin'
                          ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                          : user.role === 'analyst'
                            ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                            : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                      }`}>
                        {user.role}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-400">{user.department || '—'}</td>
                    <td className="px-4 py-3">
                      <div className="flex gap-1.5 flex-wrap">
                        {PERMISSIONS.map(p => user[p.key] ? (
                          <span key={p.key} className="px-2 py-0.5 bg-green-500/20 text-green-400 border border-green-500/30 text-xs rounded-md font-medium">
                            {p.label}
                          </span>
                        ) : null)}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => toggleActive(user.id)}
                        className={`px-2.5 py-1 rounded-full text-xs font-bold transition-colors ${
                          user.is_active
                            ? 'bg-green-500/20 text-green-400 border border-green-500/30 hover:bg-green-500/30'
                            : 'bg-gray-500/20 text-gray-400 border border-gray-500/30 hover:bg-gray-500/30'
                        }`}
                      >
                        {user.is_active ? 'ACTIVE' : 'DISABLED'}
                      </button>
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400">
                      {user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex gap-2">
                        <button
                          onClick={() => resetPassword(user.id)}
                          className="px-2.5 py-1 bg-yellow-500/10 hover:bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 rounded-lg text-xs font-medium transition-colors"
                        >
                          Reset Pwd
                        </button>
                        <button
                          onClick={() => deleteUser(user.id, user.email)}
                          className="px-2.5 py-1 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg text-xs font-medium transition-colors"
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create user modal */}
      {showCreate && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <div className="bg-gray-900 border border-gray-700 rounded-2xl p-6 w-full max-w-lg max-h-[90vh] overflow-y-auto shadow-2xl">
            <h2 className="text-white font-bold text-lg mb-4">Create New User</h2>
            <div className="flex flex-col gap-3">
              {[
                { label: 'Full Name', key: 'full_name', type: 'text', placeholder: 'John Smith' },
                { label: 'Email', key: 'email', type: 'email', placeholder: 'john.smith@company.com' },
                { label: 'Password', key: 'password', type: 'password', placeholder: 'Temporary password' },
                { label: 'Department', key: 'department', type: 'text', placeholder: 'IT, Security, Finance...' },
              ].map(f => (
                <div key={f.key}>
                  <label className="text-gray-400 text-xs font-semibold mb-1 block">{f.label}</label>
                  <input
                    type={f.type}
                    value={form[f.key]}
                    onChange={e => setForm(p => ({ ...p, [f.key]: e.target.value }))}
                    placeholder={f.placeholder}
                    className="w-full bg-gray-800/90 border border-gray-700 rounded-xl px-3.5 py-2 text-white text-sm focus:border-blue-500 outline-none"
                  />
                </div>
              ))}
              <div>
                <label className="text-gray-400 text-xs font-semibold mb-1 block">Role</label>
                <select
                  value={form.role}
                  onChange={e => setForm(p => ({ ...p, role: e.target.value }))}
                  className="w-full bg-gray-800/90 border border-gray-700 rounded-xl px-3.5 py-2 text-white text-sm focus:border-blue-500 outline-none"
                >
                  <option value="user">User</option>
                  <option value="admin">Admin</option>
                  <option value="analyst">Analyst</option>
                </select>
              </div>
              <div className="pt-2">
                <label className="text-gray-400 text-xs font-semibold mb-2 block">Permissions</label>
                <div className="space-y-2">
                  {PERMISSIONS.map(p => (
                    <label key={p.key} className="flex items-center gap-2.5 cursor-pointer bg-gray-800/50 p-2.5 rounded-xl border border-gray-700/50">
                      <input
                        type="checkbox"
                        checked={form[p.key]}
                        onChange={e => setForm(prev => ({ ...prev, [p.key]: e.target.checked }))}
                        className="rounded border-gray-700 text-blue-600 focus:ring-blue-500 h-4 w-4"
                      />
                      <span className="text-gray-200 text-sm font-medium">{p.label}</span>
                    </label>
                  ))}
                </div>
              </div>
            </div>
            <div className="flex gap-3 mt-6">
              <button
                onClick={createUser}
                disabled={!form.email || !form.password || !form.full_name}
                className="flex-1 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl font-medium text-sm disabled:opacity-50 transition-colors shadow-lg shadow-blue-600/20"
              >
                Create User
              </button>
              <button
                onClick={() => setShowCreate(false)}
                className="flex-1 py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded-xl text-sm transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Reset password result modal */}
      {resetResult && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <div className="bg-gray-900 border border-yellow-500/30 rounded-2xl p-6 w-full max-w-md shadow-2xl">
            <h3 className="text-yellow-400 font-bold text-lg mb-2">🔑 Temporary Password Generated</h3>
            <p className="text-gray-400 text-xs mb-4">Share this password securely with the user. They will be prompted to update it.</p>
            <div className="bg-black/60 border border-gray-800 rounded-xl px-4 py-3 font-mono text-white text-lg text-center mb-5 select-all tracking-wider">
              {resetResult.temp_password}
            </div>
            <button
              onClick={() => {
                navigator.clipboard.writeText(resetResult.temp_password);
                window.showToast?.('Temporary password copied to clipboard!', 'success');
                setResetResult(null);
              }}
              className="w-full py-2.5 bg-yellow-600 hover:bg-yellow-500 text-white rounded-xl font-medium text-sm transition-colors"
            >
              Copy Password & Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
