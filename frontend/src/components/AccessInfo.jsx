import React from 'react';

export default function AccessInfo({ accessInfo }) {
  if (!accessInfo) return null;
  return (
    <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-4 mb-4 backdrop-blur-md shadow-lg">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className="text-blue-400 font-semibold text-sm flex items-center gap-1.5">
            <span>🌍</span> Login Detected
          </span>
          {accessInfo.is_proxy && (
            <span className="px-2 py-0.5 bg-red-500/20 text-red-400 border border-red-500/30 text-xs rounded-md font-bold">
              PROXY
            </span>
          )}
          {accessInfo.is_datacenter && (
            <span className="px-2 py-0.5 bg-orange-500/20 text-orange-400 border border-orange-500/30 text-xs rounded-md font-bold">
              DATACENTER
            </span>
          )}
        </div>
        <span className="text-[11px] text-blue-300/70 font-mono">
          {accessInfo.time ? new Date(accessInfo.time).toLocaleTimeString() : ''}
        </span>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
        <div className="bg-gray-900/50 p-2 rounded-lg border border-gray-800">
          <span className="text-gray-400 block mb-0.5">IP Address</span>
          <span className="text-white font-mono font-medium">{accessInfo.ip}</span>
        </div>
        <div className="bg-gray-900/50 p-2 rounded-lg border border-gray-800">
          <span className="text-gray-400 block mb-0.5">Location</span>
          <span className="text-white font-medium truncate block">{accessInfo.location}</span>
        </div>
        <div className="bg-gray-900/50 p-2 rounded-lg border border-gray-800">
          <span className="text-gray-400 block mb-0.5">ISP / Network</span>
          <span className="text-white font-medium truncate block">{accessInfo.isp}</span>
        </div>
        <div className="bg-gray-900/50 p-2 rounded-lg border border-gray-800">
          <span className="text-gray-400 block mb-0.5">Access Timestamp</span>
          <span className="text-white font-medium">
            {accessInfo.time ? new Date(accessInfo.time).toLocaleString() : 'Just now'}
          </span>
        </div>
      </div>
    </div>
  );
}
