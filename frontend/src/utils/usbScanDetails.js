export function parseUsbScanDetails(details) {
  if (!details || typeof details !== 'string') {
    return null;
  }

  try {
    const parsed = JSON.parse(details);
    if (parsed && parsed.scan_type === 'usb_file_intelligence') {
      return parsed;
    }
  } catch {
    return null;
  }

  return null;
}

export function getUsbScanActivities(activities) {
  return (activities || []).filter((activity) => (
    activity?.action_type === 'usb_scan_complete' || activity?.action_type === 'usb_threat_mitigated'
  ));
}

export function formatUsbActivity(activity) {
  const payload = parseUsbScanDetails(activity?.details);
  if (!payload) {
    return null;
  }

  return {
    id: activity?.id ?? `${activity?.action_type}-${activity?.timestamp ?? activity?.time ?? Date.now()}`,
    action: activity?.action_type,
    timestamp: activity?.timestamp ?? activity?.time ?? null,
    drive: payload.drive || 'USB',
    summary: payload.summary || 'USB scan completed.',
    threatTypes: Array.isArray(payload.threat_types) ? payload.threat_types : [],
    findings: Array.isArray(payload.findings) ? payload.findings : [],
    dangerousCount: payload.dangerous_count ?? 0,
    suspiciousCount: payload.suspicious_count ?? 0,
    quarantinedCount: payload.quarantined_count ?? 0,
    blockedCount: payload.blocked_count ?? 0,
    scannerVersion: payload.scanner_version || '-',
  };
}
