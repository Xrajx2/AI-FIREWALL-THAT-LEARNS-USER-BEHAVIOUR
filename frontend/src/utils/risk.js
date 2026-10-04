export function scoreToRiskLevel(score) {
  const normalized = Number(score || 0);
  if (normalized <= 30) {
    return 'Normal';
  }
  if (normalized <= 70) {
    return 'Suspicious';
  }
  return 'Dangerous';
}

export function normalizeRiskLevel(level, fallbackScore = 0) {
  const normalized = String(level || '').trim().toLowerCase();
  if (normalized === 'normal' || normalized === 'suspicious' || normalized === 'dangerous') {
    return normalized.charAt(0).toUpperCase() + normalized.slice(1);
  }
  if (normalized === 'low') {
    return 'Normal';
  }
  if (normalized === 'medium' || normalized === 'high') {
    return 'Suspicious';
  }
  if (normalized === 'critical') {
    return 'Dangerous';
  }
  return scoreToRiskLevel(fallbackScore);
}

export function getRiskTone(level, score = 0) {
  const resolved = normalizeRiskLevel(level, score);
  if (resolved === 'Dangerous') {
    return {
      badge: 'bg-danger/10 border-danger/30 text-danger',
      text: 'text-danger',
      soft: 'bg-danger/5 border-danger/20',
    };
  }
  if (resolved === 'Suspicious') {
    return {
      badge: 'bg-warning/10 border-warning/30 text-warning',
      text: 'text-warning',
      soft: 'bg-warning/5 border-warning/20',
    };
  }
  return {
    badge: 'bg-success/10 border-success/30 text-success',
    text: 'text-success',
    soft: 'bg-success/5 border-success/20',
  };
}

export function formatRecommendedAction(action) {
  return String(action || 'monitor')
    .split('_')
    .filter(Boolean)
    .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
    .join(' ');
}
