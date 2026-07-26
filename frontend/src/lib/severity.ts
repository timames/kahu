export function severityClass(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical": return "severity-critical";
    case "high": return "severity-high";
    case "medium": return "severity-medium";
    case "low": return "severity-low";
    default: return "severity-info";
  }
}

export function severityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical": return "text-sev-critical";
    case "high": return "text-sev-high";
    case "medium": return "text-sev-medium";
    case "low": return "text-sev-low";
    default: return "text-sev-info";
  }
}

export function timeAgo(dateStr: string): string {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diff = Math.max(0, now - then);
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}
