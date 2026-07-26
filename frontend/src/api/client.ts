const BASE = "/api";

function getToken(): string | null {
  try {
    const raw = localStorage.getItem("kahu_auth");
    if (raw) return JSON.parse(raw).token;
  } catch { /* ignore */ }
  return null;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string>),
  };
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${BASE}${path}`, { ...init, headers });

  if (res.status === 401) {
    // Token expired or invalid — clear auth and redirect to login
    localStorage.removeItem("kahu_auth");
    window.location.href = "/login";
    throw new Error("Session expired");
  }

  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

// ── Auth ──
export const checkSetupRequired = () =>
  request<{ setup_required: boolean }>("/auth/setup-required");

export const login = (username: string, password: string) =>
  request<TokenResponse>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });

export const setup = (username: string, email: string, password: string) =>
  request<TokenResponse>("/auth/setup", {
    method: "POST",
    body: JSON.stringify({ username, email, password }),
  });

export const getMe = () => request<UserInfo>("/auth/me");

// ── Health ──
export const getHealth = () => request<{ status: string }>("/health");

// ── Briefing ──
export const getBriefing = () =>
  request<{ briefing: string; context: Record<string, number>; degraded: boolean }>("/briefing");

// ── Triage ──
export const getQueue = (limit = 50) =>
  request<{ alerts: Alert[]; total: number }>(`/triage/queue?limit=${limit}`);

export const getHistory = (limit = 50) =>
  request<{ alerts: Alert[]; total: number }>(`/triage/history?limit=${limit}`);

export const disposeAlert = (alertId: string, verdict: string, notes = "") =>
  request("/triage/disposition", {
    method: "POST",
    body: JSON.stringify({ alert_id: alertId, verdict, notes, analyst: "analyst" }),
  });

export const getTriageStatus = () => request<TriageStatus>("/triage/status");

// ── Investigation ──
export const investigate = (message: string, sessionId?: string) =>
  request<InvestigationResponse>("/investigation/query", {
    method: "POST",
    body: JSON.stringify({ message, session_id: sessionId }),
  });

export const getTimeline = (target: string, hours = 24) =>
  request<TimelineResponse>(`/investigation/timeline?target=${encodeURIComponent(target)}&hours=${hours}`);

// ── Reports ──
export const getExecutiveReport = (days = 7) =>
  request<Report>(`/reports/executive?days=${days}`);

export const generateIncidentReport = (alertIds: string[], title = "") =>
  request<Report>("/reports/incident", {
    method: "POST",
    body: JSON.stringify({ alert_ids: alertIds, title }),
  });

export const getEvidencePackage = (days = 30) =>
  request<Report>(`/reports/evidence?days=${days}`);

// ── Compliance ──
export const getFrameworks = () => request<Framework[]>("/compliance/frameworks");
export const getProfiles = () => request<Profile[]>("/compliance/profiles");
export const getCoverage = (frameworkId: string) =>
  request<CoverageData>(`/compliance/frameworks/${frameworkId}/coverage`);

// ── Connectors ──
export const getConnectorCatalog = () => request<ConnectorType[]>("/connectors/catalog");
export const getConnectorSources = () => request<ConnectorSource[]>("/connectors/sources");

// ── Recon ──
export const dnsLookup = (target: string) =>
  request(`/recon/dns?target=${encodeURIComponent(target)}`);

export const portScan = (target: string, ports?: string) =>
  request("/recon/port-scan", {
    method: "POST",
    body: JSON.stringify({ target, ports }),
  });

// ── Vulns ──
export const getVulnSummary = () => request("/vulns/summary");
export const getVulnResults = (taskId: string) => request(`/vulns/results/${taskId}`);

// ── Score ──
export const getScore = () => request<ScoreData>("/m/score");
export const getTickets = () => request<{ tickets: Ticket[] }>("/m/tickets");

// ── Types ──
export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  username: string;
  role: string;
}

export interface UserInfo {
  id: string;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
}

export interface Alert {
  id: string;
  severity: string;
  rule_id: string;
  rule_description: string;
  agent_name: string | null;
  created_at: string;
  llm_triage: {
    severity?: string;
    explanation?: string;
    recommended_actions?: string[];
    confidence?: number;
  } | null;
  raw_event: Record<string, unknown>;
  disposition?: {
    verdict: string;
    analyst: string;
    notes: string | null;
  } | null;
}

export interface TriageStatus {
  pipeline_running: boolean;
  ollama_healthy: boolean;
  total_processed: number;
  queue_depth: number;
  degraded: boolean;
}

export interface InvestigationResponse {
  response: string;
  session_id: string;
  context_used: number;
  context_sources: { postgres: number; wazuh_indexer: number };
  filters_applied: Record<string, string>;
  degraded: boolean;
}

export interface TimelineResponse {
  target: string;
  hours: number;
  event_count: number;
  events: TimelineEvent[];
}

export interface TimelineEvent {
  time: string;
  source: string;
  severity?: string;
  severity_level?: number;
  rule_id: string;
  description: string;
  agent: string;
  src_ip: string;
  verdict?: string;
  log_excerpt?: string;
}

export interface Report {
  report_type: string;
  generated_at: string;
  narrative: string;
  data: Record<string, unknown>;
  degraded: boolean;
  period?: { since: string; until: string };
}

export interface Framework {
  id: string;
  name: string;
  description: string;
  version: string;
  families: Record<string, unknown>;
}

export interface Profile {
  id: string;
  framework_id: string;
  activated_at: string;
}

export interface CoverageData {
  framework: string;
  coverage: Record<string, unknown>;
}

export interface ConnectorType {
  id: string;
  name: string;
  category: string;
  icon: string;
  auth_method: string;
}

export interface ConnectorSource {
  id: string;
  connector_type: string;
  name: string;
  status: string;
  event_count: number;
  last_event_at: string | null;
}

export interface ScoreData {
  pono_score: number;
  trend: string;
  xp: number;
  streak: number;
  today_count: number;
  avg_response_minutes: number;
  badges: string[];
}

export interface Ticket {
  id: string;
  title: string;
  severity: string;
  status: string;
  created_at: string;
  alert_id: string;
}
