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

// ── Glance ──
export const getGlance = () => request<GlanceData>("/m/glance");

// ── Triage ──
export const getQueue = (limit = 50) =>
  request<{ alerts: Alert[]; total: number }>(`/triage/queue?limit=${limit}`);

export const getHistory = (limit = 50) =>
  request<{ alerts: Alert[]; total: number }>(`/triage/history?limit=${limit}`);

export const disposeAlert = (alertId: string, verdict: string, notes = "") =>
  request(`/triage/alerts/${alertId}/disposition`, {
    method: "POST",
    body: JSON.stringify({ verdict, analyst: "analyst", notes: notes || null }),
  });

export const getTriageStatus = () => request<TriageStatus>("/triage/status");

// ── Swipe Feed ──
export const getSwipeFeed = (limit = 10) =>
  request<SwipeFeedResponse>(`/m/feed?limit=${limit}`);
export const swipeAlert = (alertId: string, direction: string, analyst = "analyst") =>
  request<SwipeResult>(`/m/feed/${alertId}/swipe`, {
    method: "POST",
    body: JSON.stringify({ direction, analyst }),
  });

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
export const getFrameworks = () =>
  request<{ frameworks: Framework[] }>("/compliance/frameworks").then((r) => r.frameworks);
export const getProfiles = () =>
  request<{ profiles: Profile[] }>("/compliance/profiles").then((r) => r.profiles);
export const getCoverage = (frameworkId: string) =>
  request<CoverageData>(`/compliance/frameworks/${frameworkId}/coverage`);

// ── Connectors ──
export const getConnectorCatalog = () =>
  request<ConnectorCatalogResponse>("/connectors/catalog");
export const getConnectorSources = () => request<ConnectorSource[]>("/connectors/sources");
export const getConnectorOverview = () => request<ConnectorOverview>("/connectors/overview");
export const addConnectorSource = (body: {
  connector_type: string;
  name: string;
  config: Record<string, string>;
  credentials: Record<string, string>;
}) => request<ConnectorSource>("/connectors/sources", { method: "POST", body: JSON.stringify(body) });
export const testConnectorSource = (sourceId: string) =>
  request<ConnectorTestResult>(`/connectors/sources/${sourceId}/test`, { method: "POST" });
export const deleteConnectorSource = (sourceId: string) =>
  request(`/connectors/sources/${sourceId}`, { method: "DELETE" });
export const toggleConnectorSource = (sourceId: string) =>
  request<ConnectorSource>(`/connectors/sources/${sourceId}/toggle`, { method: "PATCH" });

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

// ── Pono Score ──
export const getPonoScore = () => request<PonoSnapshot | null>("/pono/current");
export const getPonoHistory = (limit = 100) =>
  request<PonoHistoryResponse>(`/pono/history?limit=${limit}`);
export const recalculatePono = () =>
  request<PonoSnapshot>("/pono/recalculate", { method: "POST" });
export const getPonoStatus = () =>
  request<{ loop_running: boolean }>("/pono/status");

// ── Validation ──
export const getValidationDrift = () => request<ValidationDrift>("/validation/drift");
export const getValidationRounds = (limit = 10) =>
  request<ValidationRoundsResponse>(`/validation/rounds?limit=${limit}`);
export const triggerValidation = (sampleSize = 13) =>
  request<ValidationRoundData>(`/validation/rounds?sample_size=${sampleSize}`, { method: "POST" });

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
  wazuh_alert_id: string;
  severity: string;
  rule_id: string;
  rule_description: string;
  agent_name: string | null;
  created_at: string;
  has_disposition: boolean;
  llm_explanation: string | null;
  degraded: boolean;
}

export interface GlanceData {
  color: string;
  count: number;
  headline: string;
  breakdown: { critical: number; high: number; medium: number; low: number; info: number };
  last_updated: string;
}

export interface TriageStatus {
  pipeline_running: boolean;
  ollama_healthy: boolean;
  total_processed: number;
  queue_depth: number;
  degraded: boolean;
}

export interface SwipeCard {
  id: string;
  severity: string;
  title: string;
  explanation: string;
  ai_verdict: string | null;
  ai_confidence: number;
  agent: string | null;
  source_ip: string | null;
  timestamp: string;
  recommended_actions: string[];
  controls: string[];
}

export interface SwipeFeedResponse {
  cards: SwipeCard[];
  remaining: number;
}

export interface SwipeResult {
  id: string;
  verdict: string;
  message: string;
  xp_earned: number;
  ticket_id: string | null;
  ticket_type: string | null;
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

export interface ConnectorField {
  name: string;
  label: string;
  type: string;
  required: boolean;
  placeholder: string;
  help_text: string;
}

export interface ConnectorType {
  id: string;
  name: string;
  category: string;
  icon: string;
  auth_method: string;
  description: string;
  events_per_day: string;
  setup_guide_url: string;
  fields: ConnectorField[];
}

export interface ConnectorCategory {
  id: string;
  name: string;
  count: number;
}

export interface ConnectorCatalogResponse {
  categories: ConnectorCategory[];
  connectors: ConnectorType[];
}

export interface ConnectorSource {
  id: string;
  connector_type: string;
  name: string;
  type_name: string;
  type_icon: string;
  category: string;
  status: string;
  events_today: number;
  events_total: number;
  last_event_at: string | null;
  error_message: string | null;
  created_at: string;
}

export interface ConnectorOverview {
  total_sources: number;
  active_sources: number;
  error_sources: number;
  events_today: number;
  categories: { id: string; sources: number; active: number; events_today: number }[];
}

export interface ConnectorTestResult {
  success: boolean;
  message: string;
  events_sample: number;
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

export interface PonoComponent {
  name: string;
  raw_score: number;
  weighted_score: number;
  max_points: number;
  assessed: boolean;
  label: string;
  evidence_age_days: number;
  details: Record<string, unknown> | null;
}

export interface PonoSnapshot {
  id: string;
  timestamp: string;
  pono_score: number;
  schema_version: string;
  components: PonoComponent[];
  biggest_gain: {
    component: string;
    current_score: number;
    max_points: number;
    available_gain: number;
    assessed: boolean;
  } | null;
  pono_drop: {
    event: string;
    current_score: number;
    previous_score: number;
    drop: number;
  } | null;
  trigger: string;
}

export interface PonoHistoryPoint {
  id: string;
  timestamp: string;
  pono_score: number;
  trigger: string;
}

export interface PonoHistoryResponse {
  snapshots: PonoHistoryPoint[];
  total: number;
  offset: number;
  limit: number;
}

export interface ValidationDrift {
  has_validation: boolean;
  drift_detected: boolean | null;
  validation_rate: number | null;
  pono_score_at_start: number | null;
  round_id: string | null;
  round_date: string | null;
}

export interface ValidationRoundData {
  id: string;
  started_at: string;
  sample_size: number;
  fleet_size: number;
  samples_passed: number;
  samples_failed: number;
  samples_unreachable: number;
  validation_rate: number | null;
  drift_detected: boolean | null;
  pono_score_at_start: number;
}

export interface ValidationRoundsResponse {
  rounds: ValidationRoundData[];
  total: number;
  offset: number;
  limit: number;
}
