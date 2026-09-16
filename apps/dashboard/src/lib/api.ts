import {
  Session,
  Command,
  AuthEvent,
  SessionSummaryDetail,
  ThreatIntelItem,
  MitreTechniqueCount,
  TopCommand,
  TopAttacker,
  AttackerDetail,
  CommandSummary,
  AdaptiveStrategy,
  Stats,
  AuthStats,
  AIAnalysisResponse,
} from './types';


const API_BASE = "/api/backend";
const COLLECTOR_BASE = "/api/collector";
const THREAT_INTEL_BASE = "/api/threat-intel";
const ADAPTIVE_BASE = "/api/adaptive";
const INTENT_BASE = "/api/intent";

async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    cache: 'no-store',
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`API Error: ${response.status} - ${error}`);
  }

  return response.json();
}

export const api = {
  // Sessions
  getSessions: (params?: {
    status?: string;
    limit?: number;
    offset?: number;
    hours?: number;
    intent?: string;
    min_skill_level?: number;
    attacker_ip?: string;
    session_id?: string;
    has_commands?: boolean;
    auth_success?: boolean;
  }) => {
    const search = new URLSearchParams();
    if (params?.limit) search.set('limit', params.limit.toString());
    if (params?.offset) search.set('offset', params.offset.toString());
    if (params?.hours) search.set('hours', params.hours.toString());
    if (params?.intent && params.intent !== 'all') search.set('intent', params.intent);
    if (params?.min_skill_level !== undefined) search.set('min_skill_level', params.min_skill_level.toString());
    if (params?.attacker_ip) search.set('attacker_ip', params.attacker_ip);
    if (params?.session_id) search.set('session_id', params.session_id);
    if (params?.has_commands !== undefined) search.set('has_commands', params.has_commands.toString());
    if (params?.auth_success !== undefined) search.set('auth_success', params.auth_success.toString());
    // Backend returns array directly: SessionSummary[]
    return fetchJson<any[]>(`${API_BASE}/sessions?${search}`).then(sessions => ({
      sessions: Array.isArray(sessions) ? sessions : [],
      total: Array.isArray(sessions) ? sessions.length : 0,
    }));
  },

  getSession: (sessionId: string): Promise<Session> =>
    fetchJson<Session>(`${API_BASE}/sessions/${sessionId}`),

  getSessionCommands: async (sessionId: string): Promise<{ commands: Command[] }> => {
    try {
      const data = await fetchJson<any>(`${API_BASE}/sessions/${sessionId}/commands?limit=500`);
      const list = Array.isArray(data) ? data : (data?.commands || []);
      const commands: Command[] = list.map((c: any) => ({
        ...c,
        id: c.event_id || c.id || `cmd-${Math.random().toString(36).slice(2, 8)}`,
        event_id: c.event_id || c.id,
        exit_code: c.exit_code,
        success: c.exit_code === 0 || c.success === true,
        arguments: c.arguments || [],
        mitre_techniques: c.mitre_techniques || [],
      }));
      return { commands };
    } catch (e) {
      console.warn(`Failed to fetch commands for ${sessionId}:`, e);
      return { commands: [] };
    }
  },

  getSessionAuth: async (sessionId: string): Promise<{ auth_events: AuthEvent[] }> => {
    try {
      const data = await fetchJson<any>(`${API_BASE}/sessions/${sessionId}/auth?limit=100`);
      const list = Array.isArray(data) ? data : (data?.auth_events || []);
      const auth_events: AuthEvent[] = list.map((a: any) => ({
        ...a,
        id: a.event_id || a.id,
        event_id: a.event_id || a.id,
      }));
      return { auth_events };
    } catch (e) {
      console.warn(`Failed to fetch auth for ${sessionId}:`, e);
      return { auth_events: [] };
    }
  },

  // Session Summary & Threat Analysis
  getSessionSummary: async (sessionId: string): Promise<SessionSummaryDetail> => {
    const data = await fetchJson<any>(`${API_BASE}/sessions/${sessionId}/summary`);
    return {
      session_id: data.session_id,
      summary: data.summary,
      narrative: data.summary,
      primary_objective: data.intent,
      intent: data.intent,
      skill_level: data.skill_level,
      mitre_techniques: data.mitre_techniques || [],
      iocs: data.iocs || [],
      created_at: data.created_at,
    };
  },

  getThreatIntel: async (sessionId: string): Promise<any> => {
    try {
      const summary = await api.getSessionSummary(sessionId);
      const uniqueTechs = Array.from(new Set(summary.mitre_techniques || []));
      return {
        session_id: summary.session_id,
        timestamp: summary.created_at,
        iocs: summary.iocs || [],
        techniques: uniqueTechs.map((t) => ({
          technique_id: t,
          name: t,
          tactic: 'Discovery',
          severity: 'medium',
          trigger: '',
          confidence: 0.85,
        })),
        tactic_summary: {},
        summary: {
          ...summary,
          mitre_techniques: uniqueTechs,
          primary_objective: summary.intent,
          narrative: summary.summary,
          risk_level: summary.skill_level >= 7 ? 'critical' : summary.skill_level >= 4 ? 'high' : 'low',
        },
      };
    } catch (e) {
      console.warn(`Session threat intel summary unavailable for ${sessionId}:`, e);
      return null;
    }
  },

  getCaseFile: (sessionId: string): Promise<any> =>
    fetchJson<any>(`${API_BASE}/sessions/${sessionId}/case-file`),

  getAssessment: (sessionId: string): Promise<any> =>
    fetchJson<any>(`${API_BASE}/sessions/${sessionId}/assessment`),

  // Threat Intel Listing & MITRE
  listThreatIntel: (params?: { limit?: number; severity?: string; ioc_type?: string }): Promise<ThreatIntelItem[]> => {
    const search = new URLSearchParams();
    if (params?.limit) search.set('limit', params.limit.toString());
    if (params?.severity && params.severity !== 'all') search.set('severity', params.severity);
    if (params?.ioc_type && params.ioc_type !== 'all') search.set('ioc_type', params.ioc_type);
    return fetchJson<ThreatIntelItem[]>(`${API_BASE}/threat-intel?${search}`).then((res) => (Array.isArray(res) ? res : []));
  },

  getMitreTechniques: (): Promise<MitreTechniqueCount[]> =>
    fetchJson<MitreTechniqueCount[]>(`${API_BASE}/mitre/techniques`).then((res) => (Array.isArray(res) ? res : [])),

  // Global Commands Forensics
  getCommands: (params?: { limit?: number; offset?: number; session_id?: string; command?: string; attacker_ip?: string; intent?: string; hours?: number; include_synthetic?: boolean }): Promise<Command[]> => {
    const search = new URLSearchParams();
    if (params?.limit) search.set("limit", params.limit.toString());
    if (params?.offset) search.set("offset", params.offset.toString());
    if (params?.session_id) search.set("session_id", params.session_id);
    if (params?.command) search.set("command", params.command);
    if (params?.attacker_ip) search.set("attacker_ip", params.attacker_ip);
    if (params?.intent && params.intent !== "all") search.set("intent", params.intent);
    if (params?.hours) search.set("hours", params.hours.toString());
    if (params?.include_synthetic) search.set("include_synthetic", "true");
    return fetchJson<Command[]>(`${API_BASE}/commands?${search}`).then((res) => (Array.isArray(res) ? res : []));
  },

  getCommandSummary: (command: string): Promise<CommandSummary> =>
    fetchJson<CommandSummary>(`${API_BASE}/commands/summary?command=${encodeURIComponent(command)}`),

  // Global Auth Attempts
  getAuthAttempts: (params?: { limit?: number; offset?: number; session_id?: string; username?: string; success?: boolean; hours?: number }): Promise<AuthEvent[]> => {
    const search = new URLSearchParams();
    if (params?.limit) search.set("limit", params.limit.toString());
    if (params?.offset) search.set("offset", params.offset.toString());
    if (params?.session_id) search.set("session_id", params.session_id);
    if (params?.username) search.set("username", params.username);
    if (params?.success !== undefined) search.set("success", params.success.toString());
    if (params?.hours) search.set("hours", params.hours.toString());
    return fetchJson<AuthEvent[]>(`${API_BASE}/auth?${search}`).then((res) => (Array.isArray(res) ? res : []));
  },

  getAuthStats: (hours?: number): Promise<AuthStats> => {
    const search = hours ? `?hours=${hours}` : '';
    return fetchJson<AuthStats>(`${API_BASE}/auth/stats${search}`).catch(() => ({
      total_probes: 0,
      authenticated_sessions: 0,
      unique_sources: 0,
      unique_usernames: 0,
      unique_passwords: 0,
      top_usernames: [],
      top_passwords: [],
      auth_policy: 'password_only',
      publickey_allowed: false,
    }));
  },

  // Analytics: Top Commands & Attackers
  getTopCommands: (params?: { limit?: number; hours?: number }): Promise<TopCommand[]> => {
    const search = new URLSearchParams();
    if (params?.limit) search.set('limit', params.limit.toString());
    if (params?.hours) search.set('hours', params.hours.toString());
    return fetchJson<TopCommand[]>(`${API_BASE}/commands/top?${search}`).then((res) => (Array.isArray(res) ? res : []));
  },

  getTopAttackers: (params?: { limit?: number; hours?: number; sort_by?: string }): Promise<TopAttacker[]> => {
    const search = new URLSearchParams();
    if (params?.limit) search.set('limit', params.limit.toString());
    if (params?.hours) search.set('hours', params.hours.toString());
    if (params?.sort_by) search.set('sort_by', params.sort_by);
    return fetchJson<TopAttacker[]>(`${API_BASE}/attackers/top?${search}`).then((res) => (Array.isArray(res) ? res : []));
  },

  getAttackerDetail: (attackerIp: string): Promise<AttackerDetail> =>
    fetchJson<AttackerDetail>(`${API_BASE}/attackers/${encodeURIComponent(attackerIp)}`),

  // Search Sessions
  searchSessions: (query: string, limit: number = 50): Promise<Session[]> => {
    const search = new URLSearchParams({ query, limit: limit.toString() });
    return fetchJson<any[]>(`${API_BASE}/search/sessions?${search}`, { method: 'POST' }).then((res) =>
      Array.isArray(res) ? res : []
    );
  },

  // Stats
  getStats: (hours?: number): Promise<Stats> => {
    const search = hours ? `?hours=${hours}` : '';
    return fetchJson<Stats>(`${API_BASE}/stats${search}`);
  },

  // Connection health check
  getHealth: () => api.checkConnection(),
  checkConnection: async () => {
    try {
      const response = await fetch(`${API_BASE}/health`);
      if (!response.ok) {
        return {
          connected: false,
          status: 'error',
          clickhouse: 'unknown',
          postgres: 'unknown',
          redis: 'unknown',
          timestamp: new Date().toISOString(),
          error: `HTTP ${response.status}`,
          lastChecked: Date.now(),
        };
      }
      const data = await response.json();
      return {
        connected: data.status === 'healthy' || data.status === 'degraded',
        status: data.status,
        clickhouse: data.clickhouse,
        postgres: data.postgres,
        redis: data.redis,
        timestamp: data.timestamp,
        lastChecked: Date.now(),
      };
    } catch (error) {
      return {
        connected: false,
        status: 'error',
        clickhouse: 'unknown',
        postgres: 'unknown',
        redis: 'unknown',
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : 'Unknown error',
        lastChecked: Date.now(),
      };
    }
  },

  // Adaptive Engine
  getAdaptiveStrategies: (): Promise<Record<string, AdaptiveStrategy>> =>
    fetchJson<Record<string, AdaptiveStrategy>>(`${ADAPTIVE_BASE}/strategies`).catch(() => ({})),

  getAdaptiveSession: (sessionId: string): Promise<any> =>
    fetchJson<any>(`${ADAPTIVE_BASE}/session/${sessionId}`).catch(() => null),

  // Intent Engine
  getIntentHistory: (sessionId: string) =>
    fetchJson<{ intents: any[] }>(`${INTENT_BASE}/sessions/${sessionId}/intents`).catch(() => ({ intents: [] })),

  // Collector
  getCollectorHealth: () =>
    fetchJson<any>(`${COLLECTOR_BASE}/health`),

  // Real-time events (SSE)
  analyzeSessionWithAI: (sessionId: string) => {
    return fetchJson<AIAnalysisResponse>(`${API_BASE}/sessions/${encodeURIComponent(sessionId)}/ai-analysis`, {
      method: 'POST',
    });
  },

  subscribeToEvents: (onEvent: (event: any) => void, onConnected?: () => void, onDisconnected?: () => void) => {

    if (typeof window === 'undefined') return () => {};
    try {
      const eventSource = new EventSource(`${COLLECTOR_BASE}/events/live`);
      eventSource.onopen = () => { if (onConnected) onConnected(); };
      eventSource.onmessage = (event) => {
        try {
          onEvent(JSON.parse(event.data));
        } catch (e) {
          console.error('Failed to parse SSE event:', e);
        }
      };
      eventSource.onerror = () => {
        if (onDisconnected) onDisconnected();
        eventSource.close();
      };
      return () => eventSource.close();
    } catch {
      return () => {};
    }
  },
};