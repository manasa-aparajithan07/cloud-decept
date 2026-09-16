import { create } from 'zustand';
import {
  DashboardState,
  Session,
  Command,
  AuthEvent,
  ThreatIntelligenceEvent,
  ThreatIntelItem,
  MitreTechniqueCount,
  TopCommand,
  TopAttacker,
  Stats,
  RealTimeEvent,
} from './types';
import { api } from './api';

interface ConnectionStatus {
  connected: boolean;
  status: string;
  clickhouse: string;
  postgres: string;
  redis: string;
  timestamp: string;
  error?: string;
  lastChecked: number;
}

interface DashboardActions {
  // Global Commands & Auth
  fetchGlobalCommands: (params?: { limit?: number; offset?: number; session_id?: string; command?: string; attacker_ip?: string; intent?: string; hours?: number; include_synthetic?: boolean }) => Promise<void>;
  fetchGlobalAuth: (params?: { limit?: number; offset?: number; session_id?: string; username?: string; success?: boolean; hours?: number }) => Promise<void>;
  fetchAuthStats: (hours?: number) => Promise<void>;

  // Sessions
  fetchSessions: (params?: { status?: string; limit?: number; offset?: number; hours?: number; intent?: string; min_skill_level?: number; attacker_ip?: string; session_id?: string; has_commands?: boolean; auth_success?: boolean }) => Promise<void>;
  fetchSession: (sessionId: string) => Promise<void>;
  fetchSessionCommands: (sessionId: string) => Promise<void>;
  fetchSessionAuth: (sessionId: string) => Promise<void>;
  fetchSessionThreatIntel: (sessionId: string) => Promise<void>;
  searchSessions: (query: string) => Promise<void>;
  setSelectedSession: (session: Session | null) => void;

  // Analytics & Threat Intelligence
  fetchThreatIntelItems: (params?: { limit?: number; severity?: string; ioc_type?: string }) => Promise<void>;
  fetchMitreTechniques: () => Promise<void>;
  fetchTopCommands: (hours?: number, limit?: number) => Promise<void>;
  fetchTopAttackers: (hours?: number, limit?: number, sort_by?: string) => Promise<void>;

  // Stats
  fetchStats: (hours?: number) => Promise<void>;
  fetchAllTimeStats: () => Promise<void>;

  // Connection status
  fetchConnectionStatus: () => Promise<ConnectionStatus>;
  connectionStatus: ConnectionStatus | null;

  // Real-time events
  addRealTimeEvent: (event: RealTimeEvent) => void;
  clearRealTimeEvents: () => void;
  setConnected: (connected: boolean) => void;
  setLiveConnected: (connected: boolean) => void;

  // Filters
  setFilters: (filters: Partial<DashboardState['filters']>) => void;
  resetFilters: () => void;

  // Subscriptions
  subscribeToEvents: () => () => void;

  // Time Window Control
  timeWindowHours: number;
  setTimeWindowHours: (hours: number) => void;
}

const defaultFilters = {
  status: 'all',
  intent: 'all',
  country: 'all',
  dateRange: [undefined, undefined] as [Date | undefined, Date | undefined],
};

// Transform backend session data to include UI-compatible fields with strictly separated lifecycle, auth outcome, and shell status
export function transformSession(s: any): Session {
  if (!s || typeof s !== 'object') {
    return {
      session_id: '',
      attacker_ip: '',
      start_time: new Date().toISOString(),
      commands_executed: 0,
      lifecycle_status: 'closed',
      auth_outcome: 'unknown',
      shell_status: 'not_granted',
      status: 'closed',
    } as Session;
  }

  const startTimeMs = s.start_time ? new Date(s.start_time).getTime() : Date.now();
  const nowMs = Date.now();
  const ageSeconds = Math.max(0, Math.floor((nowMs - startTimeMs) / 1000));

  const hasExplicitEnd = Boolean(
    s.end_time &&
    !String(s.end_time).startsWith('1970') &&
    s.end_time !== s.start_time &&
    (s.duration_seconds > 0 || (s.duration && s.duration > 0) || s.disconnection_reason)
  );

  const cmdCount = Number(s.commands_executed ?? s.command_count ?? 0);
  const credsCount = Number(s.credentials_tried ?? s.auth_attempts ?? 0);

  // 1. Session Lifecycle Status (transport/socket connection lifecycle)
  let lifecycle_status: 'active' | 'closed' | 'timed_out' | 'stale' = 'closed';
  if (s.lifecycle_status === 'active' || s.status === 'active' || (!hasExplicitEnd && ageSeconds < 300)) {
    lifecycle_status = 'active';
  } else if (!hasExplicitEnd && ageSeconds < 3600) {
    lifecycle_status = 'timed_out';
  } else if (!hasExplicitEnd && ageSeconds >= 3600) {
    lifecycle_status = 'stale';
  } else {
    lifecycle_status = 'closed';
  }

  // 2. Shell Status (interactive shell granted only if commands were executed)
  const shell_status: 'granted' | 'not_granted' = cmdCount > 0 ? 'granted' : 'not_granted';

  // 3. Authentication Outcome (strictly separate from lifecycle status & shell execution)
  let auth_outcome: 'accepted' | 'rejected' | 'incomplete' | 'unknown' = 'unknown';
  const hasExplicitAuthSuccess = s.auth_success === true || s.auth_outcome === 'accepted';
  if (hasExplicitAuthSuccess) {
    auth_outcome = 'accepted';
  } else if (cmdCount > 0) {
    // Commands exist AND auth success telemetry is missing/unrecorded
    auth_outcome = 'incomplete';
  } else if (s.auth_success === false || s.auth_outcome === 'rejected' || credsCount > 0) {
    auth_outcome = 'rejected';
  } else {
    auth_outcome = 'unknown';
  }

  // 4. Legacy status: if shell was granted, it can NEVER be 'failed'
  let status: 'active' | 'closed' | 'failed' | 'timed_out' | 'stale' = 'closed';
  if (lifecycle_status === 'active') {
    status = 'active';
  } else if (shell_status === 'not_granted' && auth_outcome === 'rejected') {
    status = 'failed';
  } else if (lifecycle_status === 'timed_out') {
    status = 'timed_out';
  } else if (lifecycle_status === 'stale') {
    status = 'stale';
  } else {
    status = 'closed';
  }

  return {
    ...s,
    src_ip: s.attacker_ip || s.src_ip || '',
    src_country: s.country || s.src_country || '',
    command_count: cmdCount,
    commands_executed: cmdCount,
    credentials_tried: credsCount,
    lifecycle_status,
    auth_outcome,
    shell_status,
    status,
    auth_success: hasExplicitAuthSuccess,
    intent_history: s.intent ? [s.intent] : (s.intent_history || []),
    skill_level: typeof s.skill_level === 'number' ? s.skill_level : 0,
    threat_score: typeof s.skill_level === 'number' ? s.skill_level : 0,
    tactics: s.tactics || [],
  };
}

let statsFetchPromise: Promise<any> | null = null;

let eventBuffer: RealTimeEvent[] = [];
let batchTimeout: ReturnType<typeof setTimeout> | null = null;

export const useDashboardStore = create<DashboardState & DashboardActions>((set, get) => ({
  // State
  sessions: [],
  selectedSession: null,
  commands: [],
  sessionAuth: [],
  globalCommands: [],
  globalCommandsLoading: false,
  globalAuth: [],
  globalAuthLoading: false,
  authStats: null,
  authStatsLoading: false,
  threatIntel: null,
  threatIntelItems: [],
  mitreTechniques: [],
  topCommands: [],
  topAttackers: [],
  stats: null,
  statsLoading: false,
  statsError: null,
  sessionsLoading: false,
  sessionsError: null,
  realTimeEvents: [],
  isConnected: false,
  isLiveConnected: false,
  liveEventCount: 0,
  connectionStatus: null,
  filters: defaultFilters,
  timeWindowHours: 24,

  // Actions
  fetchGlobalCommands: async (params) => {
    set({ globalCommandsLoading: true });
    try {
      const data = await api.getCommands(params);
      set({ globalCommands: data || [], globalCommandsLoading: false });
    } catch (e) {
      console.error('Failed to fetch global commands:', e);
      set({ globalCommands: [], globalCommandsLoading: false });
    }
  },

  fetchGlobalAuth: async (params) => {
    set({ globalAuthLoading: true });
    try {
      const data = await api.getAuthAttempts(params);
      set({ globalAuth: data || [], globalAuthLoading: false });
    } catch (e) {
      console.error('Failed to fetch global auth:', e);
      set({ globalAuth: [], globalAuthLoading: false });
    }
  },

  fetchAuthStats: async (hours) => {
    set({ authStatsLoading: true });
    try {
      const data = await api.getAuthStats(hours);
      set({ authStats: data || null, authStatsLoading: false });
    } catch (e) {
      console.error('Failed to fetch auth stats:', e);
      set({ authStats: null, authStatsLoading: false });
    }
  },
  setTimeWindowHours: (hours) => {
    set({ timeWindowHours: hours });
    get().fetchStats(hours);
  },
  fetchSessions: async (params) => {
    set({ sessionsLoading: true, sessionsError: null });
    try {
      const data = await api.getSessions(params);
      const transformed = (data.sessions || []).map(transformSession);
      set({ sessions: transformed, sessionsLoading: false, sessionsError: null });
    } catch (error: any) {
      console.error('Failed to fetch sessions:', error);
      set({ sessions: [], sessionsLoading: false, sessionsError: error?.message || 'Failed to load sessions' });
    }
  },

  fetchSession: async (sessionId) => {
    try {
      const session = await api.getSession(sessionId);
      set({ selectedSession: transformSession(session) });
    } catch (error) {
      console.error('Failed to fetch session:', error);
      set({ selectedSession: null });
    }
  },

  fetchSessionCommands: async (sessionId) => {
    try {
      const data = await api.getSessionCommands(sessionId);
      set({ commands: data.commands || [] });
    } catch (error) {
      console.error('Failed to fetch commands:', error);
      set({ commands: [] });
    }
  },

  fetchSessionAuth: async (sessionId) => {
    try {
      const data = await api.getSessionAuth(sessionId);
      set({ sessionAuth: data.auth_events || [] });
    } catch (error) {
      console.error('Failed to fetch auth:', error);
      set({ sessionAuth: [] });
    }
  },

  fetchSessionThreatIntel: async (sessionId) => {
    try {
      const data = await api.getThreatIntel(sessionId);
      set({ threatIntel: data });
    } catch (error) {
      console.error('Failed to fetch threat intel:', error);
      set({ threatIntel: null });
    }
  },

  searchSessions: async (query: string) => {
    try {
      if (!query || query.trim() === '') {
        await get().fetchSessions();
        return;
      }
      const data = await api.searchSessions(query.trim(), 50);
      set({ sessions: (data || []).map(transformSession) });
    } catch (error) {
      console.error('Failed to search sessions:', error);
    }
  },

  fetchThreatIntelItems: async (params) => {
    try {
      const items = await api.listThreatIntel(params);
      set({ threatIntelItems: items });
    } catch (error) {
      console.error('Failed to fetch threat intel items:', error);
      set({ threatIntelItems: [] });
    }
  },

  fetchMitreTechniques: async () => {
    try {
      const techniques = await api.getMitreTechniques();
      set({ mitreTechniques: techniques });
    } catch (error) {
      console.error('Failed to fetch MITRE techniques:', error);
      set({ mitreTechniques: [] });
    }
  },

  fetchTopCommands: async (hours = 24, limit = 20) => {
    try {
      const top = await api.getTopCommands({ hours, limit });
      set({ topCommands: top });
    } catch (error) {
      console.error('Failed to fetch top commands:', error);
      set({ topCommands: [] });
    }
  },

  fetchTopAttackers: async (hours = 168, limit = 20, sort_by?: string) => {
    try {
      const top = await api.getTopAttackers({ hours, limit, sort_by });
      set({ topAttackers: top });
    } catch (error) {
      console.error('Failed to fetch top attackers:', error);
      set({ topAttackers: [] });
    }
  },

  setSelectedSession: (session) => {
    set({ selectedSession: session });
    if (session) {
      get().fetchSessionCommands(session.session_id);
      get().fetchSessionAuth(session.session_id);
      get().fetchSessionThreatIntel(session.session_id);
    } else {
      set({ commands: [], sessionAuth: [], threatIntel: null });
    }
  },

  fetchStats: async (hours: number = 24) => {
    if (typeof window !== 'undefined') {


    }
    // If a fetch is already in flight, return the shared promise
    if (statsFetchPromise) {
      return statsFetchPromise;
    }
    set({ statsLoading: true, statsError: null });
    statsFetchPromise = (async () => {
      try {
        const rawData = await api.getStats(hours);
        if (typeof window !== 'undefined') {

        }
        const data = (rawData as any)?.stats || (rawData as any)?.data || rawData;
        if (typeof window !== 'undefined') {

        }
        set({ stats: data, statsLoading: false, statsError: null });
        if (typeof window !== 'undefined') {

        }
        return data;
      } catch (error: any) {
        console.error('[CloudDecept] STATS FETCH ERROR:', error);
        set({ statsLoading: false, statsError: error?.message || 'Failed to load statistics' });
      } finally {
        statsFetchPromise = null;
      }
    })();
    return statsFetchPromise;
  },

  fetchAllTimeStats: async () => {
    return get().fetchStats(24);
  },

  // Unified connection status
  fetchConnectionStatus: async () => {
    try {
      const status = await api.checkConnection();
      set({
        connectionStatus: status,
        isConnected: status.connected,
      });
      return status;
    } catch (error) {
      const status: ConnectionStatus = {
        connected: false,
        status: 'error',
        clickhouse: 'unknown',
        postgres: 'unknown',
        redis: 'unknown',
        timestamp: new Date().toISOString(),
        error: error instanceof Error ? error.message : 'Unknown error',
        lastChecked: Date.now(),
      };
      set({ connectionStatus: status, isConnected: false });
      return status;
    }
  },

  addRealTimeEvent: (event) => {
    // Ignore internal connection events from the backend
    if (event && (event as any).type === "connected") return;
    
    eventBuffer.push(event);
    
    // STRICT RAW BUFFER BOUNDS (Phase 13 Final Validation)
    if (eventBuffer.length > 500) {
      eventBuffer = eventBuffer.slice(-100);
    }
    
    set(state => ({ liveEventCount: state.liveEventCount + 1 }));
    
    if (!batchTimeout) {
      batchTimeout = setTimeout(() => {
        // Prevent buffer from growing unbounded if interval is delayed
        const toAdd = eventBuffer.slice(-100).reverse(); // take most recent 100, newest first
        set((state) => ({
          realTimeEvents: [...toAdd, ...state.realTimeEvents].slice(0, 100),
        }));
        eventBuffer = [];
        batchTimeout = null;
      }, 500); // 500ms batching interval
    }
  },

  clearRealTimeEvents: () => {
    set({ realTimeEvents: [] });
  },

  setLiveConnected: (connected) => {
    set({ isLiveConnected: connected });
  },

  setConnected: (connected) => {
    set({ isConnected: connected });
  },

  setFilters: (filters) => {
    set((state) => ({
      filters: { ...state.filters, ...filters },
    }));
    get().fetchSessions({ status: filters.status, intent: filters.intent });
  },

  resetFilters: () => {
    set({ filters: defaultFilters });
    get().fetchSessions();
  },

  subscribeToEvents: () => {
    let unsubscribe: (() => void) | null = null;
    try {
      unsubscribe = api.subscribeToEvents(
        (event) => get().addRealTimeEvent(event),
        () => get().setLiveConnected(true),
        () => get().setLiveConnected(false)
      );
    } catch (error) {
      console.error('Failed to subscribe to events:', error);
    }
    return () => {
      if (unsubscribe) unsubscribe();
    };
  },
}));
