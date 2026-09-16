export interface Session {
  session_id: string;
  attacker_ip: string;
  country?: string;
  start_time: string;
  end_time?: string;
  duration_seconds?: number;
  username?: string;
  password?: string;
  auth_success?: boolean;
  protocol?: string;
  commands_executed: number;
  files_transferred?: number;
  credentials_tried?: number;
  intent?: string;
  skill_level?: number;
  asn?: string;
  disconnection_reason?: string;

  // Computed/derived fields for UI compatibility
  src_ip?: string;
  src_country?: string;
  command_count?: number;
  intent_history?: string[];
  threat_score?: number;
  tactics?: string[];
  lifecycle_status?: 'active' | 'closed' | 'timed_out' | 'stale';
  auth_outcome?: 'accepted' | 'rejected' | 'incomplete' | 'unknown';
  shell_status?: 'granted' | 'not_granted';
  status?: 'active' | 'closed' | 'failed' | 'timed_out' | 'stale';
  assessment?: FinalAssessment;
}

export interface FinalAssessment {
  status: 'classified' | 'insufficient_evidence' | 'unknown' | 'not_analyzed';
  intent: string;
  threat_level: 'low' | 'medium' | 'high' | 'critical' | 'unclassified';
  threat_score: number;
  skill_level: number;
  mitre_techniques: string[];
  tactics: string[];
  confidence: number;
  evidence_count: number;
  analysis_status: 'completed' | 'insufficient_evidence' | 'pending';
  analyzed_at?: string | null;
  source: string;
  provenance: string;
}

export interface AdaptiveDeceptionRecord {
  status: 'NOT_EVALUATED' | 'EVALUATED_NO_ACTION' | 'PASSIVE_TELEMETRY' | 'DECEPTION_APPLIED' | 'FAILED';
  action_taken: boolean;
  decision: string;
  reason: string;
  strategy?: string;
  details?: Record<string, any>;
}

export interface ForensicCaseFile {
  case_id: string;
  exported_at: string;
  session: Session;
  attacker: {
    ip: string;
    country: string;
    asn?: string;
  };
  assessment: FinalAssessment;
  auth_attempts: AuthEvent[];
  commands: Command[];
  timeline: any[];
  threat_intel?: any;
  adaptive_deception?: AdaptiveDeceptionRecord | null;
}

export interface Command {
  event_id?: string;
  id?: string;
  session_id: string;
  timestamp: string;
  command: string;
  arguments?: string[];
  output?: string;
  exit_code?: number;
  duration_ms?: number;
  success?: boolean;
  intent?: string;
  intent_confidence?: number;
  mitre_techniques?: string[];
  attacker_ip?: string;
  country?: string;
  protocol?: string;
  source_class?: string;
}

export interface AuthEvent {
  event_id?: string;
  id?: string;
  session_id: string;
  timestamp: string;
  username: string;
  password: string;
  success: boolean;
  auth_method?: string;
  src_ip?: string;
  src_port?: number;
  attacker_ip?: string;
  country?: string;
}

export interface IOC {
  type: string;
  value: string;
  context?: string;
  confidence?: number;
  first_seen?: string;
}

export interface Technique {
  technique_id: string;
  name?: string;
  tactic?: string;
  severity?: string;
  trigger?: string;
  confidence?: number;
}

export interface SessionSummaryDetail {
  session_id: string;
  summary: string;
  intent: string;
  skill_level: number;
  mitre_techniques: string[];
  iocs: (IOC | Record<string, any>)[];
  created_at: string;
  // Compatibility fields
  primary_objective?: string;
  narrative?: string;
  techniques_summary?: string;
  iocs_of_interest?: string[];
  risk_level?: string;
  defensive_recommendations?: string[];
  generated_at?: string;
  model?: string;
}

// Backward-compatible alias
export type SessionSummary = SessionSummaryDetail;

export interface ThreatIntelligenceEvent {
  session_id?: string;
  timestamp?: string;
  iocs?: IOC[];
  techniques?: Technique[];
  tactic_summary?: Record<string, number>;
  summary?: SessionSummaryDetail;
}

export interface ThreatIntelItem {
  id: string;
  ioc_type: string;
  ioc_value: string;
  confidence: number;
  mitre_techniques: string[];
  mitre_tactics: string[];
  severity: string;
  context: string;
  enrichment: Record<string, any>;
  created_at: string;
}

export interface MitreTechniqueCount {
  technique: string;
  count: number;
}

export interface TopAttacker {
  attacker_ip: string;
  country: string;
  sessions?: number;
  total_sessions?: number;
  unique_sessions?: number;
  total_commands?: number;
  max_skill_level?: number;
  primary_intent?: string;
  last_seen?: string;
}

export interface AttackerDetail {
  attacker_ip: string;
  country: string;
  total_sessions: number;
  unique_sessions: number;
  first_seen?: string | null;
  last_seen?: string | null;
  total_commands: number;
  sessions_with_commands: number;
  total_auth_attempts: number;
  successful_auth_attempts: number;
  sessions_with_successful_auth: number;
  classified_sessions: number;
  unknown_sessions: number;
  unclassified_sessions: number;
  max_skill_level: number;
  primary_intent: string;
  recent_sessions: Session[];
  top_commands?: { command: string; executions: number; sessions: number }[];
}

export interface TopCommand {
  command: string;
  executions: number;
  unique_sessions: number;
  unique_sources?: number;
  external_attackers?: number;
  internal_sources?: number;
  external_executions?: number;
  internal_executions?: number;
  first_seen?: string | null;
  last_seen?: string | null;
}

export interface CommandSourceBreakdown {
  attacker_ip: string;
  country: string;
  source_class: string;
  executions: number;
  unique_sessions: number;
  first_seen?: string | null;
  last_seen?: string | null;
}

export interface CommandEventItem {
  event_id: string;
  session_id: string;
  timestamp: string;
  command: string;
  arguments?: string[];
  output?: string;
  exit_code?: number;
  duration_ms?: number;
  attacker_ip?: string;
  country?: string;
  protocol?: string;
  source_class?: string;
}

export interface CommandDataQuality {
  raw_physical_rows: number;
  attributable_events: number;
  excluded_synthetic_events: number;
  orphan_events: number;
}

export interface CommandSummary {
  command: string;
  total_executions: number;
  unique_sessions: number;
  unique_sources: number;
  external_attackers: number;
  internal_sources: number;
  external_executions: number;
  internal_executions: number;
  first_seen?: string | null;
  last_seen?: string | null;
  sources: CommandSourceBreakdown[];
  recent_events: CommandEventItem[];
  data_quality: CommandDataQuality;
}

export interface AdaptiveStrategy {
  name: string;
  description: string;
}

export interface AdaptationEvent {
  id?: string;
  session_id: string;
  timestamp: string;
  intent: string;
  strategy: string;
  action: string;
  success: boolean;
  details?: Record<string, unknown>;
}

export interface QuarantinedSessionsBreakdown {
  total: number;
  internal_infrastructure: number;
  synthetic_tests: number;
  orphan_sessions: number;
}

export interface DataIntegrityStore {
  total_commands_raw: number;
  orphan_commands: number;
  synthetic_commands: number;
  internal_commands: number;
  external_commands: number;
  total_sessions_raw: number;
  external_sessions: number;
  quarantined_sessions: number;
  total_auth_attempts_raw?: number;
  orphan_auth_attempts?: number;
  external_auth_attempts?: number;
  formula_balanced: boolean;
}

export interface AuthOutcomes {
  total_attempts: number;
  accepted_attempts: number;
  rejected_attempts: number;
  accepted_sessions: number;
  interactive_sessions: number;
  command_bearing_sessions?: number;
}

export interface Stats {
  // All-time totals (authoritative)
  total_sessions: number;
  total_commands: number;
  unique_attackers: number;

  // Authoritative external attacker metrics (Phase 3.2 truthful semantics)
  external_sessions?: number;
  external_commands?: number;
  external_auth_sessions?: number;
  quarantined_sessions?: QuarantinedSessionsBreakdown;
  interactive_sessions?: number;
  command_bearing_sessions?: number;
  unique_external_attackers?: number;
  auth_outcomes?: AuthOutcomes;
  data_integrity?: DataIntegrityStore;
  assessed_sessions_count?: number;
  unassessed_sessions_count?: number;

  // Recent window (configurable, default 24h)
  recent_sessions: number;
  recent_commands: number;
  recent_unique_attackers: number;

  // Active sessions
  active_sessions: number;

  // Aggregated data for charts
  top_intents: { intent: string; count: number }[];
  top_countries: { country: string; count: number; attackers?: number }[];
  threat_distribution: { level: string; count: number }[];
  sessions_per_hour: { hour: string; count: number; date?: string }[];
  commands_per_day: { date: string; count: number }[];
  sessions_per_day?: { date: string; count: number }[];
  successful_auth_sessions?: number;
}

export interface RealTimeEvent {
  type: 'session_start' | 'session_end' | 'command' | 'auth' | 'intent' | 'adaptation' | 'threat_intel';
  timestamp: string;
  data: unknown;
}

export interface DashboardState {
  sessions: Session[];
  selectedSession: Session | null;
  commands: Command[];
  sessionAuth: AuthEvent[];
  threatIntel: ThreatIntelligenceEvent | null;
  threatIntelItems: ThreatIntelItem[];
  mitreTechniques: MitreTechniqueCount[];
  topCommands: TopCommand[];
  topAttackers: TopAttacker[];
  stats: Stats | null;
  statsLoading: boolean;
  statsError: string | null;
  sessionsLoading: boolean;
  sessionsError: string | null;
  realTimeEvents: RealTimeEvent[];
  globalCommands: Command[];
  globalCommandsLoading: boolean;
  globalAuth: AuthEvent[];
  globalAuthLoading: boolean;
  authStats: AuthStats | null;
  authStatsLoading: boolean;
  isConnected: boolean;
  isLiveConnected: boolean;
  liveEventCount: number;
  filters: {
    status: string;
    intent: string;
    country: string;
    dateRange: [Date | undefined, Date | undefined];
  };
}

export interface AuthStats {
  total_probes: number;
  authenticated_sessions: number;
  unique_sources: number;
  unique_usernames: number;
  unique_passwords: number;
  top_usernames: { username: string; count: number }[];
  top_passwords: { password: string; count: number }[];
  auth_policy?: string;
  publickey_allowed?: boolean;
}

export interface MitreInterpretationItem {
  technique_id: string;
  interpretation: string;
}

export interface RiskAssessment {
  verified_severity: string;
  contextual_impact: string;
}

export interface AIForensicAnalysis {
  incident_summary: string;
  likely_intent: string;
  key_evidence: string[];
  attack_progression: string[];
  mitre_interpretation: MitreInterpretationItem[];
  risk_assessment: RiskAssessment | string;
  recommended_actions: string[];
  confidence: 'High' | 'Medium' | 'Low' | string;
  limitations: string[];
  analyzed_at?: string;
  model_used?: string;
}

export interface AIAnalysisResponse {
  session_id: string;
  analysis: AIForensicAnalysis;
  cached: boolean;
  evidence_hash?: string;
  model_used?: string;
  timestamp: string;
}