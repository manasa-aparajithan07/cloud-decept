'use client';

import { useEffect, useState, useMemo, useCallback } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  Shield,
  Activity,
  Terminal,
  Target,
  KeyRound,
  AlertTriangle,
  Globe,
  Radio,
  Clock,
  ArrowRight,
  ExternalLink,
  ChevronRight,
  RefreshCw,
  Zap,
  Play,
  Pause,
  AlertOctagon,
  CheckCircle2,
  Lock,
  Cpu,
  Flame,
} from 'lucide-react';
import { cn, formatTimestamp, formatDuration } from '@/lib/utils';
import { useDashboardStore, transformSession } from '@/lib/store';
import { GeographicMap } from '@/components/GeographicMap';
import { getCountryName } from '@/lib/countries';
import { normalizeIntent } from '@/lib/intents';
import { evaluateThreat } from '@/lib/threatScore';
import { api } from '@/lib/api';
import { Session } from '@/lib/types';

export default function OverviewPage() {
  const router = useRouter();
  const {
    stats,
    statsLoading,
    fetchStats,
    sessions,
    fetchSessions,
    topAttackers,
    fetchTopAttackers,
    topCommands,
    fetchTopCommands,
    realTimeEvents,
    isLiveConnected,
    subscribeToEvents,
    timeWindowHours,
    connectionStatus,
    fetchConnectionStatus,
  } = useDashboardStore();

  const [livePaused, setLivePaused] = useState(false);
  const [interactiveSessions, setInteractiveSessions] = useState<Session[]>([]);

  // Subscribe to live SSE overlay
  useEffect(() => {
    const unsubscribe = subscribeToEvents();
    return () => unsubscribe();
  }, [subscribeToEvents]);

  // Fetch interactive sessions with commands across dataset for high-value triage
  useEffect(() => {
    api.getSessions({ has_commands: true, limit: 12, hours: 87600 })
      .then((res) => {
        const transformed = (res.sessions || []).map(transformSession);
        setInteractiveSessions(transformed);
      })
      .catch((err) => console.warn('Could not load interactive sessions:', err));
  }, []);

  // Fetch authoritative REST telemetry on mount & time window change
  useEffect(() => {
    fetchStats(timeWindowHours);
    fetchSessions({ hours: timeWindowHours, limit: 100 });
    fetchTopAttackers(timeWindowHours, 12, 'commands');
    fetchTopCommands(timeWindowHours, 10);
    fetchConnectionStatus();
  }, [fetchStats, fetchSessions, fetchTopAttackers, fetchTopCommands, fetchConnectionStatus, timeWindowHours]);

  const windowLabel =
    timeWindowHours >= 87600 ? 'ALL-TIME' :
    timeWindowHours === 1 ? 'LAST 1 HOUR' :
    timeWindowHours === 24 ? 'LAST 24 HOURS' :
    timeWindowHours === 168 ? 'LAST 7 DAYS' :
    timeWindowHours === 720 ? 'LAST 30 DAYS' : `LAST ${timeWindowHours}H`;

  // Filtered live events for display
  const displayedLiveEvents = useMemo(() => {
    if (livePaused) return [];
    return (realTimeEvents || []).slice(0, 15);
  }, [realTimeEvents, livePaused]);

  // Authoritative latest event timestamp from real telemetry
  const latestEventTime = useMemo(() => {
    if (realTimeEvents && realTimeEvents.length > 0 && realTimeEvents[0].timestamp) {
      return realTimeEvents[0].timestamp;
    }
    if (sessions && sessions.length > 0 && sessions[0].start_time) {
      return sessions[0].start_time;
    }
    return connectionStatus?.timestamp || null;
  }, [realTimeEvents, sessions, connectionStatus]);

  // Threat analyzed sessions count (sum of assessed severity levels)
  const analyzedSessionsCount = useMemo(() => {
    const dist = stats?.threat_distribution || [];
    return dist.reduce((acc, curr) => {
      const lvl = curr.level.toLowerCase();
      if (lvl === 'critical' || lvl === 'high' || lvl === 'medium' || lvl === 'low') {
        return acc + curr.count;
      }
      return acc;
    }, 0);
  }, [stats]);

  // Internal test run count from top commands
  const internalTestRunsCount = useMemo(() => {
    return (topCommands || []).reduce((acc, curr) => acc + (curr.internal_executions ?? 0), 0);
  }, [topCommands]);

  // High-Value Incidents: deterministic triage of meaningful sessions with commands or high threat
  const highValueIncidents = useMemo(() => {
    const candidateSessions = [
      ...(interactiveSessions || []),
      ...(sessions || []),
    ];

    const seen = new Set<string>();
    const uniqueCandidates: Session[] = [];
    for (const s of candidateSessions) {
      if (!seen.has(s.session_id)) {
        seen.add(s.session_id);
        uniqueCandidates.push(s);
      }
    }

    return uniqueCandidates
      .filter((s) => {
        const cmdCount = s.command_count || s.commands_executed || 0;
        const threatScore = s.threat_score ?? (s.skill_level ? s.skill_level * 10 : 0);
        // Minimum legitimate qualification:
        // A. Actual command execution (cmdCount > 0)
        // OR
        // B. Verified authentication success WITH significant threat evidence (threatScore >= 40)
        // Connection duration or failed probes must NEVER qualify.
        const isVerifiedAuth = s.auth_success === true;
        return cmdCount > 0 || (isVerifiedAuth && threatScore >= 40);
      })
      .sort((a, b) => {
        const cmdsA = a.command_count || a.commands_executed || 0;
        const cmdsB = b.command_count || b.commands_executed || 0;
        if (cmdsB !== cmdsA) return cmdsB - cmdsA; // 1. Most commands first (Story A ranks #1)

        const threatA = a.threat_score ?? (a.skill_level ? a.skill_level * 10 : 0);
        const threatB = b.threat_score ?? (b.skill_level ? b.skill_level * 10 : 0);
        if (threatB !== threatA) return threatB - threatA; // 2. Highest threat score

        const timeA = new Date(a.start_time).getTime();
        const timeB = new Date(b.start_time).getTime();
        if (timeB !== timeA) return timeB - timeA; // 3. Most recent start time

        // 4. Deterministic secondary tie-breaker (guarantees stable rendering)
        return (b.session_id || '').localeCompare(a.session_id || '');
      })
      .slice(0, 4);
  }, [sessions, interactiveSessions]);

  // Priority Attackers: prioritize interactive post-auth actors over pure brute-force sprayers
  const prioritizedAttackers = useMemo(() => {
    const raw = topAttackers || [];
    return [...raw].sort((a, b) => {
      const cmdsA = a.total_commands ?? 0;
      const cmdsB = b.total_commands ?? 0;
      // If one has executed commands and the other hasn't, prioritize the interactive one
      if (cmdsA > 0 && cmdsB === 0) return -1;
      if (cmdsB > 0 && cmdsA === 0) return 1;
      // If both have commands, sort by command count
      if (cmdsA !== cmdsB) return cmdsB - cmdsA;
      // Otherwise sort by total sessions
      const sessA = a.total_sessions || a.sessions || a.unique_sessions || 0;
      const sessB = b.total_sessions || b.sessions || b.unique_sessions || 0;
      return sessB - sessA;
    }).slice(0, 6);
  }, [topAttackers]);

  // Country data for geographic map
  const mapData = useMemo(() => {
    return (stats?.top_countries || []).map((c) => ({
      country: c.country,
      count: c.count,
    }));
  }, [stats]);

  const handleCountrySelect = useCallback((countryCode: string) => {
    router.push(`/sessions?country=${encodeURIComponent(countryCode)}`);
  }, [router]);

  return (
    <div className="space-y-5 font-mono pb-12">
      {/* 1. GLOBAL SECURITY HEADER */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-3 border-b border-cyan-500/20">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-cyan-950/60 border border-cyan-500/40">
              <Shield className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-lg sm:text-xl font-bold tracking-wider text-white uppercase flex items-center gap-2">
                <span>CLOUDDECEPT</span>
                <span className="text-slate-500 font-normal">|</span>
                <span className="text-cyan-400 font-semibold text-xs tracking-widest bg-cyan-950/50 px-2 py-0.5 rounded border border-cyan-500/30">
                  CYBER DECEPTION SOC
                </span>
              </h1>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Active Honeypot Telemetry & Adversary Deception Pipeline • Scope: <span className="text-cyan-300 font-semibold">{windowLabel}</span>
              </p>
            </div>
          </div>
        </div>

        {/* Real-time System Indicators (Truthful Telemetry) */}
        <div className="flex flex-wrap items-center gap-2 text-[10px]">
          {/* API Health */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#070e22] border border-cyan-500/20">
            <span className={cn('w-1.5 h-1.5 rounded-full', connectionStatus?.connected ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400')} />
            <span className="text-slate-400">API:</span>
            <span className={cn('font-bold', connectionStatus?.connected ? 'text-emerald-300' : 'text-rose-300')}>
              {connectionStatus?.connected ? 'ONLINE' : 'OFFLINE'}
            </span>
          </div>

          {/* ClickHouse Status */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#070e22] border border-cyan-500/20">
            <span className={cn('w-1.5 h-1.5 rounded-full', connectionStatus?.clickhouse === 'healthy' ? 'bg-emerald-400' : 'bg-amber-400')} />
            <span className="text-slate-400">TELEMETRY:</span>
            <span className="text-slate-200 font-bold">CLICKHOUSE</span>
          </div>

          {/* Live SSE Stream */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#070e22] border border-cyan-500/20">
            <Radio className={cn('w-3 h-3', isLiveConnected ? 'text-emerald-400 animate-pulse' : 'text-slate-500')} />
            <span className="text-slate-400">FEED:</span>
            <span className={cn('font-bold', isLiveConnected ? 'text-emerald-300' : 'text-slate-400')}>
              {isLiveConnected ? 'LIVE STREAM' : 'REST POLLING'}
            </span>
          </div>

          {/* Latest Event Time */}
          {latestEventTime && (
            <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#070e22] border border-cyan-500/20 text-slate-400">
              <Clock className="w-3 h-3 text-cyan-400" />
              <span>LAST EVENT:</span>
              <span className="text-cyan-300 font-bold">{formatTimestamp(latestEventTime)}</span>
            </div>
          )}

          <button
            onClick={() => {
              fetchStats(timeWindowHours);
              fetchSessions({ hours: timeWindowHours, limit: 100 });
              fetchTopAttackers(timeWindowHours, 12);
              fetchTopCommands(timeWindowHours, 10);
              fetchConnectionStatus();
            }}
            className="p-1.5 rounded-md bg-[#070e22] border border-cyan-500/25 text-slate-300 hover:text-cyan-300 hover:border-cyan-400 transition-all"
            title="Refresh dashboard telemetry"
          >
            <RefreshCw className={cn('w-3.5 h-3.5 text-cyan-400', statsLoading && 'animate-spin')} />
          </button>
        </div>
      </div>

      {/* ADVERSARY INVESTIGATION WORKFLOW STRIP */}
      <div className="p-3 rounded-xl bg-[#070e22] border border-cyan-500/20 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px]">
            FORENSIC ATTACK PATHWAY:
          </span>
          <span className="text-slate-200 font-semibold text-[11px]">
            Attacker IP → Auth Probe → Shell Commands → MITRE ATT&CK → Case File
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-[11px]">
          <Link
            href="/attackers"
            className="px-2.5 py-1 rounded bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-500/30 text-cyan-300 font-bold flex items-center gap-1 transition-all"
          >
            <span>External Attackers</span>
            <ChevronRight className="w-3 h-3" />
          </Link>
          <Link
            href="/sessions?filter=commands"
            className="px-2.5 py-1 rounded bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-500/30 text-emerald-300 font-bold flex items-center gap-1 transition-all"
          >
            <span>Interactive Sessions (With Commands)</span>
            <ChevronRight className="w-3 h-3" />
          </Link>
          <Link
            href="/sessions/9707d005efc0"
            className="px-2.5 py-1 rounded bg-purple-950/80 hover:bg-purple-900 border border-purple-500/30 text-purple-300 font-bold flex items-center gap-1 transition-all"
            title="Demonstration: Actor 175.207.59.187 executing 17 discovery commands"
          >
            <span>Story A Case File</span>
            <ExternalLink className="w-3 h-3" />
          </Link>
        </div>
      </div>

      {/* 2. CORE VERIFIED METRICS (Compact Above-the-Fold Strip) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5">
        {/* External Attackers */}
        <Link
          href="/attackers"
          className="p-3 rounded-lg bg-[#070e22] border border-cyan-500/20 hover:border-cyan-400 transition-all block group"
        >
          <div className="text-[10px] text-slate-400 uppercase flex items-center justify-between">
            <span>EXTERNAL ATTACKERS</span>
            <Target className="w-3 h-3 text-cyan-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="text-xl font-bold text-white mt-1">
            {timeWindowHours >= 87600
              ? (stats?.unique_attackers ?? 0).toLocaleString()
              : (stats?.recent_unique_attackers ?? 0).toLocaleString()}
          </div>
          <div className="text-[9px] text-cyan-300 font-semibold mt-0.5 tracking-wider flex items-center gap-1">
            <span>UNIQUE SOURCES</span>
            <ChevronRight className="w-2.5 h-2.5 opacity-60" />
          </div>
        </Link>

        {/* External Attacker Sessions */}
        <Link
          href="/sessions"
          className="p-3 rounded-lg bg-[#070e22] border border-cyan-500/20 hover:border-cyan-400 transition-all block group"
          title={`Authoritative external attacker sessions. Excludes ${stats?.quarantined_sessions?.total != null ? stats.quarantined_sessions.total : 71} quarantined internal/test/orphan sessions.`}
        >
          <div className="text-[10px] text-slate-400 uppercase flex items-center justify-between">
            <span>ATTACKER SESSIONS</span>
            <Activity className="w-3 h-3 text-cyan-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="text-xl font-bold text-white mt-1">
            {timeWindowHours >= 87600
              ? (stats?.external_sessions != null ? stats.external_sessions.toLocaleString() : (stats?.total_sessions ? (stats.total_sessions - (stats.quarantined_sessions?.total ?? 71)).toLocaleString() : '—'))
              : (stats?.recent_sessions ?? 0).toLocaleString()}
          </div>
          <div className="text-[9px] text-slate-400 mt-0.5 tracking-wider">
            {stats?.active_sessions ? (
              <span className="text-emerald-400 font-bold">{stats.active_sessions} ACTIVE NOW</span>
            ) : stats?.external_sessions != null ? (
              <span>{stats.external_sessions.toLocaleString()} EXTERNAL</span>
            ) : (
              <span>EXTERNAL SESSIONS</span>
            )}
          </div>
        </Link>

        {/* External Command Executions */}
        <Link
          href="/commands"
          className="p-3 rounded-lg bg-[#070e22] border border-cyan-500/20 hover:border-cyan-400 transition-all block group"
          title="Authoritative deduplicated external command executions. Excludes internal loopback and synthetic e2e runs."
        >
          <div className="text-[10px] text-slate-400 uppercase flex items-center justify-between">
            <span>COMMAND RUNS</span>
            <Terminal className="w-3 h-3 text-emerald-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="text-xl font-bold text-emerald-400 mt-1">
            {timeWindowHours >= 87600
              ? (stats?.external_commands != null ? stats.external_commands.toLocaleString() : '—')
              : (stats?.recent_commands ?? 0).toLocaleString()}
          </div>
          <div className="text-[9px] text-emerald-300/80 font-semibold mt-0.5 tracking-wider">
            {stats?.external_commands != null ? `${stats.external_commands.toLocaleString()} ATTRIBUTED` : 'ATTRIBUTED COMMANDS'}
          </div>
        </Link>

        {/* Successful Auth Sessions */}
        <Link
          href="/auth"
          className="p-3 rounded-lg bg-[#070e22] border border-cyan-500/20 hover:border-cyan-400 transition-all block group"
          title={stats?.external_auth_sessions != null
            ? `Accepted authentication sessions: ${stats.external_auth_sessions.toLocaleString()} external attacker sessions (${(stats.successful_auth_sessions ?? stats.external_auth_sessions).toLocaleString()} global total).`
            : 'Accepted authentication sessions'}
        >
          <div className="text-[10px] text-slate-400 uppercase flex items-center justify-between">
            <span>AUTH SUCCESSES</span>
            <KeyRound className="w-3 h-3 text-amber-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="text-xl font-bold text-amber-300 mt-1">
            {stats?.external_auth_sessions != null ? stats.external_auth_sessions.toLocaleString() : (stats?.successful_auth_sessions != null ? stats.successful_auth_sessions.toLocaleString() : '—')}
          </div>
          <div className="text-[9px] text-amber-400/80 font-semibold mt-0.5 tracking-wider">
            {stats?.external_auth_sessions != null ? (
              `${stats.external_auth_sessions.toLocaleString()} EXT (${(stats?.successful_auth_sessions ?? stats.external_auth_sessions).toLocaleString()} GLOBAL)`
            ) : (
              'AUTH ACTIVITY'
            )}
          </div>
        </Link>

        {/* Threat-Analyzed Sessions */}
        <Link
          href="/threat-intel"
          className="p-3 rounded-lg bg-[#070e22] border border-cyan-500/20 hover:border-cyan-400 transition-all block group"
        >
          <div className="text-[10px] text-slate-400 uppercase flex items-center justify-between">
            <span>ANALYZED SESSIONS</span>
            <Shield className="w-3 h-3 text-purple-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="text-xl font-bold text-purple-300 mt-1">
            {analyzedSessionsCount.toLocaleString()}
          </div>
          <div className="text-[9px] text-purple-400/80 font-semibold mt-0.5 tracking-wider">
            AI / HEURISTIC SCORED
          </div>
        </Link>

        {/* Internal / Test Runs (Quarantined) */}
        <div
          className="p-3 rounded-lg bg-[#070e22] border border-slate-700/60 relative overflow-hidden group"
          title={`Dataset-wide Quarantined: ${stats?.quarantined_sessions?.internal_infrastructure ?? '—'} internal infrastructure, ${stats?.quarantined_sessions?.synthetic_tests ?? '—'} synthetic tests, ${stats?.quarantined_sessions?.orphan_sessions ?? '—'} orphan`}
        >
          <div className="text-[10px] text-slate-400 uppercase flex items-center justify-between">
            <span>INTERNAL / TEST</span>
            <Cpu className="w-3 h-3 text-slate-500" />
          </div>
          <div className="text-xl font-bold text-slate-300 mt-1">
            {stats?.quarantined_sessions?.total != null ? stats.quarantined_sessions.total.toLocaleString() : '—'}
          </div>
          <div className="text-[9px] text-slate-400 mt-0.5 tracking-wider font-semibold truncate" title="Quarantined test and infrastructure sessions">
            {stats?.quarantined_sessions ? (
              `${stats.quarantined_sessions.internal_infrastructure} INFRA • ${stats.quarantined_sessions.synthetic_tests} TEST • ${stats.quarantined_sessions.orphan_sessions} ORPHAN`
            ) : (
              'QUARANTINED SESSIONS'
            )}
          </div>
        </div>
      </div>

      {/* 3. HIGH-VALUE ATTACK INCIDENTS (Deterministic Case Triage) */}
      <div className="rounded-xl border border-cyan-500/25 bg-[#070e22] overflow-hidden">
        <div className="p-3 bg-[#040816] border-b border-cyan-500/20 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Flame className="w-4 h-4 text-rose-400" />
            <h2 className="text-xs font-bold text-white uppercase tracking-wider">
              HIGH-VALUE ATTACK INCIDENTS — FORENSIC ACTION REQUIRED
            </h2>
          </div>
          <span className="text-[10px] text-slate-400">
            Sessions exhibiting post-auth execution, cloud reconnaissance, or payload staging
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 divide-y md:divide-y-0 md:divide-x divide-cyan-500/15">
          {highValueIncidents.length === 0 ? (
            <div className="col-span-full p-8 text-center text-xs text-slate-500">
              No high-value post-auth activity detected in the selected period.
            </div>
          ) : (
            highValueIncidents.map((s) => {
              const ip = s.src_ip || s.attacker_ip || 'unknown';
              const country = getCountryName(s.src_country || s.country);
              const cmdCount = s.command_count || s.commands_executed || 0;
              const threat = evaluateThreat(s.threat_score ?? (s.skill_level ? s.skill_level * 10 : 20));
              const intent = normalizeIntent(s.intent);

              return (
                <div key={s.session_id} className="p-3.5 space-y-2.5 hover:bg-cyan-950/20 transition-all flex flex-col justify-between">
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="font-bold text-white font-mono">{ip}</span>
                      <span className={cn('px-1.5 py-0.5 rounded text-[9px] font-bold border', threat.badgeClass)}>
                        {threat.label.toUpperCase()}
                      </span>
                    </div>

                    <div className="flex items-center gap-2 text-[10px] text-slate-400">
                      <span>{country}</span>
                      <span>•</span>
                      <span>{formatDuration(s.duration_seconds || 0)}</span>
                    </div>

                    <div className="p-2 rounded bg-[#040816] border border-cyan-500/15 space-y-1 text-[11px]">
                      <div className="flex items-center justify-between text-slate-300">
                        <span className="text-slate-500 text-[10px]">COMMANDS:</span>
                        <span className="font-bold text-emerald-400">{cmdCount} Executed</span>
                      </div>
                      <div className="flex items-center justify-between text-slate-300">
                        <span className="text-slate-500 text-[10px]">INTENT:</span>
                        <span className="text-cyan-300 font-semibold truncate max-w-[120px]">{intent.label}</span>
                      </div>
                      <div className="flex items-center justify-between text-slate-300">
                        <span className="text-slate-500 text-[10px]">AUTH:</span>
                        <span className={cn(
                          "font-semibold",
                          cmdCount > 0 || s.auth_success === true
                            ? "text-emerald-300"
                            : s.status === 'failed' || s.auth_success === false
                            ? "text-rose-400"
                            : "text-slate-400"
                        )}>
                          {cmdCount > 0
                            ? (s.username ? `${s.username} (shell)` : 'SHELL GRANTED')
                            : s.auth_success === true
                            ? (s.username ? `${s.username} (accepted)` : 'AUTH ACCEPTED')
                            : s.status === 'failed' || s.auth_success === false
                            ? 'AUTH REJECTED'
                            : 'AUTH UNKNOWN'}
                        </span>
                      </div>
                    </div>
                  </div>

                  <Link
                    href={`/sessions/${s.session_id}`}
                    className="w-full flex items-center justify-center gap-1.5 py-1.5 rounded bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/30 text-[10px] font-bold text-cyan-300 transition-all uppercase"
                  >
                    <span>INVESTIGATE CASE-{s.session_id.slice(0, 8).toUpperCase()}</span>
                    <ExternalLink className="w-2.5 h-2.5" />
                  </Link>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* 4. GEOGRAPHIC ATTACK ORIGINS & REAL-TIME EVENT STREAM */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left: World Attack Map */}
        <div className="lg:col-span-8 rounded-xl border border-cyan-500/20 bg-[#070e22] overflow-hidden flex flex-col">
          <div className="p-3 bg-[#040816] border-b border-cyan-500/15 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-bold text-white uppercase tracking-wider">
                GLOBAL ATTACK ORIGINS & ADVERSARY HOTSPOTS
              </span>
            </div>
            <span className="text-[10px] text-slate-400">
              Click any country hotspot to filter attack sessions
            </span>
          </div>

          <div className="flex-1 p-2 min-h-[340px] relative">
            <GeographicMap
              data={mapData}
              totalSessions={stats?.recent_sessions || stats?.total_sessions || 1}
              isLoading={statsLoading}
              onCountrySelect={handleCountrySelect}
            />
          </div>
        </div>

        {/* Right: Live Attack Activity Stream */}
        <div className="lg:col-span-4 rounded-xl border border-cyan-500/20 bg-[#070e22] overflow-hidden flex flex-col">
          <div className="p-3 bg-[#040816] border-b border-cyan-500/15 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Radio className={cn('w-4 h-4', isLiveConnected ? 'text-emerald-400 animate-pulse' : 'text-slate-500')} />
              <span className="text-xs font-bold text-white uppercase tracking-wider">
                LIVE ATTACK FEED
              </span>
            </div>

            <button
              onClick={() => setLivePaused(!livePaused)}
              className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-bold"
            >
              {livePaused ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}
              <span>{livePaused ? 'RESUME' : 'PAUSE'}</span>
            </button>
          </div>

          <div className="flex-1 p-3 space-y-2 overflow-y-auto max-h-[380px] scrollbar-thin">
            {!isLiveConnected && (
              <div className="p-2 rounded bg-cyan-950/30 border border-cyan-500/20 text-[10px] text-cyan-300">
                Operating under authoritative REST background polling.
              </div>
            )}

            {displayedLiveEvents.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500 space-y-2">
                <Clock className="w-6 h-6 text-slate-600 mx-auto" />
                <p>Waiting for fresh incoming adversary telemetry...</p>
                <p className="text-[10px] text-slate-600">Events stream live as external connections hit the honeypot.</p>
              </div>
            ) : (
              displayedLiveEvents.map((evt, idx) => {
                const data = (evt.data as any) || {};
                const eventType = evt.type || data.event_type || 'event';
                const sessionId = (evt as any).session_id || data.session_id || '';
                const attackerIp = (evt as any).attacker_ip || data.attacker_ip || 'unknown';

                return (
                  <div
                    key={idx}
                    className="p-2.5 rounded-lg bg-[#040816] border border-cyan-500/15 text-xs space-y-1 hover:border-cyan-500/40 transition-all font-mono"
                  >
                    <div className="flex items-center justify-between text-[10px]">
                      <span className="text-cyan-400 font-bold uppercase">{eventType}</span>
                      <span className="text-slate-500">{formatTimestamp(evt.timestamp || new Date().toISOString())}</span>
                    </div>

                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white">{attackerIp}</span>
                      {sessionId && (
                        <Link
                          href={`/sessions/${sessionId}`}
                          className="text-cyan-400 hover:underline text-[10px] flex items-center gap-0.5"
                        >
                          <span>{sessionId.slice(0, 8)}</span>
                          <ExternalLink className="w-2.5 h-2.5" />
                        </Link>
                      )}
                    </div>

                    {data.command && (
                      <div className="text-[11px] text-emerald-300 truncate bg-[#02050f] p-1 rounded">
                        $ {data.command}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>

      {/* 5. PRIORITY ATTACKERS & TOP EXECUTED COMMANDS */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Priority Attackers (Differentiating Command Actors vs High-Volume Sprayers) */}
        <div className="rounded-xl border border-cyan-500/20 bg-[#070e22] overflow-hidden">
          <div className="p-3 bg-[#040816] border-b border-cyan-500/15 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Target className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-bold text-white uppercase tracking-wider">
                PRIORITY THREAT ACTORS ({windowLabel})
              </span>
            </div>
            <Link
              href="/attackers"
              className="text-[10px] text-cyan-400 hover:underline flex items-center gap-1 font-bold"
            >
              <span>View All Dossiers</span>
              <ChevronRight className="w-3 h-3" />
            </Link>
          </div>

          <div className="divide-y divide-cyan-500/10">
            {prioritizedAttackers.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500">
                No external attacker activity recorded in this time window.
              </div>
            ) : (
              prioritizedAttackers.map((att) => {
                const threat = evaluateThreat(att.max_skill_level ?? 2);
                const country = getCountryName(att.country);
                const totalCmds = att.total_commands ?? 0;
                const totalSess = att.total_sessions || att.sessions || att.unique_sessions || 0;
                const isInteractive = totalCmds > 0;

                return (
                  <div
                    key={att.attacker_ip}
                    className="p-3 flex items-center justify-between hover:bg-cyan-950/20 transition-all text-xs"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white">{att.attacker_ip}</span>
                        <span className="text-slate-600">•</span>
                        <span className="text-slate-400 text-[11px]">{country}</span>
                        {isInteractive ? (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-500/30">
                            POST-AUTH COMMANDS
                          </span>
                        ) : (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-slate-900 text-slate-400 border border-slate-700">
                            CREDENTIAL SPRAYER
                          </span>
                        )}
                      </div>
                      <div className="text-[10px] text-slate-500 flex items-center gap-2">
                        <span>{normalizeIntent(att.primary_intent).label}</span>
                        <span>•</span>
                        <span className={cn('font-bold', threat.badgeClass)}>
                          TIER: {threat.label.toUpperCase()}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      <div className="text-right">
                        <span className="text-cyan-300 font-bold block">
                          {totalSess.toLocaleString()} Sessions
                        </span>
                        <span className={cn('text-[10px] font-bold block', isInteractive ? 'text-emerald-400' : 'text-slate-500')}>
                          {totalCmds.toLocaleString()} Cmds
                        </span>
                      </div>

                      <Link
                        href={`/attackers?ip=${encodeURIComponent(att.attacker_ip)}`}
                        className="p-1 rounded bg-cyan-500/15 text-cyan-300 hover:bg-cyan-500/30"
                        title="Investigate Attacker Dossier"
                      >
                        <ChevronRight className="w-4 h-4" />
                      </Link>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Top Executed Commands (Exact Phase 2B Verified) */}
        <div className="rounded-xl border border-cyan-500/20 bg-[#070e22] overflow-hidden">
          <div className="p-3 bg-[#040816] border-b border-cyan-500/15 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-bold text-white uppercase tracking-wider">
                ACTIVE BEHAVIORS / TOP COMMANDS ({windowLabel})
              </span>
            </div>
            <Link
              href="/commands"
              className="text-[10px] text-cyan-400 hover:underline flex items-center gap-1 font-bold"
            >
              <span>Command Explorer</span>
              <ChevronRight className="w-3 h-3" />
            </Link>
          </div>

          <div className="divide-y divide-cyan-500/10">
            {(topCommands || []).length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500">
                No shell commands executed in this time window.
              </div>
            ) : (
              (topCommands || []).slice(0, 6).map((cmd) => (
                <div
                  key={cmd.command}
                  className="p-3 flex items-center justify-between hover:bg-cyan-950/20 transition-all text-xs"
                >
                  <div className="space-y-1 truncate max-w-sm">
                    <div className="flex items-center gap-1.5 truncate">
                      <span className="text-emerald-400 font-bold">$</span>
                      <span className="font-bold text-white font-mono truncate">{cmd.command}</span>
                    </div>
                    <div className="text-[10px] text-slate-500 flex items-center gap-2">
                      <span className="text-emerald-400 font-semibold">{cmd.external_executions ?? cmd.executions} External Runs</span>
                      <span>•</span>
                      <span>{cmd.unique_sources ?? cmd.unique_sessions} External Sources</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 flex-shrink-0">
                    <div className="text-right">
                      <span className="text-emerald-400 font-bold block">
                        {cmd.unique_sessions} Sessions
                      </span>
                    </div>

                    <Link
                      href={`/commands?command=${encodeURIComponent(cmd.command)}&exact=true`}
                      className="p-1 rounded bg-cyan-500/15 text-cyan-300 hover:bg-cyan-500/30"
                      title="Explore exact command forensic dossier"
                    >
                      <ChevronRight className="w-4 h-4" />
                    </Link>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* 6. RECENT ATTACK SESSIONS TABLE */}
      <div className="rounded-xl border border-cyan-500/20 bg-[#070e22] overflow-hidden">
        <div className="p-3 bg-[#040816] border-b border-cyan-500/15 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-bold text-white uppercase tracking-wider">
              RECENT ATTACK SESSIONS ({windowLabel})
            </span>
          </div>
          <Link
            href="/sessions"
            className="text-[10px] text-cyan-400 hover:underline flex items-center gap-1 font-bold"
          >
            <span>View All Sessions</span>
            <ExternalLink className="w-2.5 h-2.5" />
          </Link>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#040816] text-[10px] text-slate-400 uppercase border-b border-cyan-500/15">
              <tr>
                <th className="py-2.5 px-4">STATUS</th>
                <th className="py-2.5 px-4">CASE FILE</th>
                <th className="py-2.5 px-4">ATTACKER IP</th>
                <th className="py-2.5 px-4">ORIGIN</th>
                <th className="py-2.5 px-4">DURATION</th>
                <th className="py-2.5 px-4">COMMANDS</th>
                <th className="py-2.5 px-4">INTENT</th>
                <th className="py-2.5 px-4">THREAT</th>
                <th className="py-2.5 px-4 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyan-500/10 font-mono">
              {(sessions || []).slice(0, 8).map((s) => {
                const ip = s.src_ip || s.attacker_ip || 'unknown';
                const threat = evaluateThreat(s.threat_score ?? (s.skill_level ? s.skill_level * 10 : 10));
                const intent = normalizeIntent(s.intent);
                const cmdCount = s.command_count || s.commands_executed || 0;

                const statusPill =
                  s.status === 'active' ? (
                    <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 animate-pulse">
                      ACTIVE
                    </span>
                  ) : s.status === 'failed' ? (
                    <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">
                      AUTH FAIL
                    </span>
                  ) : s.status === 'timed_out' ? (
                    <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                      TIMED OUT
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-500/30">
                      CLOSED
                    </span>
                  );

                return (
                  <tr key={s.session_id} className="hover:bg-cyan-950/20 transition-all">
                    <td className="py-2.5 px-4">{statusPill}</td>
                    <td className="py-2.5 px-4 font-bold text-white">
                      <Link href={`/sessions/${s.session_id}`} className="text-cyan-400 hover:underline">
                        CASE-{s.session_id.slice(0, 8).toUpperCase()}
                      </Link>
                    </td>
                    <td className="py-2.5 px-4 text-slate-200">
                      <Link href={`/attackers?ip=${encodeURIComponent(ip)}`} className="hover:text-cyan-300 hover:underline">
                        {ip}
                      </Link>
                    </td>
                    <td className="py-2.5 px-4 text-slate-400">
                      {getCountryName(s.src_country || s.country)}
                    </td>
                    <td className="py-2.5 px-4 text-slate-300">
                      {formatDuration(s.duration_seconds || 0)}
                    </td>
                    <td className="py-2.5 px-4">
                      {cmdCount > 0 ? (
                        <span className="text-emerald-400 font-bold">
                          {cmdCount}
                        </span>
                      ) : (
                        <span className="text-slate-600">0</span>
                      )}
                    </td>
                    <td className="py-2.5 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 border border-slate-700 text-slate-300">
                        {intent.label}
                      </span>
                    </td>
                    <td className="py-2.5 px-4">
                      <span className={cn('px-2 py-0.5 rounded text-[10px] font-bold border', threat.badgeClass)}>
                        {threat.label.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <Link
                        href={`/sessions/${s.session_id}`}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-cyan-500/15 border border-cyan-500/30 text-[10px] font-bold text-cyan-300 hover:bg-cyan-500/25 transition-all"
                      >
                        <span>INVESTIGATE</span>
                        <ExternalLink className="w-2.5 h-2.5" />
                      </Link>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
