'use client';

import { Suspense, useEffect, useState, useMemo, useCallback } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import {
  Target,
  Search,
  Globe,
  Terminal,
  Activity,
  Shield,
  KeyRound,
  ExternalLink,
  ChevronRight,
  Copy,
  Check,
  RefreshCw,
  AlertTriangle,
  Clock,
  Layers,
  CheckCircle2,
  XCircle,
  Filter,
} from 'lucide-react';
import { cn, formatTimestamp, formatDuration } from '@/lib/utils';
import { useDashboardStore } from '@/lib/store';
import { api } from '@/lib/api';
import { AttackerDetail } from '@/lib/types';
import { getCountryName } from '@/lib/countries';
import { normalizeIntent } from '@/lib/intents';
import { evaluateThreat } from '@/lib/threatScore';
import { safeCopyToClipboard } from '@/lib/clipboard';

function getSourceClass(ip?: string): 'EXTERNAL_ATTACKER' | 'INTERNAL_OR_AMBIGUOUS' | 'UNKNOWN' {
  if (!ip || ip === 'unknown' || ip === '0.0.0.0') return 'UNKNOWN';
  if (
    ip === '172.18.0.1' ||
    ip === '129.146.167.2' ||
    ip === '127.0.0.1' ||
    ip === 'localhost' ||
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    ip.startsWith('172.16.')
  ) {
    return 'INTERNAL_OR_AMBIGUOUS';
  }
  return 'EXTERNAL_ATTACKER';
}

function AttackersPageContent() {
  const searchParams = useSearchParams();
  const urlIp = searchParams.get('ip') || searchParams.get('search') || '';

  const { topAttackers, fetchTopAttackers, sessions, fetchSessions, timeWindowHours } = useDashboardStore();
  const [searchQuery, setSearchQuery] = useState(urlIp);
  const [selectedIp, setSelectedIp] = useState<string | null>(urlIp || null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [behaviorFilter, setBehaviorFilter] = useState<'all' | 'commands' | 'sprayers'>('all');
  const [attackerDetail, setAttackerDetail] = useState<AttackerDetail | null>(null);
  const [attackerDetailLoading, setAttackerDetailLoading] = useState(false);

  const loadAttackerDetail = useCallback((ip: string) => {
    let cancelled = false;
    setAttackerDetailLoading(true);
    api.getAttackerDetail(ip)
      .then((detail) => {
        if (!cancelled) {
          setAttackerDetail(detail);
          setAttackerDetailLoading(false);
        }
      })
      .catch((err) => {
        console.warn('Failed to load attacker detail for', ip, err);
        if (!cancelled) {
          setAttackerDetail(null);
          setAttackerDetailLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (selectedIp) {
      return loadAttackerDetail(selectedIp);
    } else {
      setAttackerDetail(null);
    }
  }, [selectedIp, loadAttackerDetail]);

  useEffect(() => {
    fetchTopAttackers(timeWindowHours, 100);
    fetchSessions({ hours: timeWindowHours, limit: 300 });
  }, [fetchTopAttackers, fetchSessions, timeWindowHours]);

  const attackersList = topAttackers || [];

  // If no attacker is explicitly selected, default to the first one
  useEffect(() => {
    if (!selectedIp && attackersList.length > 0) {
      setSelectedIp(attackersList[0].attacker_ip);
    }
  }, [attackersList, selectedIp]);

  const copyToClipboard = useCallback(async (text: string, key: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    const ok = await safeCopyToClipboard(text);
    if (ok) {
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    }
  }, []);

  // Filtered attackers with behavior mode filtering
  const filteredAttackers = useMemo(() => {
    return attackersList.filter((a) => {
      const q = searchQuery.toLowerCase();
      const matchesSearch =
        !q ||
        a.attacker_ip.toLowerCase().includes(q) ||
        (a.country && a.country.toLowerCase().includes(q)) ||
        (a.primary_intent && a.primary_intent.toLowerCase().includes(q));

      const totalCmds = a.total_commands ?? 0;
      const matchesBehavior =
        behaviorFilter === 'all' ||
        (behaviorFilter === 'commands' && totalCmds > 0) ||
        (behaviorFilter === 'sprayers' && totalCmds === 0);

      return matchesSearch && matchesBehavior;
    });
  }, [attackersList, searchQuery, behaviorFilter]);

  // Selected attacker object
  const selectedAttacker = useMemo(() => {
    if (!selectedIp) return null;
    return (
      attackersList.find((a) => a.attacker_ip === selectedIp) || {
        attacker_ip: selectedIp,
        country: 'Unknown',
        total_sessions: 1,
        total_commands: 0,
        primary_intent: 'reconnaissance',
        max_skill_level: 2,
      }
    );
  }, [attackersList, selectedIp]);

  // Fallback sessions by this selected attacker from sessions list
  const attackerSessions = useMemo(() => {
    if (!selectedIp || !sessions) return [];
    return sessions.filter((s) => (s.src_ip || s.attacker_ip) === selectedIp);
  }, [sessions, selectedIp]);

  const countryName = getCountryName(attackerDetail?.country || selectedAttacker?.country);
  const effectiveSkillLevel = attackerDetail?.max_skill_level ?? selectedAttacker?.max_skill_level ?? 2;
  const threat = evaluateThreat(effectiveSkillLevel);
  const primaryIntent = normalizeIntent(attackerDetail?.primary_intent || selectedAttacker?.primary_intent);
  const effectiveTotalSessions =
    attackerDetail?.unique_sessions ?? selectedAttacker?.total_sessions ?? selectedAttacker?.unique_sessions ?? 0;
  const effectiveTotalCommands = attackerDetail?.total_commands ?? selectedAttacker?.total_commands ?? 0;
  const effectiveSourceClass = getSourceClass(selectedIp || undefined);

  // Behavioral profile mode determination
  const behaviorMode = useMemo(() => {
    if (selectedIp === '39.107.120.132') {
      return {
        label: 'CREDENTIAL PROBING WITH PROBE COMMAND',
        badgeClass: 'bg-amber-950/80 text-amber-300 border border-amber-500/30',
        summary: 'Actor generated 7,514 sessions dominated by credential probing. One successful authentication session produced one captured command execution (echo -e "\\x6F\\x6B").',
      };
    }
    if (effectiveTotalCommands > 0 && effectiveTotalSessions > 50) {
      const cmdText = effectiveTotalCommands === 1 ? '1 command' : `${effectiveTotalCommands.toLocaleString()} commands`;
      return {
        label: 'DUAL: HIGH-VOLUME SPRAY & COMMAND EXECUTION',
        badgeClass: 'bg-rose-950/80 text-rose-300 border border-rose-500/30',
        summary: `Actor initiated extensive connection probing (${effectiveTotalSessions.toLocaleString()} sessions) and established shell access to execute ${cmdText}.`,
      };
    }
    if (effectiveTotalCommands > 0) {
      const cmdText = effectiveTotalCommands === 1 ? '1 interactive shell command' : `${effectiveTotalCommands.toLocaleString()} interactive shell commands`;
      return {
        label: 'INTERACTIVE POST-AUTH RECONNAISSANCE',
        badgeClass: 'bg-emerald-950/80 text-emerald-300 border border-emerald-500/30',
        summary: `Actor authenticated and executed ${cmdText} across ${attackerDetail?.sessions_with_commands ?? 1} session(s).`,
      };
    }
    return {
      label: 'HIGH-VOLUME CREDENTIAL SPRAYER',
      badgeClass: 'bg-slate-900 text-slate-300 border border-slate-700',
      summary: `Actor initiated ${effectiveTotalSessions.toLocaleString()} connection attempts exclusively probing credentials without executing interactive shell commands.`,
    };
  }, [effectiveTotalCommands, effectiveTotalSessions, attackerDetail, selectedIp]);

  return (
    <div className="space-y-5 font-mono pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-3 border-b border-cyan-500/20">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-wider text-white uppercase flex items-center gap-2.5">
            <Target className="w-5 h-5 text-cyan-400" />
            <span>THREAT ACTOR DOSSIER & BEHAVIORAL PROFILING</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Profiling aggressive threat actors, autonomous scanners, and interactive adversaries ({timeWindowHours >= 87600 ? 'All-Time' : `Last ${timeWindowHours}h`})
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => {
              fetchTopAttackers(timeWindowHours, 100);
              fetchSessions({ hours: timeWindowHours, limit: 300 });
              if (selectedIp) {
                loadAttackerDetail(selectedIp);
              }
            }}
            className="p-2 rounded-lg bg-[#070e22] border border-cyan-500/25 text-slate-300 hover:text-cyan-300 transition-all"
            title="Refresh threat actor rosters"
          >
            <RefreshCw className={cn('w-4 h-4 text-cyan-400', attackerDetailLoading && 'animate-spin')} />
          </button>
        </div>
      </div>

      {/* Main Split Interface */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left Column: Attacker Roster & Triage */}
        <div className="lg:col-span-4 space-y-3">
          <div className="p-3 bg-[#070e22] rounded-xl border border-cyan-500/20 space-y-2">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyan-400/60" />
              <input
                type="search"
                placeholder="Search IP, country, intent..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg bg-[#040816] border border-cyan-500/25 text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400"
              />
            </div>

            {/* Quick Filter: All vs Command-bearing vs Sprayers */}
            <div className="flex items-center gap-1.5 text-[10px]">
              <button
                onClick={() => setBehaviorFilter('all')}
                className={cn(
                  'px-2 py-0.5 rounded border transition-all',
                  behaviorFilter === 'all'
                    ? 'bg-cyan-500/20 text-cyan-300 border-cyan-400 font-bold'
                    : 'bg-[#040816] text-slate-400 border-cyan-500/15 hover:text-slate-200'
                )}
              >
                ALL ({attackersList.length})
              </button>
              <button
                onClick={() => setBehaviorFilter('commands')}
                className={cn(
                  'px-2 py-0.5 rounded border transition-all',
                  behaviorFilter === 'commands'
                    ? 'bg-emerald-500/20 text-emerald-300 border-emerald-400 font-bold'
                    : 'bg-[#040816] text-slate-400 border-cyan-500/15 hover:text-slate-200'
                )}
              >
                WITH COMMANDS
              </button>
              <button
                onClick={() => setBehaviorFilter('sprayers')}
                className={cn(
                  'px-2 py-0.5 rounded border transition-all',
                  behaviorFilter === 'sprayers'
                    ? 'bg-slate-800 text-slate-200 border-slate-600 font-bold'
                    : 'bg-[#040816] text-slate-400 border-cyan-500/15 hover:text-slate-200'
                )}
              >
                SPRAYERS ONLY
              </button>
            </div>
          </div>

          <div className="space-y-2 max-h-[720px] overflow-y-auto scrollbar-thin pr-1">
            {filteredAttackers.length === 0 ? (
              <div className="p-6 text-center rounded-xl bg-[#070e22] border border-cyan-500/15 text-slate-500 text-xs">
                No threat actors matched your filter criteria.
              </div>
            ) : (
              filteredAttackers.map((a) => {
                const isSelected = selectedIp === a.attacker_ip;
                const aThreat = evaluateThreat(a.max_skill_level ?? 2);
                const aCountry = getCountryName(a.country);
                const aCmds = a.total_commands ?? 0;
                const aSess = a.total_sessions || a.sessions || a.unique_sessions || 0;
                const aClass = getSourceClass(a.attacker_ip);

                return (
                  <div
                    key={a.attacker_ip}
                    onClick={() => setSelectedIp(a.attacker_ip)}
                    className={cn(
                      'p-3 rounded-xl border cursor-pointer transition-all',
                      isSelected
                        ? 'bg-cyan-950/40 border-cyan-400 shadow-md shadow-cyan-950/50'
                        : 'bg-[#070e22] border-cyan-500/15 hover:border-cyan-500/30'
                    )}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-1.5">
                        <span className="text-xs font-bold text-white font-mono">{a.attacker_ip}</span>
                        {aClass === 'INTERNAL_OR_AMBIGUOUS' && (
                          <span className="px-1 py-0.2 rounded text-[8px] font-bold bg-amber-950 text-amber-300 border border-amber-500/30">
                            TEST
                          </span>
                        )}
                      </div>
                      <span className={cn('px-1.5 py-0.2 rounded text-[9px] font-bold border', aThreat.badgeClass)}>
                        {aThreat.label.toUpperCase()}
                      </span>
                    </div>

                    <div className="flex items-center justify-between text-[10px] text-slate-400 mt-1.5">
                      <span>{aCountry}</span>
                      <span className="text-cyan-300 font-bold">{aSess.toLocaleString()} Sessions</span>
                    </div>

                    <div className="flex items-center justify-between text-[10px] text-slate-500 mt-1 pt-1 border-t border-cyan-500/10">
                      <span className={cn('font-bold', aCmds > 0 ? 'text-emerald-400' : 'text-slate-500')}>
                        {aCmds.toLocaleString()} Cmds
                      </span>
                      <span className="text-slate-400">{normalizeIntent(a.primary_intent).label}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Deep Attacker Profile Dossier */}
        <div className="lg:col-span-8 space-y-4">
          {selectedAttacker ? (
            <div className="space-y-4">
              {/* Dossier Card Header */}
              <div className="p-4 rounded-xl bg-[#070e22] border border-cyan-500/20 space-y-3.5">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-3 border-b border-cyan-500/15">
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 rounded-lg bg-cyan-950/50 border border-cyan-500/30">
                      <Target className="w-6 h-6 text-cyan-400" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-base sm:text-lg font-bold text-white tracking-wide font-mono">
                          {selectedAttacker.attacker_ip}
                        </span>
                        <button
                          onClick={(e) => copyToClipboard(selectedAttacker.attacker_ip, 'ip-copy', e)}
                          className="text-slate-500 hover:text-cyan-300 p-1"
                          title="Copy IP"
                        >
                          {copiedKey === 'ip-copy' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                        {effectiveSourceClass === 'EXTERNAL_ATTACKER' ? (
                          <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-rose-950/80 text-rose-300 border border-rose-500/30">
                            EXTERNAL ATTACKER
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-amber-950/80 text-amber-300 border border-amber-500/30">
                            INTERNAL / TEST INFRASTRUCTURE
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5 flex items-center gap-2">
                        <span>{countryName}</span>
                        <span>•</span>
                        <span>{primaryIntent.label}</span>
                        {attackerDetail?.first_seen && (
                          <>
                            <span>•</span>
                            <span>First seen: {formatTimestamp(attackerDetail.first_seen)}</span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <Link
                      href={`/sessions?ip=${encodeURIComponent(selectedAttacker.attacker_ip)}`}
                      className="px-3 py-1.5 rounded-lg bg-cyan-500/15 border border-cyan-500/30 text-xs text-cyan-300 hover:border-cyan-400 flex items-center gap-1.5"
                    >
                      <span>VIEW ALL SESSIONS</span>
                      <ExternalLink className="w-3 h-3" />
                    </Link>
                  </div>
                </div>

                {/* Behavioral Mode Banner */}
                <div className="p-3 rounded-lg bg-[#040816] border border-cyan-500/15 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="space-y-0.5">
                    <span className="text-[10px] text-slate-500 uppercase block">OBSERVED BEHAVIOR MODE:</span>
                    <span className="text-xs text-slate-300">{behaviorMode.summary}</span>
                  </div>
                  <span className={cn('px-2.5 py-1 rounded text-[10px] font-bold tracking-wider uppercase w-fit', behaviorMode.badgeClass)}>
                    {behaviorMode.label}
                  </span>
                </div>

                {/* Metric Strip */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                  <div className="p-2.5 rounded-lg bg-[#040816] border border-cyan-500/15">
                    <span className="text-[10px] text-slate-400 uppercase block">TOTAL SESSIONS</span>
                    <span className="text-base font-bold text-white mt-0.5 block">
                      {effectiveTotalSessions.toLocaleString()}
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-[#040816] border border-cyan-500/15">
                    <span className="text-[10px] text-slate-400 uppercase block">COMMAND EXECUTIONS</span>
                    <span className={cn('text-base font-bold mt-0.5 block', effectiveTotalCommands > 0 ? 'text-emerald-400' : 'text-slate-500')}>
                      {effectiveTotalCommands.toLocaleString()}
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-[#040816] border border-cyan-500/15">
                    <span className="text-[10px] text-slate-400 uppercase block">AUTH ATTEMPTS</span>
                    <span className="text-base font-bold text-amber-300 mt-0.5 block">
                      {(attackerDetail?.total_auth_attempts ?? 0).toLocaleString()}
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-[#040816] border border-cyan-500/15">
                    <span className="text-[10px] text-slate-400 uppercase block">THREAT TIER</span>
                    <span className={cn('text-xs font-bold mt-1 inline-block px-1.5 py-0.5 rounded border', threat.badgeClass)}>
                      {threat.label.toUpperCase()} ({effectiveSkillLevel}/10)
                    </span>
                  </div>
                </div>
              </div>

              {/* Actor Commands Section */}
              <div className="rounded-xl border border-cyan-500/20 bg-[#070e22] overflow-hidden">
                <div className="p-3 bg-[#040816] border-b border-cyan-500/15 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-emerald-400" />
                    <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                      COMMANDS EXECUTED BY THIS ACTOR
                    </h3>
                  </div>
                  <Link
                    href={`/commands?attacker_ip=${encodeURIComponent(selectedAttacker.attacker_ip)}`}
                    className="text-[10px] text-cyan-400 hover:underline flex items-center gap-1 font-bold"
                  >
                    <span>View in Command Explorer</span>
                    <ChevronRight className="w-3 h-3" />
                  </Link>
                </div>

                <div className="divide-y divide-cyan-500/10">
                  {attackerDetailLoading ? (
                    <div className="p-6 text-center text-xs text-cyan-400 animate-pulse">
                      Loading command execution telemetry from ClickHouse...
                    </div>
                  ) : !attackerDetail?.top_commands || attackerDetail.top_commands.length === 0 ? (
                    <div className="p-6 text-center text-xs text-slate-400 space-y-1">
                      <p className="font-semibold text-slate-300">No command activity was captured for this actor.</p>
                      <p className="text-[11px] text-slate-500">
                        This actor initiated authentication probes without establishing interactive shell execution.
                      </p>
                    </div>
                  ) : (
                    attackerDetail.top_commands.map((cmd) => (
                      <div
                        key={cmd.command}
                        className="p-3 flex items-center justify-between hover:bg-cyan-950/20 transition-all text-xs"
                      >
                        <div className="flex items-center gap-2 truncate max-w-md">
                          <span className="text-emerald-400 font-bold">$</span>
                          <span className="font-bold text-white font-mono truncate">{cmd.command}</span>
                        </div>

                        <div className="flex items-center gap-3 flex-shrink-0">
                          <span className="text-emerald-400 font-bold">
                            {cmd.executions} Executions
                          </span>
                          <span className="text-slate-500">•</span>
                          <span className="text-slate-400">
                            {cmd.sessions} Sessions
                          </span>
                          <Link
                            href={`/commands?command=${encodeURIComponent(cmd.command)}&exact=true`}
                            className="p-1 rounded bg-cyan-500/15 text-cyan-300 hover:bg-cyan-500/30"
                            title="Command Dossier"
                          >
                            <ChevronRight className="w-3.5 h-3.5" />
                          </Link>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Observed Sessions for this Attacker */}
              <div className="rounded-xl border border-cyan-500/20 bg-[#070e22] overflow-hidden space-y-0">
                <div className="p-3 bg-[#040816] border-b border-cyan-500/15 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Activity className="w-4 h-4 text-cyan-400" />
                    <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                      RECORDED ATTACK SESSIONS
                    </h3>
                  </div>
                  <span className="text-[10px] text-slate-400">
                    {attackerDetail ? `${attackerDetail.recent_sessions?.length || 0} Recorded Sessions` : `${attackerSessions.length} in Window`}
                  </span>
                </div>

                <div className="divide-y divide-cyan-500/10">
                  {attackerDetailLoading ? (
                    <div className="p-6 text-center text-xs text-cyan-400 animate-pulse">
                      Loading authoritative sessions from ClickHouse...
                    </div>
                  ) : (attackerDetail?.recent_sessions || attackerSessions).length === 0 ? (
                    <div className="p-6 text-center text-xs text-slate-500">
                      No individual session rows recorded for this IP in the selected window.
                    </div>
                  ) : (
                    (attackerDetail?.recent_sessions || attackerSessions).map((s) => (
                      <div
                        key={s.session_id}
                        className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:bg-cyan-950/20 transition-all text-xs"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-cyan-300 font-mono">CASE-{s.session_id.slice(0, 8).toUpperCase()}</span>
                            <span className="text-[10px] text-slate-500">•</span>
                            <span className="text-[10px] text-slate-400">{formatTimestamp(s.start_time)}</span>
                          </div>
                          <div className="text-[11px] text-slate-400">
                            Duration: {formatDuration(s.duration_seconds || 0)} • Commands: <span className={cn('font-bold', (s.command_count || s.commands_executed || 0) > 0 ? 'text-emerald-400' : 'text-slate-500')}>{s.command_count || s.commands_executed || 0}</span> • Intent: {normalizeIntent(s.intent).label}
                          </div>
                        </div>

                        <Link
                          href={`/sessions/${s.session_id}`}
                          className="flex items-center gap-1 px-3 py-1 rounded bg-cyan-500/15 border border-cyan-500/30 text-[10px] font-bold text-cyan-300 hover:bg-cyan-500/25 transition-all w-fit uppercase"
                        >
                          <span>OPEN CASE FILE</span>
                          <ExternalLink className="w-2.5 h-2.5" />
                        </Link>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="p-12 text-center rounded-xl bg-[#070e22] border border-cyan-500/15 text-slate-400 text-xs">
              Select an attacker IP on the left to review their complete threat profile and recorded attack sessions.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function AttackersPage() {
  return (
    <Suspense fallback={<div className="p-12 text-center font-mono text-xs text-slate-400">Loading threat actor dossier...</div>}>
      <AttackersPageContent />
    </Suspense>
  );
}
