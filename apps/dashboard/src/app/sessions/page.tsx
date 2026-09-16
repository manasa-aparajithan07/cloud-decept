'use client';

import { Suspense, useEffect, useState, useMemo, useCallback } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import {
  Search,
  Filter,
  Download,
  Terminal,
  Clock,
  Shield,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  RefreshCw,
  Activity,
  KeyRound,
  Globe,
  AlertTriangle,
} from 'lucide-react';
import { cn, formatTimestamp, formatDuration } from '@/lib/utils';
import { useDashboardStore } from '@/lib/store';
import { getCountryName } from '@/lib/countries';
import { normalizeIntent } from '@/lib/intents';
import { evaluateThreat } from '@/lib/threatScore';

function SessionsPageContent() {
  const searchParams = useSearchParams();
  const urlSearch = searchParams.get('search') || '';
  const urlCountry = searchParams.get('country') || '';
  const urlIp = searchParams.get('ip') || '';
  const urlFilter = searchParams.get('filter') || '';
  const urlHasCmds = searchParams.get('has_commands') === 'true';

  const { sessions, sessionsLoading, fetchSessions, timeWindowHours } = useDashboardStore();
  const [searchQuery, setSearchQuery] = useState(urlSearch || urlIp);
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'closed' | 'timed_out' | 'stale'>('all');
  const [quickFilter, setQuickFilter] = useState<'all' | 'commands' | 'auth_success' | 'high_threat'>(
    urlFilter === 'commands' || urlHasCmds ? 'commands' : urlFilter === 'auth_success' ? 'auth_success' : 'all'
  );
  const [intentFilter, setIntentFilter] = useState<string>('all');
  const [countryFilter, setCountryFilter] = useState<string>(urlCountry || 'all');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 25;

  const isIp = useCallback((val: string) => /^(?:\d{1,3}\.){3}\d{1,3}$/.test(val.trim()), []);
  const isSessionId = useCallback((val: string) => /^[a-fA-F0-9]{8,32}$/.test(val.trim()), []);

  const loadSessions = useCallback(() => {
    const trimmed = searchQuery.trim();
    if (urlIp) {
      fetchSessions({ attacker_ip: urlIp, hours: 87600, limit: 300 });
    } else if (isIp(trimmed)) {
      fetchSessions({ attacker_ip: trimmed, hours: 87600, limit: 300 });
    } else if (isSessionId(trimmed)) {
      fetchSessions({ session_id: trimmed, hours: 87600, limit: 300 });
    } else if (quickFilter === 'commands') {
      fetchSessions({ has_commands: true, hours: 87600, limit: 300 });
    } else if (quickFilter === 'auth_success') {
      fetchSessions({ auth_success: true, hours: 87600, limit: 300 });
    } else {
      fetchSessions({ hours: timeWindowHours, limit: 300 });
    }
  }, [searchQuery, urlIp, isIp, isSessionId, quickFilter, fetchSessions, timeWindowHours]);

  useEffect(() => {
    loadSessions();
  }, [loadSessions]);

  const filteredSessions = useMemo(() => {
    const list = sessions || [];
    return list.filter((s) => {
      const q = searchQuery.toLowerCase();
      const matchesSearch =
        !q ||
        s.session_id.toLowerCase().includes(q) ||
        (s.attacker_ip && s.attacker_ip.toLowerCase().includes(q)) ||
        (s.src_ip && s.src_ip.toLowerCase().includes(q)) ||
        (s.country && s.country.toLowerCase().includes(q)) ||
        (s.intent && s.intent.toLowerCase().includes(q));

      const cmdCount = s.command_count || s.commands_executed || 0;
      const isAuthAccepted = s.auth_outcome === 'accepted' || s.auth_success === true;

      const matchesStatus =
        statusFilter === 'all' ||
        s.lifecycle_status === statusFilter ||
        (s.status === statusFilter && statusFilter !== 'closed') ||
        (statusFilter === 'closed' && (s.lifecycle_status === 'closed' || s.status === 'closed' || s.status === 'failed'));

      const matchesIntent = intentFilter === 'all' || s.intent === intentFilter;
      const matchesCountry = countryFilter === 'all' || s.country === countryFilter || s.src_country === countryFilter;
      const matchesQuick =
        quickFilter === 'all' ||
        (quickFilter === 'commands' && cmdCount > 0) ||
        (quickFilter === 'auth_success' && isAuthAccepted) ||
        (quickFilter === 'high_threat' && (s.threat_score ?? s.skill_level ?? 0) >= 40);

      return matchesSearch && matchesStatus && matchesIntent && matchesCountry && matchesQuick;
    });
  }, [sessions, searchQuery, statusFilter, intentFilter, countryFilter, quickFilter]);

  const totalPages = Math.max(1, Math.ceil(filteredSessions.length / itemsPerPage));
  const paginatedSessions = useMemo(() => {
    return filteredSessions.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);
  }, [filteredSessions, currentPage, itemsPerPage]);

  const exportToCSV = () => {
    if (filteredSessions.length === 0) return;
    const headers = [
      'Session ID',
      'Attacker IP',
      'Country',
      'Protocol',
      'Start Time',
      'Duration (s)',
      'Commands',
      'Auth Attempts',
      'Auth Outcome',
      'Shell Status',
      'Intent',
      'Threat Score',
      'Lifecycle Status',
    ];
    const rows = filteredSessions.map((s) => {
      const cmdCount = s.command_count || s.commands_executed || 0;
      const isAuthAccepted = s.auth_outcome === 'accepted' || s.auth_success === true;
      const isAuthIncomplete = !isAuthAccepted && (s.auth_outcome === 'incomplete' || (cmdCount > 0 && s.auth_success !== true));
      const authOutcome = isAuthAccepted
        ? 'ACCEPTED'
        : isAuthIncomplete
        ? 'INCOMPLETE'
        : s.auth_outcome === 'rejected' || s.auth_success === false
        ? 'REJECTED'
        : 'UNKNOWN';
      const shellStatus = cmdCount > 0 ? 'GRANTED' : 'NOT GRANTED';
      return [
        s.session_id,
        s.src_ip || s.attacker_ip || '',
        s.src_country || s.country || '',
        s.protocol || 'ssh',
        s.start_time,
        s.duration_seconds || 0,
        cmdCount,
        s.credentials_tried || 0,
        authOutcome,
        shellStatus,
        normalizeIntent(s.intent, cmdCount).label,
        s.threat_score ?? s.skill_level ?? 0,
        s.lifecycle_status || s.status || 'closed',
      ];
    });

    const csvContent = [
      headers.join(','),
      ...rows.map((r) => r.map((cell) => `"${cell}"`).join(',')),
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `clouddecept-sessions-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 font-mono pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-3 border-b border-cyan-500/15">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-wider text-white uppercase flex items-center gap-2.5">
            <Activity className="w-5 h-5 text-cyan-400" />
            <span>SESSION INVESTIGATION REGISTRY</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Authoritative ClickHouse honeypot sessions ({timeWindowHours >= 87600 ? 'All-Time' : `Last ${timeWindowHours}h`}) with lifecycle status classification
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => loadSessions()}
            className="p-2 rounded-lg bg-[#070e22] border border-cyan-500/25 text-slate-300 hover:text-cyan-300"
            title="Refresh sessions"
          >
            <RefreshCw className={cn('w-4 h-4', sessionsLoading && 'animate-spin text-cyan-400')} />
          </button>
          <button
            onClick={exportToCSV}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#070e22] border border-cyan-500/25 text-xs text-cyan-300 hover:border-cyan-400"
          >
            <Download className="w-3.5 h-3.5" />
            <span>EXPORT CSV</span>
          </button>
        </div>
      </div>

      {/* Quick Triage Bar */}
      <div className="flex flex-wrap items-center gap-2 p-2.5 rounded-xl bg-[#070e22] border border-cyan-500/20 text-xs">
        <span className="text-[10px] text-slate-400 uppercase tracking-wider px-2 font-bold flex items-center gap-1.5">
          <Filter className="w-3.5 h-3.5 text-cyan-400" />
          <span>TRIAGE PRESETS:</span>
        </span>
        <button
          onClick={() => { setQuickFilter('all'); setCurrentPage(1); }}
          className={cn(
            'px-2.5 py-1 rounded text-xs font-bold transition-all',
            quickFilter === 'all'
              ? 'bg-cyan-500/25 text-cyan-300 border border-cyan-400/50'
              : 'bg-[#040816] text-slate-400 hover:text-slate-200 border border-slate-800'
          )}
        >
          All Sessions
        </button>
        <button
          onClick={() => { setQuickFilter('commands'); setCurrentPage(1); }}
          className={cn(
            'px-2.5 py-1 rounded text-xs font-bold transition-all flex items-center gap-1.5',
            quickFilter === 'commands'
              ? 'bg-emerald-500/25 text-emerald-300 border border-emerald-400/50'
              : 'bg-[#040816] text-slate-400 hover:text-emerald-300 border border-slate-800'
          )}
        >
          <Terminal className="w-3 h-3 text-emerald-400" />
          <span>Interactive / With Commands</span>
        </button>
        <button
          onClick={() => { setQuickFilter('auth_success'); setCurrentPage(1); }}
          className={cn(
            'px-2.5 py-1 rounded text-xs font-bold transition-all flex items-center gap-1.5',
            quickFilter === 'auth_success'
              ? 'bg-cyan-500/25 text-cyan-300 border border-cyan-400/50'
              : 'bg-[#040816] text-slate-400 hover:text-cyan-300 border border-slate-800'
          )}
        >
          <KeyRound className="w-3 h-3 text-cyan-400" />
          <span>Authenticated / Accepted Auth</span>
        </button>
        <button
          onClick={() => { setQuickFilter('high_threat'); setCurrentPage(1); }}
          className={cn(
            'px-2.5 py-1 rounded text-xs font-bold transition-all flex items-center gap-1.5',
            quickFilter === 'high_threat'
              ? 'bg-rose-500/25 text-rose-300 border border-rose-400/50'
              : 'bg-[#040816] text-slate-400 hover:text-rose-300 border border-slate-800'
          )}
        >
          <AlertTriangle className="w-3 h-3 text-rose-400" />
          <span>High Threat (Score &ge; 40)</span>
        </button>
      </div>

      {/* Filter Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 bg-[#070e22] p-3.5 rounded-xl border border-cyan-500/20">
        {/* Search Input */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyan-400/60" />
          <input
            type="search"
            placeholder="Search IP, session ID, intent..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg bg-[#040816] border border-cyan-500/25 text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400"
          />
        </div>

        {/* Status Filter */}
        <select
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value as any);
            setCurrentPage(1);
          }}
          className="px-3 py-1.5 rounded-lg bg-[#040816] border border-cyan-500/25 text-xs text-cyan-300 focus:outline-none focus:border-cyan-400"
        >
          <option value="all">All Session Lifecycles</option>
          <option value="active">Active / Connected Now</option>
          <option value="closed">Closed</option>
          <option value="timed_out">Timed Out (&lt; 1h)</option>
          <option value="stale">Stale (&gt; 1h)</option>
        </select>

        {/* Intent Filter */}
        <select
          value={intentFilter}
          onChange={(e) => {
            setIntentFilter(e.target.value);
            setCurrentPage(1);
          }}
          className="px-3 py-1.5 rounded-lg bg-[#040816] border border-cyan-500/25 text-xs text-cyan-300 focus:outline-none focus:border-cyan-400"
        >
          <option value="all">All Adversary Objectives</option>
          <option value="credential_hunting">Credential Hunting</option>
          <option value="system_discovery">System Discovery</option>
          <option value="persistence">Persistence</option>
          <option value="privilege_escalation">Privilege Escalation</option>
          <option value="defense_evasion">Defense Evasion</option>
          <option value="reconnaissance">Reconnaissance</option>
          <option value="unknown">Unknown / Insufficient Evidence</option>
        </select>

        {/* Matched Counter */}
        <div className="flex items-center justify-between px-3 py-1.5 rounded-lg bg-[#040816] border border-cyan-500/15 text-xs text-slate-400">
          <span>MATCHED SESSIONS</span>
          <span className="text-cyan-300 font-bold">{filteredSessions.length} sessions</span>
        </div>
      </div>

      {/* Sessions Table */}
      <div className="rounded-xl border border-cyan-500/20 bg-[#070e22] overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#040816] text-[10px] text-slate-400 uppercase border-b border-cyan-500/15">
              <tr>
                <th className="py-3 px-4">LIFECYCLE</th>
                <th className="py-3 px-4">AUTH</th>
                <th className="py-3 px-4">SHELL</th>
                <th className="py-3 px-4">SESSION ID</th>
                <th className="py-3 px-4">ATTACKER IP</th>
                <th className="py-3 px-4">ORIGIN</th>
                <th className="py-3 px-4">DURATION</th>
                <th className="py-3 px-4">CMDS</th>
                <th className="py-3 px-4">AUTH ATTEMPTS</th>
                <th className="py-3 px-4">INTENT</th>
                <th className="py-3 px-4">THREAT</th>
                <th className="py-3 px-4 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyan-500/10 font-mono">
              {sessionsLoading && filteredSessions.length === 0 ? (
                <tr>
                  <td colSpan={12} className="py-8 text-center text-slate-400">
                    <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin mx-auto mb-2" />
                    Querying ClickHouse sessions...
                  </td>
                </tr>
              ) : filteredSessions.length === 0 ? (
                <tr>
                  <td colSpan={12} className="py-8 text-center text-slate-500">
                    No sessions match the current search filters in this time window.
                  </td>
                </tr>
              ) : (
                paginatedSessions.map((s) => {
                  const ip = s.src_ip || s.attacker_ip || 'unknown';
                  const countryName = getCountryName(s.src_country || s.country);
                  const threat = evaluateThreat(s.threat_score ?? s.skill_level);
                  const cmdCount = s.command_count || s.commands_executed || 0;
                  const intent = normalizeIntent(s.intent, cmdCount);

                  const isAuthAccepted = s.auth_outcome === 'accepted' || s.auth_success === true;
                  const isAuthIncomplete = !isAuthAccepted && (s.auth_outcome === 'incomplete' || (cmdCount > 0 && s.auth_success !== true));
                  const isAuthRejected = !isAuthAccepted && !isAuthIncomplete && (s.auth_outcome === 'rejected' || s.auth_success === false);

                  const lifecyclePill =
                    s.lifecycle_status === 'active' || s.status === 'active' ? (
                      <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 animate-pulse">
                        ACTIVE NOW
                      </span>
                    ) : s.lifecycle_status === 'timed_out' || s.status === 'timed_out' ? (
                      <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                        TIMED OUT
                      </span>
                    ) : s.lifecycle_status === 'stale' || s.status === 'stale' ? (
                      <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-slate-800 text-slate-400 border border-slate-700">
                        STALE
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-500/30">
                        CLOSED
                      </span>
                    );

                  const authPill = isAuthAccepted ? (
                    <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                      ACCEPTED
                    </span>
                  ) : isAuthIncomplete ? (
                    <span
                      className="px-2 py-0.5 rounded text-[9px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30"
                      title="Commands executed without accepted auth telemetry"
                    >
                      INCOMPLETE
                    </span>
                  ) : isAuthRejected ? (
                    <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">
                      REJECTED
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-slate-800 text-slate-400 border border-slate-700">
                      UNKNOWN
                    </span>
                  );

                  const shellPill = cmdCount > 0 ? (
                    <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                      GRANTED
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-slate-900 text-slate-500 border border-slate-800">
                      NOT GRANTED
                    </span>
                  );

                  return (
                    <tr key={s.session_id} className="hover:bg-cyan-950/20 transition-all">
                      <td className="py-2.5 px-4">{lifecyclePill}</td>
                      <td className="py-2.5 px-4">{authPill}</td>
                      <td className="py-2.5 px-4">{shellPill}</td>
                      <td className="py-2.5 px-4">
                        <Link
                          href={`/sessions/${s.session_id}`}
                          className="text-cyan-400 hover:underline font-bold"
                          title="Open Case File"
                        >
                          {s.session_id.slice(0, 10)}...
                        </Link>
                      </td>
                      <td className="py-2.5 px-4">
                        <Link
                          href={`/attackers?ip=${encodeURIComponent(ip)}`}
                          className="text-slate-200 hover:text-cyan-300 hover:underline"
                        >
                          {ip}
                        </Link>
                      </td>
                      <td className="py-2.5 px-4 text-slate-400 truncate max-w-[120px]">
                        {countryName}
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
                        {(s.credentials_tried || 0) > 0 ? (
                          <span className="text-amber-400 font-bold">
                            {s.credentials_tried}
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
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-cyan-500/15 border border-cyan-500/30 text-[10px] font-bold text-cyan-300 hover:bg-cyan-500/25 hover:border-cyan-400 transition-all"
                        >
                          <span>INVESTIGATE</span>
                          <ExternalLink className="w-2.5 h-2.5" />
                        </Link>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between pt-4 border-t border-cyan-500/15 text-xs text-slate-400">
          <span>Page {currentPage} of {totalPages}</span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="px-3 py-1.5 rounded-lg bg-[#070e22] border border-cyan-500/25 text-slate-300 disabled:opacity-40"
            >
              Previous
            </button>
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="px-3 py-1.5 rounded-lg bg-[#070e22] border border-cyan-500/25 text-slate-300 disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
export default function SessionsPage() {
  return (
    <Suspense fallback={<div className="p-12 text-center font-mono text-xs text-slate-400">Loading telemetry interface...</div>}>
      <SessionsPageContent />
    </Suspense>
  );
}
