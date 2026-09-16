'use client';

import { Suspense, useEffect, useState, useMemo, useCallback } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  Search,
  Terminal,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  Download,
  ExternalLink,
  Shield,
  Clock,
  Filter,
  RefreshCw,
  ArrowLeft,
  Database,
  Layers,
  UserCheck,
  AlertTriangle,
  Globe,
  Activity,
  X,
} from 'lucide-react';
import { cn, formatTimestamp } from '@/lib/utils';
import { useDashboardStore } from '@/lib/store';
import { normalizeIntent } from '@/lib/intents';
import { safeCopyToClipboard } from '@/lib/clipboard';
import { api } from '@/lib/api';
import { Command, CommandSummary } from '@/lib/types';
import { getTechniqueInfo } from '@/lib/mitre';

function renderSourceBadge(sourceClass?: string) {
  if (sourceClass === 'EXTERNAL_HONEYPOT') {
    return (
      <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-500/30">
        EXTERNAL ATTACKER
      </span>
    );
  }
  if (sourceClass === 'INTERNAL_INFRASTRUCTURE') {
    return (
      <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-amber-950/80 text-amber-300 border border-amber-500/30">
        INTERNAL / GATEWAY
      </span>
    );
  }
  return (
    <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-slate-900 text-slate-400 border border-slate-700">
      UNATTRIBUTABLE
    </span>
  );
}

function GlobalCommandsContent() {
  const router = useRouter();
  const searchParams = useSearchParams();

  // Query parameters from URL
  const searchParam = searchParams.get('search') || searchParams.get('command') || '';
  const attackerIpParam = searchParams.get('attacker_ip') || searchParams.get('ip') || '';
  const sessionIdParam = searchParams.get('session_id') || '';

  const { timeWindowHours } = useDashboardStore();

  // Global listing state
  const [commandsList, setCommandsList] = useState<Command[]>([]);
  const [commandsLoading, setCommandsLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState(searchParam);
  const [selectedIntent, setSelectedIntent] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<'all' | 'success' | 'failed'>('all');
  const [includeSynthetic, setIncludeSynthetic] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [expandedCommands, setExpandedCommands] = useState<Set<string>>(new Set());
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Command summary drill-down state (when viewing a specific command)
  const [commandSummary, setCommandSummary] = useState<CommandSummary | null>(null);
  const [summaryLoading, setSummaryLoading] = useState(false);

  const itemsPerPage = 50;

  // Sync searchQuery when URL searchParam changes
  useEffect(() => {
    setSearchQuery(searchParam);
  }, [searchParam]);

  // Fetch command summary if searchParam is present
  useEffect(() => {
    if (!searchParam) {
      setCommandSummary(null);
      return;
    }

    let active = true;
    setSummaryLoading(true);
    api
      .getCommandSummary(searchParam)
      .then((data) => {
        if (active) {
          setCommandSummary(data);
          setSummaryLoading(false);
        }
      })
      .catch((err) => {
        console.error('Failed to load command summary:', err);
        if (active) {
          setCommandSummary(null);
          setSummaryLoading(false);
        }
      });

    return () => {
      active = false;
    };
  }, [searchParam]);

  // Fetch global commands list
  const fetchCommandsData = useCallback(async () => {
    setCommandsLoading(true);
    try {
      // If filtering by specific session, attacker, or command, default to all-time
      const hasSpecificFilter = Boolean(searchParam || attackerIpParam || sessionIdParam);
      const hoursToUse = hasSpecificFilter ? 87600 : timeWindowHours;

      const data = await api.getCommands({
        command: searchParam || undefined,
        attacker_ip: attackerIpParam || undefined,
        session_id: sessionIdParam || undefined,
        intent: selectedIntent !== 'all' ? selectedIntent : undefined,
        hours: hoursToUse,
        include_synthetic: includeSynthetic,
        limit: 300,
      });
      setCommandsList(data || []);
    } catch (e) {
      console.error('Failed to load commands list:', e);
      setCommandsList([]);
    } finally {
      setCommandsLoading(false);
    }
  }, [searchParam, attackerIpParam, sessionIdParam, selectedIntent, timeWindowHours, includeSynthetic]);

  useEffect(() => {
    fetchCommandsData();
  }, [fetchCommandsData]);

  const copyToClipboard = useCallback(async (text: string, key: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    const ok = await safeCopyToClipboard(text);
    if (ok) {
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    }
  }, []);

  const toggleCommand = (cmdId: string) => {
    setExpandedCommands((prev) => {
      const next = new Set(prev);
      if (next.has(cmdId)) next.delete(cmdId);
      else next.add(cmdId);
      return next;
    });
  };

  const handleClearDrillDown = () => {
    const params = new URLSearchParams(searchParams.toString());
    params.delete('search');
    params.delete('command');
    router.push(`/commands?${params.toString()}`);
  };

  const handleClearFilter = (key: 'attacker_ip' | 'session_id') => {
    const params = new URLSearchParams(searchParams.toString());
    params.delete(key);
    if (key === 'attacker_ip') params.delete('ip');
    router.push(`/commands?${params.toString()}`);
  };

  const filteredCommands = useMemo(() => {
    return commandsList.filter((cmd) => {
      const q = searchQuery.toLowerCase().trim();
      const matchesSearch =
        !q ||
        cmd.command.toLowerCase().includes(q) ||
        (cmd.output?.toLowerCase() ?? '').includes(q) ||
        cmd.session_id.toLowerCase().includes(q) ||
        (cmd.attacker_ip?.toLowerCase() ?? '').includes(q) ||
        (cmd.intent?.toLowerCase() ?? '').includes(q);

      const matchesIntent = selectedIntent === 'all' || cmd.intent === selectedIntent;
      const isSuccess = cmd.exit_code === 0 || cmd.success;
      const matchesStatus =
        selectedStatus === 'all' ||
        (selectedStatus === 'success' && isSuccess) ||
        (selectedStatus === 'failed' && !isSuccess);

      return matchesSearch && matchesIntent && matchesStatus;
    });
  }, [commandsList, searchQuery, selectedIntent, selectedStatus]);

  const totalPages = Math.max(1, Math.ceil(filteredCommands.length / itemsPerPage));
  const paginatedCommands = useMemo(() => {
    return filteredCommands.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);
  }, [filteredCommands, currentPage, itemsPerPage]);

  const exportToCSV = () => {
    if (filteredCommands.length === 0) return;
    const headers = [
      'Timestamp',
      'Attacker IP',
      'Country',
      'Source Class',
      'Session ID',
      'Command',
      'Exit Code',
      'Duration MS',
      'Intent',
      'Output',
    ];
    const rows = filteredCommands.map((c) => [
      c.timestamp ?? '',
      c.attacker_ip ?? '',
      c.country ?? '',
      c.source_class ?? '',
      c.session_id ?? '',
      c.command ?? '',
      c.exit_code ?? 0,
      c.duration_ms ?? 0,
      normalizeIntent(c.intent).label,
      (c.output ?? '').replace(/\n/g, ' ').replace(/"/g, '""'),
    ]);

    const csvContent = [headers.join(','), ...rows.map((r) => r.map((cell) => `"${cell}"`).join(','))].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `clouddecept-command-forensics-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 font-mono pb-12">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-3 border-b border-cyan-500/15">
        <div>
          <div className="flex items-center gap-3">
            {searchParam && (
              <button
                onClick={handleClearDrillDown}
                className="p-1.5 rounded-lg bg-[#070e22] border border-cyan-500/25 text-cyan-300 hover:border-cyan-400 flex items-center gap-1 text-xs"
                title="Back to Global Commands Explorer"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>All Commands</span>
              </button>
            )}
            <h1 className="text-xl sm:text-2xl font-bold tracking-wider text-white uppercase flex items-center gap-2.5">
              <Terminal className="w-5 h-5 text-cyan-400" />
              <span>{searchParam ? 'COMMAND FORENSIC DOSSIER' : 'COMMAND FORENSICS EXPLORER'}</span>
            </h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            {searchParam
              ? `Deep forensic attribution, telemetry quality audit, and actor source breakdown for: $ ${searchParam}`
              : `Analyzing shell commands across honeypot sessions (${
                  searchParam || attackerIpParam || sessionIdParam ? 'All-Time Filtered' : `Last ${timeWindowHours}h`
                })`}
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={fetchCommandsData}
            className="p-2 rounded-lg bg-[#070e22] border border-cyan-500/25 text-slate-300 hover:text-cyan-300"
            title="Refresh commands"
          >
            <RefreshCw className={cn('w-4 h-4', (commandsLoading || summaryLoading) && 'animate-spin text-cyan-400')} />
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

      {/* Active Filter Chips */}
      {(attackerIpParam || sessionIdParam || searchParam) && (
        <div className="flex flex-wrap items-center gap-2 p-2.5 rounded-lg bg-[#070e22] border border-cyan-500/20 text-xs">
          <span className="text-[10px] text-slate-500 uppercase tracking-wider font-bold">ACTIVE FILTERS:</span>
          {searchParam && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-500/40">
              <Terminal className="w-3 h-3 text-cyan-400" />
              <span className="font-mono font-bold">$ {searchParam}</span>
              <button onClick={handleClearDrillDown} className="hover:text-white">
                <X className="w-3 h-3" />
              </button>
            </span>
          )}
          {attackerIpParam && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-purple-950/80 text-purple-300 border border-purple-500/40">
              <UserCheck className="w-3 h-3 text-purple-400" />
              <span>Attacker IP: {attackerIpParam}</span>
              <button onClick={() => handleClearFilter('attacker_ip')} className="hover:text-white">
                <X className="w-3 h-3" />
              </button>
            </span>
          )}
          {sessionIdParam && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-blue-950/80 text-blue-300 border border-blue-500/40">
              <Activity className="w-3 h-3 text-blue-400" />
              <span>Session: {sessionIdParam.slice(0, 12)}</span>
              <button onClick={() => handleClearFilter('session_id')} className="hover:text-white">
                <X className="w-3 h-3" />
              </button>
            </span>
          )}
        </div>
      )}

      {/* DEDICATED COMMAND FORENSIC DRILL-DOWN VIEW (WHEN SEARCH/COMMAND IS ACTIVE) */}
      {searchParam && commandSummary && (
        <div className="space-y-6">
          {/* Command Banner & KPI Grid */}
          <div className="rounded-xl border border-cyan-500/20 bg-[#070e22] p-4 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-cyan-500/15">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-[#02050f] border border-cyan-500/30">
                  <Terminal className="w-6 h-6 text-emerald-400" />
                </div>
                <div>
                  <div className="text-xs text-slate-400 uppercase tracking-wider">COMMAND SIGNATURE</div>
                  <div className="text-base sm:text-lg font-bold text-white font-mono flex items-center gap-2">
                    <span className="text-emerald-400">$</span>
                    <span>{commandSummary.command}</span>
                    <button
                      onClick={(e) => copyToClipboard(commandSummary.command, 'banner-cmd', e)}
                      className="p-1 rounded hover:bg-cyan-950 text-cyan-400"
                      title="Copy command"
                    >
                      {copiedKey === 'banner-cmd' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-3 text-xs">
                <div className="text-right">
                  <div className="text-[10px] text-slate-500 uppercase">FIRST DETECTED</div>
                  <div className="text-slate-300 font-bold">{formatTimestamp(commandSummary.first_seen)}</div>
                </div>
                <div className="text-right">
                  <div className="text-[10px] text-slate-500 uppercase">LAST DETECTED</div>
                  <div className="text-slate-300 font-bold">{formatTimestamp(commandSummary.last_seen)}</div>
                </div>
              </div>
            </div>

            {/* Metrics cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-3 rounded-lg bg-[#040816] border border-cyan-500/15">
                <div className="text-[10px] text-slate-400 uppercase">ATTRIBUTABLE RUNS</div>
                <div className="text-xl font-bold text-emerald-400 mt-0.5">
                  {commandSummary.total_executions.toLocaleString()}
                </div>
                <div className="text-[9px] text-slate-500 mt-0.5">Unique event_id</div>
              </div>

              <div className="p-3 rounded-lg bg-[#040816] border border-cyan-500/15">
                <div className="text-[10px] text-slate-400 uppercase">SESSIONS INVOLVED</div>
                <div className="text-xl font-bold text-cyan-300 mt-0.5">
                  {commandSummary.unique_sessions.toLocaleString()}
                </div>
                <div className="text-[9px] text-slate-500 mt-0.5">Unique session_id</div>
              </div>

              <div className="p-3 rounded-lg bg-[#040816] border border-cyan-500/15">
                <div className="text-[10px] text-slate-400 uppercase">ATTACKER SOURCES</div>
                <div className="text-xl font-bold text-white mt-0.5">{commandSummary.unique_sources}</div>
                <div className="text-[9px] text-slate-400 mt-0.5">
                  {commandSummary.external_attackers} External • {commandSummary.internal_sources} Internal
                </div>
              </div>

              <div className="p-3 rounded-lg bg-[#040816] border border-cyan-500/15">
                <div className="text-[10px] text-slate-400 uppercase">EXECUTION BREAKDOWN</div>
                <div className="text-base font-bold text-emerald-300 mt-0.5">
                  {commandSummary.external_executions} <span className="text-xs text-slate-400">Ext</span> /{' '}
                  {commandSummary.internal_executions} <span className="text-xs text-slate-400">Int</span>
                </div>
                <div className="text-[9px] text-slate-500 mt-0.5">Honeypot vs Infrastructure</div>
              </div>
            </div>

            {/* Data Quality Transparency Card */}
            <div className="p-3.5 rounded-lg bg-[#02050f] border border-amber-500/25 space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs font-bold text-amber-300 uppercase">
                  <Database className="w-3.5 h-3.5 text-amber-400" />
                  <span>DATA INTEGRITY & TELEMETRY AUDIT</span>
                </div>
                <span className="text-[9px] text-slate-400">Reconciled against ClickHouse physical storage</span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 pt-1 text-xs">
                <div className="p-2 rounded bg-[#070e22] border border-slate-800">
                  <div className="text-[10px] text-slate-500">Physical DB Rows</div>
                  <div className="font-bold text-slate-300">
                    {commandSummary.data_quality.raw_physical_rows.toLocaleString()}
                  </div>
                  <div className="text-[8px] text-slate-500">Includes historical PEL re-deliveries</div>
                </div>

                <div className="p-2 rounded bg-[#070e22] border border-emerald-500/30">
                  <div className="text-[10px] text-emerald-400">Attributable Events</div>
                  <div className="font-bold text-emerald-300">
                    {commandSummary.data_quality.attributable_events.toLocaleString()}
                  </div>
                  <div className="text-[8px] text-emerald-500/80">Authoritative deduplicated events</div>
                </div>

                <div className="p-2 rounded bg-[#070e22] border border-slate-800">
                  <div className="text-[10px] text-slate-500">Excluded Synthetic Tests</div>
                  <div className="font-bold text-slate-400">
                    {commandSummary.data_quality.excluded_synthetic_events.toLocaleString()}
                  </div>
                  <div className="text-[8px] text-slate-500">e2e / debug testing runs</div>
                </div>

                <div className="p-2 rounded bg-[#070e22] border border-slate-800">
                  <div className="text-[10px] text-slate-500">Excluded Legacy Orphans</div>
                  <div className="font-bold text-slate-400">
                    {commandSummary.data_quality.orphan_events.toLocaleString()}
                  </div>
                  <div className="text-[8px] text-slate-500">Unassigned collector events (Sept 1-5)</div>
                </div>
              </div>
            </div>
          </div>

          {/* Sources Attribution Breakdown Table */}
          <div className="rounded-xl border border-cyan-500/20 bg-[#070e22] overflow-hidden">
            <div className="p-3.5 bg-[#040816] border-b border-cyan-500/15 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Globe className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-bold text-white uppercase tracking-wider">
                  SOURCES EXECUTING THIS COMMAND ({commandSummary.sources.length} Actors)
                </span>
              </div>
              <span className="text-[10px] text-slate-400">Click attacker IP to view full threat dossier</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#040816] text-[10px] text-slate-400 uppercase border-b border-cyan-500/10">
                  <tr>
                    <th className="p-3">Source IP</th>
                    <th className="p-3">Country</th>
                    <th className="p-3">Classification</th>
                    <th className="p-3 text-right">Executions</th>
                    <th className="p-3 text-right">Sessions</th>
                    <th className="p-3">First Seen</th>
                    <th className="p-3">Last Seen</th>
                    <th className="p-3 text-center">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyan-500/10">
                  {commandSummary.sources.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="p-6 text-center text-slate-500">
                        No attributable sources found for this command.
                      </td>
                    </tr>
                  ) : (
                    commandSummary.sources.map((src) => (
                      <tr key={src.attacker_ip} className="hover:bg-cyan-950/20 transition-all">
                        <td className="p-3 font-bold text-white">
                          <Link
                            href={`/attackers?ip=${encodeURIComponent(src.attacker_ip)}`}
                            className="text-cyan-300 hover:underline flex items-center gap-1"
                          >
                            <span>{src.attacker_ip}</span>
                            <ExternalLink className="w-2.5 h-2.5 text-cyan-400" />
                          </Link>
                        </td>
                        <td className="p-3 text-slate-300">{src.country || 'Unknown'}</td>
                        <td className="p-3">{renderSourceBadge(src.source_class)}</td>
                        <td className="p-3 text-right font-bold text-emerald-400">{src.executions}</td>
                        <td className="p-3 text-right font-bold text-cyan-300">{src.unique_sessions}</td>
                        <td className="p-3 text-slate-400 text-[11px]">{formatTimestamp(src.first_seen)}</td>
                        <td className="p-3 text-slate-400 text-[11px]">{formatTimestamp(src.last_seen)}</td>
                        <td className="p-3 text-center">
                          <Link
                            href={`/attackers?ip=${encodeURIComponent(src.attacker_ip)}`}
                            className="px-2 py-1 rounded bg-cyan-500/15 text-cyan-300 hover:bg-cyan-500/30 text-[10px]"
                          >
                            Investigate
                          </Link>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Chronological Attributable Executions */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Clock className="w-4 h-4 text-cyan-400" />
                <span>RECENT ATTRIBUTABLE EXECUTIONS (Latest {commandSummary.recent_events.length})</span>
              </h2>
            </div>

            {commandSummary.recent_events.map((ev, idx) => {
              const evKey = ev.event_id || `${ev.session_id}-${idx}`;
              const isExpanded = expandedCommands.has(evKey);
              const isSuccess = ev.exit_code === 0;
              const hasValidSession = ev.session_id && ev.session_id.trim() !== '';

              return (
                <div
                  key={evKey}
                  className="rounded-xl border border-cyan-500/20 bg-[#070e22] overflow-hidden transition-all"
                >
                  <div
                    onClick={() => toggleCommand(evKey)}
                    className="p-3.5 bg-[#040816] border-b border-cyan-500/15 flex flex-wrap items-center justify-between gap-2.5 cursor-pointer hover:bg-[#07112c]"
                  >
                    <div className="flex items-center gap-3">
                      <span className="text-emerald-400 font-bold text-xs">$</span>
                      <span className="text-xs font-bold text-white font-mono">{ev.command}</span>
                      {ev.arguments && ev.arguments.length > 0 && (
                        <span className="text-xs text-slate-400 truncate max-w-xs">{ev.arguments.join(' ')}</span>
                      )}
                    </div>

                    <div className="flex items-center gap-2.5 flex-shrink-0">
                      <span className="text-[10px] text-slate-400">{formatTimestamp(ev.timestamp)}</span>

                      {ev.attacker_ip && (
                        <Link
                          href={`/attackers?ip=${encodeURIComponent(ev.attacker_ip)}`}
                          onClick={(e) => e.stopPropagation()}
                          className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-500/30 hover:border-cyan-400 flex items-center gap-1"
                        >
                          <span>{ev.attacker_ip}</span>
                        </Link>
                      )}

                      {renderSourceBadge(ev.source_class)}

                      {hasValidSession ? (
                        <Link
                          href={`/sessions/${ev.session_id}`}
                          onClick={(e) => e.stopPropagation()}
                          className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 text-cyan-400 border border-cyan-500/30 hover:border-cyan-400 flex items-center gap-1"
                          title="View Session Case File"
                        >
                          <span>{ev.session_id.slice(0, 8)}</span>
                          <ExternalLink className="w-2.5 h-2.5" />
                        </Link>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[10px] text-slate-500 bg-slate-900 border border-slate-800">
                          Unattributable Session
                        </span>
                      )}

                      {isSuccess ? (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-500/30">
                          0 OK
                        </span>
                      ) : (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-500/30">
                          {ev.exit_code ?? 'ERR'}
                        </span>
                      )}

                      {isExpanded ? (
                        <ChevronUp className="w-4 h-4 text-cyan-400" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-slate-500" />
                      )}
                    </div>
                  </div>

                  {/* Expanded stdout/stderr */}
                  {isExpanded && (
                    <div className="p-4 bg-[#02050f] space-y-2 border-t border-cyan-500/15">
                      <div className="flex items-center justify-between text-[10px] text-slate-400 uppercase">
                        <span>EXECUTION CAPTURE RECORD</span>
                        <div className="flex items-center gap-3">
                          <span>Duration: {ev.duration_ms ?? 0} ms</span>
                          <button
                            onClick={(e) => copyToClipboard(ev.output || '', `out-${evKey}`, e)}
                            className="text-cyan-400 hover:underline flex items-center gap-1"
                          >
                            <Copy className="w-3 h-3" />
                            <span>{copiedKey === `out-${evKey}` ? 'Copied' : 'Copy Output'}</span>
                          </button>
                        </div>
                      </div>

                      <pre className="p-3 rounded-lg bg-[#040816] border border-cyan-500/20 text-xs font-mono text-emerald-300/90 overflow-x-auto whitespace-pre-wrap max-h-60 scrollbar-thin">
                        {ev.output ? (
                          ev.output
                        ) : (
                          <span className="text-slate-600 italic">(Execution yielded no stdout / stderr)</span>
                        )}
                      </pre>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* GLOBAL COMMANDS LISTING VIEW (WHEN NO SPECIFIC COMMAND DRILL-DOWN OR AS EXPLORER) */}
      {!searchParam && (
        <>
          {/* Filter Toolbar */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 bg-[#070e22] p-3.5 rounded-xl border border-cyan-500/20">
            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyan-400/60" />
              <input
                type="search"
                placeholder="Search command, output, IP..."
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setCurrentPage(1);
                }}
                className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg bg-[#040816] border border-cyan-500/25 text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400"
              />
            </div>

            {/* Intent filter */}
            <select
              value={selectedIntent}
              onChange={(e) => {
                setSelectedIntent(e.target.value);
                setCurrentPage(1);
              }}
              className="px-3 py-1.5 rounded-lg bg-[#040816] border border-cyan-500/25 text-xs text-cyan-300 focus:outline-none focus:border-cyan-400"
            >
              <option value="all">All Adversary Intents</option>
              <option value="credential_hunting">Credential Hunting</option>
              <option value="system_discovery">System Discovery</option>
              <option value="persistence">Persistence</option>
              <option value="privilege_escalation">Privilege Escalation</option>
              <option value="lateral_movement">Lateral Movement</option>
              <option value="defense_evasion">Defense Evasion</option>
              <option value="data_exfiltration">Data Exfiltration</option>
              <option value="reconnaissance">Reconnaissance</option>
              <option value="unknown">Unknown / No Pattern</option>
            </select>

            {/* Status filter */}
            <select
              value={selectedStatus}
              onChange={(e) => {
                setSelectedStatus(e.target.value as any);
                setCurrentPage(1);
              }}
              className="px-3 py-1.5 rounded-lg bg-[#040816] border border-cyan-500/25 text-xs text-cyan-300 focus:outline-none focus:border-cyan-400"
            >
              <option value="all">All Execution Results</option>
              <option value="success">Exit Code 0 (Success)</option>
              <option value="failed">Non-Zero Exit Code (Failed)</option>
            </select>

            {/* Synthetic filter toggle */}
            <label className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#040816] border border-cyan-500/25 text-xs text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={includeSynthetic}
                onChange={(e) => setIncludeSynthetic(e.target.checked)}
                className="rounded border-slate-700 text-cyan-500 focus:ring-0"
              />
              <span className="text-[11px]">Include Synthetic/Tests</span>
            </label>

            {/* Metrics Badge */}
            <div className="flex items-center justify-between px-3 py-1.5 rounded-lg bg-[#040816] border border-cyan-500/15 text-xs text-slate-400">
              <span>MATCHED</span>
              <span className="text-cyan-300 font-bold">{filteredCommands.length} executions</span>
            </div>
          </div>

          {/* Commands List */}
          {commandsLoading && filteredCommands.length === 0 ? (
            <div className="p-12 text-center rounded-xl bg-[#070e22] border border-cyan-500/15">
              <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mx-auto mb-2" />
              <div className="text-xs text-slate-300 uppercase font-bold">Querying Global ClickHouse Commands...</div>
            </div>
          ) : filteredCommands.length === 0 ? (
            <div className="p-12 text-center rounded-xl bg-[#070e22] border border-cyan-500/15">
              <Terminal className="w-10 h-10 text-slate-600 mx-auto mb-3" />
              <h3 className="text-sm font-bold text-white uppercase">NO COMMANDS FOUND FOR THIS CRITERIA</h3>
              <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
                Try expanding the time window or clearing search filters.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {paginatedCommands.map((cmd, idx) => {
                const cmdKey = cmd.event_id || `${cmd.session_id}-${idx}`;
                const isExpanded = expandedCommands.has(cmdKey);
                const intentInfo = normalizeIntent(cmd.intent);
                const isSuccess = cmd.exit_code === 0 || cmd.success;
                const hasValidSession = cmd.session_id && cmd.session_id.trim() !== '';

                return (
                  <div
                    key={cmdKey}
                    className="rounded-xl border border-cyan-500/20 bg-[#070e22] overflow-hidden transition-all"
                  >
                    {/* Header row */}
                    <div
                      onClick={() => toggleCommand(cmdKey)}
                      className="p-3.5 bg-[#040816] border-b border-cyan-500/15 flex flex-wrap items-center justify-between gap-2.5 cursor-pointer hover:bg-[#07112c]"
                    >
                      <div className="flex items-center gap-3">
                        <span className="text-emerald-400 font-bold text-xs">$</span>
                        <Link
                          href={`/commands?search=${encodeURIComponent(cmd.command)}`}
                          onClick={(e) => e.stopPropagation()}
                          className="text-xs font-bold text-white font-mono hover:text-cyan-300 hover:underline"
                          title="Drill down into command dossier"
                        >
                          {cmd.command}
                        </Link>
                        {cmd.arguments && cmd.arguments.length > 0 && (
                          <span className="text-xs text-slate-400 truncate max-w-xs">{cmd.arguments.join(' ')}</span>
                        )}
                      </div>

                      <div className="flex items-center gap-2.5 flex-shrink-0">
                        <span className="text-[10px] text-slate-400">{formatTimestamp(cmd.timestamp)}</span>

                        {cmd.attacker_ip ? (
                          <Link
                            href={`/attackers?ip=${encodeURIComponent(cmd.attacker_ip)}`}
                            onClick={(e) => e.stopPropagation()}
                            className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-500/30 hover:border-cyan-400 flex items-center gap-1"
                            title="Investigate Attacker"
                          >
                            <span>{cmd.attacker_ip}</span>
                            <ExternalLink className="w-2 h-2 text-cyan-400" />
                          </Link>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] text-slate-500 bg-slate-900 border border-slate-800">
                            Unassigned IP
                          </span>
                        )}

                        {renderSourceBadge(cmd.source_class)}

                        {hasValidSession ? (
                          <Link
                            href={`/sessions/${cmd.session_id}`}
                            onClick={(e) => e.stopPropagation()}
                            className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 text-cyan-400 border border-cyan-500/30 hover:border-cyan-400 flex items-center gap-1"
                            title="Investigate Session"
                          >
                            <span>{cmd.session_id.slice(0, 8)}</span>
                            <ExternalLink className="w-2.5 h-2.5 text-cyan-400" />
                          </Link>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] text-slate-500 bg-slate-900 border border-slate-800">
                            Unassigned Session
                          </span>
                        )}

                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 border border-slate-700 text-slate-300">
                          {intentInfo.label}
                        </span>

                        {isSuccess ? (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-500/30">
                            0 OK
                          </span>
                        ) : (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-500/30">
                            {cmd.exit_code ?? 'ERR'}
                          </span>
                        )}

                        {isExpanded ? (
                          <ChevronUp className="w-4 h-4 text-cyan-400" />
                        ) : (
                          <ChevronDown className="w-4 h-4 text-slate-500" />
                        )}
                      </div>
                    </div>

                    {/* Expanded Output */}
                    {isExpanded && (
                      <div className="p-4 bg-[#02050f] space-y-2 border-t border-cyan-500/15">
                        <div className="flex items-center justify-between text-[10px] text-slate-400 uppercase">
                          <span>COMMAND EXECUTION RECORD</span>
                          <div className="flex items-center gap-3">
                            <span>Duration: {cmd.duration_ms ?? 0} ms</span>
                            <button
                              onClick={(e) => copyToClipboard(cmd.output || '', `out-${cmdKey}`, e)}
                              className="text-cyan-400 hover:underline flex items-center gap-1"
                            >
                              <Copy className="w-3 h-3" />
                              <span>{copiedKey === `out-${cmdKey}` ? 'Copied' : 'Copy Output'}</span>
                            </button>
                            <Link
                              href={`/commands?search=${encodeURIComponent(cmd.command)}`}
                              className="px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 hover:bg-cyan-500/30 text-[10px] flex items-center gap-1"
                            >
                              <span>Full Dossier</span>
                              <ExternalLink className="w-2.5 h-2.5" />
                            </Link>
                          </div>
                        </div>

                        <pre className="p-3 rounded-lg bg-[#040816] border border-cyan-500/20 text-xs font-mono text-emerald-300/90 overflow-x-auto whitespace-pre-wrap max-h-60 scrollbar-thin">
                          {cmd.output ? (
                            cmd.output
                          ) : (
                            <span className="text-slate-600 italic">(Execution yielded no stdout / stderr)</span>
                          )}
                        </pre>

                        {cmd.mitre_techniques && cmd.mitre_techniques.length > 0 && (
                          <div className="pt-2 flex flex-wrap items-center gap-2 text-xs">
                            <span className="text-[10px] text-slate-400 uppercase">TECHNIQUES:</span>
                            <div className="flex flex-wrap items-center gap-1.5">
                              {cmd.mitre_techniques.map((t) => {
                                const info = getTechniqueInfo(t);
                                return (
                                  <div key={t} className="inline-flex items-center gap-1">
                                    <Link
                                      href={`/mitre?technique=${encodeURIComponent(t)}`}
                                      className={cn(
                                        'px-2 py-0.5 rounded text-[10px] font-bold border transition-all',
                                        info.isCustom
                                          ? 'bg-amber-950/70 text-amber-300 border-amber-500/40 hover:border-amber-400'
                                          : 'bg-cyan-900/40 text-cyan-300 border border-cyan-500/30 hover:border-cyan-400'
                                      )}
                                      title={info.name}
                                    >
                                      {t}
                                    </Link>
                                    {info.isCustom && (
                                      <span
                                        className="px-1.5 py-0.2 rounded text-[8px] font-bold bg-amber-900/50 text-amber-300 border border-amber-500/30 cursor-help"
                                        title={`Custom Taxonomy (CloudDecept research extension). Closest official: ${info.closestOfficial || 'N/A'}`}
                                      >
                                        CUSTOM
                                      </span>
                                    )}
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between pt-4 border-t border-cyan-500/15 text-xs text-slate-400">
              <span>
                Page {currentPage} of {totalPages}
              </span>
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
        </>
      )}
    </div>
  );
}

export default function GlobalCommandsPage() {
  return (
    <Suspense fallback={<div className="p-12 text-center font-mono text-xs text-slate-400">Loading command telemetry...</div>}>
      <GlobalCommandsContent />
    </Suspense>
  );
}