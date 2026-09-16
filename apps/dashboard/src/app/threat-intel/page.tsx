'use client';

import { useEffect, useState, useMemo, useCallback } from 'react';
import Link from 'next/link';
import {
  Shield,
  Search,
  AlertTriangle,
  AlertOctagon,
  FileText,
  RefreshCw,
  ExternalLink,
  Copy,
  Check,
  Terminal,
  Database,
  Globe,
  Radio,
  Clock,
  Layers,
  Cpu,
  CheckCircle2,
  HelpCircle,
} from 'lucide-react';
import { cn, formatTimestamp } from '@/lib/utils';
import { useDashboardStore } from '@/lib/store';
import { getCountryName } from '@/lib/countries';
import { normalizeIntent } from '@/lib/intents';
import { evaluateThreat } from '@/lib/threatScore';
import { safeCopyToClipboard } from '@/lib/clipboard';

export default function ThreatIntelligencePage() {
  const {
    sessions,
    fetchSessions,
    threatIntelItems,
    fetchThreatIntelItems,
    stats,
    fetchStats,
    timeWindowHours,
  } = useDashboardStore();

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  useEffect(() => {
    fetchThreatIntelItems({ limit: 100 });
    fetchSessions({ hours: timeWindowHours, limit: 300 });
    fetchStats(timeWindowHours);
  }, [fetchThreatIntelItems, fetchSessions, fetchStats, timeWindowHours]);

  const copyToClipboard = useCallback(async (text: string, key: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    const ok = await safeCopyToClipboard(text);
    if (ok) {
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    }
  }, []);

  const iocList = threatIntelItems || [];

  const filteredIocs = useMemo(() => {
    return iocList.filter((item) => {
      const q = searchQuery.toLowerCase();
      const matchesSearch =
        !q ||
        item.ioc_value.toLowerCase().includes(q) ||
        item.ioc_type.toLowerCase().includes(q) ||
        item.context.toLowerCase().includes(q);

      const matchesSeverity =
        selectedSeverity === 'all' || item.severity.toLowerCase() === selectedSeverity.toLowerCase();
      return matchesSearch && matchesSeverity;
    });
  }, [iocList, searchQuery, selectedSeverity]);

  // Threat severity breakdown from stats
  const threatCounts = useMemo(() => {
    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unclassified: 0,
    };

    (stats?.threat_distribution || []).forEach((td) => {
      const lvl = td.level.toLowerCase();
      if (lvl === 'critical') counts.critical = td.count;
      else if (lvl === 'high') counts.high = td.count;
      else if (lvl === 'medium') counts.medium = td.count;
      else if (lvl === 'low') counts.low = td.count;
      else if (lvl === 'unclassified') counts.unclassified = td.count;
    });

    const evaluated = counts.critical + counts.high + counts.medium + counts.low;
    if (counts.unclassified === 0) {
      counts.unclassified = Math.max(0, (stats?.total_sessions || 0) - evaluated);
    }
    return counts;
  }, [stats]);

  // Provenance counts across loaded sessions
  const provenanceStats = useMemo(() => {
    const list = sessions || [];
    let aiCount = 0;
    let fallbackCount = 0;
    let pendingCount = 0;

    list.forEach((s) => {
      if (s.assessment?.source === 'threat-intel-service') {
        aiCount++;
      } else if (s.intent && s.intent !== 'reconnaissance') {
        fallbackCount++;
      } else {
        pendingCount++;
      }
    });

    return { aiCount, fallbackCount, pendingCount };
  }, [sessions]);

  // High risk sessions
  const highRiskSessions = useMemo(() => {
    const list = sessions || [];
    return list
      .filter((s) => (s.skill_level ?? s.threat_score ?? 0) >= 3 || (s.command_count || s.commands_executed || 0) > 0)
      .slice(0, 10);
  }, [sessions]);

  return (
    <div className="space-y-5 font-mono pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-3 border-b border-cyan-500/20">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-wider text-white uppercase flex items-center gap-2.5">
            <Shield className="w-5 h-5 text-cyan-400" />
            <span>THREAT INTELLIGENCE & ADVERSARY CLASSIFICATION</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Indicators of Compromise (IOCs), adversarial skill evaluations, and threat taxonomy ({timeWindowHours >= 87600 ? 'All-Time' : `Last ${timeWindowHours}h`})
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => {
              fetchThreatIntelItems({ limit: 100 });
              fetchSessions({ hours: timeWindowHours, limit: 300 });
              fetchStats(timeWindowHours);
            }}
            className="p-2 rounded-lg bg-[#070e22] border border-cyan-500/25 text-slate-300 hover:text-cyan-300 transition-all"
            title="Refresh threat intel"
          >
            <RefreshCw className="w-4 h-4 text-cyan-400" />
          </button>
        </div>
      </div>

      {/* Analysis Provenance & AI Role Banner */}
      <div className="p-4 rounded-xl bg-[#070e22] border border-cyan-500/20 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-cyan-500/15 pb-2.5">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-bold text-white uppercase tracking-wider">
              AI ANALYSIS PIPELINE & CLASSIFICATION PROVENANCE
            </span>
          </div>
          <span className="text-[10px] text-slate-400">
            Truthful representation of AI evaluations vs rule-based heuristic fallbacks
          </span>
        </div>

        <p className="text-xs text-slate-300 leading-relaxed font-sans sm:text-sm">
          CloudDecept pairs high-throughput rule-based heuristic classification with asynchronous LLM forensic evaluation.
          Automated connection sprayers are triaged by rule-based taxonomy, while sessions exhibiting interactive shell execution
          or high-value cloud reconnaissance are queued for deep behavioral assessment.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 pt-1 text-xs">
          <div className="p-2.5 rounded-lg bg-[#040816] border border-purple-500/30">
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-purple-300 uppercase font-bold">AI EVALUATED</span>
              <span className="w-2 h-2 rounded-full bg-purple-400" />
            </div>
            <div className="text-lg font-bold text-white mt-1">{provenanceStats.aiCount} Sessions</div>
            <span className="text-[9px] text-slate-400">PostgreSQL session_summaries</span>
          </div>

          <div className="p-2.5 rounded-lg bg-[#040816] border border-amber-500/30">
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-amber-300 uppercase font-bold">RULE-BASED FALLBACK</span>
              <span className="w-2 h-2 rounded-full bg-amber-400" />
            </div>
            <div className="text-lg font-bold text-white mt-1">{provenanceStats.fallbackCount} Sessions</div>
            <span className="text-[9px] text-slate-400">Pre-computed command heuristics</span>
          </div>

          <div className="p-2.5 rounded-lg bg-[#040816] border border-slate-700">
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-slate-400 uppercase font-bold">PENDING / UNCLASSIFIED</span>
              <span className="w-2 h-2 rounded-full bg-slate-500" />
            </div>
            <div className="text-lg font-bold text-slate-300 mt-1">{provenanceStats.pendingCount} Sessions</div>
            <span className="text-[9px] text-slate-500">Awaiting deep assessment</span>
          </div>
        </div>
      </div>

      {/* Threat Severity Taxonomy Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
        <div className="p-3 rounded-xl bg-[#070e22] border border-rose-500/30">
          <div className="flex items-center justify-between">
            <span className="text-[10px] text-rose-400 uppercase font-bold">CRITICAL</span>
            <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="text-xl font-bold text-white mt-1">{threatCounts.critical}</div>
          <span className="text-[9px] text-slate-400">Exploit / Droppers</span>
        </div>

        <div className="p-3 rounded-xl bg-[#070e22] border border-orange-500/30">
          <div className="flex items-center justify-between">
            <span className="text-[10px] text-orange-400 uppercase font-bold">HIGH RISK</span>
            <AlertTriangle className="w-3.5 h-3.5 text-orange-400" />
          </div>
          <div className="text-xl font-bold text-white mt-1">{threatCounts.high}</div>
          <span className="text-[9px] text-slate-400">Cloud Recon / Enum</span>
        </div>

        <div className="p-3 rounded-xl bg-[#070e22] border border-amber-500/30">
          <div className="flex items-center justify-between">
            <span className="text-[10px] text-amber-400 uppercase font-bold">MEDIUM RISK</span>
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-xl font-bold text-white mt-1">{threatCounts.medium}</div>
          <span className="text-[9px] text-slate-400">Reconnaissance Probes</span>
        </div>

        <div className="p-3 rounded-xl bg-[#070e22] border border-emerald-500/30">
          <div className="flex items-center justify-between">
            <span className="text-[10px] text-emerald-400 uppercase font-bold">LOW RISK</span>
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-xl font-bold text-white mt-1">{threatCounts.low}</div>
          <span className="text-[9px] text-slate-400">Basic Connectivity</span>
        </div>

        <div className="p-3 rounded-xl bg-[#070e22] border border-slate-700/60">
          <div className="flex items-center justify-between">
            <span className="text-[10px] text-slate-400 uppercase font-bold">UNCLASSIFIED</span>
            <HelpCircle className="w-3.5 h-3.5 text-slate-500" />
          </div>
          <div className="text-xl font-bold text-slate-300 mt-1">{threatCounts.unclassified}</div>
          <span className="text-[9px] text-slate-500">Early Disconnects</span>
        </div>
      </div>

      {/* High-Risk Assessed Sessions Table */}
      <div className="rounded-xl border border-cyan-500/20 bg-[#070e22] overflow-hidden">
        <div className="p-3 bg-[#040816] border-b border-cyan-500/15 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            <h2 className="text-xs font-bold text-white uppercase tracking-wider">
              PRIORITY ASSESSED ATTACK SESSIONS
            </h2>
          </div>
          <span className="text-[10px] text-slate-400">Sessions with active command executions or threat ratings</span>
        </div>

        <div className="divide-y divide-cyan-500/10">
          {highRiskSessions.length === 0 ? (
            <div className="p-6 text-center text-xs text-slate-500">
              No high-risk sessions observed in the current time window.
            </div>
          ) : (
            highRiskSessions.map((s) => {
              const ip = s.src_ip || s.attacker_ip || 'unknown';
              const threat = evaluateThreat(s.threat_score ?? (s.skill_level ? s.skill_level * 10 : 20));
              const intent = normalizeIntent(s.intent);
              const cmdCount = s.command_count || s.commands_executed || 0;

              return (
                <div
                  key={s.session_id}
                  className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 hover:bg-cyan-950/20 transition-all text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2.5">
                      <span className={cn('px-1.5 py-0.5 rounded text-[9px] font-bold border', threat.badgeClass)}>
                        {threat.label.toUpperCase()} ({s.skill_level ?? 2}/10)
                      </span>
                      <span className="font-bold text-white font-mono">{ip}</span>
                      <span className="text-slate-600">•</span>
                      <span className="text-slate-400">{getCountryName(s.src_country || s.country)}</span>
                      <span className="text-slate-600">•</span>
                      <span className="text-cyan-300 font-bold">{intent.label}</span>
                    </div>
                    <div className="text-[11px] text-slate-400">
                      CASE-{s.session_id.slice(0, 8).toUpperCase()} • Commands: <span className={cn('font-bold', cmdCount > 0 ? 'text-emerald-400' : 'text-slate-500')}>{cmdCount}</span> • Duration: {s.duration_seconds || 0}s
                    </div>
                  </div>

                  <Link
                    href={`/sessions/${s.session_id}`}
                    className="flex items-center gap-1 px-3 py-1 rounded bg-cyan-500/15 border border-cyan-500/30 text-[10px] font-bold text-cyan-300 hover:bg-cyan-500/25 transition-all w-fit uppercase"
                  >
                    <span>INVESTIGATE CASE</span>
                    <ExternalLink className="w-2.5 h-2.5" />
                  </Link>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Extracted IOCs Section */}
      <div className="space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#070e22] p-3 rounded-xl border border-cyan-500/20">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyan-400/60" />
            <input
              type="search"
              placeholder="Search IOC value, type, context..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg bg-[#040816] border border-cyan-500/25 text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400"
            />
          </div>

          <div className="flex items-center gap-2">
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-[#040816] border border-cyan-500/25 text-xs text-cyan-300 focus:outline-none focus:border-cyan-400"
            >
              <option value="all">All IOC Severities</option>
              <option value="critical">Critical Only</option>
              <option value="high">High Only</option>
              <option value="medium">Medium Only</option>
              <option value="low">Low Only</option>
            </select>
          </div>
        </div>

        <div className="rounded-xl border border-cyan-500/20 bg-[#070e22] overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#040816] text-[10px] text-slate-400 uppercase border-b border-cyan-500/15">
                <tr>
                  <th className="py-2.5 px-4">SEVERITY</th>
                  <th className="py-2.5 px-4">IOC TYPE</th>
                  <th className="py-2.5 px-4">INDICATOR VALUE</th>
                  <th className="py-2.5 px-4">CONFIDENCE</th>
                  <th className="py-2.5 px-4">CONTEXT</th>
                  <th className="py-2.5 px-4">FIRST SEEN</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyan-500/10 font-mono">
                {filteredIocs.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-slate-500">
                      No threat indicators match the current query or time window.
                    </td>
                  </tr>
                ) : (
                  filteredIocs.map((ioc, idx) => (
                    <tr key={ioc.id || idx} className="hover:bg-cyan-950/20">
                      <td className="py-2.5 px-4">
                        <span className={cn(
                          'px-2 py-0.5 rounded text-[9px] font-bold border uppercase',
                          ioc.severity === 'critical' ? 'bg-rose-950/50 text-rose-300 border-rose-500/40' :
                          ioc.severity === 'high' ? 'bg-orange-950/50 text-orange-300 border-orange-500/40' :
                          ioc.severity === 'medium' ? 'bg-amber-950/50 text-amber-300 border-amber-500/40' :
                          'bg-emerald-950/50 text-emerald-300 border-emerald-500/40'
                        )}>
                          {ioc.severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 font-bold text-cyan-300 uppercase text-[10px]">{ioc.ioc_type}</td>
                      <td className="py-2.5 px-4 font-bold text-white">
                        <div className="flex items-center gap-1.5">
                          <span>{ioc.ioc_value}</span>
                          <button
                            onClick={(e) => copyToClipboard(ioc.ioc_value, `ioc-${idx}`, e)}
                            className="text-slate-500 hover:text-cyan-300"
                          >
                            {copiedKey === `ioc-${idx}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          </button>
                        </div>
                      </td>
                      <td className="py-2.5 px-4 text-slate-300">{(ioc.confidence * 100).toFixed(0)}%</td>
                      <td className="py-2.5 px-4 text-slate-400 max-w-xs truncate">{ioc.context}</td>
                      <td className="py-2.5 px-4 text-slate-400">{formatTimestamp(ioc.created_at)}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}