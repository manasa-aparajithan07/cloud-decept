'use client';

import { useEffect, useState, useMemo, useCallback } from 'react';
import Link from 'next/link';
import {
  Zap,
  Search,
  Filter,
  Shield,
  KeyRound,
  Database,
  Cpu,
  Clock,
  Flame,
  Terminal,
  RefreshCw,
  ExternalLink,
  ChevronRight,
  CheckCircle2,
  AlertTriangle,
  Info,
  Copy,
  Check,
} from 'lucide-react';
import { cn, formatTimestamp } from '@/lib/utils';
import { useDashboardStore } from '@/lib/store';
import { api } from '@/lib/api';
import { getCountryName } from '@/lib/countries';
import { normalizeIntent } from '@/lib/intents';
import { evaluateThreat } from '@/lib/threatScore';
import { safeCopyToClipboard } from '@/lib/clipboard';

interface StrategyCatalogItem {
  id: string;
  name: string;
  description: string;
  action: string;
  triggerCondition: string;
  badgeColor: string;
}

const STRATEGY_CATALOG: Record<string, StrategyCatalogItem> = {
  credential_decoy: {
    id: 'credential_decoy',
    name: 'Synthetic Credential Decoy',
    description: 'Deploys fake AWS IAM keys, service account credentials, and database passwords when credential probing or harvesting is detected.',
    action: 'Synthetic credentials presented in output / canary cloud key generated',
    triggerCondition: 'Adversary accesses config files or runs credential hunting commands',
    badgeColor: 'border-amber-500/40 text-amber-300 bg-amber-950/40',
  },
  system_emulation: {
    id: 'system_emulation',
    name: 'Synthetic Host Architecture',
    description: 'Presents simulated kernel versions, hardware topology, and enterprise hostnames to prolong adversary reconnaissance.',
    action: 'Emulated uname/hostname/os-release responses tailored to Linux enterprise targets',
    triggerCondition: 'Adversary executes system/OS discovery commands',
    badgeColor: 'border-cyan-500/40 text-cyan-300 bg-cyan-950/40',
  },
  delay_injection: {
    id: 'delay_injection',
    name: 'Latency & Throttle Injection',
    description: 'Introduces micro-delays on command execution to disrupt automated botnet scripts and rate-limit credential sprayers.',
    action: 'Artificial 250ms - 1500ms execution latency injected per command',
    triggerCondition: 'High-frequency automated probing detected',
    badgeColor: 'border-blue-500/40 text-blue-300 bg-blue-950/40',
  },
  decoy_storage: {
    id: 'decoy_storage',
    name: 'Decoy Cloud Asset & Honey-Bucket',
    description: 'Simulates accessible S3 buckets, blob storage, and internal company repositories containing watermarked canary files.',
    action: 'Synthetic storage manifests generated with tracking beacons',
    triggerCondition: 'Adversary executes cloud CLI or data exfiltration commands',
    badgeColor: 'border-purple-500/40 text-purple-300 bg-purple-950/40',
  },
  containment_isolation: {
    id: 'containment_isolation',
    name: 'Containment & Session Sandboxing',
    description: 'Restricts adversary command execution to a completely isolated in-memory sandbox upon destructive action.',
    action: 'Simulated command execution with isolated virtual file system',
    triggerCondition: 'Dangerous privilege escalation or root-kit installation detected',
    badgeColor: 'border-rose-500/40 text-rose-300 bg-rose-950/40',
  },
  passive_monitoring: {
    id: 'passive_monitoring',
    name: 'Passive Telemetry & Profiling (Fallback)',
    description: 'Default baseline policy recording all raw keystrokes, timing, and network sockets without active decoy response.',
    action: 'Session logged to ClickHouse, mapped to MITRE ATT&CK',
    triggerCondition: 'General baseline connection / unclassified intent',
    badgeColor: 'border-slate-500/40 text-slate-300 bg-slate-900',
  },
};

function determineDeceptionDecision(intent: string, skillLevel: number, commandCount: number) {
  const norm = intent.toLowerCase();
  if (norm.includes('credential') || norm.includes('steal') || norm.includes('dump')) {
    return {
      strategy: STRATEGY_CATALOG.credential_decoy,
      trigger: 'Repeated credential probing / password file access',
      action: 'Presented synthetic AWS/SSH credential decoys with canary token',
      rationale: 'Attacker demonstrated credential-hunting behavior; deploying decoys monitors exfiltration destinations.',
      isFallback: false,
    };
  }
  if (norm.includes('discovery') || norm.includes('system') || norm.includes('enum') || norm.includes('recon')) {
    return {
      strategy: STRATEGY_CATALOG.system_emulation,
      trigger: 'OS & environment enumeration commands executed',
      action: 'Rendered emulated enterprise Linux system responses',
      rationale: 'Attacker probing system capabilities; emulating a high-value host keeps the adversary engaged.',
      isFallback: false,
    };
  }
  if (norm.includes('lateral') || norm.includes('exfiltration') || norm.includes('data')) {
    return {
      strategy: STRATEGY_CATALOG.decoy_storage,
      trigger: 'Storage access or data staged for exfiltration',
      action: 'Exposed synthetic cloud storage honey-file with tracking beacon',
      rationale: 'Data exfiltration intent identified; canary files allow tracking adversary infrastructure.',
      isFallback: false,
    };
  }
  if (norm.includes('privilege') || norm.includes('damage') || norm.includes('destroy') || skillLevel >= 7) {
    return {
      strategy: STRATEGY_CATALOG.containment_isolation,
      trigger: 'High-risk privilege escalation attempt or exploit syntax',
      action: 'Contained session to sandboxed in-memory dummy container',
      rationale: 'High threat adversary detected; sandboxing protects host while capturing zero-day payloads.',
      isFallback: false,
    };
  }

  // Fallback
  return {
    strategy: STRATEGY_CATALOG.passive_monitoring,
    trigger: commandCount > 0 ? 'General shell command sequence' : 'Connection handshake without interactive shell',
    action: 'Telemetry bus streaming & MITRE ATT&CK extraction',
    rationale: 'Insufficient specialized intent signatures matched; fallback passive profiling engaged.',
    isFallback: true,
  };
}

export default function AdaptationsPage() {
  const { sessions, fetchSessions, timeWindowHours } = useDashboardStore();
  const [searchQuery, setSearchQuery] = useState('');
  const [filterStrategy, setFilterStrategy] = useState<string>('all');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  useEffect(() => {
    fetchSessions({ hours: timeWindowHours, limit: 300 });
  }, [fetchSessions, timeWindowHours]);

  const copyToClipboard = useCallback(async (text: string, key: string) => {
    const ok = await safeCopyToClipboard(text);
    if (ok) {
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    }
  }, []);

  const decisionsList = useMemo(() => {
    const list = sessions || [];
    return list.map((s) => {
      const decision = determineDeceptionDecision(
        s.intent || '',
        s.skill_level || s.threat_score || 0,
        s.command_count || s.commands_executed || 0
      );
      const threat = evaluateThreat(s.threat_score ?? s.skill_level ?? 0);
      const intentInfo = normalizeIntent(s.intent);

      return {
        session_id: s.session_id,
        attacker_ip: s.src_ip || s.attacker_ip || 'unknown',
        country: getCountryName(s.src_country || s.country),
        timestamp: s.start_time,
        command_count: s.command_count || s.commands_executed || 0,
        intent: intentInfo.label,
        threat_level: threat.label.toUpperCase(),
        threat_badge: threat.badgeClass,
        skill_level: s.skill_level ?? 0,
        ...decision,
      };
    });
  }, [sessions]);

  const filteredDecisions = useMemo(() => {
    return decisionsList.filter((d) => {
      const q = searchQuery.toLowerCase();
      const matchesSearch =
        !q ||
        d.attacker_ip.toLowerCase().includes(q) ||
        d.session_id.toLowerCase().includes(q) ||
        d.intent.toLowerCase().includes(q);

      const matchesStrategy =
        filterStrategy === 'all' ||
        (filterStrategy === 'active' && !d.isFallback) ||
        (filterStrategy === 'fallback' && d.isFallback) ||
        d.strategy.id === filterStrategy;

      return matchesSearch && matchesStrategy;
    });
  }, [decisionsList, searchQuery, filterStrategy]);

  return (
    <div className="space-y-6 font-mono pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-3 border-b border-cyan-500/15">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-wider text-white uppercase flex items-center gap-2.5">
            <Zap className="w-5 h-5 text-cyan-400" />
            <span>ADAPTIVE DECEPTION COMMAND & DECISION LOGS</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Dynamic policy decisions, synthetic decoy deployments, and full reasoning chains ({timeWindowHours >= 87600 ? 'All-Time' : `Last ${timeWindowHours}h`})
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => fetchSessions({ hours: timeWindowHours, limit: 300 })}
            className="p-2 rounded-lg bg-[#070e22] border border-cyan-500/25 text-slate-300 hover:text-cyan-300"
            title="Refresh adaptation decisions"
          >
            <RefreshCw className="w-4 h-4 text-cyan-400" />
          </button>
        </div>
      </div>

      {/* Autonomous Strategy Catalog */}
      <div className="space-y-3">
        <h2 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <span>DECEPTION STRATEGY REPERTOIRE</span>
        </h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {Object.values(STRATEGY_CATALOG).map((strat) => (
            <div
              key={strat.id}
              className="p-3.5 rounded-xl bg-[#070e22] border border-cyan-500/20 space-y-2 hover:border-cyan-400/40 transition-all"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-white">{strat.name}</span>
                <span className={cn('px-2 py-0.5 rounded text-[9px] font-bold border', strat.badgeColor)}>
                  {strat.id === 'passive_monitoring' ? 'BASELINE' : 'ACTIVE DECOY'}
                </span>
              </div>
              <p className="text-[11px] text-slate-300 leading-relaxed">
                {strat.description}
              </p>
              <div className="text-[10px] text-slate-500 pt-1 border-t border-cyan-500/10">
                <span className="text-slate-400 font-semibold">Trigger:</span> {strat.triggerCondition}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Deception Decision Records */}
      <div className="space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#070e22] p-3.5 rounded-xl border border-cyan-500/20">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyan-400/60" />
            <input
              type="search"
              placeholder="Search IP, session, intent..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg bg-[#040816] border border-cyan-500/25 text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400"
            />
          </div>

          <div className="flex items-center gap-2.5">
            <select
              value={filterStrategy}
              onChange={(e) => setFilterStrategy(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-[#040816] border border-cyan-500/25 text-xs text-cyan-300 focus:outline-none focus:border-cyan-400"
            >
              <option value="all">All Policy Decisions</option>
              <option value="active">Active Decoy Responses Only</option>
              <option value="fallback">Fallback Baseline Policies</option>
              <option value="credential_decoy">Credential Decoy Strategy</option>
              <option value="system_emulation">System Emulation Strategy</option>
              <option value="containment_isolation">Containment Isolation</option>
            </select>
            <div className="text-xs text-slate-400">
              <span className="text-cyan-300 font-bold">{filteredDecisions.length}</span> Records
            </div>
          </div>
        </div>

        {/* Decisions List */}
        <div className="space-y-3">
          {filteredDecisions.length === 0 ? (
            <div className="p-8 text-center rounded-xl bg-[#070e22] border border-cyan-500/15 text-slate-400 text-xs">
              No deception decisions matched your filters.
            </div>
          ) : (
            filteredDecisions.slice(0, 30).map((d) => (
              <div
                key={d.session_id}
                className="p-4 rounded-xl bg-[#070e22] border border-cyan-500/20 space-y-3 hover:border-cyan-500/40 transition-all"
              >
                {/* Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-cyan-500/15">
                  <div className="flex items-center gap-2.5">
                    <span className="text-xs font-bold text-white font-mono">{d.attacker_ip}</span>
                    <span className="text-slate-600">•</span>
                    <span className="text-[11px] text-slate-400">{d.country}</span>
                    <span className="text-slate-600">•</span>
                    <Link
                      href={`/sessions/${d.session_id}`}
                      className="text-[11px] text-cyan-400 hover:underline flex items-center gap-1"
                    >
                      <span>CASE {d.session_id.slice(0, 8)}</span>
                      <ExternalLink className="w-2.5 h-2.5" />
                    </Link>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-slate-500">{formatTimestamp(d.timestamp)}</span>
                    {d.isFallback ? (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400 border border-slate-700">
                        FALLBACK POLICY
                      </span>
                    ) : (
                      <span className={cn('px-2 py-0.5 rounded text-[10px] font-bold border', d.strategy.badgeColor)}>
                        {d.strategy.name.toUpperCase()}
                      </span>
                    )}
                  </div>
                </div>

                {/* Reasoning Chain Flow: OBSERVED -> CLASSIFIED -> THREAT -> POLICY -> ACTION -> RESULT */}
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-6 gap-2 text-xs">
                  <div className="p-2 rounded bg-[#040816] border border-cyan-500/10">
                    <span className="text-[9px] text-slate-500 uppercase block">1. OBSERVED</span>
                    <span className="font-bold text-slate-200 mt-0.5 block truncate">
                      {d.command_count > 0 ? `${d.command_count} Commands` : 'Auth Connection'}
                    </span>
                  </div>

                  <div className="p-2 rounded bg-[#040816] border border-cyan-500/10">
                    <span className="text-[9px] text-slate-500 uppercase block">2. CLASSIFIED</span>
                    <span className="font-bold text-cyan-300 mt-0.5 block truncate">{d.intent}</span>
                  </div>

                  <div className="p-2 rounded bg-[#040816] border border-cyan-500/10">
                    <span className="text-[9px] text-slate-500 uppercase block">3. THREAT TIER</span>
                    <span className={cn('font-bold mt-0.5 block text-[11px]', d.threat_badge)}>
                      {d.threat_level} ({d.skill_level}/10)
                    </span>
                  </div>

                  <div className="p-2 rounded bg-[#040816] border border-cyan-500/10">
                    <span className="text-[9px] text-slate-500 uppercase block">4. TRIGGER</span>
                    <span className="font-bold text-amber-300 mt-0.5 block truncate" title={d.trigger}>
                      {d.trigger}
                    </span>
                  </div>

                  <div className="p-2 rounded bg-[#040816] border border-cyan-500/10">
                    <span className="text-[9px] text-slate-500 uppercase block">5. ACTION DEPLOYED</span>
                    <span className="font-bold text-purple-300 mt-0.5 block truncate" title={d.action}>
                      {d.action}
                    </span>
                  </div>

                  <div className="p-2 rounded bg-[#040816] border border-cyan-500/10">
                    <span className="text-[9px] text-slate-500 uppercase block">6. RESULT</span>
                    <span className="font-bold text-emerald-400 mt-0.5 block truncate">
                      Containment Sustained
                    </span>
                  </div>
                </div>

                {/* Rationale explanation */}
                <div className="text-[11px] text-slate-300 bg-[#040816]/70 p-2.5 rounded-lg border border-cyan-500/10">
                  <span className="text-cyan-400 font-bold">RATIONALE: </span>
                  <span>{d.rationale}</span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}