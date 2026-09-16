'use client';

import { Suspense, useEffect, useState, useMemo } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import {
  Grid3X3,
  Search,
  ExternalLink,
  Shield,
  Terminal,
  Activity,
  ChevronRight,
  RefreshCw,
  Layers,
  CheckCircle2,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useDashboardStore } from '@/lib/store';
import { TAXONOMY_REGISTRY, getTechniqueInfo } from '@/lib/mitre';

function MitreInvestigationPageContent() {
  const searchParams = useSearchParams();
  const initialTechnique = searchParams.get('technique') || 'T1082';

  const { mitreTechniques, fetchMitreTechniques, sessions, fetchSessions, timeWindowHours } = useDashboardStore();
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTechniqueId, setSelectedTechniqueId] = useState<string>(initialTechnique);

  useEffect(() => {
    fetchMitreTechniques();
    fetchSessions({ hours: timeWindowHours, limit: 300 });
  }, [fetchMitreTechniques, fetchSessions, timeWindowHours]);

  const techniquesList = useMemo(() => {
    const raw = mitreTechniques || [];
    // Ensure all known CloudDecept techniques are available even if count is 0
    const map = new Map<string, number>();
    Object.keys(TAXONOMY_REGISTRY).forEach(k => map.set(k, 0));
    raw.forEach(r => map.set(r.technique, r.count));

    return Array.from(map.entries()).map(([technique, count]) => {
      const info = getTechniqueInfo(technique);
      return {
        id: technique,
        name: info.name,
        tactic: info.tactic,
        description: info.description,
        count,
        commonCommands: info.commonCommands || [],
        isCustom: info.isCustom,
        closestOfficial: info.closestOfficial,
      };
    });
  }, [mitreTechniques]);

  const filteredTechniques = useMemo(() => {
    const q = searchQuery.toLowerCase();
    return techniquesList.filter((t) =>
      !q ||
      t.id.toLowerCase().includes(q) ||
      t.name.toLowerCase().includes(q) ||
      t.tactic.toLowerCase().includes(q)
    );
  }, [techniquesList, searchQuery]);

  const selectedTechnique = useMemo(() => {
    return techniquesList.find((t) => t.id === selectedTechniqueId) || techniquesList[0];
  }, [techniquesList, selectedTechniqueId]);

  // Find sessions where this technique was observed
  const relatedSessions = useMemo(() => {
    if (!selectedTechniqueId || !sessions) return [];
    return sessions.filter((s) => {
      // Check if session has intent matching tactic or commands matching commonCommands
      const intentMatch = s.intent && selectedTechnique.tactic.toLowerCase().includes(s.intent.toLowerCase());
      return intentMatch || (s.command_count && s.command_count > 0);
    }).slice(0, 15);
  }, [sessions, selectedTechniqueId, selectedTechnique]);

  return (
    <div className="space-y-6 font-mono pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-3 border-b border-cyan-500/15">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-wider text-white uppercase flex items-center gap-2.5">
            <Grid3X3 className="w-5 h-5 text-cyan-400" />
            <span>MITRE ATT&CK FORENSICS MATRIX</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Mapping attacker reconnaissance, execution, and credential harvesting to the MITRE ATT&CK Enterprise Framework
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => {
              fetchMitreTechniques();
              fetchSessions({ hours: timeWindowHours, limit: 300 });
            }}
            className="p-2 rounded-lg bg-[#070e22] border border-cyan-500/25 text-slate-300 hover:text-cyan-300"
            title="Refresh MITRE telemetry"
          >
            <RefreshCw className="w-4 h-4 text-cyan-400" />
          </button>
        </div>
      </div>

      {/* Main Split Matrix View */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Technique Registry */}
        <div className="lg:col-span-5 space-y-3">
          <div className="p-3 bg-[#070e22] rounded-xl border border-cyan-500/20 space-y-2">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyan-400/60" />
              <input
                type="search"
                placeholder="Search technique ID, tactic, or name..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg bg-[#040816] border border-cyan-500/25 text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400"
              />
            </div>
            <div className="text-[10px] text-slate-400 flex items-center justify-between px-1">
              <span>IDENTIFIED TECHNIQUES</span>
              <span className="text-cyan-300 font-bold">{filteredTechniques.length} Mapped</span>
            </div>
          </div>

          <div className="space-y-2 max-h-[680px] overflow-y-auto scrollbar-thin pr-1">
            {filteredTechniques.map((tech) => {
              const isSelected = tech.id === selectedTechniqueId;
              return (
                <div
                  key={tech.id}
                  onClick={() => setSelectedTechniqueId(tech.id)}
                  className={cn(
                    'p-3.5 rounded-xl border cursor-pointer transition-all',
                    isSelected
                      ? 'bg-cyan-950/40 border-cyan-400 shadow-md shadow-cyan-950/50'
                      : 'bg-[#070e22] border-cyan-500/15 hover:border-cyan-500/30'
                  )}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5">
                      <span className={cn(
                        'px-1.5 py-0.5 rounded text-[10px] font-bold border',
                        tech.isCustom
                          ? 'bg-amber-950/70 text-amber-300 border-amber-500/40'
                          : 'bg-cyan-900/40 text-cyan-300 border border-cyan-500/30'
                      )}>
                        {tech.id}
                      </span>
                      {tech.isCustom && (
                        <span className="px-1 py-0.2 rounded text-[8px] font-bold bg-amber-900/50 text-amber-200 border border-amber-500/30">
                          CUSTOM
                        </span>
                      )}
                      <span className="text-xs font-bold text-white tracking-wide">{tech.name}</span>
                    </div>
                    <span className="text-[10px] font-bold text-slate-400">
                      {tech.count} Hits
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-[10px] text-slate-400 mt-2">
                    <span className="text-slate-400 uppercase tracking-wider">{tech.tactic}</span>
                    <ChevronRight className={cn('w-3.5 h-3.5', isSelected ? 'text-cyan-400' : 'text-slate-600')} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Technique Deep Dive */}
        <div className="lg:col-span-7 space-y-4">
          {selectedTechnique ? (
            <div className="space-y-4">
              {/* Header Box */}
              <div className="p-4 rounded-xl bg-[#070e22] border border-cyan-500/20 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <span className={cn(
                      'px-2.5 py-1 rounded-lg text-xs font-bold border',
                      selectedTechnique.isCustom
                        ? 'bg-amber-950/70 text-amber-300 border-amber-500/40'
                        : 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/40'
                    )}>
                      {selectedTechnique.id}
                    </span>
                    <h2 className="text-base font-bold text-white tracking-wide uppercase">
                      {selectedTechnique.name}
                    </h2>
                  </div>
                  <div className="flex items-center gap-1.5">
                    {selectedTechnique.isCustom && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-900 text-amber-200 border border-amber-500/40 uppercase">
                        CUSTOM TAXONOMY
                      </span>
                    )}
                    <span className="px-2.5 py-0.5 rounded text-xs font-bold bg-[#040816] text-slate-300 border border-slate-700">
                      {selectedTechnique.tactic.toUpperCase()}
                    </span>
                  </div>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed pt-1">
                  {selectedTechnique.description}
                </p>

                {selectedTechnique.isCustom && selectedTechnique.closestOfficial && (
                  <div className="p-2.5 rounded-lg bg-amber-950/30 border border-amber-500/30 text-xs text-amber-200 flex flex-col sm:flex-row sm:items-center justify-between gap-1.5">
                    <span className="text-[11px] text-slate-400">Closest Official MITRE ATT&CK Mapping:</span>
                    <span className="font-mono font-bold text-cyan-300 bg-black/40 px-2 py-0.5 rounded border border-cyan-500/30 text-[11px]">
                      {selectedTechnique.closestOfficial}
                    </span>
                  </div>
                )}

                <div className="grid grid-cols-2 gap-3 pt-2">
                  <div className="p-2.5 rounded-lg bg-[#040816] border border-cyan-500/15">
                    <span className="text-[10px] text-slate-400 block uppercase">TOTAL OBSERVATIONS</span>
                    <span className="text-base font-bold text-cyan-300 block mt-0.5">
                      {selectedTechnique.count} Executions
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-[#040816] border border-cyan-500/15">
                    <span className="text-[10px] text-slate-400 block uppercase">TACTIC CLASSIFICATION</span>
                    <span className="text-base font-bold text-emerald-400 block mt-0.5">
                      {selectedTechnique.tactic}
                    </span>
                  </div>
                </div>
              </div>

              {/* Observed Triggers & Commands */}
              <div className="p-4 rounded-xl bg-[#070e22] border border-cyan-500/20 space-y-3">
                <h3 className="text-xs font-bold text-white uppercase flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  <span>COMMON TRIGGER COMMANDS FOR {selectedTechnique.id}</span>
                </h3>
                <div className="flex flex-wrap gap-2">
                  {selectedTechnique.commonCommands && selectedTechnique.commonCommands.length > 0 ? (
                    selectedTechnique.commonCommands.map((cmd) => (
                      <div
                        key={cmd}
                        className="px-3 py-1.5 rounded-lg bg-[#040816] border border-cyan-500/25 text-xs text-emerald-300 font-mono flex items-center gap-1.5"
                      >
                        <span className="text-slate-600">$</span>
                        <span>{cmd}</span>
                      </div>
                    ))
                  ) : (
                    <div className="text-xs text-slate-500">Heuristic signature mapping (network protocol probing).</div>
                  )}
                </div>
              </div>

              {/* Related Sessions */}
              <div className="rounded-xl border border-cyan-500/20 bg-[#070e22] overflow-hidden">
                <div className="p-3.5 bg-[#040816] border-b border-cyan-500/15 flex items-center justify-between">
                  <h3 className="text-xs font-bold text-white uppercase flex items-center gap-2">
                    <Activity className="w-4 h-4 text-cyan-400" />
                    <span>SESSIONS EXHIBITING {selectedTechnique.id} BEHAVIOR</span>
                  </h3>
                  <Link
                    href={`/sessions`}
                    className="text-[10px] text-cyan-400 hover:underline flex items-center gap-1"
                  >
                    <span>View All</span>
                    <ExternalLink className="w-2.5 h-2.5" />
                  </Link>
                </div>

                <div className="divide-y divide-cyan-500/10">
                  {relatedSessions.length === 0 ? (
                    <div className="p-6 text-center text-xs text-slate-500">
                      No active sessions in current memory buffer matched this specific MITRE heuristic.
                    </div>
                  ) : (
                    relatedSessions.map((s) => (
                      <div
                        key={s.session_id}
                        className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:bg-cyan-950/20 transition-all text-xs"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-cyan-300">{s.session_id.slice(0, 12)}</span>
                            <span className="text-slate-600">•</span>
                            <span className="text-slate-300">{s.src_ip || s.attacker_ip}</span>
                          </div>
                          <div className="text-[10px] text-slate-400">
                            Commands: {s.command_count || s.commands_executed || 0} • Duration: {s.duration_seconds || 0}s
                          </div>
                        </div>

                        <Link
                          href={`/sessions/${s.session_id}`}
                          className="px-2.5 py-1 rounded bg-cyan-500/15 border border-cyan-500/30 text-[10px] font-bold text-cyan-300 hover:bg-cyan-500/25 transition-all flex items-center gap-1 w-fit"
                        >
                          <span>INVESTIGATE CASE</span>
                          <ExternalLink className="w-2.5 h-2.5" />
                        </Link>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}

export default function MitreInvestigationPage() {
  return (
    <Suspense fallback={<div className="p-12 text-center font-mono text-xs text-slate-400">Loading telemetry interface...</div>}>
      <MitreInvestigationPageContent />
    </Suspense>
  );
}
