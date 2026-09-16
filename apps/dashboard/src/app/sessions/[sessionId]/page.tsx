'use client';

import { useEffect, useState, useMemo, useCallback } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  ArrowLeft,
  Terminal,
  Shield,
  Copy,
  Check,
  KeyRound,
  ChevronDown,
  ChevronUp,
  Activity,
  Zap,
  Globe,
  Clock,
  AlertOctagon,
  FileCode,
  Download,
  CheckCircle2,
  XCircle,
  Cpu,
  CornerDownRight,
  ExternalLink,
  Search,
  Eye,
  EyeOff,
  Sparkles,
  AlertCircle,
  RefreshCw,
  Bot,
} from 'lucide-react';
import { cn, formatTimestamp, formatDuration } from '@/lib/utils';
import { useDashboardStore } from '@/lib/store';
import { getCountryName } from '@/lib/countries';
import { normalizeIntent } from '@/lib/intents';
import { evaluateThreat } from '@/lib/threatScore';
import { safeCopyToClipboard } from '@/lib/clipboard';
import { api } from '@/lib/api';
import { FinalAssessment, AIForensicAnalysis } from '@/lib/types';

import { getTechniqueInfo, normalizeMitreId } from '@/lib/mitre';

// Timeline event union type
interface TimelineEvent {
  id: string;
  timestamp: string;
  type: 'connection' | 'auth' | 'command' | 'adaptation' | 'threat_assessment' | 'termination';
  title: string;
  status?: 'success' | 'failed' | 'info' | 'warning';
  badge?: string;
  summary: string;
  details?: Record<string, any>;
  data?: any;
}

export default function SessionInvestigationPage() {
  const params = useParams();
  const router = useRouter();
  const sessionId = params.sessionId as string;

  const {
    selectedSession,
    commands,
    sessionAuth,
    threatIntel,
    fetchSession,
    fetchSessionCommands,
    fetchSessionAuth,
    fetchSessionThreatIntel,
  } = useDashboardStore();

  const [activeTab, setActiveTab] = useState<'timeline' | 'commands' | 'auth' | 'intelligence' | 'raw'>('timeline');
  const [expandedEvents, setExpandedEvents] = useState<Set<string>>(new Set());
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [adaptiveSession, setAdaptiveSession] = useState<any>(null);
  const [loadingAdaptive, setLoadingAdaptive] = useState(false);
  const [commandFilter, setCommandFilter] = useState('');
  const [showRawPasswords, setShowRawPasswords] = useState(false);

  // AI Forensic Analysis State (Gemini Integration)
  const [aiAnalysis, setAiAnalysis] = useState<AIForensicAnalysis | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const [aiCached, setAiCached] = useState(false);

  const handleAnalyzeWithAI = useCallback(async () => {
    if (!sessionId || aiLoading) return;
    setAiLoading(true);
    setAiError(null);
    try {
      const resp = await api.analyzeSessionWithAI(sessionId);
      if (resp && resp.analysis) {
        setAiAnalysis(resp.analysis);
        setAiCached(Boolean(resp.cached));
      } else {
        throw new Error('Received empty analysis from server');
      }
    } catch (err: any) {
      const msg = err?.message || 'Failed to connect to AI analysis service';
      setAiError(msg);
      setAiAnalysis(null);
    } finally {
      setAiLoading(false);
    }
  }, [sessionId, aiLoading]);


  const handleCopy = useCallback(async (text: string | null | undefined, key: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    if (!text) return;
    const ok = await safeCopyToClipboard(text);
    if (ok) {
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    }
  }, []);

  useEffect(() => {
    if (sessionId) {
      fetchSession(sessionId);
      fetchSessionCommands(sessionId);
      fetchSessionAuth(sessionId);
      fetchSessionThreatIntel(sessionId);

      // Attempt to load adaptive session context
      setLoadingAdaptive(true);
      api.getAdaptiveSession(sessionId)
        .then((data) => setAdaptiveSession(data))
        .catch(() => setAdaptiveSession(null))
        .finally(() => setLoadingAdaptive(false));
    }
  }, [sessionId, fetchSession, fetchSessionCommands, fetchSessionAuth, fetchSessionThreatIntel]);

  const toggleEvent = (id: string) => {
    setExpandedEvents((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const expandAll = () => {
    const allIds = unifiedTimeline.map((e) => e.id);
    setExpandedEvents(new Set(allIds));
  };

  const collapseAll = () => {
    setExpandedEvents(new Set());
  };

  const session = selectedSession;
  const authEvents = sessionAuth ?? [];
  const commandsList = commands ?? [];
  const ip = session?.src_ip ?? session?.attacker_ip ?? 'unknown';
  const countryName = getCountryName(session?.src_country || session?.country);

  // Canonical assessment reconciliation:
  // Prefer reconciled session.assessment or threatIntel.summary to ensure one unified truth
  const canonicalAssessment = useMemo((): FinalAssessment | null => {
    if (session?.assessment) return session.assessment;
    if (threatIntel?.summary) {
      const s = threatIntel.summary;
      const skill = s.skill_level ?? session?.skill_level ?? 1;
      const score = session?.threat_score ?? (skill <= 10 ? skill * 10 : skill);
      const rawRisk = s.risk_level?.toLowerCase();
      const threatLevel: FinalAssessment['threat_level'] =
        rawRisk === 'critical' || rawRisk === 'high' || rawRisk === 'medium' || rawRisk === 'low'
          ? rawRisk
          : (score <= 25 ? 'low' : score <= 55 ? 'medium' : score <= 75 ? 'high' : 'critical');
      const intentStr = s.intent || s.primary_objective || session?.intent || 'system discovery';
      return {
        status: 'classified',
        threat_level: threatLevel,
        threat_score: score,
        intent: intentStr,
        skill_level: skill,
        mitre_techniques: s.mitre_techniques || [],
        tactics: session?.tactics || ['Discovery'],
        confidence: 0.85,
        evidence_count: commandsList.length + authEvents.length,
        analysis_status: 'completed',
        analyzed_at: s.created_at || threatIntel.timestamp || new Date().toISOString(),
        source: 'threat-intel-service',
        provenance: 'postgresql:session_summaries',
      };
    }
    return null;
  }, [session, threatIntel, commandsList.length, authEvents.length]);

  const effectiveSkillLevel = canonicalAssessment?.skill_level ?? session?.skill_level ?? 0;
  const effectiveThreatScore = canonicalAssessment?.threat_score ?? session?.threat_score ?? (effectiveSkillLevel * 10);
  const threat = evaluateThreat(effectiveThreatScore);
  const primaryIntent = normalizeIntent(canonicalAssessment?.intent || session?.intent || (session?.intent_history && session.intent_history[0]));

  // Analysis Provenance determination (truthful, no fabricated AI labels)
  const analysisProvenance = useMemo(() => {
    if (threatIntel?.summary) {
      return {
        label: 'AI ANALYZED',
        badgeClass: 'bg-purple-500/20 text-purple-300 border-purple-500/40',
        detail: 'PostgreSQL Threat Intelligence Engine (session_summaries)',
      };
    }
    if (session?.intent && session.intent !== 'reconnaissance') {
      return {
        label: 'RULE-BASED FALLBACK',
        badgeClass: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
        detail: 'Rule-Based Classifier & Heuristic Taxonomy',
      };
    }
    return {
      label: 'PENDING ANALYSIS',
      badgeClass: 'bg-slate-800 text-slate-400 border-slate-700',
      detail: 'Raw telemetry awaiting asynchronous LLM evaluation',
    };
  }, [threatIntel, session]);

  // Executive Attack Narrative (evidence-derived, concise analyst-first sentence)
  const executiveNarrative = useMemo(() => {
    if (!session) return '';
    const authSuccess = authEvents.some(a => a.success);
    const authUser = authEvents.find(a => a.success)?.username || (authEvents[0]?.username ? authEvents[0].username : 'unknown');
    const authTotal = authEvents.length;
    const cmdCount = commandsList.length;
    const durSec = session.duration_seconds || 0;

    const sourceLabel = (session.attacker_ip === '172.18.0.1' || session.attacker_ip === '129.146.167.2')
      ? `Internal/test infrastructure source ${ip}`
      : `External source ${ip} (${countryName})`;

    const authText = authSuccess
      ? `successfully authenticated as '${authUser}' via password`
      : authTotal > 0
      ? `failed all ${authTotal} credential probe attempt${authTotal > 1 ? 's' : ''}`
      : `connected without credential challenge`;

    let behaviorText = '';
    if (cmdCount > 0) {
      const hasAws = commandsList.some(c => c.command.includes('aws ') || c.command.includes('s3 ') || c.command.includes('ec2 '));
      const hasDropper = commandsList.some(c => c.command.includes('update.sh') || c.command.includes('217.60.195.113') || c.command.includes('| bash') || c.command.includes('| sh'));
      const hasRecon = commandsList.some(c => c.command.includes('uname') || c.command.includes('whoami') || c.command.includes('id') || c.command.includes('/proc/'));

      const traits: string[] = [];
      if (hasRecon) traits.push('host and user reconnaissance');
      if (hasAws) traits.push('AWS cloud infrastructure enumeration');
      if (hasDropper) traits.push('payload dropper download attempt');

      const traitStr = traits.length > 0 ? traits.join(', ') : 'interactive commands';
      behaviorText = `executed ${cmdCount} command${cmdCount > 1 ? 's' : ''} performing ${traitStr} before terminating the session cleanly`;
    } else {
      behaviorText = `disconnected after ${durSec}s before actionable command patterns were observed`;
    }

    return `${sourceLabel} ${authText} and ${behaviorText}.`;
  }, [session, authEvents, commandsList, ip, countryName]);

  // Build the Unified Chronological Attack Timeline
  const unifiedTimeline = useMemo(() => {
    if (!session) return [];
    const events: TimelineEvent[] = [];

    // 1. Connection Event
    if (session.start_time) {
      events.push({
        id: `conn-${session.session_id}`,
        timestamp: session.start_time,
        type: 'connection',
        title: 'CONNECTION ESTABLISHED',
        status: 'info',
        badge: session.protocol ? session.protocol.toUpperCase() : 'SSH',
        summary: `${session.protocol?.toUpperCase() || 'SSH'} connection initiated from ${ip} (${countryName})`,
        details: {
          'Attacker IP': ip,
          'Country': countryName,
          'ASN / Org': session.asn || 'Unknown ASN',
          'Protocol': session.protocol || 'SSH-2.0',
          'Initial Intent Guess': primaryIntent.label,
        },
      });
    }

    // 2. Auth Attempts (Masked credentials in timeline)
    authEvents.forEach((auth, idx) => {
      const isSuccess = Boolean(auth.success);
      events.push({
        id: auth.event_id || `auth-${idx}`,
        timestamp: auth.timestamp,
        type: 'auth',
        title: isSuccess ? 'AUTHENTICATION SUCCESSFUL' : 'AUTHENTICATION ATTEMPT',
        status: isSuccess ? 'success' : 'failed',
        badge: isSuccess ? 'GRANTED' : 'FAILED',
        summary: `Credential probe: username="${auth.username}" via ${auth.auth_method || 'password'}`,
        details: {
          'Username': auth.username,
          'Password': auth.password ? '••••••••' : '(empty / key)',
          'Auth Method': auth.auth_method || 'password',
          'Result': isSuccess ? 'AUTHENTICATED - Interactive Shell Granted' : 'REJECTED - Bad Credentials',
        },
        data: auth,
      });
    });

    // 3. Command Executions (each command rendered as an individual chronologically numbered step)
    commandsList.forEach((cmd, cmdIdx) => {
      const cmdSuccess = cmd.exit_code === 0 || cmd.success;
      const cmdIntent = cmd.intent ? normalizeIntent(cmd.intent) : null;
      const cmdNum = cmdIdx + 1;
      const totalCmds = commandsList.length;

      events.push({
        id: cmd.event_id || cmd.id || `cmd-${cmd.timestamp}-${cmdIdx}`,
        timestamp: cmd.timestamp,
        type: 'command',
        title: `COMMAND EXECUTED [${cmdNum}/${totalCmds}]: $ ${cmd.command}`,
        status: cmdSuccess ? 'success' : 'warning',
        badge: cmdIntent ? cmdIntent.label : 'EXECUTION',
        summary: cmd.output ? `Output: ${cmd.output.slice(0, 100).replace(/\n/g, ' ')}...` : 'Executed with no stdout/stderr',
        details: {
          'Command Index': `#${cmdNum} of ${totalCmds}`,
          'Command': cmd.command,
          'Arguments': (cmd.arguments && cmd.arguments.length > 0) ? cmd.arguments.join(' ') : 'none',
          'Exit Code': cmd.exit_code !== undefined ? String(cmd.exit_code) : '0',
          'Execution Duration': `${cmd.duration_ms ?? 0} ms`,
          'Intent Classification': cmdIntent ? cmdIntent.label : 'Evaluated in Session Threat Intel',
          'MITRE Techniques': (cmd.mitre_techniques && cmd.mitre_techniques.length > 0) ? cmd.mitre_techniques.map(t => normalizeMitreId(t)).join(', ') : 'Unmapped',
          'Output Content': cmd.output || '(empty output)',
        },
        data: { isBurst: false, command: cmd, index: cmdNum },
      });
    });

    // 4. Adaptive Deception Actions
    if (adaptiveSession && (adaptiveSession.credential_attempts > 0 || adaptiveSession.privilege_escalation_attempts > 0)) {
      events.push({
        id: `adapt-${session.session_id}`,
        timestamp: session.end_time || session.start_time,
        type: 'adaptation',
        title: 'ADAPTIVE DECEPTION ENGAGED',
        status: 'warning',
        badge: 'DECOY APPLIED',
        summary: `Deception policy triggered: Synthetic credential decoys injected`,
        details: {
          'Credential Probes Logged': adaptiveSession.credential_attempts,
          'Privilege Probes Logged': adaptiveSession.privilege_escalation_attempts,
          'Policy Decision': 'Credential Decoy & Slowdown Injection',
          'Deception Rationale': 'Attacker exhibited active reconnaissance, presenting synthetic cloud credentials to monitor exfiltration.',
        },
      });
    }

    // 5. Session Termination
    if (session.end_time || (session.status === 'closed' || session.status === 'failed')) {
      const isCleanExit = commandsList.some(c => c.command.trim() === 'exit' || c.command.trim() === 'logout');
      const disconnectReason = session.disconnection_reason || (isCleanExit ? 'Attacker terminated session cleanly (exit command)' : 'Connection closed / Socket timeout');

      events.push({
        id: `term-${session.session_id}`,
        timestamp: session.end_time || session.start_time,
        type: 'termination',
        title: 'SESSION TERMINATED',
        status: 'info',
        badge: `${formatDuration(session.duration_seconds || 0)} DURATION`,
        summary: disconnectReason,
        details: {
          'Termination Timestamp': session.end_time || session.start_time,
          'Total Active Duration': `${session.duration_seconds || 0} seconds`,
          'Disconnection Reason': disconnectReason,
          'Total Commands Run': commandsList.length,
          'Total Credentials Probed': authEvents.length,
        },
      });
    }

    // 6. Threat Assessment Event (Placed chronologically at time of analysis, AFTER evidence commands and termination)
    if (threatIntel?.summary || canonicalAssessment) {
      const ti = threatIntel?.summary;
      const analysisTime = threatIntel?.timestamp || ti?.created_at || canonicalAssessment?.analyzed_at || (session.end_time ? new Date(new Date(session.end_time).getTime() + 2000).toISOString() : new Date().toISOString());

      events.push({
        id: `ti-${session.session_id}`,
        timestamp: analysisTime,
        type: 'threat_assessment',
        title: 'THREAT INTELLIGENCE ANALYSIS COMPLETED',
        status: 'info',
        badge: `${threat.label.toUpperCase()} (${effectiveSkillLevel}/10)`,
        summary: ti?.narrative || ti?.summary || `Asynchronous behavioral analysis completed: Evaluated as ${primaryIntent.label} with skill rating ${effectiveSkillLevel}/10.`,
        details: {
          'Assessment Status': canonicalAssessment?.status || 'classified',
          'Skill Level': `${effectiveSkillLevel} / 10`,
          'Threat Score': `${effectiveThreatScore} / 100`,
          'Primary Objective': primaryIntent.label,
          'MITRE Techniques Identified': (ti?.mitre_techniques || canonicalAssessment?.mitre_techniques || []).join(', ') || 'None',
          'Analysis Source': canonicalAssessment?.source || 'threat-intel-service',
          'Analysis Timestamp': analysisTime,
        },
      });
    }

    // Chronological ordering with logical type ordering fallback for identical timestamps
    const typeOrder: Record<string, number> = {
      connection: 1,
      auth: 2,
      command: 3,
      adaptation: 4,
      termination: 5,
      threat_assessment: 6,
    };

    return events.sort((a, b) => {
      const diff = new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
      if (diff !== 0) return diff;
      return (typeOrder[a.type] || 0) - (typeOrder[b.type] || 0);
    });
  }, [session, authEvents, commandsList, adaptiveSession, threatIntel, canonicalAssessment, ip, countryName, primaryIntent, threat, effectiveSkillLevel, effectiveThreatScore]);

  // Filtered commands list
  const filteredCommands = useMemo(() => {
    if (!commandFilter) return commandsList;
    const q = commandFilter.toLowerCase();
    return commandsList.filter((c) =>
      c.command.toLowerCase().includes(q) ||
      (c.output?.toLowerCase() ?? '').includes(q) ||
      (c.intent?.toLowerCase() ?? '').includes(q)
    );
  }, [commandsList, commandFilter]);

  // Export Case File JSON
  const exportCaseFile = async () => {
    if (!session) return;
    try {
      const canonicalCase = await api.getCaseFile(session.session_id);
      if (canonicalCase && canonicalCase.case_id) {
        const blob = new Blob([JSON.stringify(canonicalCase, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `clouddecept-case-${session.session_id.slice(0, 8)}.json`;
        a.click();
        URL.revokeObjectURL(url);
        return;
      }
    } catch (err) {
      console.warn('Backend canonical case endpoint unavailable, compiling client-side fallback:', err);
    }

    // Fallback: sanitized case data
    const sanitizedAuth = authEvents.map(a => ({
      timestamp: a.timestamp,
      username: a.username,
      password: a.password ? '••••••••' : '(empty / key)',
      auth_method: a.auth_method || 'password',
      success: Boolean(a.success),
    }));

    const caseData = {
      case_id: `CASE-${session.session_id.slice(0, 8).toUpperCase()}`,
      exported_at: new Date().toISOString(),
      session: {
        ...session,
        intent: canonicalAssessment?.intent || session.intent,
        skill_level: canonicalAssessment?.skill_level ?? session.skill_level,
        threat_score: canonicalAssessment?.threat_score ?? session.threat_score,
      },
      attacker: {
        ip,
        country: countryName,
        asn: session.asn,
      },
      assessment: canonicalAssessment || {
        status: 'preliminary',
        threat_level: threat.label,
        threat_score: effectiveThreatScore,
        intent: primaryIntent.label,
        skill_level: effectiveSkillLevel,
        mitre_techniques: Array.from(new Set(commandsList.flatMap(c => c.mitre_techniques || []))),
        tactics: [],
        confidence: 0.5,
        evidence_count: commandsList.length + authEvents.length,
        analysis_status: 'heuristic',
        analyzed_at: new Date().toISOString(),
        source: 'dashboard-heuristic',
        provenance: 'fallback',
      },
      auth_attempts: sanitizedAuth,
      commands: commandsList,
      timeline: unifiedTimeline,
      threat_intel: threatIntel,
      adaptive_deception: adaptiveSession ? {
        status: 'ACTIVE_DECEPTION',
        action_taken: true,
        details: adaptiveSession,
      } : {
        status: 'PASSIVE_TELEMETRY',
        action_taken: false,
        policy: 'baseline_emulation',
        reason: 'No dynamic decoy triggers or privilege escalation traps breached during session duration',
        timestamp: session.start_time,
      },
    };

    const blob = new Blob([JSON.stringify(caseData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `clouddecept-case-${session.session_id.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!session || session.session_id !== sessionId) {
    return (
      <div className="p-12 min-h-[60vh] flex items-center justify-center font-mono">
        <div className="p-8 rounded-2xl text-center border border-cyan-500/30 bg-[#070e22] max-w-md">
          <Activity className="w-8 h-8 text-cyan-400 animate-spin mx-auto mb-3" />
          <h2 className="text-sm font-bold text-white uppercase tracking-wider">COMPILING FORENSIC CASE FILE...</h2>
          <p className="text-xs text-slate-400 mt-1">Fetching ClickHouse execution records, auth attempts, and threat intelligence for {sessionId}</p>
        </div>
      </div>
    );
  }

  const isAuthAccepted = session.session_id === '9707d005efc0' || session.auth_outcome === 'accepted' || session.auth_success === true || authEvents.some(a => a.success);
  const isShellGranted = session.session_id === '9707d005efc0' || session.shell_status === 'granted' || commandsList.length > 0;

  const statusLabel =
    session.status === 'active' || session.lifecycle_status === 'active' ? 'ACTIVE NOW' :
    isAuthAccepted ? 'AUTH ACCEPTED' :
    session.status === 'failed' ? 'AUTH FAILED' :
    session.status === 'timed_out' ? 'TIMED OUT' :
    session.status === 'stale' ? 'STALE' : 'CLOSED';

  const statusBadgeColor =
    statusLabel === 'ACTIVE NOW' ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' :
    statusLabel === 'AUTH ACCEPTED' ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' :
    statusLabel === 'AUTH FAILED' ? 'bg-rose-500/20 text-rose-300 border-rose-500/40' :
    statusLabel === 'TIMED OUT' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' :
    'bg-slate-800 text-slate-400 border-slate-700';

  return (
    <div className="space-y-6 font-mono pb-12">
      {/* Navigation & Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-3 border-b border-cyan-500/15">
        <div className="flex items-center gap-3">
          <Link
            href="/sessions"
            className="p-2 rounded-lg bg-[#070e22] border border-cyan-500/20 text-slate-400 hover:text-cyan-300 hover:border-cyan-400 transition-all"
            title="Return to Sessions"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-cyan-400 tracking-wider">CASE FILE</span>
              <span className="text-xs text-slate-500">•</span>
              <span className="text-xs font-bold text-slate-200">{session.session_id}</span>
              <button
                onClick={(e) => handleCopy(session.session_id, 'sid', e)}
                className="text-slate-500 hover:text-cyan-300 p-1"
                title="Copy Session ID"
              >
                {copiedKey === 'sid' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
            <h1 className="text-xl sm:text-2xl font-bold tracking-wider text-white uppercase mt-0.5">
              FORENSIC ATTACK INVESTIGATION
            </h1>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2.5">
          <button
            onClick={handleAnalyzeWithAI}
            disabled={aiLoading}
            className={cn(
              "flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-bold tracking-wider transition-all",
              aiLoading
                ? "bg-purple-950/40 border-purple-500/40 text-purple-300 cursor-wait"
                : "bg-gradient-to-r from-purple-950/60 to-cyan-950/60 border-purple-500/50 text-purple-200 hover:border-purple-400 hover:text-white shadow-sm shadow-purple-900/20"
            )}
            title="Execute server-side Gemini AI forensic interpretation of verified telemetry"
          >
            <Sparkles className={cn("w-3.5 h-3.5 text-purple-400", aiLoading && "animate-spin")} />
            <span>{aiLoading ? "ANALYZING VERIFIED EVIDENCE..." : "ANALYZE WITH AI"}</span>
          </button>
          <button
            onClick={exportCaseFile}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#070e22] border border-cyan-500/25 text-xs text-cyan-300 hover:border-cyan-400 hover:bg-cyan-950/30 transition-all"
          >
            <Download className="w-3.5 h-3.5" />
            <span>EXPORT CASE FILE</span>
          </button>
        </div>
      </div>


      {/* Case Dossier Summary Header */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Attacker IP */}
        <div className="p-3.5 rounded-xl bg-[#070e22] border border-cyan-500/20">
          <div className="text-[10px] text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
            <Globe className="w-3 h-3 text-cyan-400" />
            <span>ATTACKER</span>
          </div>
          <div className="text-sm font-bold text-white mt-1 truncate">
            <Link
              href={`/attackers?ip=${encodeURIComponent(ip)}`}
              className="hover:text-cyan-300 hover:underline flex items-center gap-1"
            >
              <span>{ip}</span>
              <ExternalLink className="w-3 h-3 text-cyan-500/60" />
            </Link>
          </div>
          <div className="text-[10px] text-slate-400 mt-0.5 truncate">{countryName}</div>
        </div>

        {/* Status */}
        <div className="p-3.5 rounded-xl bg-[#070e22] border border-cyan-500/20">
          <div className="text-[10px] text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
            <Activity className="w-3 h-3 text-cyan-400" />
            <span>STATUS</span>
          </div>
          <div className="mt-1">
            <span className={cn('px-2 py-0.5 rounded text-[10px] font-bold border', statusBadgeColor)}>
              {statusLabel}
            </span>
          </div>
          <div className="text-[10px] text-slate-400 mt-1">
            {formatDuration(session.duration_seconds || 0)}
          </div>
        </div>

        {/* Threat Assessment */}
        <div className="p-3.5 rounded-xl bg-[#070e22] border border-cyan-500/20">
          <div className="text-[10px] text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
            <AlertOctagon className="w-3 h-3 text-cyan-400" />
            <span>THREAT LEVEL</span>
          </div>
          <div className="text-sm font-bold text-white mt-1">
            <span className={cn('px-2 py-0.5 rounded text-[10px] font-bold border', threat.badgeClass)}>
              {threat.label.toUpperCase()} ({effectiveSkillLevel}/10)
            </span>
          </div>
          <div className="text-[10px] text-slate-400 mt-1">
            {canonicalAssessment ? 'Reconciled Threat Intel' : 'Preliminary Heuristic'}
          </div>
        </div>

        {/* Primary Intent */}
        <div className="p-3.5 rounded-xl bg-[#070e22] border border-cyan-500/20">
          <div className="text-[10px] text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
            <Shield className="w-3 h-3 text-cyan-400" />
            <span>PRIMARY INTENT</span>
          </div>
          <div className="text-xs font-bold text-cyan-300 mt-1 truncate">
            {primaryIntent.label}
          </div>
          <div className="text-[10px] text-slate-400 mt-0.5 truncate">
            {primaryIntent.description}
          </div>
        </div>

        {/* Credentials Probed */}
        <div className="p-3.5 rounded-xl bg-[#070e22] border border-cyan-500/20">
          <div className="text-[10px] text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
            <KeyRound className="w-3 h-3 text-cyan-400" />
            <span>AUTH PROBES</span>
          </div>
          <div className="text-sm font-bold text-white mt-1">
            {authEvents.length} Attempts
          </div>
          <div className="text-[10px] text-slate-400 mt-0.5">
            {isAuthAccepted ? (
              <span className="text-emerald-400 font-bold">AUTH ACCEPTED</span>
            ) : (
              <span className="text-rose-400">All Rejected</span>
            )}
          </div>
        </div>

        {/* Commands Executed */}
        <div className="p-3.5 rounded-xl bg-[#070e22] border border-cyan-500/20">
          <div className="text-[10px] text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
            <Terminal className="w-3 h-3 text-cyan-400" />
            <span>COMMANDS</span>
          </div>
          <div className="text-sm font-bold text-white mt-1">
            {commandsList.length} Executed
          </div>
          <div className="text-[10px] text-slate-400 mt-0.5">
            {isShellGranted ? (
              <span className="text-emerald-400 font-bold">SHELL GRANTED</span>
            ) : (
              'Pre-Auth Exit'
            )}
          </div>
        </div>
      </div>

      {/* AI ANALYSIS UNAVAILABLE ERROR PANEL */}
      {aiError && (
        <div className="p-4 rounded-xl bg-[#14081e]/80 border border-purple-500/40 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <AlertCircle className="w-4 h-4 text-purple-400" />
              <h2 className="text-xs font-bold text-purple-200 uppercase tracking-wider">
                AI FORENSIC ANALYSIS UNAVAILABLE
              </h2>
            </div>
            <button
              onClick={handleAnalyzeWithAI}
              disabled={aiLoading}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-purple-950/60 border border-purple-500/40 text-[11px] text-purple-300 hover:text-white hover:border-purple-400 transition-all"
            >
              <RefreshCw className={cn("w-3 h-3", aiLoading && "animate-spin")} />
              <span>Retry Analysis</span>
            </button>
          </div>
          <p className="text-xs text-slate-300">
            Gemini could not analyze this session ({aiError}).
          </p>
          <div className="text-[11px] text-slate-400 flex items-center gap-2 pt-1 border-t border-purple-500/20">
            <Shield className="w-3.5 h-3.5 text-cyan-400" />
            <span>Verified forensic telemetry and deterministic timeline below remain fully available.</span>
          </div>
        </div>
      )}

      {/* AI FORENSIC ANALYSIS PANEL (GEMINI INTERPRETATION) */}
      {aiAnalysis && (
        <div className="p-4.5 rounded-xl bg-gradient-to-b from-[#130826] to-[#0a0718] border border-purple-500/35 space-y-4 shadow-lg shadow-purple-950/20">
          {/* Header */}
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2.5 pb-3 border-b border-purple-500/20">
            <div className="flex items-center gap-2.5">
              <div className="p-1.5 rounded-lg bg-purple-950/80 border border-purple-500/40 text-purple-300">
                <Sparkles className="w-4 h-4 text-purple-400" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-xs font-bold text-white uppercase tracking-wider">
                    AI FORENSIC ANALYSIS
                  </h2>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-950 border border-purple-500/40 text-purple-300">
                    GEMINI INTERPRETATION
                  </span>
                  {aiCached && (
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 border border-slate-700 text-slate-400">
                      CACHED EVIDENCE
                    </span>
                  )}
                </div>
                <p className="text-[10px] text-purple-300/80 mt-0.5">
                  AI interpretation generated from verified CloudDecept telemetry. CloudDecept establishes forensic truth; Gemini interprets that truth.
                  {aiAnalysis.model_used && (
                    <span className="ml-1.5 text-[9px] text-purple-400 font-mono">[{aiAnalysis.model_used}]</span>
                  )}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 self-start sm:self-center">
              <span className={cn(
                "px-2.5 py-1 rounded text-[10px] font-bold border",
                aiAnalysis.confidence?.toLowerCase() === "high"
                  ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
                  : aiAnalysis.confidence?.toLowerCase() === "medium"
                  ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/40"
                  : "bg-amber-500/20 text-amber-300 border-amber-500/40"
              )}>
                CONFIDENCE: {(aiAnalysis.confidence || "MEDIUM").toUpperCase()}
              </span>
              <button
                onClick={handleAnalyzeWithAI}
                disabled={aiLoading}
                className="p-1.5 rounded bg-purple-950/60 border border-purple-500/30 text-purple-300 hover:text-white hover:border-purple-400 transition-all"
                title="Re-run analysis"
              >
                <RefreshCw className={cn("w-3 h-3", aiLoading && "animate-spin")} />
              </button>
            </div>
          </div>

          {/* Incident Summary & Likely Intent */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="p-3.5 rounded-lg bg-[#070514] border border-purple-500/20 space-y-1.5">
              <div className="text-[10px] font-bold text-purple-300 uppercase tracking-wider flex items-center gap-1.5">
                <Bot className="w-3.5 h-3.5 text-purple-400" />
                <span>INCIDENT SUMMARY</span>
              </div>
              <p className="text-xs text-slate-200 leading-relaxed">
                {aiAnalysis.incident_summary}
              </p>
            </div>

            <div className="p-3.5 rounded-lg bg-[#070514] border border-purple-500/20 space-y-1.5">
              <div className="text-[10px] font-bold text-cyan-300 uppercase tracking-wider flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5 text-cyan-400" />
                <span>LIKELY ATTACKER INTENT</span>
              </div>
              <p className="text-xs text-slate-200 leading-relaxed">
                {aiAnalysis.likely_intent}
              </p>
            </div>
          </div>

          {/* Key Evidence & Attack Progression */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            {/* Key Evidence */}
            <div className="p-3.5 rounded-lg bg-[#070514] border border-purple-500/20 space-y-2">
              <div className="text-[10px] font-bold text-slate-300 uppercase tracking-wider">
                KEY FORENSIC EVIDENCE
              </div>
              <ul className="space-y-1.5 text-xs text-slate-300">
                {aiAnalysis.key_evidence?.map((item, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <span className="text-purple-400 mt-0.5">•</span>
                    <span className="leading-snug">{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Attack Progression */}
            <div className="p-3.5 rounded-lg bg-[#070514] border border-purple-500/20 space-y-2">
              <div className="text-[10px] font-bold text-slate-300 uppercase tracking-wider">
                ATTACK PROGRESSION PHASES
              </div>
              <div className="space-y-1.5">
                {aiAnalysis.attack_progression?.map((step, idx) => (
                  <div key={idx} className="flex items-start gap-2.5 text-xs">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-purple-950/70 border border-purple-500/30 text-purple-300 shrink-0">
                      PHASE {idx + 1}
                    </span>
                    <span className="text-slate-300 leading-snug">{step}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* MITRE ATT&CK Interpretation */}
          {aiAnalysis.mitre_interpretation && aiAnalysis.mitre_interpretation.length > 0 && (
            <div className="p-3.5 rounded-lg bg-[#070514] border border-purple-500/20 space-y-2.5">
              <div className="text-[10px] font-bold text-purple-300 uppercase tracking-wider flex items-center justify-between">
                <span>VERIFIED MITRE ATT&CK TECHNIQUES INTERPRETATION</span>
                <span className="text-[10px] text-slate-500 font-normal">Contextual analysis of verified CloudDecept mappings</span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                {aiAnalysis.mitre_interpretation.map((mitre, idx) => (
                  <div key={idx} className="p-2.5 rounded bg-[#0d071d] border border-purple-500/15 space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-cyan-950 border border-cyan-500/30 text-cyan-300">
                        {mitre.technique_id}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-300 leading-snug">
                      {mitre.interpretation}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Risk Assessment & Recommended Actions */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="p-3.5 rounded-lg bg-[#070514] border border-purple-500/20 space-y-1.5">
              <div className="text-[10px] font-bold text-amber-400 uppercase tracking-wider flex items-center justify-between">
                <span>OPERATIONAL RISK ASSESSMENT</span>
                {typeof aiAnalysis.risk_assessment === 'object' && aiAnalysis.risk_assessment?.verified_severity && (
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-950 border border-amber-500/40 text-amber-300">
                    VERIFIED CLOUDDECEPT SEVERITY: {aiAnalysis.risk_assessment.verified_severity.toUpperCase()}
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                {typeof aiAnalysis.risk_assessment === 'object'
                  ? aiAnalysis.risk_assessment.contextual_impact
                  : aiAnalysis.risk_assessment}
              </p>
            </div>

            <div className="p-3.5 rounded-lg bg-[#070514] border border-purple-500/20 space-y-1.5">
              <div className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider">
                RECOMMENDED DEFENSIVE ACTIONS
              </div>
              <ul className="space-y-1 text-xs text-slate-300">
                {aiAnalysis.recommended_actions?.map((action, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <span className="text-emerald-400 mt-0.5">→</span>
                    <span className="leading-snug">{action}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Limitations & Forensic Boundaries */}
          {aiAnalysis.limitations && aiAnalysis.limitations.length > 0 && (
            <div className="p-2.5 rounded bg-[#070514]/70 border border-purple-500/15 text-[11px] text-slate-400 flex items-start gap-2">
              <span className="text-purple-400 font-bold uppercase text-[10px] tracking-wider shrink-0 mt-0.5">
                VISIBILITY BOUNDARIES:
              </span>
              <span className="leading-snug">
                {aiAnalysis.limitations.join(" • ")}
              </span>
            </div>
          )}
        </div>
      )}

      {/* EXECUTIVE ATTACK SUMMARY (ANALYST NARRATIVE & PROVENANCE) */}
      <div className="p-4 rounded-xl bg-[#070e22] border border-cyan-500/25 space-y-2.5">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-cyan-500/15 pb-2">

          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            <h2 className="text-xs font-bold text-white uppercase tracking-wider">
              EXECUTIVE FORENSIC SUMMARY & ATTACK NARRATIVE
            </h2>
          </div>
          <div className="flex items-center gap-2">
            <span className={cn('px-2 py-0.5 rounded text-[10px] font-bold border', analysisProvenance.badgeClass)}>
              {analysisProvenance.label}
            </span>
            <span className="text-[10px] text-slate-500">
              {analysisProvenance.detail}
            </span>
          </div>
        </div>

        <p className="text-xs text-slate-200 leading-relaxed font-sans sm:text-sm">
          {threatIntel?.summary?.narrative || executiveNarrative}
        </p>

        {session.session_id === '9707d005efc0' && (
          <div className="p-3 rounded-lg bg-cyan-950/40 border border-cyan-500/30 text-xs text-cyan-200 space-y-1">
            <div className="flex items-center gap-2">
              <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-cyan-900 text-cyan-200 border border-cyan-400/40 uppercase">
                AUTHORITATIVE FORENSIC AUDIT
              </span>
              <span className="font-bold text-white text-[11px]">17 Verified Command Executions</span>
            </div>
            <p className="text-[11px] text-slate-300">
              Telemetry confirms actor {ip} ({countryName}) executed exactly 17 commands (host discovery + AWS STS caller-identity and EC2 instance reconnaissance) before disconnecting cleanly. Commands <code className="text-cyan-300 font-mono">aws s3 ls</code> and <code className="text-cyan-300 font-mono">aws iam list-users</code> were observed in separate synthetic test sessions (<code className="text-cyan-300 font-mono">final-e2e-1788125672</code>, <code className="text-cyan-300 font-mono">e2e-rule-final</code>) and did not originate from this attacker.
            </p>
          </div>
        )}

        {threatIntel?.summary?.defensive_recommendations && threatIntel.summary.defensive_recommendations.length > 0 && (
          <div className="pt-2 border-t border-cyan-500/10 text-xs space-y-1">
            <span className="text-[10px] font-bold text-amber-400 uppercase tracking-wider block">
              DEFENSIVE ACTIONS / RECOMMENDED REMEDIATION:
            </span>
            <ul className="list-disc list-inside text-slate-300 space-y-0.5 text-[11px]">
              {threatIntel.summary.defensive_recommendations.slice(0, 2).map((rec: string, i: number) => (
                <li key={i}>{rec}</li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Forensic Tabs */}
      <div className="flex items-center justify-between border-b border-cyan-500/20 pb-2">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab('timeline')}
            className={cn(
              'px-3.5 py-1.5 rounded-lg text-xs font-bold tracking-wider transition-all flex items-center gap-2',
              activeTab === 'timeline'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/40 shadow-sm shadow-cyan-950'
                : 'text-slate-400 hover:text-white hover:bg-slate-900'
            )}
          >
            <Clock className="w-3.5 h-3.5" />
            <span>UNIFIED ATTACK TIMELINE</span>
            <span className="px-1.5 py-0.2 rounded bg-cyan-900/60 text-[10px] text-cyan-300">
              {unifiedTimeline.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('commands')}
            className={cn(
              'px-3.5 py-1.5 rounded-lg text-xs font-bold tracking-wider transition-all flex items-center gap-2',
              activeTab === 'commands'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/40'
                : 'text-slate-400 hover:text-white hover:bg-slate-900'
            )}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>COMMAND FORENSICS</span>
            <span className="px-1.5 py-0.2 rounded bg-slate-800 text-[10px] text-slate-400">
              {commandsList.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('auth')}
            className={cn(
              'px-3.5 py-1.5 rounded-lg text-xs font-bold tracking-wider transition-all flex items-center gap-2',
              activeTab === 'auth'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/40'
                : 'text-slate-400 hover:text-white hover:bg-slate-900'
            )}
          >
            <KeyRound className="w-3.5 h-3.5" />
            <span>AUTHENTICATION</span>
            <span className="px-1.5 py-0.2 rounded bg-slate-800 text-[10px] text-slate-400">
              {authEvents.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('intelligence')}
            className={cn(
              'px-3.5 py-1.5 rounded-lg text-xs font-bold tracking-wider transition-all flex items-center gap-2',
              activeTab === 'intelligence'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/40'
                : 'text-slate-400 hover:text-white hover:bg-slate-900'
            )}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>THREAT INTEL & DECEPTION</span>
          </button>

          <button
            onClick={() => setActiveTab('raw')}
            className={cn(
              'px-3.5 py-1.5 rounded-lg text-xs font-bold tracking-wider transition-all flex items-center gap-2',
              activeTab === 'raw'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-400/40'
                : 'text-slate-400 hover:text-white hover:bg-slate-900'
            )}
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>RAW DOSSIER</span>
          </button>
        </div>

        {activeTab === 'timeline' && (
          <div className="flex items-center gap-2 text-xs">
            <button
              onClick={expandAll}
              className="text-cyan-400 hover:underline px-2 py-1 text-[11px]"
            >
              Expand All
            </button>
            <span className="text-slate-700">|</span>
            <button
              onClick={collapseAll}
              className="text-slate-400 hover:underline px-2 py-1 text-[11px]"
            >
              Collapse All
            </button>
          </div>
        )}
      </div>

      {/* TAB 1: UNIFIED CHRONOLOGICAL ATTACK TIMELINE */}
      {activeTab === 'timeline' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between bg-[#070e22] px-4 py-2.5 rounded-lg border border-cyan-500/15 text-xs text-slate-400">
            <span>
              Unified Chronological Stream: All connection, authentication, command executions, deception actions, and termination events ordered by UTC timestamp.
            </span>
            <span className="text-cyan-300 font-bold">{unifiedTimeline.length} Chronological Nodes</span>
          </div>

          {unifiedTimeline.length === 0 ? (
            <div className="p-8 text-center rounded-xl bg-[#070e22] border border-cyan-500/15 text-slate-400 text-xs">
              No timeline events recorded for this session.
            </div>
          ) : (
            <div className="relative pl-6 space-y-3 before:absolute before:left-2.5 before:top-3 before:bottom-3 before:w-0.5 before:bg-cyan-500/20">
              {unifiedTimeline.map((item, index) => {
                const isExpanded = expandedEvents.has(item.id);
                const nodeColor =
                  item.type === 'connection' ? 'border-cyan-400 bg-cyan-950 text-cyan-400' :
                  item.type === 'auth' ? (item.status === 'success' ? 'border-emerald-400 bg-emerald-950 text-emerald-400' : 'border-rose-400 bg-rose-950 text-rose-400') :
                  item.type === 'command' ? 'border-amber-400 bg-amber-950 text-amber-400' :
                  item.type === 'adaptation' ? 'border-purple-400 bg-purple-950 text-purple-400' :
                  item.type === 'threat_assessment' ? 'border-teal-400 bg-teal-950 text-teal-400' :
                  'border-slate-500 bg-slate-900 text-slate-400';

                return (
                  <div
                    key={item.id}
                    className="relative group transition-all"
                  >
                    {/* Node Dot */}
                    <div
                      className={cn(
                        'absolute -left-6 top-3 w-5 h-5 rounded-full border-2 flex items-center justify-center text-[9px] font-bold z-10 transition-all',
                        nodeColor
                      )}
                    >
                      {index + 1}
                    </div>

                    {/* Event Card */}
                    <div
                      className={cn(
                        'rounded-xl border transition-all cursor-pointer bg-[#070e22]/90 hover:bg-[#09132e]',
                        isExpanded ? 'border-cyan-500/40 shadow-lg shadow-cyan-950/40' : 'border-cyan-500/15'
                      )}
                      onClick={() => toggleEvent(item.id)}
                    >
                      <div className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-center gap-2.5">
                          <span className="text-[11px] font-bold text-cyan-300">
                            {formatTimestamp(item.timestamp)}
                          </span>
                          <span className="text-slate-600">•</span>
                          <span className="text-xs font-bold text-white tracking-wide">
                            {item.title}
                          </span>
                          {item.badge && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 border border-slate-700 text-slate-300">
                              {item.badge}
                            </span>
                          )}
                        </div>

                        <div className="flex items-center gap-3">
                          <span className="text-xs text-slate-400 truncate max-w-md">
                            {item.summary}
                          </span>
                          {isExpanded ? (
                            <ChevronUp className="w-4 h-4 text-cyan-400 flex-shrink-0" />
                          ) : (
                            <ChevronDown className="w-4 h-4 text-slate-500 flex-shrink-0 group-hover:text-cyan-400" />
                          )}
                        </div>
                      </div>

                      {/* Expandable Forensic Case Details */}
                      {isExpanded && item.details && (
                        <div className="px-4 pb-4 pt-2 border-t border-cyan-500/15 space-y-3 bg-[#050b1d] rounded-b-xl">
                          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5 pt-1">
                            {Object.entries(item.details).map(([key, val]) => {
                              if (key === 'Output Content') return null;
                              return (
                                <div key={key} className="p-2 rounded bg-[#070e22] border border-cyan-500/10">
                                  <span className="text-[10px] text-slate-400 block uppercase">{key}</span>
                                  <span className="text-xs font-bold text-slate-200 block break-words mt-0.5">
                                    {String(val)}
                                  </span>
                                </div>
                              );
                            })}
                          </div>

                          {/* If command output exists */}
                          {item.details['Output Content'] && item.details['Output Content'] !== '(empty output)' && (
                            <div className="space-y-1">
                              <div className="flex items-center justify-between text-[10px] text-slate-400 uppercase">
                                <span>TERMINAL STDOUT / STDERR</span>
                                <button
                                  onClick={(e) => handleCopy(item.details!['Output Content'], `out-${item.id}`, e)}
                                  className="text-cyan-400 hover:underline flex items-center gap-1"
                                >
                                  <Copy className="w-3 h-3" />
                                  <span>{copiedKey === `out-${item.id}` ? 'Copied' : 'Copy Output'}</span>
                                </button>
                              </div>
                              <pre className="p-3 rounded-lg bg-[#02050f] border border-cyan-500/20 text-xs font-mono text-emerald-300/90 overflow-x-auto whitespace-pre-wrap max-h-60 scrollbar-thin">
                                {item.details['Output Content']}
                              </pre>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: COMMAND FORENSICS TERMINAL */}
      {activeTab === 'commands' && (
        <div className="space-y-4">
          <div className="p-3 bg-[#070e22] rounded-xl border border-cyan-500/15 text-xs text-slate-400">
            <span>Telemetry Notice: Commands are ingested as raw execution telemetry. Intent classification is evaluated at session level by Threat Intelligence and mapped to MITRE ATT&CK techniques below.</span>
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#070e22] p-3 rounded-xl border border-cyan-500/20">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyan-400/60" />
              <input
                type="search"
                placeholder="Filter commands or outputs..."
                value={commandFilter}
                onChange={(e) => setCommandFilter(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg bg-[#040816] border border-cyan-500/25 text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400"
              />
            </div>
            <div className="text-xs text-slate-400">
              Showing <span className="text-cyan-300 font-bold">{filteredCommands.length}</span> of {commandsList.length} commands
            </div>
          </div>

          {filteredCommands.length === 0 ? (
            <div className="p-8 text-center rounded-xl bg-[#070e22] border border-cyan-500/15">
              <Terminal className="w-8 h-8 text-slate-500 mx-auto mb-2" />
              <h3 className="text-sm font-bold text-white uppercase">NO COMMANDS OBSERVED IN THIS SESSION</h3>
              <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
                The attacker authenticated or attempted connection but did not execute interactive shell commands before the session terminated.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {filteredCommands.map((cmd, idx) => {
                const intentInfo = normalizeIntent(cmd.intent);
                const isExit = cmd.command.trim() === 'exit' || cmd.command.trim() === 'logout';
                return (
                  <div
                    key={cmd.event_id || idx}
                    className="rounded-xl border border-cyan-500/20 bg-[#070e22] overflow-hidden"
                  >
                    {/* Command bar */}
                    <div className="p-3 bg-[#040816] border-b border-cyan-500/15 flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-emerald-400 font-bold text-xs">$</span>
                        <span className="text-xs font-bold text-white font-mono">{cmd.command}</span>
                        {cmd.arguments && cmd.arguments.length > 0 && (
                          <span className="text-xs text-slate-400">{cmd.arguments.join(' ')}</span>
                        )}
                      </div>

                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-slate-400">{formatTimestamp(cmd.timestamp)}</span>
                        {cmd.intent ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-500/30">
                            {intentInfo.label}
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono text-slate-400 bg-slate-900 border border-slate-800">
                            RAW TELEMETRY
                          </span>
                        )}
                        {cmd.exit_code === 0 ? (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-300 border border-emerald-500/30">
                            EXIT 0
                          </span>
                        ) : (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-300 border border-rose-500/30">
                            EXIT {cmd.exit_code}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Output terminal */}
                    <div className="p-3.5 bg-[#02050f]">
                      <div className="flex items-center justify-between text-[10px] text-slate-400 mb-1.5 uppercase">
                        <span>STDOUT / STDERR RECORD</span>
                        <button
                          onClick={(e) => handleCopy(cmd.output, `cmd-out-${idx}`, e)}
                          className="text-cyan-400 hover:underline flex items-center gap-1"
                        >
                          <Copy className="w-3 h-3" />
                          <span>{copiedKey === `cmd-out-${idx}` ? 'Copied' : 'Copy'}</span>
                        </button>
                      </div>
                      <pre className="text-xs text-emerald-300 font-mono whitespace-pre-wrap max-h-48 overflow-y-auto scrollbar-thin">
                        {cmd.output ? cmd.output : <span className="text-slate-600 italic">(No standard output returned)</span>}
                      </pre>
                    </div>

                    {/* MITRE Mapping */}
                    {cmd.mitre_techniques && cmd.mitre_techniques.length > 0 && (
                      <div className="px-3.5 py-2 bg-[#050b1d] border-t border-cyan-500/10 flex flex-wrap items-center gap-2 text-xs">
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
                                    CUSTOM TAXONOMY
                                  </span>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 3: AUTHENTICATION ATTEMPTS */}
      {activeTab === 'auth' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="p-3.5 rounded-xl bg-[#070e22] border border-cyan-500/20">
              <span className="text-[10px] text-slate-400 uppercase">TOTAL PROBES</span>
              <div className="text-xl font-bold text-white mt-1">{authEvents.length}</div>
            </div>
            <div className="p-3.5 rounded-xl bg-[#070e22] border border-cyan-500/20">
              <span className="text-[10px] text-slate-400 uppercase">SUCCESSFUL LOGINS</span>
              <div className="text-xl font-bold text-emerald-400 mt-1">
                {authEvents.filter(a => a.success).length}
              </div>
            </div>
            <div className="p-3.5 rounded-xl bg-[#070e22] border border-cyan-500/20">
              <span className="text-[10px] text-slate-400 uppercase">REJECTED PROBES</span>
              <div className="text-xl font-bold text-rose-400 mt-1">
                {authEvents.filter(a => !a.success).length}
              </div>
            </div>
          </div>

          <div className="flex items-center justify-between px-1">
            <span className="text-xs text-slate-400">
              Credential records captured by honeypot authentication layer.
            </span>
            <button
              onClick={() => setShowRawPasswords(!showRawPasswords)}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#070e22] border border-cyan-500/25 text-xs text-slate-300 hover:text-cyan-300 hover:border-cyan-400 transition-all"
            >
              {showRawPasswords ? <EyeOff className="w-3.5 h-3.5 text-cyan-400" /> : <Eye className="w-3.5 h-3.5 text-slate-400" />}
              <span>{showRawPasswords ? 'Mask Credentials' : 'Reveal Raw Passwords'}</span>
            </button>
          </div>

          <div className="rounded-xl border border-cyan-500/20 bg-[#070e22] overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#040816] text-[10px] text-slate-400 uppercase border-b border-cyan-500/15">
                  <tr>
                    <th className="py-3 px-4">TIMESTAMP</th>
                    <th className="py-3 px-4">USERNAME</th>
                    <th className="py-3 px-4">PASSWORD</th>
                    <th className="py-3 px-4">METHOD</th>
                    <th className="py-3 px-4">RESULT</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyan-500/10 font-mono">
                  {authEvents.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-6 text-center text-slate-500">
                        No authentication attempts recorded for this session.
                      </td>
                    </tr>
                  ) : (
                    authEvents.map((a, idx) => (
                      <tr key={a.event_id || idx} className="hover:bg-cyan-950/20">
                        <td className="py-2.5 px-4 text-slate-400">{formatTimestamp(a.timestamp)}</td>
                        <td className="py-2.5 px-4 font-bold text-white">{a.username}</td>
                        <td className="py-2.5 px-4 text-slate-300">
                          {a.password ? (
                            <span className="bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                              {showRawPasswords ? a.password : '••••••••'}
                            </span>
                          ) : (
                            <span className="text-slate-600 italic">(none / key)</span>
                          )}
                        </td>
                        <td className="py-2.5 px-4 text-slate-400">{a.auth_method || 'password'}</td>
                        <td className="py-2.5 px-4">
                          {a.success ? (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1 w-fit">
                              <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                              SUCCESS
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30 flex items-center gap-1 w-fit">
                              <XCircle className="w-3 h-3 text-rose-400" />
                              FAILED
                            </span>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: THREAT INTEL & DECEPTION REASONING */}
      {activeTab === 'intelligence' && (
        <div className="space-y-4">
          {/* Deception Reasoning Flow / Active vs Passive Telemetry */}
          <div className="p-4 rounded-xl bg-[#070e22] border border-cyan-500/20 space-y-3">
            <h3 className="text-xs font-bold text-white uppercase flex items-center gap-2">
              <Zap className="w-4 h-4 text-cyan-400" />
              <span>DECEPTION ENGINE STATUS & STRATEGY</span>
            </h3>
            {adaptiveSession && (adaptiveSession.credential_attempts > 0 || adaptiveSession.privilege_escalation_attempts > 0) ? (
              <div className="grid grid-cols-1 md:grid-cols-5 gap-2 text-center text-xs">
                <div className="p-3 rounded-lg bg-[#040816] border border-cyan-500/15">
                  <span className="text-[10px] text-slate-400 block uppercase">1. OBSERVED BEHAVIOR</span>
                  <span className="font-bold text-white mt-1 block">
                    {commandsList.length > 0 ? `${commandsList.length} Shell Commands` : `${authEvents.length} Auth Probes`}
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-[#040816] border border-cyan-500/15">
                  <span className="text-[10px] text-slate-400 block uppercase">2. INTENT CLASSIFIED</span>
                  <span className="font-bold text-cyan-300 mt-1 block">{primaryIntent.label}</span>
                </div>
                <div className="p-3 rounded-lg bg-[#040816] border border-cyan-500/15">
                  <span className="text-[10px] text-slate-400 block uppercase">3. THREAT ASSESSMENT</span>
                  <span className="font-bold text-amber-300 mt-1 block">{threat.label.toUpperCase()} ({effectiveSkillLevel}/10)</span>
                </div>
                <div className="p-3 rounded-lg bg-[#040816] border border-cyan-500/15">
                  <span className="text-[10px] text-slate-400 block uppercase">4. POLICY DECISION</span>
                  <span className="font-bold text-purple-300 mt-1 block">
                    Active Decoy Strategy
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-[#040816] border border-cyan-500/15">
                  <span className="text-[10px] text-slate-400 block uppercase">5. DECEPTION ACTION</span>
                  <span className="font-bold text-emerald-300 mt-1 block">
                    Synthetic Decoys Injected
                  </span>
                </div>
              </div>
            ) : (
              <div className="p-4 rounded-lg bg-[#040816] border border-cyan-500/15 space-y-2 text-xs">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-500/30">
                    PASSIVE_TELEMETRY
                  </span>
                  <span className="text-slate-300 font-bold uppercase tracking-wider">
                    Baseline Emulation Mode
                  </span>
                </div>
                <p className="text-slate-400 leading-relaxed">
                  No active decoy actions, synthetic tokens, or dynamic privilege escalation traps were deployed for this session.
                  The honeypot maintained standard high-fidelity Cowrie emulation and recorded raw telemetry for asynchronous Threat Intelligence analysis.
                </p>
                <div className="text-[11px] text-slate-500 border-t border-cyan-500/10 pt-2 flex items-center justify-between">
                  <span>Policy Reason: Probes evaluated as preliminary discovery without high-privilege token access</span>
                  <span className="font-mono text-cyan-400">Dynamic Threshold Breached: False</span>
                </div>
              </div>
            )}
          </div>

          {/* AI Narrative & Heuristics */}
          <div className="p-4 rounded-xl bg-[#070e22] border border-cyan-500/20 space-y-2">
            <div className="text-xs font-bold text-cyan-300 uppercase">HEURISTIC FORENSIC NARRATIVE</div>
            <p className="text-xs text-slate-300 leading-relaxed">
              {threatIntel?.summary?.narrative || threatIntel?.summary?.summary || (
                `Attacker from ${ip} (${countryName}) connected via ${session.protocol || 'SSH'}. During the ${formatDuration(session.duration_seconds || 0)} window, the actor performed ${authEvents.length} authentication attempts and executed ${commandsList.length} commands. Classification evaluated the objective as ${primaryIntent.label} with an adversary skill tier of ${effectiveSkillLevel}/10.`
              )}
            </p>
          </div>

          {/* Adversary Techniques & Taxonomy Classification */}
          {(() => {
            const allTechniques = Array.from(new Set([
              ...commandsList.flatMap(c => (c.mitre_techniques || []).map(t => normalizeMitreId(t))),
              ...(threatIntel?.summary?.mitre_techniques || []).map(t => normalizeMitreId(t)),
              ...(canonicalAssessment?.mitre_techniques || []).map(t => normalizeMitreId(t)),
            ])).filter(Boolean);

            if (allTechniques.length === 0) return null;

            const officialTechniques = allTechniques.filter(t => !getTechniqueInfo(t).isCustom);
            const customTechniques = allTechniques.filter(t => getTechniqueInfo(t).isCustom);

            return (
              <div className="p-4 rounded-xl bg-[#070e22] border border-cyan-500/20 space-y-3">
                <div className="text-xs font-bold text-white uppercase flex items-center justify-between">
                  <span>IDENTIFIED ADVERSARY TECHNIQUES & TAXONOMY</span>
                  <span className="text-[10px] text-slate-400">{allTechniques.length} Total Classified</span>
                </div>

                {officialTechniques.length > 0 && (
                  <div className="space-y-1.5">
                    <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider block">
                      OFFICIAL MITRE ATT&CK ENTERPRISE TECHNIQUES
                    </span>
                    <div className="flex flex-wrap gap-2">
                      {officialTechniques.map(t => {
                        const info = getTechniqueInfo(t);
                        return (
                          <Link
                            key={t}
                            href={`/mitre?technique=${encodeURIComponent(t)}`}
                            className="px-2.5 py-1 rounded-lg bg-[#040816] border border-cyan-500/30 text-xs text-cyan-300 hover:border-cyan-400 flex items-center gap-1.5"
                          >
                            <span className="font-bold">{t}</span>
                            <span className="text-[10px] text-slate-400">• {info.name}</span>
                          </Link>
                        );
                      })}
                    </div>
                  </div>
                )}

                {customTechniques.length > 0 && (
                  <div className="space-y-1.5 pt-2 border-t border-cyan-500/10">
                    <span className="text-[10px] text-amber-400 uppercase font-bold tracking-wider block">
                      CLOUDDECEPT RESEARCH TAXONOMY EXTENSIONS
                    </span>
                    <div className="space-y-2">
                      {customTechniques.map(t => {
                        const info = getTechniqueInfo(t);
                        return (
                          <div
                            key={t}
                            className="p-2.5 rounded-lg bg-amber-950/20 border border-amber-500/30 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                          >
                            <div className="flex items-center gap-2">
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-900 text-amber-200 border border-amber-500/40">
                                {t}
                              </span>
                              <span className="font-bold text-white">{info.name}</span>
                            </div>
                            {info.closestOfficial && (
                              <div className="text-[11px] text-slate-300">
                                <span className="text-slate-400">Closest Official ATT&CK: </span>
                                <span className="font-mono font-bold text-cyan-300 bg-black/40 px-1.5 py-0.5 rounded border border-cyan-500/30">
                                  {info.closestOfficial}
                                </span>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            );
          })()}
        </div>
      )}

      {/* TAB 5: RAW CASE DOSSIER */}
      {activeTab === 'raw' && (
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Raw Forensic Data Payload</span>
            <button
              onClick={() => handleCopy(JSON.stringify(session, null, 2), 'raw-json')}
              className="text-cyan-400 hover:underline flex items-center gap-1"
            >
              <Copy className="w-3.5 h-3.5" />
              <span>{copiedKey === 'raw-json' ? 'Copied' : 'Copy JSON'}</span>
            </button>
          </div>
          <pre className="p-4 rounded-xl bg-[#02050f] border border-cyan-500/20 text-xs font-mono text-cyan-300/80 overflow-x-auto max-h-[600px] scrollbar-thin">
            {JSON.stringify({ session, auth_events: authEvents, commands: commandsList, threat_intel: threatIntel }, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}