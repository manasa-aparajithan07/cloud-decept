'use client';

import { useEffect, useState, useMemo, useCallback } from 'react';
import Link from 'next/link';
import {
  KeyRound,
  Search,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Download,
  RefreshCw,
  Copy,
  Check,
  Shield,
  Filter,
  Eye,
  EyeOff,
  Globe,
  UserCheck,
} from 'lucide-react';
import { cn, formatTimestamp } from '@/lib/utils';
import { useDashboardStore } from '@/lib/store';
import { safeCopyToClipboard } from '@/lib/clipboard';
import { getCountryName } from '@/lib/countries';

export default function AuthenticationForensicsPage() {
  const { globalAuth, globalAuthLoading, fetchGlobalAuth, authStats, fetchAuthStats, timeWindowHours } = useDashboardStore();
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'success' | 'failed'>('all');
  const [currentPage, setCurrentPage] = useState(1);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [showRawPasswords, setShowRawPasswords] = useState(false);
  const itemsPerPage = 50;

  useEffect(() => {
    fetchGlobalAuth({ hours: timeWindowHours, limit: 300 });
    fetchAuthStats(timeWindowHours);
  }, [fetchGlobalAuth, fetchAuthStats, timeWindowHours]);

  const copyToClipboard = useCallback(async (text: string, key: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    const ok = await safeCopyToClipboard(text);
    if (ok) {
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    }
  }, []);

  const filteredAuth = useMemo(() => {
    const list = globalAuth || [];
    return list.filter((a) => {
      const q = searchQuery.toLowerCase();
      const ip = a.attacker_ip || a.src_ip || '';
      const matchesSearch =
        !q ||
        a.username.toLowerCase().includes(q) ||
        (a.password?.toLowerCase() ?? '').includes(q) ||
        a.session_id.toLowerCase().includes(q) ||
        ip.toLowerCase().includes(q) ||
        (a.country && a.country.toLowerCase().includes(q));

      const isSuccess = Boolean(a.success);
      const matchesStatus =
        statusFilter === 'all' ||
        (statusFilter === 'success' && isSuccess) ||
        (statusFilter === 'failed' && !isSuccess);

      return matchesSearch && matchesStatus;
    });
  }, [globalAuth, searchQuery, statusFilter]);

  // Aggregate stats (authoritative queries, falling back to filtered table only during active search)
  const isFiltered = Boolean(searchQuery || statusFilter !== 'all');

  const totalProbes = isFiltered
    ? filteredAuth.length
    : (authStats?.total_probes && authStats.total_probes > 0
        ? authStats.total_probes
        : filteredAuth.length);

  const authenticatedSessions = isFiltered
    ? filteredAuth.filter((a) => a.success).length
    : (authStats?.authenticated_sessions && authStats.authenticated_sessions > 0
        ? authStats.authenticated_sessions
        : filteredAuth.filter((a) => a.success).length);

  const uniqueSources = isFiltered
    ? new Set(filteredAuth.map((a) => a.attacker_ip || a.src_ip || 'unknown')).size
    : (authStats?.unique_sources && authStats.unique_sources > 0
        ? authStats.unique_sources
        : new Set(filteredAuth.map((a) => a.attacker_ip || a.src_ip || 'unknown')).size);

  const uniqueUsernames = isFiltered
    ? new Set(filteredAuth.map((a) => a.username?.trim()).filter(Boolean)).size
    : (authStats?.unique_usernames && authStats.unique_usernames > 0
        ? authStats.unique_usernames
        : new Set(filteredAuth.map((a) => a.username?.trim()).filter(Boolean)).size);

  const uniquePasswords = isFiltered
    ? new Set(filteredAuth.map((a) => a.password?.trim()).filter(Boolean)).size
    : (authStats?.unique_passwords && authStats.unique_passwords > 0
        ? authStats.unique_passwords
        : new Set(filteredAuth.map((a) => a.password?.trim()).filter(Boolean)).size);

  // Top Targeted Usernames (filtered blanks/placeholders)
  const topUsernames = useMemo(() => {
    if (!isFiltered && authStats?.top_usernames && authStats.top_usernames.length > 0) {
      return authStats.top_usernames
        .filter((u) => u.username && u.username.trim() !== '')
        .map((u) => [u.username, u.count] as [string, number]);
    }
    const counts: Record<string, number> = {};
    filteredAuth.forEach((a) => {
      const u = (a.username || '').trim();
      if (u) {
        counts[u] = (counts[u] || 0) + 1;
      }
    });
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
  }, [filteredAuth, isFiltered, authStats]);

  // Top Targeted Passwords (filtered blanks/placeholders)
  const topPasswords = useMemo(() => {
    if (!isFiltered && authStats?.top_passwords && authStats.top_passwords.length > 0) {
      return authStats.top_passwords
        .filter((p) => p.password && p.password.trim() !== '')
        .map((p) => [p.password, p.count] as [string, number]);
    }
    const counts: Record<string, number> = {};
    filteredAuth.forEach((a) => {
      const p = (a.password || '').trim();
      if (p) {
        counts[p] = (counts[p] || 0) + 1;
      }
    });
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
  }, [filteredAuth, isFiltered, authStats]);

  const totalPages = Math.max(1, Math.ceil(filteredAuth.length / itemsPerPage));
  const paginatedAuth = useMemo(() => {
    return filteredAuth.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);
  }, [filteredAuth, currentPage, itemsPerPage]);

  const exportToCSV = () => {
    if (filteredAuth.length === 0) return;
    const headers = ['Timestamp', 'Attacker IP', 'Country', 'Session ID', 'Username', 'Password', 'Result', 'Auth Method'];
    const rows = filteredAuth.map((a) => [
      a.timestamp ?? '',
      a.attacker_ip || a.src_ip || '',
      a.country || '',
      a.session_id ?? '',
      a.username ?? '',
      showRawPasswords ? (a.password ?? '').replace(/"/g, '""') : '••••••••',
      a.success ? 'SUCCESS' : 'FAILED',
      a.auth_method ?? 'password',
    ]);

    const csvContent = [
      headers.join(','),
      ...rows.map((r) => r.map((cell) => `"${cell}"`).join(',')),
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `clouddecept-auth-forensics-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-5 font-mono pb-12">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-3 border-b border-cyan-500/20">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-wider text-white uppercase flex items-center gap-2.5">
            <KeyRound className="w-5 h-5 text-cyan-400" />
            <span>AUTHENTICATION & CREDENTIAL FORENSICS</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Analyzing authentication activity, credential attempts, and session logins ({timeWindowHours >= 87600 ? 'All-Time' : `Last ${timeWindowHours}h`})
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => {
              fetchGlobalAuth({ hours: timeWindowHours, limit: 300 });
              fetchAuthStats(timeWindowHours);
            }}
            className="p-2 rounded-lg bg-[#070e22] border border-cyan-500/25 text-slate-300 hover:text-cyan-300 transition-all"
            title="Refresh authentication events"
          >
            <RefreshCw className={cn('w-4 h-4 text-cyan-400', globalAuthLoading && 'animate-spin')} />
          </button>
          <button
            onClick={exportToCSV}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#070e22] border border-cyan-500/25 text-xs text-cyan-300 hover:border-cyan-400 transition-all"
          >
            <Download className="w-3.5 h-3.5" />
            <span>EXPORT CSV</span>
          </button>
        </div>
      </div>

      {/* Policy Notice Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 p-2.5 rounded-xl bg-[#070e22] border border-cyan-500/20 text-xs">
        <span className="flex items-center gap-2 text-slate-300">
          <Shield className="w-4 h-4 text-cyan-400" />
          <span>Honeypot Policy: <strong className="text-cyan-300">Password-Only Authentication</strong> (SSH publickey disabled; userdb-restricted)</span>
        </span>
        <span className="text-[10px] text-slate-400">
          Telemetry Source: <strong className="text-cyan-300">ClickHouse auth_attempts</strong>
        </span>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
        <div className="p-3 rounded-xl bg-[#070e22] border border-cyan-500/20">
          <span className="text-[10px] text-slate-400 uppercase">AUTH PROBES LOGGED</span>
          <div className="text-xl font-bold text-white mt-1">{totalProbes.toLocaleString()}</div>
          <span className="text-[9px] text-slate-500">{isFiltered ? 'Matching Filter Query' : 'Total Ingested Events'}</span>
        </div>
        <div className="p-3 rounded-xl bg-[#070e22] border border-emerald-500/30">
          <span className="text-[10px] text-emerald-400 uppercase font-bold">AUTHENTICATED SESSIONS</span>
          <div className="text-xl font-bold text-emerald-400 mt-1">{authenticatedSessions.toLocaleString()}</div>
          <span className="text-[9px] text-emerald-500/80">
            Session-Level Verified Access
          </span>
        </div>
        <div className="p-3 rounded-xl bg-[#070e22] border border-cyan-500/20">
          <span className="text-[10px] text-slate-400 uppercase">UNIQUE AUTH SOURCES</span>
          <div className="text-xl font-bold text-cyan-300 mt-1">{uniqueSources.toLocaleString()}</div>
          <span className="text-[9px] text-slate-500">Distinct Originating IPs</span>
        </div>
        <div className="p-3 rounded-xl bg-[#070e22] border border-cyan-500/20">
          <span className="text-[10px] text-slate-400 uppercase">UNIQUE USERNAMES</span>
          <div className="text-xl font-bold text-white mt-1">{uniqueUsernames.toLocaleString()}</div>
          <span className="text-[9px] text-slate-500">Targeted Account Identifiers</span>
        </div>
        <div className="p-3 rounded-xl bg-[#070e22] border border-cyan-500/20">
          <span className="text-[10px] text-slate-400 uppercase">UNIQUE PASSWORDS</span>
          <div className="text-xl font-bold text-amber-300 mt-1">{uniquePasswords.toLocaleString()}</div>
          <span className="text-[9px] text-slate-500">Observed Password Values</span>
        </div>
      </div>

      {/* Top Dictionaries Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Top Usernames */}
        <div className="p-4 rounded-xl bg-[#070e22] border border-cyan-500/20 space-y-2.5">
          <h3 className="text-xs font-bold text-white uppercase flex items-center justify-between">
            <span>MOST TARGETED USERNAMES</span>
            <span className="text-[10px] text-cyan-400 font-normal">Account Frequency Ranking</span>
          </h3>
          <div className="space-y-1.5">
            {topUsernames.length === 0 ? (
              <div className="text-xs text-slate-500 py-3">No username data available.</div>
            ) : (
              topUsernames.map(([uname, count]) => (
                <div key={uname} className="flex items-center justify-between text-xs p-2 rounded bg-[#040816] border border-cyan-500/10">
                  <span className="font-bold text-cyan-300 font-mono">{uname}</span>
                  <span className="text-slate-400">{count.toLocaleString()} attempts</span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Top Passwords */}
        <div className="p-4 rounded-xl bg-[#070e22] border border-cyan-500/20 space-y-2.5">
          <h3 className="text-xs font-bold text-white uppercase flex items-center justify-between">
            <span>MOST FREQUENT PASSWORDS</span>
            <span className="text-[10px] text-amber-400 font-normal">Observed Credential Values</span>
          </h3>
          <div className="space-y-1.5">
            {topPasswords.length === 0 ? (
              <div className="text-xs text-slate-500 py-3">No password data available.</div>
            ) : (
              topPasswords.map(([pw, count]) => (
                <div key={pw} className="flex items-center justify-between text-xs p-2 rounded bg-[#040816] border border-cyan-500/10">
                  <span className="font-bold text-amber-300 font-mono">
                    {showRawPasswords ? pw : '••••••••'}
                  </span>
                  <span className="text-slate-400">{count.toLocaleString()} attempts</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#070e22] p-3 rounded-xl border border-cyan-500/20">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyan-400/60" />
          <input
            type="search"
            placeholder="Search IP, username, password, session ID..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg bg-[#040816] border border-cyan-500/25 text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400"
          />
        </div>

        <div className="flex items-center gap-2.5">
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value as any);
              setCurrentPage(1);
            }}
            className="px-3 py-1.5 rounded-lg bg-[#040816] border border-cyan-500/25 text-xs text-cyan-300 focus:outline-none focus:border-cyan-400"
          >
            <option value="all">All Authentication Results</option>
            <option value="success">Successful Logins Only</option>
            <option value="failed">Failed Probes Only</option>
          </select>

          <button
            onClick={() => setShowRawPasswords(!showRawPasswords)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#040816] border border-cyan-500/25 text-xs text-slate-300 hover:text-cyan-300 transition-all"
          >
            {showRawPasswords ? <EyeOff className="w-3.5 h-3.5 text-cyan-400" /> : <Eye className="w-3.5 h-3.5 text-slate-400" />}
            <span>{showRawPasswords ? 'Mask Passwords' : 'Show Passwords'}</span>
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="rounded-xl border border-cyan-500/20 bg-[#070e22] overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#040816] text-[10px] text-slate-400 uppercase border-b border-cyan-500/15">
              <tr>
                <th className="py-2.5 px-4">TIMESTAMP</th>
                <th className="py-2.5 px-4">ATTACKER IP</th>
                <th className="py-2.5 px-4">ORIGIN</th>
                <th className="py-2.5 px-4">SESSION ID</th>
                <th className="py-2.5 px-4">USERNAME</th>
                <th className="py-2.5 px-4">PASSWORD</th>
                <th className="py-2.5 px-4">METHOD</th>
                <th className="py-2.5 px-4">RESULT</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyan-500/10 font-mono">
              {globalAuthLoading && filteredAuth.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-400">
                    <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin mx-auto mb-2" />
                    Querying ClickHouse auth attempts...
                  </td>
                </tr>
              ) : filteredAuth.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500">
                    No authentication events match this query. External connection probes did not issue credentials in this scope.
                  </td>
                </tr>
              ) : (
                paginatedAuth.map((a, idx) => {
                  const ip = a.attacker_ip || a.src_ip || 'unknown';
                  const country = getCountryName(a.country);
                  return (
                    <tr key={a.event_id || idx} className="hover:bg-cyan-950/20 transition-all">
                      <td className="py-2.5 px-4 text-slate-400">{formatTimestamp(a.timestamp)}</td>
                      <td className="py-2.5 px-4 font-bold text-white">
                        {ip !== 'unknown' ? (
                          <Link
                            href={`/attackers?ip=${encodeURIComponent(ip)}`}
                            className="text-cyan-300 hover:underline flex items-center gap-1"
                          >
                            <span>{ip}</span>
                            <ExternalLink className="w-2.5 h-2.5 text-cyan-400 opacity-60" />
                          </Link>
                        ) : (
                          <span className="text-slate-500">unknown</span>
                        )}
                      </td>
                      <td className="py-2.5 px-4 text-slate-400">{country}</td>
                      <td className="py-2.5 px-4">
                        <Link
                          href={`/sessions/${a.session_id}`}
                          className="text-cyan-400 hover:underline flex items-center gap-1 font-bold"
                        >
                          <span>CASE-{a.session_id.slice(0, 8).toUpperCase()}</span>
                          <ExternalLink className="w-2.5 h-2.5" />
                        </Link>
                      </td>
                      <td className="py-2.5 px-4 font-bold text-white">{a.username}</td>
                      <td className="py-2.5 px-4 text-slate-300">
                        {a.password ? (
                          <span className="bg-slate-900 px-2 py-0.5 rounded border border-slate-800 font-mono">
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
                            SUCCESSFUL LOGIN
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30 flex items-center gap-1 w-fit">
                            <XCircle className="w-3 h-3 text-rose-400" />
                            REJECTED
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="p-3 bg-[#040816] border-t border-cyan-500/15 flex items-center justify-between text-xs text-slate-400">
            <span>
              Showing {(currentPage - 1) * itemsPerPage + 1} to{' '}
              {Math.min(currentPage * itemsPerPage, filteredAuth.length)} of {filteredAuth.length} attempts
            </span>
            <div className="flex items-center gap-2">
              <button
                disabled={currentPage <= 1}
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                className="px-2.5 py-1 rounded bg-[#070e22] border border-cyan-500/20 disabled:opacity-40 hover:border-cyan-400 text-cyan-300"
              >
                Previous
              </button>
              <span className="text-white font-bold">
                {currentPage} / {totalPages}
              </span>
              <button
                disabled={currentPage >= totalPages}
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                className="px-2.5 py-1 rounded bg-[#070e22] border border-cyan-500/20 disabled:opacity-40 hover:border-cyan-400 text-cyan-300"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
