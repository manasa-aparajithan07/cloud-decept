'use client';

import { useEffect, useCallback, useMemo } from 'react';
import { useDashboardStore } from '@/lib/store';

/**
 * Authoritative Statistics Hook for CloudDecept Dashboard.
 * Serves as the single source of truth for global metrics across Overview, Analytics, and Sessions,
 * preventing contradictory metrics and stale subset calculations.
 */
export function useDashboardStats(options: { autoRefreshIntervalMs?: number } = {}) {
  const stats = useDashboardStore((s) => s.stats);
  const statsLoading = useDashboardStore((s) => s.statsLoading);
  const statsError = useDashboardStore((s) => s.statsError);
  const fetchStats = useDashboardStore((s) => s.fetchStats);
  const connectionStatus = useDashboardStore((s) => s.connectionStatus);
  const fetchConnectionStatus = useDashboardStore((s) => s.fetchConnectionStatus);

  const timeWindowHours = useDashboardStore((s) => s.timeWindowHours);

  const refresh = useCallback(async () => {
    await Promise.allSettled([
      fetchStats(timeWindowHours),
      fetchConnectionStatus(),
    ]);
  }, [fetchStats, fetchConnectionStatus, timeWindowHours]);

  // Optional periodic background refresh
  useEffect(() => {
    if (!options.autoRefreshIntervalMs || options.autoRefreshIntervalMs <= 0) return;
    const interval = setInterval(refresh, options.autoRefreshIntervalMs);
    return () => clearInterval(interval);
  }, [options.autoRefreshIntervalMs, refresh]);

  const threatDistributionMap = useMemo(() => {
    const map: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unclassified: 0,
    };
    const list = stats?.threat_distribution || (stats as any)?.threatDistribution;
    if (list && Array.isArray(list)) {
      for (const item of list) {
        if (item && item.level) {
          map[item.level.toLowerCase()] = item.count || 0;
        }
      }
    }
    return map;
  }, [stats?.threat_distribution, (stats as any)?.threatDistribution]);

  return {
    // Raw Stats Object
    stats,

    // Authoritative All-Time Global Metrics
    totalSessions: (stats as any)?.total_sessions ?? (stats as any)?.totalSessions ?? 0,
    totalCommands: (stats as any)?.total_commands ?? (stats as any)?.totalCommands ?? 0,
    uniqueAttackers: (stats as any)?.unique_attackers ?? (stats as any)?.uniqueAttackers ?? 0,
    activeSessions: (stats as any)?.active_sessions ?? (stats as any)?.activeSessions ?? 0,

    // Authoritative External Attacker Metrics (Phase 3.2 & 3.6 truthful semantics)
    externalSessions: (stats as any)?.external_sessions ?? 0,
    externalCommands: (stats as any)?.external_commands ?? 0,
    externalAuthSessions: (stats as any)?.external_auth_sessions ?? 0,
    interactiveSessions: (stats as any)?.interactive_sessions ?? 0,
    commandBearingSessions: (stats as any)?.command_bearing_sessions ?? (stats as any)?.interactive_sessions ?? 0,
    uniqueExternalAttackers: (stats as any)?.unique_external_attackers ?? (stats as any)?.unique_attackers ?? 0,
    authOutcomes: (stats as any)?.auth_outcomes ?? null,
    dataIntegrity: (stats as any)?.data_integrity ?? null,
    assessedSessionsCount: (stats as any)?.assessed_sessions_count ?? 0,
    unassessedSessionsCount: (stats as any)?.unassessed_sessions_count ?? 0,

    // Authoritative Recent Window Metrics (Last 24h)
    recentSessions24h: (stats as any)?.recent_sessions ?? (stats as any)?.recentSessions ?? 0,
    recentCommands24h: (stats as any)?.recent_commands ?? (stats as any)?.recentCommands ?? 0,
    recentAttackers24h: (stats as any)?.recent_unique_attackers ?? (stats as any)?.recentUniqueAttackers ?? 0,

    // Authoritative Chart Time-Series & Aggregations
    topIntents: ((stats as any)?.top_intents ?? (stats as any)?.topIntents ?? []) as { intent: string; count: number }[],
    topCountries: ((stats as any)?.top_countries ?? (stats as any)?.topCountries ?? []) as { country: string; count: number; attackers?: number }[],
    threatDistribution: threatDistributionMap,
    threatDistributionList: ((stats as any)?.threat_distribution ?? (stats as any)?.threatDistribution ?? []) as { level: string; count: number }[],
    sessionsPerHour: ((stats as any)?.sessions_per_hour ?? (stats as any)?.sessionsPerHour ?? []) as { hour: string; count: number; date?: string }[],
    commandsPerDay: ((stats as any)?.commands_per_day ?? (stats as any)?.commandsPerDay ?? []) as { date: string; count: number }[],
    sessionsPerDay: ((stats as any)?.sessions_per_day ?? (stats as any)?.sessionsPerDay ?? []) as { date: string; count: number }[],

    // Connection & State
    isApiHealthy: connectionStatus?.connected ?? false,
    isLoading: statsLoading,
    isError: Boolean(statsError),
    error: statsError,
    refresh,
  };
}
