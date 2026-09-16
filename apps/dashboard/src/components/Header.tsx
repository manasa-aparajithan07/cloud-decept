'use client';

import { useState, useEffect } from 'react';
import { cn } from '@/lib/utils';
import {
  Search,
  RefreshCw,
  Clock,
  Menu,
} from 'lucide-react';
import { useDashboardStore } from '@/lib/store';
import { useSidebar } from '@/lib/SidebarContext';
import { useRouter } from 'next/navigation';

export function Header() {
  const router = useRouter();
  const connectionStatus = useDashboardStore((s) => s.connectionStatus);
  const isLiveConnected = useDashboardStore((s) => s.isLiveConnected);
  const liveEventCount = useDashboardStore((s) => s.liveEventCount);
  const fetchConnectionStatus = useDashboardStore((s) => s.fetchConnectionStatus);
  const fetchStats = useDashboardStore((s) => s.fetchStats);
  const timeWindowHours = useDashboardStore((s) => s.timeWindowHours);
  const setTimeWindowHours = useDashboardStore((s) => s.setTimeWindowHours);
  const { collapsed, setCollapsed } = useSidebar();
  const [currentTime, setCurrentTime] = useState<string>('');
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [autoSync, setAutoSync] = useState(true);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(now.toUTCString().replace('GMT', 'UTC'));
    };
    updateTime();
    const timer = setInterval(updateTime, 1000);
    return () => clearInterval(timer);
  }, []);

  // Initialize connection health on initial mount
  useEffect(() => {
    fetchConnectionStatus();
    const healthInterval = setInterval(() => {
      fetchConnectionStatus();
    }, 30000);
    return () => clearInterval(healthInterval);
  }, [fetchConnectionStatus]);

  // Auto-sync polling every 20s if enabled
  useEffect(() => {
    if (!autoSync) return;
    const interval = setInterval(() => {
      fetchStats(timeWindowHours);
    }, 20000);
    return () => clearInterval(interval);
  }, [autoSync, fetchStats, timeWindowHours]);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      await Promise.allSettled([
        fetchConnectionStatus(),
        fetchStats(timeWindowHours),
      ]);
    } finally {
      setTimeout(() => setIsRefreshing(false), 500);
    }
  };

  const isApiHealthy = connectionStatus?.connected ?? false;

  return (
    <header className="fixed top-0 right-0 z-30 h-16 bg-[#040816]/90 backdrop-blur-2xl border-b border-cyan-500/15 flex items-center px-4 sm:px-6 w-full lg:w-[calc(100%-16rem)] transition-all duration-300">
      <div className="flex-1 flex items-center justify-between gap-3 max-w-full">
        {/* Left: Mobile hamburger & Global Search */}
        <div className="flex items-center gap-3 flex-1 min-w-0">
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="lg:hidden p-2 rounded-lg text-slate-400 hover:text-cyan-300 hover:bg-slate-900 border border-slate-800"
            aria-label="Toggle navigation"
          >
            <Menu className="w-5 h-5" />
          </button>

          <div className="relative min-w-0 flex-1 max-w-md hidden sm:block">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyan-400/60" />
            <input
              type="search"
              placeholder="Search threat events, IPs, MITRE techniques..."
              onKeyDown={(e) => {
                if (e.key === 'Enter' && e.currentTarget.value.trim()) {
                  router.push(`/sessions?search=${encodeURIComponent(e.currentTarget.value.trim())}`);
                }
              }}
              className="w-full pl-9 pr-12 py-1.5 text-xs font-mono rounded-lg bg-[#070e22] border border-cyan-500/20 text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/30 transition-all"
              aria-label="Global SOC search"
            />
            <kbd className="absolute right-2.5 top-1/2 -translate-y-1/2 px-1.5 py-0.5 text-[9px] font-mono text-slate-400 bg-slate-800/80 rounded border border-slate-700/60 pointer-events-none">
              /
            </kbd>
          </div>
        </div>

        {/* Right: SOC Operational HUD */}
        <div className="flex items-center gap-2.5 sm:gap-3.5 flex-shrink-0">
          {/* Live UTC Clock */}
          <div className="hidden xl:flex items-center gap-2 px-3 py-1 rounded-lg bg-[#070e22] border border-cyan-500/15 text-[11px] font-mono text-cyan-300/90">
            <Clock className="w-3.5 h-3.5 text-cyan-400/70" />
            <span>{currentTime || 'SYNCHRONIZING UTC...'}</span>
          </div>

          {/* Live SSE Overlay Status */}
          <div className="hidden md:flex items-center gap-2 px-2.5 py-1 rounded-lg bg-[#070e22] border border-cyan-500/20 font-mono text-[11px]">
            <span
              className={cn(
                'w-2 h-2 rounded-full',
                isLiveConnected ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)] animate-pulse' : 'bg-rose-500'
              )}
            />
            <span className={cn('font-bold tracking-wider', isLiveConnected ? 'text-emerald-400' : 'text-slate-400')}>
              {isLiveConnected ? 'LIVE ●' : 'LIVE OFFLINE'}
            </span>
            {isLiveConnected && (
              <span className="text-slate-500 border-l border-slate-800 pl-2 text-[10px]">
                {liveEventCount} EVTS
              </span>
            )}
          </div>

          {/* System API Status */}
          <div className="flex items-center gap-2 px-2.5 py-1 rounded-lg bg-[#070e22] border border-cyan-500/20">
            <span
              className={cn(
                'w-2 h-2 rounded-full',
                isApiHealthy ? 'bg-emerald-400' : 'bg-rose-500'
              )}
            />
            <span className="text-[11px] font-mono font-bold tracking-wider text-slate-300 uppercase hidden lg:block">
              {isApiHealthy ? 'SYSTEM OPERATIONAL' : 'SYSTEM DISCONNECTED'}
            </span>
          </div>

          {/* Auto-Sync Toggle */}
          <button
            onClick={() => setAutoSync(!autoSync)}
            className={cn(
              'hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-lg border font-mono text-[11px] transition-all',
              autoSync
                ? 'bg-cyan-950/40 border-cyan-500/30 text-cyan-300'
                : 'bg-[#070e22] border-slate-800 text-slate-500'
            )}
            title={autoSync ? 'Auto-sync active (20s)' : 'Auto-sync paused'}
          >
            <span className={cn('w-1.5 h-1.5 rounded-full', autoSync ? 'bg-cyan-400' : 'bg-slate-600')} />
            <span>SYNC</span>
          </button>

          {/* Time Window Selector */}
          <select
            className="px-2.5 py-1.5 rounded-lg bg-[#070e22] border border-cyan-500/25 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-400 cursor-pointer"
            value={timeWindowHours}
            onChange={(e) => setTimeWindowHours(Number(e.target.value))}
            aria-label="Select global time window"
          >
            <option value={1}>1H (Hour)</option>
            <option value={24}>24H (Day)</option>
            <option value={168}>7D (Week)</option>
            <option value={720}>30D (Month)</option>
            <option value={87600}>All-Time</option>
          </select>

          {/* Manual Refresh Action */}
          <button
            onClick={handleRefresh}
            disabled={isRefreshing}
            className="p-2 rounded-lg bg-[#070e22] border border-cyan-500/20 text-slate-300 hover:text-cyan-300 hover:border-cyan-400/40 transition-all disabled:opacity-50"
            title="Refresh backend telemetry"
            aria-label="Refresh telemetry status"
          >
            <RefreshCw className={cn('w-4 h-4', isRefreshing && 'animate-spin text-cyan-400')} />
          </button>
        </div>
      </div>
    </header>
  );
}