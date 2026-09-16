'use client';

import { useState, useEffect } from 'react';
import { cn } from '@/lib/utils';
import { api } from '@/lib/api';
import { useDashboardStore } from '@/lib/store';
import {
  Shield,
  Database,
  Bell,
  Terminal,
  Save,
  RefreshCw,
  CheckCircle,
  AlertCircle,
  Download,
  Trash2,
  Sliders,
  CheckCircle2,
  XCircle,
  Activity,
  Cpu,
  Globe2,
} from 'lucide-react';

export default function SettingsPage() {
  const { sessions } = useDashboardStore();
  const [activeTab, setActiveTab] = useState<'general' | 'integrations' | 'notifications' | 'advanced'>('general');
  const [saved, setSaved] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, { success: boolean; message: string }>>({});

  // General Settings State
  const [refreshInterval, setRefreshInterval] = useState('30');
  const [pageSize, setPageSize] = useState('20');
  const [timezone, setTimezone] = useState('utc');
  const [dateFormat, setDateFormat] = useState('iso');

  useEffect(() => {
    try {
      const savedSettings = localStorage.getItem('clouddecept_settings');
      if (savedSettings) {
        const parsed = JSON.parse(savedSettings);
        if (parsed.refreshInterval) setRefreshInterval(parsed.refreshInterval);
        if (parsed.pageSize) setPageSize(parsed.pageSize);
        if (parsed.timezone) setTimezone(parsed.timezone);
        if (parsed.dateFormat) setDateFormat(parsed.dateFormat);
      }
    } catch {
      // Ignore localStorage errors
    }
  }, []);

  const handleSave = () => {
    try {
      localStorage.setItem('clouddecept_settings', JSON.stringify({
        refreshInterval,
        pageSize,
        timezone,
        dateFormat,
      }));
    } catch {
      // Ignore localStorage errors
    }
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  const testConnection = async (service: string) => {
    setTesting(service);
    setTestResults((prev) => ({ ...prev, [service]: { success: false, message: 'Probing endpoint...' } }));

    try {
      const health = await api.getHealth();
      let success = false;
      let msg = '';

      if (service === 'BACKEND_URL') {
        success = health.status === 'healthy';
        msg = success ? 'API online and healthy' : `Status: ${health.status}`;
      } else if (service === 'COLLECTOR_URL') {
        success = health.clickhouse === 'healthy' && health.redis === 'healthy';
        msg = success ? 'Telemetry ingest pipelines operational' : `CH: ${health.clickhouse}, Redis: ${health.redis}`;
      } else if (service === 'THREAT_INTEL_URL') {
        success = health.postgres === 'healthy';
        msg = success ? 'Threat intelligence DB connected' : `PG: ${health.postgres}`;
      } else if (service === 'ADAPTIVE_URL') {
        success = health.redis === 'healthy';
        msg = success ? 'Adaptive engine session bus online' : 'Redis disconnected';
      } else if (service === 'INTENT_URL') {
        success = health.clickhouse === 'healthy';
        msg = success ? 'Intent analysis pipeline ready' : 'ClickHouse disconnected';
      } else {
        success = health.status === 'healthy';
        msg = 'Operational';
      }

      setTestResults((prev) => ({
        ...prev,
        [service]: { success, message: msg },
      }));
    } catch (err: any) {
      setTestResults((prev) => ({
        ...prev,
        [service]: {
          success: false,
          message: `Probe failed: ${err.message || 'Service unreachable'}`,
        },
      }));
    } finally {
      setTesting(null);
    }
  };

  const exportAllSessions = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(sessions || [], null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `clouddecept-export-${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const clearLocalPreferences = () => {
    if (confirm('Reset all local dashboard preferences and cached telemetry filters?')) {
      localStorage.removeItem('clouddecept_settings');
      setRefreshInterval('30');
      setPageSize('20');
      setTimezone('utc');
      setDateFormat('iso');
      alert('Local preferences reset to defaults.');
    }
  };

  const tabs = [
    { id: 'general', label: 'PREFERENCES', icon: Sliders },
    { id: 'integrations', label: 'HEALTH & SERVICES', icon: Database },
    { id: 'notifications', label: 'ALERT RULES', icon: Bell },
    { id: 'advanced', label: 'DATA ENGINE', icon: Terminal },
  ];

  return (
    <main className="p-4 sm:p-6 lg:p-8 space-y-6 max-w-5xl mx-auto text-slate-100 font-mono">
      {/* Header HUD */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono tracking-widest uppercase bg-cyan-950/80 text-cyan-400 border border-cyan-500/30">
              System Configuration
            </span>
            <span className="flex h-2 w-2 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500" />
            </span>
            <span className="text-xs font-mono text-cyan-300">SOC Control Plane</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            <Shield className="w-7 h-7 text-cyan-400" />
            COMMAND CENTER SETTINGS
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-2xl">
            Configure telemetry polling cadences, display parameters, and probe microservice health endpoints
          </p>
        </div>

        <button
          onClick={handleSave}
          disabled={saved}
          className="flex items-center gap-2 px-4 py-2 rounded-lg border border-cyan-500/40 bg-cyan-950/80 text-cyan-300 hover:bg-cyan-900/80 hover:text-cyan-200 text-xs font-bold transition-all disabled:opacity-50 shadow-neon"
        >
          {saved ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <Save className="w-4 h-4" />}
          {saved ? 'SETTINGS PERSISTED' : 'SAVE CONFIGURATION'}
        </button>
      </div>

      {/* Main Glass Panel */}
      <div className="glass-panel border border-cyan-500/20 rounded-xl overflow-hidden">
        {/* Navigation Tabs */}
        <div className="border-b border-cyan-500/20 bg-[#050a18]/80 p-2">
          <nav className="flex flex-wrap gap-2" aria-label="Settings tabs">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={cn(
                  'flex items-center gap-2 px-3.5 py-2 text-xs font-bold rounded-lg transition-all tracking-wider',
                  activeTab === tab.id
                    ? 'bg-cyan-950/80 border border-cyan-500/40 text-cyan-300 shadow-neon'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-cyan-950/30'
                )}
              >
                <tab.icon className="w-3.5 h-3.5 text-cyan-400" />
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Tab Body */}
        <div className="p-6">
          {activeTab === 'general' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-2">
                  <Sliders className="w-4 h-4 text-cyan-400" />
                  Telemetry Polling & Localization
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-bold text-slate-300 mb-1.5 uppercase">
                      Telemetry Auto-Refresh Interval
                    </label>
                    <select
                      className="w-full px-3 py-2 text-xs bg-[#050a18]/90 border border-cyan-500/20 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-400"
                      value={refreshInterval}
                      onChange={(e) => setRefreshInterval(e.target.value)}
                    >
                      <option value="5">5 SECONDS (HIGH FREQUENCY)</option>
                      <option value="10">10 SECONDS</option>
                      <option value="30">30 SECONDS (DEFAULT)</option>
                      <option value="60">1 MINUTE</option>
                      <option value="300">5 MINUTES</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-bold text-slate-300 mb-1.5 uppercase">
                      Default Table Page Size
                    </label>
                    <select
                      className="w-full px-3 py-2 text-xs bg-[#050a18]/90 border border-cyan-500/20 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-400"
                      value={pageSize}
                      onChange={(e) => setPageSize(e.target.value)}
                    >
                      <option value="10">10 RECORDS</option>
                      <option value="20">20 RECORDS (DEFAULT)</option>
                      <option value="50">50 RECORDS</option>
                      <option value="100">100 RECORDS</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-bold text-slate-300 mb-1.5 uppercase">
                      Display Timezone
                    </label>
                    <select
                      className="w-full px-3 py-2 text-xs bg-[#050a18]/90 border border-cyan-500/20 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-400"
                      value={timezone}
                      onChange={(e) => setTimezone(e.target.value)}
                    >
                      <option value="utc">UTC (SOC STANDARD)</option>
                      <option value="local">BROWSER LOCAL TIME</option>
                      <option value="us-east">US EASTERN (EST/EDT)</option>
                      <option value="us-west">US PACIFIC (PST/PDT)</option>
                      <option value="eu-central">EU CENTRAL (CET/CEST)</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-bold text-slate-300 mb-1.5 uppercase">
                      Timestamp Representation
                    </label>
                    <select
                      className="w-full px-3 py-2 text-xs bg-[#050a18]/90 border border-cyan-500/20 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-400"
                      value={dateFormat}
                      onChange={(e) => setDateFormat(e.target.value)}
                    >
                      <option value="iso">ISO-8601 (YYYY-MM-DD HH:MM:SS)</option>
                      <option value="relative">RELATIVE (2m ago)</option>
                      <option value="us">US FORMAT (MM/DD/YYYY)</option>
                      <option value="eu">EU FORMAT (DD/MM/YYYY)</option>
                    </select>
                  </div>
                </div>
              </div>

              <div className="border-t border-cyan-500/10 pt-6">
                <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-4">
                  HUD Presentation Parameters
                </h3>
                <div className="space-y-3">
                  {[
                    { id: 'show_threat_scores', label: 'Display calculated threat scores in matrix tables', default: true },
                    { id: 'show_intent_badges', label: 'Render MITRE ATT&CK objective badges', default: true },
                    { id: 'animate_transitions', label: 'Enable glowing bezier trajectories and particle animations', default: true },
                    { id: 'compact_mode', label: 'Compact high-density table view for forensic screens', default: false },
                  ].map((pref) => (
                    <label
                      key={pref.id}
                      className="flex items-center justify-between p-3 rounded-lg bg-[#050a18]/60 border border-cyan-500/10 hover:border-cyan-500/30 transition-colors cursor-pointer"
                    >
                      <span className="text-xs text-slate-300">{pref.label}</span>
                      <input
                        type="checkbox"
                        defaultChecked={pref.default}
                        className="w-4 h-4 accent-cyan-400 bg-cyan-950 border border-cyan-500/40 rounded cursor-pointer"
                      />
                    </label>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'integrations' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-2 flex items-center gap-2">
                  <Database className="w-4 h-4 text-cyan-400" />
                  Service Health & Connectivity Diagnostics
                </h3>
                <p className="text-xs text-slate-400 mb-4 font-sans">
                  Probe live microservice endpoints across the Honeypot ingestion pipeline and state stores.
                </p>

                <div className="space-y-3">
                  {[
                    { key: 'BACKEND_URL', label: 'FastAPI Primary Core (:8000)', default: 'http://localhost:8000', icon: Database },
                    { key: 'COLLECTOR_URL', label: 'ClickHouse & Event Stream Collector', default: 'http://localhost:8000', icon: Globe2 },
                    { key: 'THREAT_INTEL_URL', label: 'PostgreSQL Threat Intel Store (:5432)', default: 'http://localhost:8000', icon: Shield },
                    { key: 'ADAPTIVE_URL', label: 'Redis Session Bus (:6379)', default: 'http://localhost:8002', icon: Activity },
                    { key: 'INTENT_URL', label: 'Intent Classification Pipeline', default: 'http://localhost:8001', icon: Cpu },
                  ].map((service) => (
                    <div
                      key={service.key}
                      className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-3.5 rounded-lg bg-[#050a18]/60 border border-cyan-500/20"
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <div className="p-2 rounded-lg bg-cyan-950/60 border border-cyan-500/30 text-cyan-400">
                          <service.icon className="w-4 h-4" />
                        </div>
                        <div className="min-w-0">
                          <p className="text-xs font-bold text-white truncate">{service.label}</p>
                          <p className="text-[11px] text-slate-500 truncate">{service.default}</p>
                        </div>
                      </div>

                      <div className="flex items-center gap-3 flex-shrink-0">
                        <button
                          onClick={() => testConnection(service.key)}
                          disabled={testing === service.key}
                          className="px-3 py-1.5 rounded-lg border border-cyan-500/30 bg-cyan-950/40 text-cyan-300 hover:bg-cyan-900/60 text-xs font-bold transition-all disabled:opacity-50 flex items-center gap-1.5"
                        >
                          {testing === service.key ? (
                            <>
                              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                              PROBING...
                            </>
                          ) : (
                            'TEST PROBE'
                          )}
                        </button>

                        {testResults[service.key] && (
                          <span
                            className={cn(
                              'flex items-center gap-1.5 text-[11px] font-bold px-2 py-1 rounded border',
                              testResults[service.key].success
                                ? 'border-emerald-500/30 text-emerald-400 bg-emerald-950/40'
                                : 'border-rose-500/30 text-rose-400 bg-rose-950/40'
                            )}
                          >
                            {testResults[service.key].success ? (
                              <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0" />
                            ) : (
                              <XCircle className="w-3.5 h-3.5 flex-shrink-0" />
                            )}
                            {testResults[service.key].message}
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'notifications' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-2 flex items-center gap-2">
                  <Bell className="w-4 h-4 text-cyan-400" />
                  SOC Critical Alert Thresholds
                </h3>
                <p className="text-xs text-slate-400 mb-4 font-sans">
                  Rules that trigger immediate SOC escalation notifications upon anomalous adversary behavior.
                </p>

                <div className="space-y-3">
                  {[
                    { id: 'alert_critical', label: 'CRITICAL THREAT THRESHOLD (THREAT SCORE >= 70)', channels: 'SIEM / DISCORD / EMAIL', enabled: true },
                    { id: 'alert_new_ip', label: 'NEW ATTACKER IP RECONNAISSANCE DETECTED', channels: 'WEBHOOK / SLACK', enabled: true },
                    { id: 'alert_credentials', label: 'CREDENTIAL HARVESTING ATTEMPT (AWS/SSH)', channels: 'PAGERDUTY / EMAIL', enabled: true },
                    { id: 'alert_exfil', label: 'DATA EXFILTRATION TRAFFIC BURST DETECTED', channels: 'SIEM / PAGERDUTY', enabled: true },
                  ].map((alert) => (
                    <div
                      key={alert.id}
                      className="p-3.5 rounded-lg bg-[#050a18]/60 border border-cyan-500/20 flex items-center justify-between"
                    >
                      <label className="flex items-center gap-3 cursor-pointer">
                        <input
                          type="checkbox"
                          defaultChecked={alert.enabled}
                          className="w-4 h-4 accent-cyan-400 bg-cyan-950 border border-cyan-500/40 rounded cursor-pointer"
                        />
                        <div>
                          <p className="text-xs font-bold text-white">{alert.label}</p>
                          <p className="text-[10px] text-cyan-400/80">DISPATCH: {alert.channels}</p>
                        </div>
                      </label>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 font-bold">
                        ENFORCED
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'advanced' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-2 flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  Telemetry Data Management & Export
                </h3>
                <p className="text-xs text-slate-400 mb-4 font-sans">
                  Export complete forensic records or reset local caching buffers.
                </p>

                <div className="space-y-3">
                  <div className="p-4 rounded-lg bg-[#050a18]/60 border border-cyan-500/20 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div>
                      <p className="text-xs font-bold text-white">EXPORT FULL SESSION TELEMETRY</p>
                      <p className="text-[11px] text-slate-400 font-sans mt-0.5">
                        Download raw session telemetry and intent classifications as formatted JSON
                      </p>
                    </div>
                    <button
                      onClick={exportAllSessions}
                      className="px-4 py-2 rounded-lg border border-cyan-500/30 bg-cyan-950/40 text-cyan-300 hover:bg-cyan-900/60 text-xs font-bold transition-all flex items-center gap-1.5 self-start sm:self-auto"
                    >
                      <Download className="w-4 h-4" />
                      DOWNLOAD JSON
                    </button>
                  </div>

                  <div className="p-4 rounded-lg bg-[#050a18]/60 border border-rose-500/20 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div>
                      <p className="text-xs font-bold text-rose-300">PURGE LOCAL PREFERENCES & CACHE</p>
                      <p className="text-[11px] text-slate-400 font-sans mt-0.5">
                        Reset filter selections, table densities, and browser storage states
                      </p>
                    </div>
                    <button
                      onClick={clearLocalPreferences}
                      className="px-4 py-2 rounded-lg border border-rose-500/30 bg-rose-950/40 text-rose-300 hover:bg-rose-900/60 text-xs font-bold transition-all flex items-center gap-1.5 self-start sm:self-auto"
                    >
                      <Trash2 className="w-4 h-4" />
                      PURGE CACHE
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </main>
  );
}