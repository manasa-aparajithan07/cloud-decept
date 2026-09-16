import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatTimestamp(ts?: string | number | Date | null): string {
  if (!ts) return '—';
  const date = new Date(ts);
  if (isNaN(date.getTime())) return '—';
  return date.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${minutes}m`;
}

export function getSeverityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'bg-danger-100 text-danger-800 border-danger-200';
    case 'high':
      return 'bg-red-100 text-red-800 border-red-200';
    case 'medium':
      return 'bg-warning-100 text-warning-800 border-warning-200';
    case 'low':
      return 'bg-blue-100 text-blue-800 border-blue-200';
    case 'info':
      return 'bg-gray-100 text-gray-800 border-gray-200';
    default:
      return 'bg-gray-100 text-gray-800 border-gray-200';
  }
}

export function getIntentColor(intent: string): string {
  const norm = (intent || '').toLowerCase().trim().replace(/[\s_]+/g, '_');
  switch (norm) {
    case 'steal_credentials':
    case 'credential_access':
    case 'credential_hunting':
      return 'bg-red-100 text-red-800';
    case 'system_discovery':
    case 'discovery':
    case 'cloud_recon':
      return 'bg-blue-100 text-blue-800';
    case 'move_laterally':
    case 'lateral_movement':
      return 'bg-orange-100 text-orange-800';
    case 'cause_damage':
    case 'impact':
      return 'bg-rose-100 text-rose-800';
    case 'persistence':
      return 'bg-purple-100 text-purple-800';
    case 'data_exfiltration':
    case 'data_access':
      return 'bg-amber-100 text-amber-800';
    case 'resource_hijacking':
      return 'bg-pink-100 text-pink-800';
    case 'defense_evasion':
    case 'privilege_escalation':
      return 'bg-indigo-100 text-indigo-800';
    default:
      return 'bg-gray-100 text-gray-800';
  }
}

export function getRiskColor(risk: string): string {
  switch (risk.toLowerCase()) {
    case 'critical':
      return 'bg-danger-100 text-danger-800';
    case 'high':
      return 'bg-red-100 text-red-800';
    case 'medium':
      return 'bg-warning-100 text-warning-800';
    case 'low':
      return 'bg-green-100 text-green-800';
    default:
      return 'bg-gray-100 text-gray-800';
  }
}

export function truncate(str: string, length: number): string {
  if (str.length <= length) return str;
  return str.slice(0, length) + '...';
}

export function debounce<T extends (...args: unknown[]) => unknown>(
  fn: T,
  ms: number
): (...args: Parameters<T>) => void {
  let timeoutId: ReturnType<typeof setTimeout>;
  return (...args: Parameters<T>) => {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => fn(...args), ms);
  };
}