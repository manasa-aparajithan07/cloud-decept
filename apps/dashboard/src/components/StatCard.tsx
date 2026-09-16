'use client';

import { cn } from '@/lib/utils';
import { TrendingUp, TrendingDown, Minus } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  change?: number;
  changeLabel?: string;
  icon: React.ReactNode;
  iconBg: string;
  iconColor: string;
  trend?: 'up' | 'down' | 'neutral';
}

export function StatCard({
  title,
  value,
  change,
  changeLabel = 'vs last hour',
  icon,
  iconBg,
  iconColor,
  trend,
}: StatCardProps) {
  const getTrendIcon = () => {
    switch (trend) {
      case 'up':
        return <TrendingUp className="w-4 h-4 text-green-600" />;
      case 'down':
        return <TrendingDown className="w-4 h-4 text-red-600" />;
      default:
        return <Minus className="w-4 h-4 text-gray-400" />;
    }
  };

  return (
    <div className="card p-6">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm font-medium text-gray-500">{title}</p>
          <p className="mt-1 text-3xl font-bold text-gray-900">{value}</p>
          {change !== undefined && (
            <div className="mt-2 flex items-center gap-1">
              {getTrendIcon()}
              <span
                className={cn(
                  'text-sm font-medium',
                  change >= 0 ? 'text-green-600' : 'text-red-600'
                )}
              >
                {change >= 0 ? '+' : ''}{change}% {changeLabel}
              </span>
            </div>
          )}
        </div>
        <div
          className={cn('p-3 rounded-xl', iconBg)}
          aria-hidden="true"
        >
          <span className={cn('text-2xl', iconColor)}>{icon}</span>
        </div>
      </div>
    </div>
  );
}