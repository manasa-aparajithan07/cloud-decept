'use client';

import React, { useMemo, useState, useCallback, useRef } from 'react';
import * as d3 from 'd3-geo';
import { feature } from 'topojson-client';
import worldData from 'world-atlas/countries-110m.json';
import { getCountryName } from '@/lib/countries';
import { evaluateThreat } from '@/lib/threatScore';
import { normalizeIntent } from '@/lib/intents';
import {
  Globe,
  Radio,
  Layers,
  Crosshair,
  Shield,
  Zap,
  Info,
  Maximize2,
  Minimize2,
  ExternalLink,
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface CountryStat {
  country: string;
  count: number;
}

interface GeographicMapProps {
  data: CountryStat[];
  totalSessions: number;
  isLoading?: boolean;
  onCountrySelect?: (countryCode: string) => void;
}

// Canonical ISO 3166-1 numeric ID -> ISO-2 Alpha code mapping
const NUMERIC_TO_ALPHA2: Record<string, string> = {
  '840': 'US', '156': 'CN', '643': 'RU', '276': 'DE', '528': 'NL',
  '356': 'IN', '826': 'GB', '250': 'FR', '392': 'JP', '410': 'KR',
  '076': 'BR', '124': 'CA', '036': 'AU', '702': 'SG', '792': 'TR',
  '756': 'CH', '752': 'SE', '578': 'NO', '246': 'FI', '566': 'NG',
  '710': 'ZA', '818': 'EG', '360': 'ID', '764': 'TH', '704': 'VN',
  '616': 'PL', '804': 'UA', '642': 'RO', '380': 'IT', '724': 'ES',
  '372': 'IE', '056': 'BE', '040': 'AT', '208': 'DK', '620': 'PT',
  '300': 'GR', '203': 'CZ', '348': 'HU', '376': 'IL', '682': 'SA',
  '784': 'AE', '368': 'IQ', '364': 'IR', '586': 'PK', '050': 'BD',
  '170': 'CO', '484': 'MX', '152': 'CL', '032': 'AR', '604': 'PE',
  '554': 'NZ', '458': 'MY', '608': 'PH', '144': 'LK', '504': 'MA',
};

// Reverse Alpha-2 -> Numeric ID lookup
const ALPHA2_TO_NUMERIC: Record<string, string> = Object.entries(NUMERIC_TO_ALPHA2).reduce(
  (acc, [num, a2]) => ({ ...acc, [a2]: num }),
  {}
);

// Fallback centroid coordinates [longitude, latitude]
const COUNTRY_COORDINATES: Record<string, [number, number]> = {
  US: [-95.7129, 37.0902],
  CN: [104.1954, 35.8617],
  RU: [105.3188, 61.524],
  DE: [10.4515, 51.1657],
  NL: [5.2913, 52.1326],
  IN: [78.9629, 20.5937],
  GB: [-3.436, 55.3781],
  FR: [2.2137, 46.2276],
  BR: [-51.9253, -14.235],
  JP: [138.2529, 36.2048],
  KR: [127.7669, 35.9078],
  SG: [103.8198, 1.3521],
  CA: [-106.3468, 56.1304],
  AU: [133.7751, -25.2744],
  TR: [35.2433, 38.9637],
  IR: [53.688, 32.4279],
  UA: [31.1656, 48.3794],
  PL: [19.1451, 51.9194],
  RO: [24.9668, 45.9432],
  VN: [108.2772, 14.0583],
  ID: [113.9213, -0.7893],
  TH: [100.9925, 15.87],
  ZA: [22.9375, -30.5595],
  NG: [8.6753, 9.082],
  EG: [30.8025, 26.8206],
  SA: [45.0792, 23.8859],
  AE: [53.8478, 23.4241],
  PK: [69.3451, 30.3753],
  BD: [90.3563, 23.685],
  MX: [-102.5528, 23.6345],
  AR: [-63.6167, -38.4161],
  CL: [-71.543, -35.6751],
  CO: [-74.2973, 4.5709],
  ES: [-3.7492, 40.4637],
  IT: [12.5674, 41.8719],
  SE: [18.6435, 60.1282],
  NO: [8.4689, 60.472],
  FI: [25.7482, 61.9241],
  CH: [8.2275, 46.8182],
  AT: [14.5501, 47.5162],
  BE: [4.4699, 50.5039],
  IE: [-8.2439, 53.4129],
  IL: [34.8516, 31.0461],
};

// Target Honeypot Core location (US East Deception Cluster)
const HONEYPOT_COORD: [number, number] = [-77.0369, 38.9072];

export function GeographicMap({
  data = [],
  totalSessions = 0,
  isLoading = false,
  onCountrySelect,
}: GeographicMapProps) {
  const [hoveredCountry, setHoveredCountry] = useState<{
    code: string;
    name: string;
    count: number;
    share: number;
    x: number;
    y: number;
  } | null>(null);

  const [selectedCountry, setSelectedCountry] = useState<string | null>(null);
  const [showArcs, setShowArcs] = useState(true);
  const [showHotspots, setShowHotspots] = useState(true);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const mapContainerRef = useRef<HTMLDivElement>(null);

  // SVG Canvas Dimensions
  const width = 960;
  const height = 500;

  // Set up D3 Natural Earth projection for cinematic world curvature
  const projection = useMemo(() => {
    return d3.geoNaturalEarth1().scale(158).translate([width / 2, height / 2 + 10]);
  }, [width, height]);

  const geoPath = useMemo(() => {
    return d3.geoPath().projection(projection);
  }, [projection]);

  const graticulePath = useMemo(() => {
    const graticule = d3.geoGraticule10();
    return geoPath(graticule) || '';
  }, [geoPath]);

  // Extract TopoJSON country features
  const worldFeatures = useMemo(() => {
    try {
      const countriesObj = (worldData as any).objects.countries;
      const geojson: any = feature(worldData as any, countriesObj);
      return geojson.features || [];
    } catch {
      return [];
    }
  }, []);

  // Compute Country Stats Map & Max Attack Count
  const { countryStatsMap, maxCount, sortedData } = useMemo(() => {
    const map = new Map<string, number>();
    let max = 1;
    const cleanList = (data || []).filter((d) => d && d.country && typeof d.country === 'string');

    cleanList.forEach((d) => {
      const code = d.country.toUpperCase();
      map.set(code, d.count);
      if (d.count > max) max = d.count;
    });

    const sorted = [...cleanList].sort((a, b) => b.count - a.count);
    return { countryStatsMap: map, maxCount: max, sortedData: sorted };
  }, [data]);

  // Projected Honeypot Target Location
  const honeypotXY = useMemo(() => {
    return projection(HONEYPOT_COORD) || [width * 0.28, height * 0.38];
  }, [projection, width, height]);

  // Compute Projected Centroids and Attack Flow Arcs for active countries
  const activeNodes = useMemo(() => {
    const nodes: Array<{
      code: string;
      name: string;
      count: number;
      share: number;
      xy: [number, number];
      arcPath: string;
      threat: ReturnType<typeof evaluateThreat>;
    }> = [];

    sortedData.forEach((item) => {
      if (!item || !item.country || typeof item.country !== 'string') return;
      const code = item.country.toUpperCase();
      const count = item.count;
      const share = totalSessions > 0 ? (count / totalSessions) * 100 : 0;
      const numId = ALPHA2_TO_NUMERIC[code];

      // Find feature to get accurate centroid or fallback to predefined coordinates
      let coord = COUNTRY_COORDINATES[code];
      if (numId) {
        const feat = worldFeatures.find((f: any) => String(f.id) === numId);
        if (feat) {
          try {
            coord = d3.geoCentroid(feat);
          } catch {
            // keep fallback
          }
        }
      }

      if (coord) {
        const pt = projection(coord);
        if (pt) {
          // Quadratic Bezier curve to honeypot
          const [sx, sy] = pt;
          const [dx, dy] = honeypotXY;
          const midX = (sx + dx) / 2;
          const midY = (sy + dy) / 2 - Math.min(80, Math.hypot(dx - sx, dy - sy) * 0.25);
          const arcPath = `M ${sx.toFixed(1)} ${sy.toFixed(1)} Q ${midX.toFixed(1)} ${midY.toFixed(1)} ${dx.toFixed(1)} ${dy.toFixed(1)}`;

          // Truthful threat tier based on volume share & skill
          const threatTier =
            count >= 5000
              ? 'critical'
              : count >= 1000
              ? 'high'
              : count >= 200
              ? 'medium'
              : 'low';

          nodes.push({
            code,
            name: getCountryName(code),
            count,
            share,
            xy: pt as [number, number],
            arcPath,
            threat: evaluateThreat(null, threatTier),
          });
        }
      }
    });

    return nodes;
  }, [sortedData, totalSessions, worldFeatures, projection, honeypotXY]);

  const handleCountryHover = useCallback(
    (code: string, e: React.MouseEvent<SVGPathElement>) => {
      const count = countryStatsMap.get(code) || 0;
      const share = totalSessions > 0 ? (count / totalSessions) * 100 : 0;
      const rect = e.currentTarget.getBoundingClientRect();
      const containerRect = mapContainerRef.current?.getBoundingClientRect();

      const x = containerRect ? e.clientX - containerRect.left : rect.x;
      const y = containerRect ? e.clientY - containerRect.top : rect.y;

      setHoveredCountry({
        code,
        name: getCountryName(code),
        count,
        share,
        x,
        y,
      });
    },
    [countryStatsMap, totalSessions]
  );

  const handleCountryClick = (code: string) => {
    setSelectedCountry(selectedCountry === code ? null : code);
    if (onCountrySelect) onCountrySelect(code);
  };

  return (
    <div
      ref={mapContainerRef}
      className={cn(
        'relative rounded-2xl overflow-hidden transition-all duration-300',
        'bg-gradient-to-b from-[#060b18] via-[#040813] to-[#02050c]',
        'border border-cyan-500/20 shadow-2xl shadow-cyan-950/40',
        isFullscreen ? 'fixed inset-4 z-50 p-6' : 'p-4 sm:p-6'
      )}
    >
      {/* Background Radial Glow & Scanline Effect */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_40%,rgba(6,182,212,0.12),transparent_70%)] pointer-events-none" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_30%_35%,rgba(245,158,11,0.06),transparent_50%)] pointer-events-none" />

      {/* Header Bar */}
      <div className="relative z-10 flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-cyan-500/15">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-400/30 text-cyan-300">
              <Globe className="w-4 h-4" />
            </span>
            <h2 className="text-base font-bold font-mono tracking-wider text-white uppercase flex items-center gap-2">
              <span>GLOBAL ATTACK MATRIX & HOTSPOTS</span>
              <span className="text-[10px] text-cyan-400 bg-cyan-950/70 border border-cyan-500/30 px-2 py-0.5 rounded font-mono">
                LIVE D3 SPATIAL
              </span>
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            {activeNodes.length} actively attacking sovereign territories targeting CloudDecept Core
          </p>
        </div>

        {/* Map Controls */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowArcs(!showArcs)}
            className={cn(
              'px-2.5 py-1 text-xs font-mono font-semibold rounded-lg border transition-all flex items-center gap-1.5',
              showArcs
                ? 'bg-cyan-500/20 text-cyan-300 border-cyan-400/40 shadow-sm shadow-cyan-500/20'
                : 'bg-slate-900/60 text-slate-400 border-slate-700/60 hover:text-slate-200'
            )}
            title="Toggle attack trajectories"
          >
            <Radio className="w-3.5 h-3.5 text-cyan-400" />
            Attack Arcs
          </button>

          <button
            onClick={() => setShowHotspots(!showHotspots)}
            className={cn(
              'px-2.5 py-1 text-xs font-mono font-semibold rounded-lg border transition-all flex items-center gap-1.5',
              showHotspots
                ? 'bg-amber-500/20 text-amber-300 border-amber-400/40 shadow-sm shadow-amber-500/20'
                : 'bg-slate-900/60 text-slate-400 border-slate-700/60 hover:text-slate-200'
            )}
            title="Toggle beacon hotspots"
          >
            <Crosshair className="w-3.5 h-3.5 text-amber-400" />
            Hotspots
          </button>

          <button
            onClick={() => setIsFullscreen(!isFullscreen)}
            className="p-1.5 rounded-lg text-slate-400 hover:text-cyan-300 bg-slate-900/60 border border-slate-700/60 transition-colors"
            title={isFullscreen ? 'Exit full canvas' : 'Expand full canvas'}
          >
            {isFullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Main SVG Visualization Canvas */}
      <div className="relative w-full overflow-hidden my-2 flex items-center justify-center">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="w-full h-auto max-h-[580px] drop-shadow-2xl select-none"
          preserveAspectRatio="xMidYMid meet"
        >
          <defs>
            {/* Core Glow Filter */}
            <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur in="SourceGraphic" stdDeviation="4" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>

            {/* Intense Beam Glow */}
            <filter id="beam-glow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur in="SourceGraphic" stdDeviation="6" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>

            {/* Arc Linear Gradient */}
            <linearGradient id="arc-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.8" />
              <stop offset="50%" stopColor="#38bdf8" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#f59e0b" stopOpacity="0.9" />
            </linearGradient>

            <linearGradient id="honeypot-pulse" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#fbbf24" />
              <stop offset="100%" stopColor="#10b981" />
            </linearGradient>
          </defs>

          {/* Earth Boundary Graticule Lines */}
          <path
            d={graticulePath}
            fill="none"
            stroke="rgba(6, 182, 212, 0.07)"
            strokeWidth="0.5"
            strokeDasharray="2 3"
          />

          {/* Sovereign Country Polygons */}
          <g className="countries-layer">
            {worldFeatures.map((featureItem: any, idx: number) => {
              const numId = String(featureItem.id);
              const alpha2 = NUMERIC_TO_ALPHA2[numId] || '';
              const attackCount = countryStatsMap.get(alpha2) || 0;
              const hasAttacks = attackCount > 0;
              const isSelected = selectedCountry === alpha2;
              const pathD = geoPath(featureItem);

              if (!pathD) return null;

              // Compute activity heatmap fill
              let fillColor = '#070f22'; // Base calm deep ocean/land
              let strokeColor = 'rgba(6, 182, 212, 0.18)';
              let strokeWidth = 0.6;

              if (hasAttacks) {
                const ratio = attackCount / maxCount;
                if (ratio > 0.5) {
                  fillColor = 'rgba(239, 68, 68, 0.28)';
                  strokeColor = 'rgba(239, 68, 68, 0.7)';
                  strokeWidth = 1.0;
                } else if (ratio > 0.15) {
                  fillColor = 'rgba(249, 115, 22, 0.22)';
                  strokeColor = 'rgba(249, 115, 22, 0.6)';
                  strokeWidth = 0.9;
                } else if (ratio > 0.03) {
                  fillColor = 'rgba(245, 158, 11, 0.18)';
                  strokeColor = 'rgba(245, 158, 11, 0.5)';
                } else {
                  fillColor = 'rgba(16, 185, 129, 0.15)';
                  strokeColor = 'rgba(16, 185, 129, 0.45)';
                }
              }

              if (isSelected) {
                fillColor = 'rgba(6, 182, 212, 0.35)';
                strokeColor = '#22d3ee';
                strokeWidth = 1.6;
              }

              return (
                <path
                  key={featureItem.id || idx}
                  d={pathD}
                  fill={fillColor}
                  stroke={strokeColor}
                  strokeWidth={strokeWidth}
                  className="cursor-pointer transition-all duration-200 hover:fill-cyan-500/30 hover:stroke-cyan-300"
                  onMouseEnter={(e) => alpha2 && handleCountryHover(alpha2, e)}
                  onMouseLeave={() => setHoveredCountry(null)}
                  onClick={() => alpha2 && handleCountryClick(alpha2)}
                />
              );
            })}
          </g>

          {/* Animated Flow Arcs from Top Attackers -> CloudDecept Honeypot */}
          {showArcs && (
            <g className="arcs-layer pointer-events-none">
              {activeNodes.slice(0, 16).map((node, i) => (
                <g key={`arc-${node.code}-${i}`}>
                  {/* Subtle static guide arc */}
                  <path
                    d={node.arcPath}
                    fill="none"
                    stroke="rgba(6, 182, 212, 0.2)"
                    strokeWidth="1"
                    strokeDasharray="3 3"
                  />
                  {/* Glowing moving trajectory beam */}
                  <path
                    d={node.arcPath}
                    fill="none"
                    stroke="url(#arc-gradient)"
                    strokeWidth={Math.max(1.2, Math.min(2.8, (node.count / maxCount) * 3))}
                    strokeDasharray="12 180"
                    className="animate-flow"
                    style={{ animationDuration: `${2.5 + (i % 3) * 0.8}s` }}
                    filter="url(#glow)"
                  />
                </g>
              ))}
            </g>
          )}

          {/* Glowing Attacker Hotspot Nodes */}
          {showHotspots && (
            <g className="hotspots-layer">
              {activeNodes.map((node) => {
                const [cx, cy] = node.xy;
                const radius = Math.max(3.5, Math.min(10, Math.log10(node.count + 1) * 2.8));
                const isSelected = selectedCountry === node.code;

                return (
                  <g
                    key={`node-${node.code}`}
                    className="cursor-pointer group"
                    onClick={() => handleCountryClick(node.code)}
                  >
                    {/* Outer animated halo ring */}
                    <circle
                      cx={cx}
                      cy={cy}
                      r={radius * 2}
                      fill="none"
                      stroke={node.count > 1000 ? '#ef4444' : '#06b6d4'}
                      strokeWidth="1"
                      opacity="0.4"
                      className="animate-ping"
                      style={{ animationDuration: '3s' }}
                    />
                    {/* Inner glowing node */}
                    <circle
                      cx={cx}
                      cy={cy}
                      r={radius}
                      fill={node.count > 1000 ? '#f43f5e' : '#06b6d4'}
                      stroke="#ffffff"
                      strokeWidth="1.2"
                      filter="url(#glow)"
                      className="transition-transform group-hover:scale-125"
                    />
                    {/* Country Code Tag */}
                    <text
                      x={cx}
                      y={cy - radius - 4}
                      fill="#e2e8f0"
                      fontSize="9"
                      fontWeight="bold"
                      fontFamily="monospace"
                      textAnchor="middle"
                      className="pointer-events-none drop-shadow-md"
                    >
                      {node.code}
                    </text>
                  </g>
                );
              })}
            </g>
          )}

          {/* Central CloudDecept Target Honeypot Core */}
          <g className="honeypot-target">
            <circle
              cx={honeypotXY[0]}
              cy={honeypotXY[1]}
              r="22"
              fill="none"
              stroke="#fbbf24"
              strokeWidth="1.5"
              strokeDasharray="4 4"
              className="animate-spin-slow origin-center"
              opacity="0.6"
            />
            <circle
              cx={honeypotXY[0]}
              cy={honeypotXY[1]}
              r="12"
              fill="rgba(251, 191, 36, 0.15)"
              stroke="#fbbf24"
              strokeWidth="2"
              filter="url(#beam-glow)"
            />
            <circle
              cx={honeypotXY[0]}
              cy={honeypotXY[1]}
              r="4.5"
              fill="#fbbf24"
              stroke="#ffffff"
              strokeWidth="1.5"
            />
            <text
              x={honeypotXY[0]}
              y={honeypotXY[1] + 20}
              fill="#fbbf24"
              fontSize="9"
              fontWeight="bold"
              fontFamily="monospace"
              textAnchor="middle"
              className="drop-shadow-lg"
            >
              CLOUDDECEPT CORE
            </text>
          </g>
        </svg>

        {/* Floating Contextual Glass Tooltip */}
        {hoveredCountry && (
          <div
            className="absolute pointer-events-none z-30 transition-all duration-150"
            style={{
              left: Math.min(Math.max(hoveredCountry.x, 20), (mapContainerRef.current?.clientWidth || width) - 260),
              top: Math.max(hoveredCountry.y - 140, 20),
            }}
          >
            <div className="glass-panel p-3.5 rounded-xl border border-cyan-400/40 shadow-2xl min-w-[240px] text-xs font-mono">
              <div className="flex items-center justify-between border-b border-cyan-500/20 pb-2 mb-2">
                <span className="font-bold text-white tracking-wider flex items-center gap-1.5 text-sm">
                  <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                  {hoveredCountry.name}
                </span>
                <span className="text-[10px] text-cyan-300 px-1.5 py-0.5 rounded bg-cyan-950 border border-cyan-500/30">
                  {hoveredCountry.code}
                </span>
              </div>

              <div className="space-y-1.5 text-[11px]">
                <div className="flex justify-between">
                  <span className="text-slate-400">Captured Sessions:</span>
                  <span className="font-bold text-white font-mono">
                    {hoveredCountry.count.toLocaleString()}
                  </span>
                </div>

                <div className="flex justify-between">
                  <span className="text-slate-400">Global Threat Share:</span>
                  <span className="font-semibold text-cyan-300">
                    {hoveredCountry.share.toFixed(1)}%
                  </span>
                </div>

                <div className="flex justify-between">
                  <span className="text-slate-400">Threat Assessment:</span>
                  <span
                    className={cn(
                      'font-bold uppercase text-[10px]',
                      hoveredCountry.count >= 5000
                        ? 'text-rose-400'
                        : hoveredCountry.count >= 1000
                        ? 'text-orange-400'
                        : hoveredCountry.count >= 200
                        ? 'text-amber-400'
                        : 'text-emerald-400'
                    )}
                  >
                    {hoveredCountry.count >= 5000
                      ? 'Critical Hotspot'
                      : hoveredCountry.count >= 1000
                      ? 'High Intensity'
                      : hoveredCountry.count >= 200
                      ? 'Moderate Surface'
                      : 'Low Activity Probe'}
                  </span>
                </div>

                <div className="pt-1.5 border-t border-cyan-500/10 flex justify-between text-[10px] text-slate-500">
                  <span>Target:</span>
                  <span className="text-amber-300/90 font-mono">Honeypot Core (us-east-1)</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Bottom Hotspot Territory Strip */}
      <div className="relative z-10 pt-3 border-t border-cyan-500/15">
        <div className="flex items-center justify-between mb-2">
          <span className="text-[11px] font-mono font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5 text-amber-400" />
            TOP ATTACK ORIGIN HOTSPOTS
          </span>
          <span className="text-[10px] font-mono text-cyan-400/80">
            {sortedData.length} countries aggregated
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
          {sortedData.slice(0, 6).map((item) => {
            if (!item || !item.country || typeof item.country !== 'string') return null;
            const code = item.country.toUpperCase();
            const share = totalSessions > 0 ? (item.count / totalSessions) * 100 : 0;
            const isSelected = selectedCountry === code;

            return (
              <button
                key={code}
                onClick={() => handleCountryClick(code)}
                className={cn(
                  'p-2 rounded-lg border text-left transition-all font-mono',
                  isSelected
                    ? 'bg-cyan-950/80 border-cyan-400 shadow-md shadow-cyan-900/40'
                    : 'bg-[#070e22]/70 border-cyan-500/15 hover:border-cyan-500/40 hover:bg-[#070e22]'
                )}
              >
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold text-slate-200 truncate">{getCountryName(code)}</span>
                  <span className="text-[10px] text-cyan-400">{code}</span>
                </div>
                <div className="flex items-baseline justify-between mt-1">
                  <span className="text-sm font-bold text-white">{item.count.toLocaleString()}</span>
                  <span className="text-[10px] text-slate-400">{share.toFixed(1)}%</span>
                </div>
                {/* Micro Progress Track */}
                <div className="w-full h-1 bg-slate-800 rounded-full mt-1.5 overflow-hidden">
                  <div
                    className={cn(
                      'h-full rounded-full',
                      item.count >= 5000
                        ? 'bg-rose-500'
                        : item.count >= 1000
                        ? 'bg-orange-500'
                        : item.count >= 200
                        ? 'bg-amber-500'
                        : 'bg-cyan-400'
                    )}
                    style={{ width: `${Math.min(100, Math.max(5, share))}%` }}
                  />
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
