/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  output: 'standalone',
  async rewrites() {
    return [
      {
        source: '/api/backend/:path*',
        destination: `${process.env.NEXT_PUBLIC_BACKEND_URL || process.env.BACKEND_URL || 'http://backend-api:8004'}/:path*`,
      },
      {
        source: '/api/collector/:path*',
        destination: `${process.env.NEXT_PUBLIC_COLLECTOR_URL || process.env.COLLECTOR_URL || 'http://event-collector:8000'}/:path*`,
      },
      {
        source: '/api/threat-intel/:path*',
        destination: `${process.env.NEXT_PUBLIC_THREAT_INTEL_URL || process.env.THREAT_INTEL_URL || 'http://threat-intel:8005'}/:path*`,
      },
      {
        source: '/api/adaptive/:path*',
        destination: `${process.env.NEXT_PUBLIC_ADAPTIVE_URL || process.env.ADAPTIVE_URL || 'http://adaptive-engine:8002'}/:path*`,
      },
      {
        source: '/api/intent/:path*',
        destination: `${process.env.NEXT_PUBLIC_INTENT_URL || process.env.INTENT_URL || 'http://intent-engine:8001'}/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;