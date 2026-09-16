import { Sidebar } from '@/components/Sidebar';
import { Header } from '@/components/Header';
import { SidebarProvider } from '@/lib/SidebarContext';
import '@/app/globals.css';

export const metadata = {
  title: 'CloudDecept | Autonomous Cloud Deception & Cyber Threat Command',
  description: 'Real-time honeypot attack surface telemetry, MITRE ATT&CK correlation, and adaptive deception command center.',
};

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-[#030712] text-slate-100 selection:bg-cyan-500/30 selection:text-cyan-200">
        <SidebarProvider>
          <Sidebar />
          <div className="flex flex-col min-h-screen lg:ml-64 transition-all duration-300" id="main-content">
            <Header />
            <main className="flex-1 pt-16 pb-10 px-4 sm:px-6 lg:px-8 max-w-[1920px] w-full mx-auto">
              {children}
            </main>
          </div>
        </SidebarProvider>
      </body>
    </html>
  );
}