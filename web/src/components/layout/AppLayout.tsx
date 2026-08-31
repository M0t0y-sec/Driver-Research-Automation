import { useEffect } from 'react'
import { Outlet } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { Header } from './Header'
import { CommandPalette } from './CommandPalette'
import { TooltipProvider } from '@/components/ui/tooltip'
import { Toaster } from '@/components/common/Toaster'
import { useDashboard } from '@/hooks/queries'
import { useEffect as useReactEffect } from 'react'

export function AppLayout() {
  const dashboard = useDashboard()
  useEffect(() => {
    // Touch the dashboard query so it refreshes while the user is on the app.
  }, [dashboard.dataUpdatedAt])

  return (
    <TooltipProvider delayDuration={200}>
      <div className="dra-canvas flex h-screen overflow-hidden">
        <Sidebar />
        <div className="relative z-10 flex min-w-0 flex-1 flex-col">
          <Header />
          <main className="flex-1 overflow-y-auto">
            <div className="mx-auto max-w-[1600px] p-6 lg:p-8">
              <Outlet />
            </div>
          </main>
        </div>
      </div>
      <CommandPalette />
      <Toaster />
    </TooltipProvider>
  )
}
