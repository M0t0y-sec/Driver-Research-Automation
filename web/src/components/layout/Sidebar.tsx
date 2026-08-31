import { NavLink, Link } from 'react-router-dom'
import {
  Activity,
  Boxes,
  Bug,
  CheckCircle2,
  ChevronLeft,
  Cpu,
  FlaskConical,
  Gauge,
  Lightbulb,
  ListChecks,
  Microscope,
  MonitorSmartphone,
  Network,
  Search,
  Settings,
  ShieldCheck,
  Stamp,
  Target,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useUiStore } from '@/stores/uiStore'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'

interface NavItem {
  to: string
  label: string
  icon: React.ElementType
}

interface NavSection {
  title: string
  items: NavItem[]
}

const sections: NavSection[] = [
  {
    title: 'Overview',
    items: [{ to: '/dashboard', label: 'Dashboard', icon: Gauge }],
  },
  {
    title: 'Research',
    items: [
      { to: '/projects', label: 'Projects', icon: Boxes },
      { to: '/targets', label: 'Targets', icon: Target },
      { to: '/research/runs', label: 'Research Runs', icon: Activity },
      { to: '/hypotheses', label: 'Hypotheses', icon: Lightbulb },
      { to: '/experiments', label: 'Experiments', icon: FlaskConical },
      { to: '/findings', label: 'Findings', icon: Bug },
    ],
  },
  {
    title: 'Analysis',
    items: [
      { to: '/evidence', label: 'Evidence', icon: Microscope },
      { to: '/detection', label: 'Detection Evaluation', icon: ShieldCheck },
    ],
  },
  {
    title: 'Governance',
    items: [
      { to: '/approvals', label: 'Approval Center', icon: Stamp },
      { to: '/qa', label: 'QA Center', icon: CheckCircle2 },
    ],
  },
  {
    title: 'Lab',
    items: [{ to: '/lab', label: 'Windows Lab', icon: MonitorSmartphone }],
  },
  {
    title: 'AI System',
    items: [
      { to: '/agents', label: 'Agents', icon: Cpu },
      { to: '/agents/tools', label: 'Tools', icon: Network },
    ],
  },
  {
    title: 'System',
    items: [{ to: '/settings', label: 'Settings', icon: Settings }],
  },
]

function SidebarLink({ item, collapsed }: { item: NavItem; collapsed: boolean }) {
  const Icon = item.icon
  const link = (
    <NavLink
      to={item.to}
      className={({ isActive }) =>
        cn(
          'flex items-center gap-2.5 rounded-xl px-3 py-2 text-[13px] font-medium text-muted-foreground transition-all duration-200',
          'hover:bg-white/[0.06] hover:text-foreground',
          isActive && 'bg-white/[0.08] text-foreground shadow-sm ring-1 ring-white/10',
          collapsed && 'justify-center px-0',
        )
      }
      title={collapsed ? item.label : undefined}
    >
      <Icon className="h-4 w-4 shrink-0" />
      {!collapsed && <span className="truncate">{item.label}</span>}
    </NavLink>
  )
  if (!collapsed) return link
  return (
    <Tooltip delayDuration={0}>
      <TooltipTrigger asChild>{link}</TooltipTrigger>
      <TooltipContent side="right">{item.label}</TooltipContent>
    </Tooltip>
  )
}

export function Sidebar() {
  const { sidebarCollapsed, toggleSidebar, setCommandPaletteOpen } = useUiStore()

  return (
    <aside
      className={cn(
        'glass relative z-20 flex shrink-0 flex-col border-r border-white/5 transition-[width] duration-300 ease-out',
        sidebarCollapsed ? 'w-[72px]' : 'w-[260px]',
      )}
    >
      {/* Brand */}
      <Link to="/dashboard" className="flex h-16 items-center gap-3 border-b border-white/5 px-4">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-primary/30 to-primary/10 shadow-inner ring-1 ring-white/10">
          <ListChecks className="h-4 w-4 text-primary" />
        </div>
        {!sidebarCollapsed && (
          <div className="leading-tight">
            <div className="text-sm font-bold tracking-tight">DRA</div>
            <div className="text-[10px] font-medium text-muted-foreground">
              Driver Research Automation
            </div>
          </div>
        )}
      </Link>

      {/* Search trigger */}
      <div className={cn('border-b border-white/5 p-3', sidebarCollapsed && 'px-3')}>
        <button
          onClick={() => setCommandPaletteOpen(true)}
          className={cn(
            'flex h-9 w-full items-center gap-2 rounded-xl border border-white/5 bg-white/[0.03] px-3 text-xs text-muted-foreground transition-all hover:border-white/10 hover:bg-white/[0.06] hover:text-foreground',
            sidebarCollapsed && 'justify-center px-0',
          )}
          title="Search (Ctrl+K)"
        >
          <Search className="h-3.5 w-3.5 shrink-0" />
          {!sidebarCollapsed && (
            <>
              <span>Search…</span>
              <kbd className="ml-auto rounded border bg-secondary px-1 font-mono text-[9px]">Ctrl K</kbd>
            </>
          )}
        </button>
      </div>

      {/* Nav */}
      <nav className="flex-1 space-y-4 overflow-y-auto p-3">
        {sections.map((section) => (
          <div key={section.title}>
            {!sidebarCollapsed && (
              <div className="mb-1.5 px-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/40">
                {section.title}
              </div>
            )}
            <div className="space-y-0.5">
              {section.items.map((item) => (
                <SidebarLink key={item.to} item={item} collapsed={sidebarCollapsed} />
              ))}
            </div>
          </div>
        ))}
      </nav>

      {/* Collapse toggle */}
      <div className="border-t border-white/5 p-3">
        <Button
          variant="ghost"
          size="sm"
          className={cn('w-full text-muted-foreground', sidebarCollapsed && 'px-0')}
          onClick={toggleSidebar}
        >
          <ChevronLeft className={cn('h-4 w-4 transition-transform', sidebarCollapsed && 'rotate-180')} />
          {!sidebarCollapsed && <span>Collapse</span>}
        </Button>
      </div>
    </aside>
  )
}
