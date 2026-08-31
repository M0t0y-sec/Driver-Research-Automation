import { useEffect } from 'react'
import { Link } from 'react-router-dom'
import { Bell, Search, User } from 'lucide-react'
import { useResearchList } from '@/hooks/queries'
import { RunStatusBadge } from '@/components/common/StatusBadge'
import { Button } from '@/components/ui/button'

function RunStatusBar() {
  const { data: runs } = useResearchList()
  if (!runs || runs.length === 0) return null
  const active = runs.filter((r) => r.status === 'running' || r.status === 'paused' || r.status === 'waiting_approval').slice(0, 3)
  if (active.length === 0) return null
  return (
    <div className="hidden items-center gap-3 lg:flex">
      <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
        Active runs
      </span>
      <div className="h-4 w-px bg-white/10" />
      {active.map((run) => (
        <Link
          key={run.research_id}
          to={`/research/runs/${run.research_id}`}
          className="flex items-center gap-1.5 rounded-lg px-2 py-1 transition-colors hover:bg-white/[0.06]"
        >
          <span className="font-mono text-[10px] text-muted-foreground">{run.research_id}</span>
          <RunStatusBadge status={run.status} spin={run.status === 'running'} />
        </Link>
      ))}
    </div>
  )
}

export function Header() {
  return (
    <header className="glass relative z-20 flex h-16 shrink-0 items-center gap-4 border-b border-white/5 px-5">
      <RunStatusBar />

      <div className="ml-auto flex items-center gap-1">
        <Button
          variant="ghost"
          size="sm"
          className="gap-2 rounded-xl text-muted-foreground hover:bg-white/[0.06]"
          onClick={() => {
            // Cmd+K handler is bound globally; clicking the chip is a no-op in Phase 0/1.
          }}
        >
          <Search className="h-4 w-4" />
          <span className="hidden md:inline">Search</span>
        </Button>
        <Button variant="ghost" size="icon" title="Notifications (Phase 0/1 stub)">
          <Bell className="h-4 w-4" />
        </Button>
        <div className="mx-2 h-5 w-px bg-white/10" />
        <button className="flex items-center gap-2 rounded-xl px-2 py-1.5 transition-colors hover:bg-white/[0.06]">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-gradient-to-br from-primary/20 to-primary/5 ring-1 ring-white/10">
            <User className="h-4 w-4 text-primary" />
          </div>
          <span className="hidden text-xs font-medium md:inline">researcher@dra</span>
        </button>
      </div>
    </header>
  )
}
