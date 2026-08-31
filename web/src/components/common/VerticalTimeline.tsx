import { cn } from '@/lib/utils'
import { CheckCircle2, CircleDashed, Loader2, CircleX, CirclePause } from 'lucide-react'
import type { ReactNode } from 'react'

export type TimelineState = 'pending' | 'active' | 'completed' | 'failed' | 'skipped' | 'paused'

const nodeStatusIcon: Record<TimelineState, ReactNode> = {
  pending: <CircleDashed className="h-3.5 w-3.5 text-muted-foreground/50" />,
  active: <Loader2 className="h-3.5 w-3.5 animate-spin text-info" />,
  completed: <CheckCircle2 className="h-3.5 w-3.5 text-success" />,
  failed: <CircleX className="h-3.5 w-3.5 text-danger" />,
  skipped: <CircleDashed className="h-3.5 w-3.5 text-muted-foreground/40" />,
  paused: <CirclePause className="h-3.5 w-3.5 text-warning" />,
}

export interface TimelineItem {
  key: string
  label: ReactNode
  detail?: ReactNode
  status: TimelineState
  time?: string | null
  end?: string | null
}

export function VerticalTimeline({ items, className }: { items: TimelineItem[]; className?: string }) {
  return (
    <ol className={cn('relative space-y-0', className)}>
      {items.map((item, i) => {
        const isLast = i === items.length - 1
        return (
          <li key={item.key} className="relative flex gap-3 pb-5 pl-0">
            {!isLast && <span className="absolute left-[7px] top-5 h-full w-px bg-border" aria-hidden />}
            <span className="relative z-10 mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center bg-card">
              {nodeStatusIcon[item.status]}
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <span
                  className={cn(
                    'text-xs font-medium',
                    item.status === 'pending' ? 'text-muted-foreground/70' : 'text-foreground',
                  )}
                >
                  {item.label}
                </span>
                {item.time && (
                  <span className="font-mono text-[10px] text-muted-foreground">
                    {item.time}
                    {item.end ? ` → ${item.end}` : item.status === 'active' ? ' → …' : ''}
                  </span>
                )}
              </div>
              {item.detail && (
                <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{item.detail}</p>
              )}
            </div>
          </li>
        )
      })}
    </ol>
  )
}
