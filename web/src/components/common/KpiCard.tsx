import type { ReactNode } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { cn } from '@/lib/utils'
import { TrendingDown, TrendingUp } from 'lucide-react'

export function KpiCard({
  label,
  value,
  sub,
  trend,
  icon,
  onClick,
}: {
  label: string
  value: ReactNode
  sub?: ReactNode
  trend?: number
  icon?: ReactNode
  onClick?: () => void
}) {
  return (
    <Card
      className={cn(
        'glass-interactive',
        onClick && 'cursor-pointer',
      )}
      onClick={onClick}
    >
      <CardContent className="p-5">
        <div className="flex items-start justify-between">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
            {label}
          </span>
          {icon && (
            <span className="flex h-8 w-8 items-center justify-center rounded-xl bg-white/[0.04] text-muted-foreground/80">
              {icon}
            </span>
          )}
        </div>
        <div className="mt-3 font-mono text-3xl font-semibold tabular-nums tracking-tight">
          {value}
        </div>
        <div className="mt-1 flex items-center gap-2 text-xs text-muted-foreground">
          {typeof trend === 'number' && (
            <span
              className={cn(
                'inline-flex items-center gap-0.5 font-mono',
                trend >= 0 ? 'text-success' : 'text-danger',
              )}
            >
              {trend >= 0 ? <TrendingUp className="h-3 w-3" /> : <TrendingDown className="h-3 w-3" />}
              {trend >= 0 ? '↑' : '↓'} {Math.abs(trend)}%
            </span>
          )}
          {sub}
        </div>
      </CardContent>
    </Card>
  )
}

export function MetricRow({
  label,
  value,
  mono = true,
}: {
  label: string
  value: ReactNode
  mono?: boolean
}) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-border/50 py-2 last:border-0">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className={cn('text-xs', mono && 'font-mono')}>{value}</span>
    </div>
  )
}

export function SectionCard({
  title,
  description,
  actions,
  children,
  className,
  contentClassName,
}: {
  title: ReactNode
  description?: ReactNode
  actions?: ReactNode
  children: ReactNode
  className?: string
  contentClassName?: string
}) {
  return (
    <Card className={className}>
      <div className="flex items-start justify-between gap-3 border-b border-white/5 px-5 py-4">
        <div>
          <h3 className="text-sm font-semibold tracking-tight">{title}</h3>
          {description && <p className="mt-0.5 text-xs text-muted-foreground">{description}</p>}
        </div>
        {actions}
      </div>
      <div className={cn('p-5', contentClassName)}>{children}</div>
    </Card>
  )
}
