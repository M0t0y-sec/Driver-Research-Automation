import { Skeleton } from '@/components/ui/skeleton'
import { Button } from '@/components/ui/button'
import { AlertTriangle, Inbox, RefreshCw } from 'lucide-react'
import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

// ---------------------------------------------------------------------------
// Reusable async-state views: Loading / Error / Empty.
// Every data page composes these instead of hand-rolling states.
// ---------------------------------------------------------------------------

export function LoadingView({ rows = 5, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn('space-y-2', className)} aria-busy="true" aria-label="Loading">
      <Skeleton className="h-8 w-64" />
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-12 w-full" />
      ))}
    </div>
  )
}

export function CardGridSkeleton({ count = 8 }: { count?: number }) {
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-busy="true">
      {Array.from({ length: count }).map((_, i) => (
        <Skeleton key={i} className="h-32 w-full" />
      ))}
    </div>
  )
}

export function ErrorView({
  title = 'Failed to load',
  message,
  onRetry,
}: {
  title?: string
  message?: string
  onRetry?: () => void
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-danger/30 bg-danger/5 px-6 py-14 text-center">
      <AlertTriangle className="h-8 w-8 text-danger" />
      <h3 className="mt-3 text-sm font-semibold">{title}</h3>
      <p className="mt-1 max-w-md text-xs text-muted-foreground">
        {message ?? 'The request failed or the resource does not exist. It may have been archived.'}
      </p>
      {onRetry && (
        <Button variant="outline" size="sm" className="mt-4" onClick={onRetry}>
          <RefreshCw className="h-3.5 w-3.5" /> Retry
        </Button>
      )}
    </div>
  )
}

export function EmptyView({
  title = 'Nothing here yet',
  message,
  action,
}: {
  title?: string
  message?: string
  action?: ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed px-6 py-14 text-center">
      <Inbox className="h-8 w-8 text-muted-foreground/50" />
      <h3 className="mt-3 text-sm font-semibold text-muted-foreground">{title}</h3>
      <p className="mt-1 max-w-md text-xs text-muted-foreground/80">
        {message ?? 'No items match the current filters.'}
      </p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}
