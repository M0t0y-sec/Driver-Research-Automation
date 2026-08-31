import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'
import { ArrowLeft } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { Button } from '@/components/ui/button'

export function PageHeader({
  title,
  subtitle,
  actions,
  backButton,
  className,
}: {
  title: ReactNode
  subtitle?: ReactNode
  actions?: ReactNode
  backButton?: boolean
  className?: string
}) {
  const navigate = useNavigate()
  return (
    <div className={cn('flex flex-wrap items-start justify-between gap-3', className)}>
      <div className="flex items-start gap-3">
        {backButton && (
          <Button variant="ghost" size="icon" onClick={() => navigate(-1)} aria-label="Back">
            <ArrowLeft className="h-4 w-4" />
          </Button>
        )}
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
          {subtitle && <p className="mt-1 text-sm text-muted-foreground">{subtitle}</p>}
        </div>
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  )
}
