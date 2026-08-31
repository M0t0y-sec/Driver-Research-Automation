import { Link } from 'react-router-dom'
import { Copy } from 'lucide-react'
import { useState } from 'react'
import { cn } from '@/lib/utils'
import { idPath } from '@/lib/idPath'
import { toast } from '@/components/common/Toaster'

export function IdLink({
  id,
  className,
  label,
}: {
  id: string
  className?: string
  label?: string
}) {
  return (
    <Link
      to={idPath(id)}
      className={cn(
        'font-mono text-xs text-primary underline-offset-2 hover:underline',
        className,
      )}
    >
      {label ?? id}
    </Link>
  )
}

export function CopyableText({ value, className }: { value: string; className?: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      className={cn(
        'group inline-flex max-w-full items-center gap-1.5 text-left font-mono text-xs text-muted-foreground hover:text-foreground',
        className,
      )}
      title="Copy"
      onClick={() => {
        navigator.clipboard?.writeText(value).catch(() => undefined)
        setCopied(true)
        toast('Copied to clipboard')
        setTimeout(() => setCopied(false), 1200)
      }}
    >
      <span className="truncate">{value}</span>
      <Copy className={cn('h-3 w-3 shrink-0 opacity-0 transition-opacity group-hover:opacity-60', copied && 'opacity-100')} />
    </button>
  )
}
