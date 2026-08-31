import { Link } from 'react-router-dom'
import { metaFor } from './lineageMeta'
import { idPath, idShort } from '@/lib/idPath'
import { cn } from '@/lib/utils'
import type { LineageNode } from '@/types'

export function LineageNodeChip({ node, className }: { node: LineageNode; className?: string }) {
  const meta = metaFor(node.type)
  return (
    <Link
      to={idPath(node.id)}
      className={cn(
        'group inline-flex max-w-full items-center gap-2 rounded-md border border-white/5 bg-white/[0.03] px-2.5 py-1.5 transition-colors hover:bg-white/[0.06]',
        meta.ring,
        className,
      )}
    >
      <span className={cn('h-1.5 w-1.5 rounded-full', meta.dot)} />
      <span className={cn('text-[10px] font-semibold uppercase tracking-wider', meta.color)}>
        {meta.label}
      </span>
      <span className="font-mono text-[11px] text-foreground/80 group-hover:text-foreground">
        {idShort(node.id)}
      </span>
      {node.label && (
        <span className="max-w-[14rem] truncate text-[11px] text-muted-foreground" title={node.label}>
          {node.label}
        </span>
      )}
    </Link>
  )
}

export function LineageList({ nodes, className }: { nodes: LineageNode[]; className?: string }) {
  if (nodes.length === 0) {
    return <span className="text-xs text-muted-foreground">no nodes</span>
  }
  return (
    <div className={cn('flex flex-wrap gap-1.5', className)}>
      {nodes.map((n) => (
        <LineageNodeChip key={n.id} node={n} />
      ))}
    </div>
  )
}
