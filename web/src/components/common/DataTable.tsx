import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'
import { ArrowDown, ArrowUp, ChevronsUpDown } from 'lucide-react'
import { useMemo, useState } from 'react'
import { EmptyView } from './StateViews'

// ---------------------------------------------------------------------------
// Generic sortable data table. Columns declare how to sort (key + accessor)
// so every list page stays declarative.
// ---------------------------------------------------------------------------

export interface Column<T> {
  key: string
  header: ReactNode
  render: (row: T) => ReactNode
  sortValue?: (row: T) => string | number
  className?: string
  align?: 'left' | 'right' | 'center'
}

// `id` is the canonical primary key; we accept either a string `id` or
// a record with a `key`-style id so call-sites stay flexible.
type IdKey<T> = T extends { id: infer R } ? R : T extends { key: infer R } ? R : string

export function DataTable<T>({
  data,
  columns,
  initialSortKey,
  onRowClick,
  emptyMessage,
}: {
  data: T[]
  columns: Column<T>[]
  initialSortKey?: string
  onRowClick?: (row: T) => void
  emptyMessage?: string
}) {
  const [sortKey, setSortKey] = useState<string | undefined>(initialSortKey)
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')

  const sorted = useMemo(() => {
    if (!sortKey) return data
    const col = columns.find((c) => c.key === sortKey)
    if (!col?.sortValue) return data
    const arr = [...data]
    arr.sort((a, b) => {
      const av = col.sortValue!(a)
      const bv = col.sortValue!(b)
      if (av < bv) return sortDir === 'asc' ? -1 : 1
      if (av > bv) return sortDir === 'asc' ? 1 : -1
      return 0
    })
    return arr
  }, [data, sortKey, sortDir, columns])

  const toggleSort = (key: string) => {
    const col = columns.find((c) => c.key === key)
    if (!col?.sortValue) return
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortKey(key)
      setSortDir('desc')
    }
  }

  // Pick a stable id per row from any string field ending with `_id`,
  // or fall back to the row's index. This is the only place we touch
  // the `key` prop on <tr>.
  const rowKey = (row: T, i: number): string => {
    const r = row as unknown as Record<string, unknown>
    for (const k of Object.keys(r)) {
      if (k === 'id' && typeof r[k] === 'string') return r[k] as string
    }
    return String(i)
  }

  if (data.length === 0) {
    return <EmptyView message={emptyMessage} />
  }

  return (
    <div className="overflow-x-auto rounded-lg border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b bg-secondary/40 text-left">
            {columns.map((col) => (
              <th
                key={col.key}
                className={cn(
                  'px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground',
                  col.align === 'right' && 'text-right',
                  col.align === 'center' && 'text-center',
                  col.sortValue && 'cursor-pointer select-none hover:text-foreground',
                )}
                onClick={() => toggleSort(col.key)}
              >
                <span className={cn('inline-flex items-center gap-1', col.align === 'right' && 'flex-row-reverse')}>
                  {col.header}
                  {col.sortValue && (
                    sortKey === col.key ? (
                      sortDir === 'asc' ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" />
                    ) : (
                      <ChevronsUpDown className="h-3 w-3 opacity-40" />
                    )
                  )}
                </span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row, i) => (
            <tr
              key={rowKey(row, i)}
              className={cn(
                'border-b border-border/60 transition-colors last:border-0',
                onRowClick && 'cursor-pointer hover:bg-accent/50',
              )}
              onClick={() => onRowClick?.(row)}
            >
              {columns.map((col) => (
                <td
                  key={col.key}
                  className={cn(
                    'px-3 py-2.5 align-middle',
                    col.align === 'right' && 'text-right',
                    col.align === 'center' && 'text-center',
                    col.className,
                  )}
                >
                  {col.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
