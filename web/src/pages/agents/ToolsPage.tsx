import { useToolRuns, useProjects } from '@/hooks/queries'
import { PageHeader } from '@/components/common/PageHeader'
import { DataTable, type Column } from '@/components/common/DataTable'
import { LoadingView, ErrorView } from '@/components/common/StateViews'
import { ToolRunStatusBadge, RiskBadge } from '@/components/common/StatusBadge'
import { IdLink, CopyableText } from '@/components/common/IdLink'
import { formatRelative } from '@/lib/utils'
import { useState } from 'react'
import type { ToolRun } from '@/types'

export default function ToolsPage() {
  const projects = useProjects()
  const [filter, setFilter] = useState<string>('')
  const runs = useToolRuns(filter || undefined)

  if (runs.isLoading) return <LoadingView />
  if (runs.isError) return <ErrorView onRetry={() => runs.refetch()} />

  const columns: Column<ToolRun>[] = [
    { key: 'id', header: 'ID', render: (r) => <IdLink id={r.id} />, sortValue: (r) => r.id },
    { key: 'tool', header: 'Tool', render: (r) => <span className="font-mono text-xs">{r.tool}</span>, sortValue: (r) => r.tool },
    { key: 'risk', header: 'Risk', render: (r) => <RiskBadge risk={r.risk_level} />, sortValue: (r) => r.risk_level },
    { key: 'status', header: 'Status', render: (r) => <ToolRunStatusBadge status={r.status} />, sortValue: (r) => r.status },
    { key: 'project', header: 'Project', render: (r) => <IdLink id={r.project_id} />, sortValue: (r) => r.project_id },
    { key: 'params', header: 'Parameters', render: (r) => <CopyableText value={JSON.stringify(r.parameters).slice(0, 80) + '…'} className="max-w-md" /> },
    { key: 'when', header: 'Created', render: (r) => <span className="text-xs text-muted-foreground">{formatRelative(r.created_at)}</span>, sortValue: (r) => new Date(r.created_at).getTime() },
  ]

  return (
    <div className="space-y-4">
      <PageHeader
        title="Tool Runs"
        subtitle="Every Tool Gateway invocation, with status and parameters."
        actions={
          <select
            className="rounded-md border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          >
            <option value="">All projects</option>
            {(projects.data ?? []).map((p) => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
        }
      />
      <DataTable
        data={runs.data ?? []}
        columns={columns}
        initialSortKey="when"
        emptyMessage="No tool runs yet."
      />
    </div>
  )
}
