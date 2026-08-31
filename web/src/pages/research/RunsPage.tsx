import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useResearchList, useProjects } from '@/hooks/queries'
import { PageHeader } from '@/components/common/PageHeader'
import { DataTable, type Column } from '@/components/common/DataTable'
import { RunStatusBadge } from '@/components/common/StatusBadge'
import { IdLink } from '@/components/common/IdLink'
import { LoadingView, ErrorView } from '@/components/common/StateViews'
import { formatRelative } from '@/lib/utils'
import type { ResearchRun } from '@/types'

export default function RunsPage() {
  const navigate = useNavigate()
  const projects = useProjects()
  const [projectFilter, setProjectFilter] = useState<string>('')
  const runs = useResearchList(projectFilter || undefined)

  if (runs.isLoading) return <LoadingView />
  if (runs.isError) return <ErrorView onRetry={() => runs.refetch()} />

  const columns: Column<ResearchRun>[] = [
    { key: 'id', header: 'Run', render: (r) => <IdLink id={r.research_id} />, sortValue: (r) => r.research_id },
    { key: 'project', header: 'Project', render: (r) => <IdLink id={r.project_id} />, sortValue: (r) => r.project_id },
    { key: 'target', header: 'Target', render: (r) => <IdLink id={r.target_id} />, sortValue: (r) => r.target_id },
    { key: 'phase', header: 'Phase', render: (r) => <span className="text-xs">{r.current_phase || '—'}</span>, sortValue: (r) => r.current_phase },
    { key: 'node', header: 'Node', render: (r) => <span className="text-xs text-muted-foreground">{r.current_node || '—'}</span>, sortValue: (r) => r.current_node },
    { key: 'findings', header: 'Findings', align: 'right', render: (r) => <span className="font-mono text-xs">{r.finding_ids.length}</span>, sortValue: (r) => r.finding_ids.length },
    { key: 'evidence', header: 'Evidence', align: 'right', render: (r) => <span className="font-mono text-xs">{r.evidence_ids.length}</span>, sortValue: (r) => r.evidence_ids.length },
    { key: 'status', header: 'Status', render: (r) => <RunStatusBadge status={r.status} spin={r.status === 'running'} />, sortValue: (r) => r.status },
    { key: 'when', header: 'Started', render: (r) => <span className="text-xs text-muted-foreground">{r.started_at ? formatRelative(r.started_at) : '—'}</span>, sortValue: (r) => r.started_at ? new Date(r.started_at).getTime() : 0 },
  ]

  return (
    <div className="space-y-4">
      <PageHeader
        title="Research Runs"
        subtitle="Every research run, with current phase / node."
        actions={
          <select
            className="rounded-md border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs"
            value={projectFilter}
            onChange={(e) => setProjectFilter(e.target.value)}
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
        onRowClick={(row) => navigate(`/research/runs/${row.research_id}`)}
        emptyMessage="No research runs yet."
      />
    </div>
  )
}
