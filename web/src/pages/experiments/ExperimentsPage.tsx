import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useExperiments, useProjects } from '@/hooks/queries'
import { PageHeader } from '@/components/common/PageHeader'
import { DataTable, type Column } from '@/components/common/DataTable'
import { IdLink } from '@/components/common/IdLink'
import { LoadingView, ErrorView } from '@/components/common/StateViews'
import { ExperimentStatusBadge, RiskBadge } from '@/components/common/StatusBadge'
import type { ExperimentPlan } from '@/types'

export default function ExperimentsPage() {
  const navigate = useNavigate()
  const projects = useProjects()
  const [projectFilter, setProjectFilter] = useState<string>('')
  const exps = useExperiments(projectFilter || undefined)

  if (exps.isLoading) return <LoadingView />
  if (exps.isError) return <ErrorView onRetry={() => exps.refetch()} />

  const columns: Column<ExperimentPlan>[] = [
    { key: 'id', header: 'ID', render: (e) => <IdLink id={e.id} />, sortValue: (e) => e.id },
    { key: 'hyp', header: 'Hypothesis', render: (e) => <IdLink id={e.hypothesis_id} />, sortValue: (e) => e.hypothesis_id },
    { key: 'env', header: 'Env', render: (e) => <span className="font-mono text-xs">{e.environment_id}</span>, sortValue: (e) => e.environment_id },
    { key: 'risk', header: 'Risk', render: (e) => <RiskBadge risk={e.risk_level === 'high' ? 'high' : e.risk_level === 'low' ? 'low' : 'medium'} />, sortValue: (e) => e.risk_level },
    { key: 'trials', header: 'Trials', align: 'right', render: (e) => <span className="font-mono text-xs">{e.trial_count}</span>, sortValue: (e) => e.trial_count },
    { key: 'timeout', header: 'Timeout', align: 'right', render: (e) => <span className="font-mono text-xs">{e.timeout_seconds}s</span>, sortValue: (e) => e.timeout_seconds },
    { key: 'status', header: 'Status', render: (e) => <ExperimentStatusBadge status={e.status} />, sortValue: (e) => e.status },
  ]

  return (
    <div className="space-y-4">
      <PageHeader
        title="Experiments"
        subtitle="All experiment plans (Phase 0/1 are stubs)"
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
        data={exps.data ?? []}
        columns={columns}
        initialSortKey="id"
        onRowClick={(row) => navigate(`/experiments/${row.id}`)}
        emptyMessage="No experiments planned yet."
      />
    </div>
  )
}
