import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useFindings, useProjects } from '@/hooks/queries'
import { PageHeader } from '@/components/common/PageHeader'
import { DataTable, type Column } from '@/components/common/DataTable'
import { IdLink } from '@/components/common/IdLink'
import { LoadingView, ErrorView } from '@/components/common/StateViews'
import { FindingStatusBadge, QADecisionBadge, SeverityBadge } from '@/components/common/StatusBadge'
import { formatRelative } from '@/lib/utils'
import type { Finding } from '@/types'

export default function FindingsPage() {
  const navigate = useNavigate()
  const projects = useProjects()
  const [projectFilter, setProjectFilter] = useState<string>('')
  const findings = useFindings(projectFilter || undefined)

  if (findings.isLoading) return <LoadingView />
  if (findings.isError) return <ErrorView onRetry={() => findings.refetch()} />

  const columns: Column<Finding>[] = [
    { key: 'id', header: 'ID', render: (f) => <IdLink id={f.id} />, sortValue: (f) => f.id },
    { key: 'title', header: 'Title', render: (f) => <span className="line-clamp-1 max-w-md text-xs font-medium">{f.title}</span>, sortValue: (f) => f.title },
    { key: 'class', header: 'Class', render: (f) => <span className="text-xs">{f.vulnerability_class}</span>, sortValue: (f) => f.vulnerability_class },
    { key: 'severity', header: 'Severity', render: (f) => <SeverityBadge severity={f.severity} />, sortValue: (f) => f.severity },
    { key: 'status', header: 'Status', render: (f) => <FindingStatusBadge status={f.status} />, sortValue: (f) => f.status },
    { key: 'qa', header: 'QA', render: (f) => <QADecisionBadge decision={(f.qa_status || 'inconclusive') as 'pass' | 'retry' | 'reject' | 'inconclusive'} />, sortValue: (f) => f.qa_status || '' },
    { key: 'evidence', header: 'Evidence', align: 'right', render: (f) => <span className="font-mono text-xs">{f.evidence_ids.length}</span>, sortValue: (f) => f.evidence_ids.length },
    { key: 'updated', header: 'Updated', render: (f) => <span className="text-xs text-muted-foreground">{formatRelative(f.updated_at)}</span>, sortValue: (f) => new Date(f.updated_at).getTime() },
  ]

  return (
    <div className="space-y-4">
      <PageHeader
        title="Findings"
        subtitle="Candidate findings produced by the platform"
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
        data={findings.data ?? []}
        columns={columns}
        initialSortKey="severity"
        onRowClick={(row) => navigate(`/findings/${row.id}`)}
        emptyMessage="No findings yet."
      />
    </div>
  )
}
