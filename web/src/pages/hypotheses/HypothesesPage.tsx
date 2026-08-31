import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useHypotheses, useProjects } from '@/hooks/queries'
import { PageHeader } from '@/components/common/PageHeader'
import { DataTable, type Column } from '@/components/common/DataTable'
import { IdLink } from '@/components/common/IdLink'
import { LoadingView, ErrorView } from '@/components/common/StateViews'
import { HypothesisStatusBadge, ConfidenceMeter, AttackActorBadge } from '@/components/common/StatusBadge'
import type { Hypothesis } from '@/types'
import { Lightbulb } from 'lucide-react'

export default function HypothesesPage() {
  const navigate = useNavigate()
  const projects = useProjects()
  const [projectFilter, setProjectFilter] = useState<string>('')
  const hyp = useHypotheses(projectFilter || undefined)

  if (hyp.isLoading) return <LoadingView />
  if (hyp.isError) return <ErrorView onRetry={() => hyp.refetch()} />

  const columns: Column<Hypothesis>[] = [
    { key: 'id', header: 'ID', render: (h) => <IdLink id={h.id} />, sortValue: (h) => h.id },
    { key: 'cat', header: 'Category', render: (h) => <span className="text-xs">{h.category}</span>, sortValue: (h) => h.category },
    { key: 'desc', header: 'Description', render: (h) => <span className="line-clamp-1 max-w-md text-xs">{h.description}</span>, sortValue: (h) => h.description },
    { key: 'actor', header: 'Actor', render: (h) => <AttackActorBadge actor={h.related_attack_actor} />, sortValue: (h) => h.related_attack_actor },
    { key: 'priority', header: 'Priority', render: (h) => <ConfidenceMeter value={h.priority} label="priority" />, sortValue: (h) => h.priority },
    { key: 'confidence', header: 'Confidence', render: (h) => <ConfidenceMeter value={h.confidence} label="conf" />, sortValue: (h) => h.confidence },
    { key: 'status', header: 'Status', render: (h) => <HypothesisStatusBadge status={h.status} />, sortValue: (h) => h.status },
    { key: 'review', header: 'Review', render: (h) => h.requires_human_review ? <span className="text-[10px] uppercase text-amber-300">required</span> : <span className="text-[10px] text-muted-foreground">auto</span>, sortValue: (h) => (h.requires_human_review ? 1 : 0) },
  ]

  return (
    <div className="space-y-4">
      <PageHeader
        title="Hypotheses"
        subtitle="All hypotheses generated across projects"
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
        data={hyp.data ?? []}
        columns={columns}
        initialSortKey="priority"
        onRowClick={(row) => navigate(`/hypotheses/${row.id}`)}
        emptyMessage="No hypotheses have been generated yet."
      />
    </div>
  )
}
