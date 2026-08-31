import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQAReviews, useFindings } from '@/hooks/queries'
import { PageHeader } from '@/components/common/PageHeader'
import { DataTable, type Column } from '@/components/common/DataTable'
import { SectionCard } from '@/components/common/KpiCard'
import { LoadingView, ErrorView } from '@/components/common/StateViews'
import { QADecisionBadge } from '@/components/common/StatusBadge'
import { IdLink } from '@/components/common/IdLink'
import { formatRelative } from '@/lib/utils'
import type { QAReview, Finding } from '@/types'

export default function QAReviewsPage() {
  const findings = useFindings()
  const reviews = useQAReviews()
  const [filter, setFilter] = useState<string>('')

  if (reviews.isLoading) return <LoadingView />
  if (reviews.isError) return <ErrorView onRetry={() => reviews.refetch()} />

  const findingsById = new Map<string, Finding>(
    (findings.data ?? []).map((f) => [f.id, f])
  )
  const filtered = filter ? (reviews.data ?? []).filter((r) => r.decision === filter) : (reviews.data ?? [])

  const columns: Column<QAReview>[] = [
    { key: 'id', header: 'ID', render: (q) => <IdLink id={q.id} />, sortValue: (q) => q.id },
    {
      key: 'finding',
      header: 'Finding',
      render: (q) => {
        if (!q.finding_id) return <span className="text-muted-foreground">—</span>
        const f = findingsById.get(q.finding_id)
        return (
          <div>
            <IdLink id={q.finding_id} />
            {f && <div className="text-[10px] text-muted-foreground line-clamp-1">{f.title}</div>}
          </div>
        )
      },
      sortValue: (q) => q.finding_id ?? '',
    },
    { key: 'decision', header: 'Decision', render: (q) => <QADecisionBadge decision={q.decision} />, sortValue: (q) => q.decision },
    {
      key: 'rules',
      header: 'Rules',
      align: 'right',
      render: (q) => {
        const passed = q.rule_hits.filter((h) => h.passed).length
        const failed = q.rule_hits.length - passed
        return (
          <div className="flex items-center justify-end gap-1 font-mono text-xs">
            <span className="text-emerald-400">{passed}</span>
            <span className="text-muted-foreground">/</span>
            <span className="text-rose-400">{failed}</span>
          </div>
        )
      },
      sortValue: (q) => q.rule_hits.filter((h) => h.passed).length,
    },
    { key: 'reasons', header: 'Reasons', render: (q) => <span className="line-clamp-1 max-w-md text-xs text-muted-foreground">{q.reasons.join('; ') || '—'}</span> },
    { key: 'when', header: 'Created', render: (q) => <span className="text-xs text-muted-foreground">{formatRelative(q.created_at)}</span>, sortValue: (q) => new Date(q.created_at).getTime() },
  ]

  return (
    <div className="space-y-4">
      <PageHeader
        title="QA Center"
        subtitle="Independent reviews by the QA Auditor (Rule + Evidence + LLM)."
        actions={
          <select
            className="rounded-md border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          >
            <option value="">All decisions</option>
            <option value="pass">Pass</option>
            <option value="retry">Retry</option>
            <option value="reject">Reject</option>
            <option value="inconclusive">Inconclusive</option>
          </select>
        }
      />

      <SectionCard title="All reviews" description="Filter by decision to focus on noise.">
        <DataTable
          data={filtered}
          columns={columns}
          initialSortKey="when"
          emptyMessage="No QA reviews yet."
        />
      </SectionCard>
    </div>
  )
}
