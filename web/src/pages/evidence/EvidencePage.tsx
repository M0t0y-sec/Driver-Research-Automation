import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useEvidence, useProjects } from '@/hooks/queries'
import { PageHeader } from '@/components/common/PageHeader'
import { DataTable, type Column } from '@/components/common/DataTable'
import { IdLink } from '@/components/common/IdLink'
import { LoadingView, ErrorView } from '@/components/common/StateViews'
import { EvidenceStrengthBadge } from '@/components/common/StatusBadge'
import { formatRelative } from '@/lib/utils'
import type { Evidence } from '@/types'

export default function EvidencePage() {
  const navigate = useNavigate()
  const projects = useProjects()
  const [projectFilter, setProjectFilter] = useState<string>('')
  const ev = useEvidence(projectFilter || undefined)

  if (ev.isLoading) return <LoadingView />
  if (ev.isError) return <ErrorView onRetry={() => ev.refetch()} />

  const columns: Column<Evidence>[] = [
    { key: 'id', header: 'ID', render: (e) => <IdLink id={e.id} />, sortValue: (e) => e.id },
    { key: 'type', header: 'Type', render: (e) => <span className="font-mono text-xs">{e.evidence_type}</span>, sortValue: (e) => e.evidence_type },
    { key: 'strength', header: 'Strength', render: (e) => <EvidenceStrengthBadge strength={e.evidence_strength} />, sortValue: (e) => e.evidence_strength },
    { key: 'producer', header: 'Producer', render: (e) => <span className="text-xs">{e.producer_agent}</span>, sortValue: (e) => e.producer_agent },
    { key: 'related', header: 'Related', render: (e) => e.related_hypothesis_id ? <IdLink id={e.related_hypothesis_id} /> : <span className="text-muted-foreground">—</span>, sortValue: (e) => e.related_hypothesis_id ?? '' },
    { key: 'hash', header: 'Artifact hash', render: (e) => <span className="font-mono text-[10px] text-muted-foreground">{e.source_artifact_hash.slice(0, 24)}…</span>, sortValue: (e) => e.source_artifact_hash },
    { key: 'when', header: 'Logged', render: (e) => <span className="text-xs text-muted-foreground">{formatRelative(e.timestamp)}</span>, sortValue: (e) => new Date(e.timestamp).getTime() },
  ]

  return (
    <div className="space-y-4">
      <PageHeader
        title="Evidence"
        subtitle="E0–E7 strength-graded evidence (LLM opinion → QA passed)"
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
        data={ev.data ?? []}
        columns={columns}
        initialSortKey="strength"
        onRowClick={(row) => navigate(`/evidence/${row.id}`)}
        emptyMessage="No evidence recorded."
      />
    </div>
  )
}
