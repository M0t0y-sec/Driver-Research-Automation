import { useParams } from 'react-router-dom'
import { useEvidenceOne } from '@/hooks/queries'
import { PageHeader } from '@/components/common/PageHeader'
import { SectionCard, MetricRow } from '@/components/common/KpiCard'
import { ErrorView, LoadingView } from '@/components/common/StateViews'
import { EvidenceStrengthBadge } from '@/components/common/StatusBadge'
import { IdLink, CopyableText } from '@/components/common/IdLink'

export default function EvidenceDetailPage() {
  const { id } = useParams<{ id: string }>()
  const e = useEvidenceOne(id)
  if (e.isLoading) return <LoadingView />
  if (e.isError || !e.data) return <ErrorView message="Evidence not found." onRetry={() => e.refetch()} />
  const ev = e.data

  return (
    <div className="space-y-6">
      <PageHeader title={`Evidence ${ev.id}`} subtitle={ev.summary} backButton />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <SectionCard title="Identity" description="Provenance of this evidence record.">
          <MetricRow label="ID" value={<IdLink id={ev.id} />} />
          <MetricRow label="Type" value={<span className="font-mono text-xs">{ev.evidence_type}</span>} />
          <MetricRow label="Strength" value={<EvidenceStrengthBadge strength={ev.evidence_strength} />} />
          <MetricRow label="QA status" value={ev.qa_status} />
          <MetricRow label="Producer" value={ev.producer_agent} />
          <MetricRow label="Tool version" value={ev.tool_version ?? '—'} />
          <MetricRow label="Model version" value={ev.model_version ?? '—'} />
          <MetricRow label="Confidence" value={ev.confidence} />
          <MetricRow label="Environment snapshot" value={ev.environment_snapshot_id ?? '—'} />
        </SectionCard>

        <SectionCard title="Links" description="Related entities in the chain.">
          <MetricRow label="Project" value={<IdLink id={ev.project_id} />} />
          <MetricRow label="Target" value={ev.target_id ? <IdLink id={ev.target_id} /> : '—'} />
          <MetricRow label="Hypothesis" value={ev.related_hypothesis_id ? <IdLink id={ev.related_hypothesis_id} /> : '—'} />
          <MetricRow label="Experiment" value={ev.related_experiment_id ? <IdLink id={ev.related_experiment_id} /> : '—'} />
          <MetricRow label="Crash" value={ev.related_crash_id ? <IdLink id={ev.related_crash_id} /> : '—'} />
        </SectionCard>

        <SectionCard title="Artifact" description="sha256 of the underlying artefact.">
          <pre className="break-all rounded-md border border-white/5 bg-white/[0.03] p-3 font-mono text-[11px]">
            {ev.source_artifact_hash}
          </pre>
          <div className="mt-2 text-[11px] text-muted-foreground">
            Raw: {ev.raw_artifact_ref ?? '—'}
          </div>
          <div className="text-[11px] text-muted-foreground">
            Normalised: {ev.normalized_artifact_ref ?? '—'}
          </div>
        </SectionCard>
      </div>

      {ev.lineage_ids.length > 0 && (
        <SectionCard title="Lineage" description="Entities this evidence links to.">
          <div className="flex flex-wrap gap-1.5">
            {ev.lineage_ids.map((id) => (
              <IdLink key={id} id={id} />
            ))}
          </div>
        </SectionCard>
      )}
    </div>
  )
}
