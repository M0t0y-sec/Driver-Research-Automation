import { useParams } from 'react-router-dom'
import { useHypothesis } from '@/hooks/queries'
import { PageHeader } from '@/components/common/PageHeader'
import { SectionCard, MetricRow } from '@/components/common/KpiCard'
import { ErrorView, LoadingView } from '@/components/common/StateViews'
import { ConfidenceMeter, HypothesisStatusBadge, AttackActorBadge } from '@/components/common/StatusBadge'
import { IdLink, CopyableText } from '@/components/common/IdLink'
import { Lightbulb } from 'lucide-react'

export default function HypothesisDetailPage() {
  const { id } = useParams<{ id: string }>()
  const hyp = useHypothesis(id)
  if (hyp.isLoading) return <LoadingView />
  if (hyp.isError || !hyp.data) return <ErrorView message="Hypothesis not found." onRetry={() => hyp.refetch()} />
  const h = hyp.data
  const b = h.priority_breakdown

  return (
    <div className="space-y-6">
      <PageHeader title={`HYP ${h.id}`} subtitle={h.description} backButton />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <SectionCard title="Identity" description="Where this hypothesis lives in the chain.">
          <MetricRow label="ID" value={<IdLink id={h.id} />} />
          <MetricRow label="Project" value={<IdLink id={h.project_id} />} />
          <MetricRow label="Target" value={<IdLink id={h.target_id} />} />
          <MetricRow label="Category" value={h.category} />
          <MetricRow label="Location" value={<span className="font-mono text-xs">{h.location ?? '—'}</span>} />
          <MetricRow label="Status" value={<HypothesisStatusBadge status={h.status} />} />
          <MetricRow label="Attack actor" value={<AttackActorBadge actor={h.related_attack_actor} />} />
          <MetricRow label="Source" value={h.source ?? '—'} />
          <MetricRow label="Sink" value={h.sink ?? '—'} />
        </SectionCard>

        <SectionCard title="Score breakdown" description="Priority = impact × confidence × reachability × testability.">
          <MetricRow label="Impact" value={<ConfidenceMeter value={b.impact} />} />
          <MetricRow label="Confidence" value={<ConfidenceMeter value={b.confidence} />} />
          <MetricRow label="Reachability" value={<ConfidenceMeter value={b.reachability} />} />
          <MetricRow label="Testability" value={<ConfidenceMeter value={b.testability} />} />
          <MetricRow label="Rule score" value={<ConfidenceMeter value={b.rule_score} />} />
          <MetricRow label="Final priority" value={<ConfidenceMeter value={h.priority} label="final" />} />
          <MetricRow label="Uncertainty" value={b.uncertainty ?? '—'} />
        </SectionCard>

        <SectionCard title="Observations & Evidence" description="Linked entities.">
          <MetricRow label="Observations" value={h.observation_ids.length} />
          <MetricRow label="Attack surface" value={h.attack_surface_item_ids.length} />
          <MetricRow label="Evidence" value={h.evidence_ids.length} />
          <MetricRow label="Requires human review" value={h.requires_human_review ? 'Yes' : 'No'} />
          <MetricRow label="Validation required" value={h.validation_required ? 'Yes' : 'No'} />
          <MetricRow label="Created" value={h.created_at} />
        </SectionCard>
      </div>

      {b.model_explanation && (
        <SectionCard title="Model explanation" description="From the LLM (mock in Phase 0/1).">
          <p className="text-sm leading-relaxed text-foreground/90">{b.model_explanation}</p>
        </SectionCard>
      )}
    </div>
  )
}
