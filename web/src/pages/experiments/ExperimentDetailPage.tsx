import { useParams } from 'react-router-dom'
import { useExperiment } from '@/hooks/queries'
import { PageHeader } from '@/components/common/PageHeader'
import { SectionCard, MetricRow } from '@/components/common/KpiCard'
import { ErrorView, LoadingView } from '@/components/common/StateViews'
import { ExperimentStatusBadge, RiskBadge } from '@/components/common/StatusBadge'
import { IdLink } from '@/components/common/IdLink'

export default function ExperimentDetailPage() {
  const { id } = useParams<{ id: string }>()
  const e = useExperiment(id)
  if (e.isLoading) return <LoadingView />
  if (e.isError || !e.data) return <ErrorView message="Experiment not found." onRetry={() => e.refetch()} />
  const x = e.data

  return (
    <div className="space-y-6">
      <PageHeader title={`Experiment ${x.id}`} subtitle={x.hypothesis_id} backButton />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <SectionCard title="Identity" description="Plan metadata.">
          <MetricRow label="ID" value={<IdLink id={x.id} />} />
          <MetricRow label="Hypothesis" value={<IdLink id={x.hypothesis_id} />} />
          <MetricRow label="Project" value={<IdLink id={x.project_id} />} />
          <MetricRow label="Environment" value={x.environment_id} />
          <MetricRow label="Risk" value={<RiskBadge risk={x.risk_level === 'high' ? 'high' : x.risk_level === 'low' ? 'low' : 'medium'} />} />
          <MetricRow label="Status" value={<ExperimentStatusBadge status={x.status} />} />
          <MetricRow label="Trials" value={x.trial_count} />
          <MetricRow label="Timeout" value={`${x.timeout_seconds}s`} />
        </SectionCard>

        <SectionCard title="Setup" description="Phases of the experiment.">
          <ul className="list-disc space-y-1 pl-5 text-xs text-foreground/90">
            {x.setup.map((s, i) => (<li key={i}>{s}</li>))}
          </ul>
        </SectionCard>

        <SectionCard title="Success / Failure criteria" description="How the result is judged.">
          <div className="space-y-2 text-xs">
            <div>
              <div className="text-emerald-300">Success</div>
              <ul className="mt-1 list-disc space-y-0.5 pl-5 text-muted-foreground">
                {x.success_criteria.map((s, i) => <li key={i}>{s}</li>)}
              </ul>
            </div>
            <div>
              <div className="text-rose-300">Failure</div>
              <ul className="mt-1 list-disc space-y-0.5 pl-5 text-muted-foreground">
                {x.failure_criteria.map((s, i) => <li key={i}>{s}</li>)}
              </ul>
            </div>
            <div>
              <div className="text-amber-300">Expected telemetry</div>
              <ul className="mt-1 list-disc space-y-0.5 pl-5 text-muted-foreground">
                {x.expected_telemetry.map((s, i) => <li key={i}>{s}</li>)}
              </ul>
            </div>
          </div>
        </SectionCard>
      </div>
    </div>
  )
}
