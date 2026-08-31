import { useParams } from 'react-router-dom'
import { useResearch, useCancelResearch } from '@/hooks/queries'
import { PageHeader } from '@/components/common/PageHeader'
import { SectionCard, MetricRow } from '@/components/common/KpiCard'
import { ErrorView, LoadingView } from '@/components/common/StateViews'
import { RunStatusBadge, FindingStatusBadge } from '@/components/common/StatusBadge'
import { IdLink } from '@/components/common/IdLink'
import { LineageGraph } from '@/components/common/LineageGraph'
import { useProjectLineage } from '@/hooks/queries'
import { Button } from '@/components/ui/button'
import { VerticalTimeline, type TimelineItem } from '@/components/common/VerticalTimeline'
import { StopCircle, AlertTriangle } from 'lucide-react'
import { formatDateTime } from '@/lib/utils'

const PHASES = [
  'planner', 'recon', 'static_summary', 'hypothesis', 'ranking',
  'input_generation', 'experiment_planner', 'validation', 'triage',
  'root_cause', 'impact', 'exploitability', 'evidence_registrar',
  'telemetry', 'visibility', 'detection', 'robustness', 'qa_auditor', 'reporter',
]

const RUNNING_STATES = new Set(['running', 'paused', 'waiting_approval', 'cancelled'])

export default function ResearchRunPage() {
  const { id } = useParams<{ id: string }>()
  const run = useResearch(id)
  const cancel = useCancelResearch()
  const lineage = useProjectLineage(run.data?.project_id)

  if (run.isLoading) return <LoadingView rows={3} />
  if (run.isError || !run.data) return <ErrorView message="Research run not found." onRetry={() => run.refetch()} />
  const r = run.data

  const currentIndex = PHASES.indexOf(r.current_phase)
  const isFinal = r.status === 'completed' || r.status === 'failed' || r.status === 'cancelled'
  const timeline: TimelineItem[] = PHASES.map((p) => {
    const phaseIdx = PHASES.indexOf(p)
    let status: TimelineItem['status']
    if (r.status === 'failed' && phaseIdx === currentIndex) status = 'failed'
    else if (isFinal && phaseIdx <= currentIndex) status = 'completed'
    else if (phaseIdx < currentIndex) status = 'completed'
    else if (phaseIdx === currentIndex) status = r.status === 'running' ? 'active' : 'completed'
    else status = 'pending'
    return {
      key: p,
      label: p.replace(/_/g, ' '),
      status,
      time: phaseIdx <= currentIndex ? (r.started_at ?? undefined) : undefined,
      end: phaseIdx === currentIndex && r.completed_at ? r.completed_at : undefined,
    }
  })

  const canCancel = RUNNING_STATES.has(r.status)

  return (
    <div className="space-y-6">
      <PageHeader
        title={`Run ${r.research_id}`}
        subtitle={`${r.current_phase} → ${r.current_node}`}
        backButton
        actions={
          <div className="flex items-center gap-2">
            <RunStatusBadge status={r.status} spin={r.status === 'running'} />
            {canCancel && (
              <Button
                size="sm"
                variant="outline"
                onClick={() => cancel.mutate(r.research_id)}
                disabled={cancel.isPending}
              >
                <StopCircle className="h-4 w-4" /> Cancel
              </Button>
            )}
          </div>
        }
      />

      {r.error && (
        <div className="rounded-md border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
          <div className="flex items-center gap-2 font-semibold"><AlertTriangle className="h-4 w-4" /> Run failed</div>
          <div className="mt-1 font-mono text-[11px]">{r.error}</div>
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <SectionCard title="Identity" description="Run metadata.">
          <MetricRow label="Run" value={<IdLink id={r.research_id} />} />
          <MetricRow label="Project" value={<IdLink id={r.project_id} />} />
          <MetricRow label="Target" value={<IdLink id={r.target_id} />} />
          <MetricRow label="Started" value={r.started_at ? formatDateTime(r.started_at) : '—'} />
          <MetricRow label="Completed" value={r.completed_at ? formatDateTime(r.completed_at) : '—'} />
          <MetricRow label="Status" value={<RunStatusBadge status={r.status} spin={r.status === 'running'} />} />
        </SectionCard>

        <SectionCard title="Pipeline progress" description="Current node and phase counters.">
          <MetricRow label="Hypotheses" value={r.hypothesis_ids.length} />
          <MetricRow label="Findings" value={r.finding_ids.length} />
          <MetricRow label="Evidence" value={r.evidence_ids.length} />
          <MetricRow label="QA reviews" value={r.qa_review_ids.length} />
        </SectionCard>

        <SectionCard title="Findings produced">
          {r.finding_ids.length > 0 ? (
            <div className="space-y-2">
              {r.finding_ids.map((fid) => (
                <div key={fid} className="flex items-center justify-between rounded-md border border-white/5 bg-white/[0.02] px-3 py-2">
                  <IdLink id={fid} />
                  <FindingStatusBadge status="candidate" />
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">No findings yet.</p>
          )}
        </SectionCard>
      </div>

      <SectionCard title="Pipeline timeline" description="Each node in the LangGraph subgraph.">
        <VerticalTimeline items={timeline} />
      </SectionCard>

      {r.report && (
        <SectionCard title="Report" description="Generated by the Reporter node.">
          <div className="space-y-3">
            <div>
              <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Title</div>
              <h3 className="mt-1 text-base font-semibold">{r.report.title}</h3>
            </div>
            {r.report.executive_summary && (
              <div>
                <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Executive summary</div>
                <p className="mt-1 text-sm text-foreground/90">{r.report.executive_summary}</p>
              </div>
            )}
            {r.report.sections.length > 0 && (
              <div className="space-y-2">
                {r.report.sections.map((s, i) => (
                  <div key={i} className="rounded-md border border-white/5 bg-white/[0.02] p-3">
                    <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">{s.heading}</div>
                    <p className="mt-1 text-sm text-foreground/90">{s.body}</p>
                  </div>
                ))}
              </div>
            )}
            {r.report.limitations.length > 0 && (
              <div>
                <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Limitations</div>
                <ul className="mt-1 list-disc space-y-0.5 pl-5 text-[11px] text-amber-300/90">
                  {r.report.limitations.map((l, i) => <li key={i}>{l}</li>)}
                </ul>
              </div>
            )}
          </div>
        </SectionCard>
      )}

      <SectionCard title="Lineage" description="Full chain for this project (target → finding).">
        {lineage.data && lineage.data.nodes.length > 0 ? (
          <LineageGraph lineage={lineage.data} />
        ) : (
          <div className="rounded-lg border border-dashed px-6 py-8 text-center text-xs text-muted-foreground">No lineage yet.</div>
        )}
      </SectionCard>
    </div>
  )
}
