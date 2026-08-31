import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useDetection, useVisibility, useRobustness, useProjects } from '@/hooks/queries'
import { PageHeader } from '@/components/common/PageHeader'
import { DataTable, type Column } from '@/components/common/DataTable'
import { SectionCard, MetricRow } from '@/components/common/KpiCard'
import { LoadingView, ErrorView } from '@/components/common/StateViews'
import { DetectionVerdictBadge } from '@/components/common/StatusBadge'
import { IdLink } from '@/components/common/IdLink'
import { formatRelative } from '@/lib/utils'
import { CheckCircle2, XCircle, AlertTriangle, Eye, ShieldCheck, Activity } from 'lucide-react'
import type { DetectionResult, VisibilityResult, RobustnessResult } from '@/types'

export default function DetectionPage() {
  const navigate = useNavigate()
  const projects = useProjects()
  const [projectFilter, setProjectFilter] = useState<string>('')
  const det = useDetection(projectFilter || undefined)
  const vis = useVisibility(projectFilter || undefined)
  const rob = useRobustness(projectFilter || undefined)

  const detColumns: Column<DetectionResult>[] = [
    { key: 'id', header: 'ID', render: (d) => <IdLink id={d.id} />, sortValue: (d) => d.id },
    { key: 'exec', header: 'Execution', render: (d) => <IdLink id={d.execution_id} />, sortValue: (d) => d.execution_id },
    { key: 'stage', header: 'Stage', render: (d) => <span className="text-xs uppercase">{d.detection_stage}</span>, sortValue: (d) => d.detection_stage },
    { key: 'verdict', header: 'Verdict', render: (d) => <DetectionVerdictBadge verdict={d.verdict} />, sortValue: (d) => d.verdict },
    { key: 'rate', header: 'Detection rate', align: 'right', render: (d) => <span className="font-mono text-xs">{Math.round(d.detection_rate * 100)}%</span>, sortValue: (d) => d.detection_rate },
    { key: 'trials', header: 'Trials', align: 'right', render: (d) => <span className="font-mono text-xs">{d.trials_detected}/{d.trials_total}</span>, sortValue: (d) => d.trials_total },
    { key: 'when', header: 'Created', render: (d) => <span className="text-xs text-muted-foreground">{formatRelative(d.created_at)}</span>, sortValue: (d) => new Date(d.created_at).getTime() },
  ]

  const visColumns: Column<VisibilityResult>[] = [
    { key: 'id', header: 'ID', render: (v) => <IdLink id={v.id} />, sortValue: (v) => v.id },
    { key: 'passed', header: 'Visibility', render: (v) => v.passed ? <CheckCircle2 className="h-4 w-4 text-emerald-400" /> : <XCircle className="h-4 w-4 text-rose-400" />, sortValue: (v) => (v.passed ? 1 : 0) },
    { key: 'channels', header: 'Channels visible', render: (v) => {
        const channels: string[] = []
        if (v.process_event_visible) channels.push('process')
        if (v.image_load_visible) channels.push('image')
        if (v.driver_load_visible) channels.push('driver')
        if (v.file_event_visible) channels.push('file')
        if (v.registry_event_visible) channels.push('registry')
        if (v.network_event_visible) channels.push('network')
        if (v.kernel_callback_visible) channels.push('kernel')
        if (v.etw_available) channels.push('etw')
        return <span className="text-[10px] text-muted-foreground">{channels.length > 0 ? channels.join(', ') : '—'}</span>
      } },
    { key: 'reasons', header: 'Reasons', render: (v) => v.reasons.length > 0 ? <span className="line-clamp-1 text-xs text-muted-foreground">{v.reasons.join('; ')}</span> : <span className="text-muted-foreground">—</span> },
  ]

  const robColumns: Column<RobustnessResult>[] = [
    { key: 'id', header: 'ID', render: (r) => <IdLink id={r.id} />, sortValue: (r) => r.id },
    { key: 'score', header: 'Score', render: (r) => <span className="font-mono text-xs uppercase">{r.robustness_score}</span>, sortValue: (r) => r.robustness_score },
    { key: 'baseline', header: 'Baseline rate', align: 'right', render: (r) => <span className="font-mono text-xs">{Math.round(r.baseline_detection_rate * 100)}%</span>, sortValue: (r) => r.baseline_detection_rate },
    { key: 'weak', header: 'Weak dimension', render: (r) => r.weak_dimension ? <span className="text-xs">{r.weak_dimension}</span> : <span className="text-muted-foreground">—</span>, sortValue: (r) => r.weak_dimension ?? '' },
    { key: 'variants', header: 'Variants', align: 'right', render: (r) => <span className="font-mono text-xs">{r.variant_ids.length}</span>, sortValue: (r) => r.variant_ids.length },
  ]

  return (
    <div className="space-y-4">
      <PageHeader
        title="Detection Evaluation"
        subtitle="Visibility → Detection → Robustness (Phase 0/1: stub data)"
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

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <SectionCard title="Visibility" description="Phase 0/1: not assessed.">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Eye className="h-3.5 w-3.5" /> Telemetry channels visible to the platform.
          </div>
          <div className="mt-3">
            <DataTable
              data={vis.data ?? []}
              columns={visColumns}
              initialSortKey="passed"
              emptyMessage="No visibility results."
            />
          </div>
        </SectionCard>
        <SectionCard title="Detection" description="Did the security product detect the behaviour?">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <ShieldCheck className="h-3.5 w-3.5" /> Multiple trials + positive/negative controls.
          </div>
          <div className="mt-3">
            <DataTable
              data={det.data ?? []}
              columns={detColumns}
              initialSortKey="verdict"
              emptyMessage="No detection results."
            />
          </div>
        </SectionCard>
        <SectionCard title="Robustness" description="How stable is the detection under controlled variants?">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Activity className="h-3.5 w-3.5" /> Variant generation policy applies.
          </div>
          <div className="mt-3">
            <DataTable
              data={rob.data ?? []}
              columns={robColumns}
              initialSortKey="score"
              emptyMessage="No robustness results."
            />
          </div>
        </SectionCard>
      </div>
    </div>
  )
}
