import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  Boxes,
  Target as TargetIcon,
  Activity,
  Bug,
  Lightbulb,
  FlaskConical,
  Microscope,
  ShieldCheck,
  FileText,
  GitBranch,
} from 'lucide-react'
import {
  useProject,
  useProjectLineage,
  useTargets,
  useResearchList,
  useHypotheses,
  useExperiments,
  useFindings,
  useEvidence,
  useQAReviews,
  useStartResearch,
} from '@/hooks/queries'
import { PageHeader } from '@/components/common/PageHeader'
import { KpiCard, SectionCard, MetricRow } from '@/components/common/KpiCard'
import { CardGridSkeleton, ErrorView, LoadingView } from '@/components/common/StateViews'
import { DataTable, type Column } from '@/components/common/DataTable'
import { RunStatusBadge, FindingStatusBadge, QADecisionBadge, EvidenceStrengthBadge } from '@/components/common/StatusBadge'
import { IdLink } from '@/components/common/IdLink'
import { Button } from '@/components/ui/button'
import { NewTargetDialog } from '@/components/common/NewTargetDialog'
import { LineageGraph } from '@/components/common/LineageGraph'
import { useStartResearchDialog } from '@/hooks/useDialogState'
import { formatRelative } from '@/lib/utils'
import type { Target as TargetType, ResearchRun, Hypothesis, ExperimentPlan, Finding, Evidence, QAReview } from '@/types'

export default function ProjectDetailPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const project = useProject(projectId)
  const lineage = useProjectLineage(projectId)
  const targets = useTargets(projectId)
  const research = useResearchList(projectId)
  const hypotheses = useHypotheses(projectId)
  const experiments = useExperiments(projectId)
  const findings = useFindings(projectId)
  const evidence = useEvidence(projectId)
  const qa = useQAReviews(projectId)
  const startResearch = useStartResearch()
  const [showUpload, setShowUpload] = useState(false)
  const startDialog = useStartResearchDialog()

  if (project.isLoading) {
    return (
      <div className="space-y-4">
        <LoadingView rows={2} />
        <CardGridSkeleton count={4} />
      </div>
    )
  }
  if (project.isError || !project.data) {
    return <ErrorView message="Project not found." onRetry={() => project.refetch()} />
  }
  const p = project.data

  const targetColumns: Column<TargetType>[] = [
    { key: 'id', header: 'ID', render: (t) => <IdLink id={t.id} />, sortValue: (t) => t.id },
    { key: 'name', header: 'Name', render: (t) => <span className="font-medium">{t.name}</span>, sortValue: (t) => t.name },
    { key: 'sha', header: 'SHA-256', render: (t) => <span className="font-mono text-[10px] text-muted-foreground">{t.sha256.slice(0, 24)}…</span>, sortValue: (t) => t.sha256 },
    { key: 'size', header: 'Size', align: 'right', render: (t) => <span className="font-mono text-xs">{t.size} B</span>, sortValue: (t) => t.size },
    { key: 'type', header: 'File', render: (t) => <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground">{t.file_type}</span>, sortValue: (t) => t.file_type },
    { key: 'submitted', header: 'Submitted', render: (t) => <span className="text-xs text-muted-foreground">{formatRelative(t.submitted_at)}</span>, sortValue: (t) => new Date(t.submitted_at).getTime() },
    {
      key: 'actions',
      header: '',
      align: 'right',
      render: (t) => (
        <Button
          size="sm"
          variant="outline"
          onClick={(e) => { e.stopPropagation(); startDialog.open(p.id, t.id, t.name) }}
        >
          <Activity className="h-3.5 w-3.5" /> Start research
        </Button>
      ),
    },
  ]

  const runColumns: Column<ResearchRun>[] = [
    { key: 'id', header: 'Run', render: (r) => <IdLink id={r.research_id} />, sortValue: (r) => r.research_id },
    { key: 'target', header: 'Target', render: (r) => <IdLink id={r.target_id} />, sortValue: (r) => r.target_id },
    { key: 'phase', header: 'Phase', render: (r) => <span className="text-xs">{r.current_phase || '—'}</span>, sortValue: (r) => r.current_phase },
    { key: 'node', header: 'Node', render: (r) => <span className="text-xs text-muted-foreground">{r.current_node || '—'}</span>, sortValue: (r) => r.current_node },
    { key: 'status', header: 'Status', render: (r) => <RunStatusBadge status={r.status} spin={r.status === 'running'} />, sortValue: (r) => r.status },
  ]

  const hypColumns: Column<Hypothesis>[] = [
    { key: 'id', header: 'ID', render: (h) => <IdLink id={h.id} />, sortValue: (h) => h.id },
    { key: 'cat', header: 'Category', render: (h) => <span className="text-xs">{h.category}</span>, sortValue: (h) => h.category },
    { key: 'desc', header: 'Description', render: (h) => <span className="line-clamp-1 text-xs">{h.description}</span>, sortValue: (h) => h.description },
    { key: 'priority', header: 'Priority', align: 'right', render: (h) => <span className="font-mono text-xs">{(h.priority * 100).toFixed(0)}%</span>, sortValue: (h) => h.priority },
    { key: 'human', header: 'Review', render: (h) => h.requires_human_review ? <span className="text-[10px] uppercase text-amber-300">required</span> : <span className="text-[10px] text-muted-foreground">auto</span>, sortValue: (h) => (h.requires_human_review ? 1 : 0) },
  ]

  const expColumns: Column<ExperimentPlan>[] = [
    { key: 'id', header: 'ID', render: (e) => <IdLink id={e.id} />, sortValue: (e) => e.id },
    { key: 'hyp', header: 'Hypothesis', render: (e) => <IdLink id={e.hypothesis_id} />, sortValue: (e) => e.hypothesis_id },
    { key: 'risk', header: 'Risk', render: (e) => <span className="font-mono text-xs uppercase">{e.risk_level}</span>, sortValue: (e) => e.risk_level },
    { key: 'trials', header: 'Trials', align: 'right', render: (e) => <span className="font-mono text-xs">{e.trial_count}</span>, sortValue: (e) => e.trial_count },
    { key: 'timeout', header: 'Timeout', align: 'right', render: (e) => <span className="font-mono text-xs">{e.timeout_seconds}s</span>, sortValue: (e) => e.timeout_seconds },
  ]

  const fndColumns: Column<Finding>[] = [
    { key: 'id', header: 'ID', render: (f) => <IdLink id={f.id} />, sortValue: (f) => f.id },
    { key: 'title', header: 'Title', render: (f) => <span className="line-clamp-1 text-xs font-medium">{f.title}</span>, sortValue: (f) => f.title },
    { key: 'class', header: 'Class', render: (f) => <span className="text-xs">{f.vulnerability_class}</span>, sortValue: (f) => f.vulnerability_class },
    { key: 'status', header: 'Status', render: (f) => <FindingStatusBadge status={f.status} />, sortValue: (f) => f.status },
    { key: 'qa', header: 'QA', render: (f) => <QADecisionBadge decision={(f.qa_status || 'inconclusive') as 'pass' | 'retry' | 'reject' | 'inconclusive'} />, sortValue: (f) => f.qa_status || '' },
    { key: 'evidence', header: 'Evidence', align: 'right', render: (f) => <span className="font-mono text-xs">{f.evidence_ids.length}</span>, sortValue: (f) => f.evidence_ids.length },
  ]

  const evColumns: Column<Evidence>[] = [
    { key: 'id', header: 'ID', render: (e) => <IdLink id={e.id} />, sortValue: (e) => e.id },
    { key: 'type', header: 'Type', render: (e) => <span className="font-mono text-xs">{e.evidence_type}</span>, sortValue: (e) => e.evidence_type },
    { key: 'strength', header: 'Strength', render: (e) => <EvidenceStrengthBadge strength={e.evidence_strength} />, sortValue: (e) => e.evidence_strength },
    { key: 'producer', header: 'Producer', render: (e) => <span className="text-xs">{e.producer_agent}</span>, sortValue: (e) => e.producer_agent },
    { key: 'hash', header: 'Artifact hash', render: (e) => <span className="font-mono text-[10px] text-muted-foreground">{e.source_artifact_hash.slice(0, 24)}…</span>, sortValue: (e) => e.source_artifact_hash },
  ]

  const qaColumns: Column<QAReview>[] = [
    { key: 'id', header: 'ID', render: (q) => <IdLink id={q.id} />, sortValue: (q) => q.id },
    { key: 'finding', header: 'Finding', render: (q) => q.finding_id ? <IdLink id={q.finding_id} /> : <span className="text-muted-foreground">—</span>, sortValue: (q) => q.finding_id ?? '' },
    { key: 'decision', header: 'Decision', render: (q) => <QADecisionBadge decision={q.decision} />, sortValue: (q) => q.decision },
    { key: 'rules', header: 'Rules', align: 'right', render: (q) => <span className="font-mono text-xs">{q.rule_hits.length}</span>, sortValue: (q) => q.rule_hits.length },
    { key: 'reasons', header: 'Reasons', render: (q) => <span className="line-clamp-1 text-xs text-muted-foreground">{q.reasons.join('; ') || '—'}</span> },
  ]

  return (
    <div className="space-y-6">
      <PageHeader
        title={p.name}
        subtitle={p.description || 'Research project'}
        backButton
        actions={
          <Button variant="outline" size="sm" onClick={() => setShowUpload(true)}>
            <TargetIcon className="h-4 w-4" /> Upload sample
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-4">
        <KpiCard label="Targets" value={targets.data?.length ?? 0} icon={<TargetIcon className="h-4 w-4" />} />
        <KpiCard label="Research runs" value={research.data?.length ?? 0} icon={<Activity className="h-4 w-4" />} />
        <KpiCard label="Hypotheses" value={hypotheses.data?.length ?? 0} icon={<Lightbulb className="h-4 w-4" />} />
        <KpiCard label="Findings" value={findings.data?.length ?? 0} icon={<Bug className="h-4 w-4" />} />
      </div>

      <SectionCard title="Targets" description="Uploaded samples in this project.">
        <DataTable data={targets.data ?? []} columns={targetColumns} initialSortKey="submitted" emptyMessage="No samples uploaded yet." />
      </SectionCard>

      <SectionCard title="Research lineage" description="Observation → Hypothesis → Evidence → Finding (Phase 0/1 static research).">
        {lineage.data && lineage.data.nodes.length > 0 ? (
          <LineageGraph lineage={lineage.data} />
        ) : (
          <div className="rounded-lg border border-dashed px-6 py-8 text-center text-xs text-muted-foreground">
            No lineage yet — start a research run to populate the graph.
          </div>
        )}
      </SectionCard>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <SectionCard title="Research runs" description="Run records for this project.">
          <DataTable data={research.data ?? []} columns={runColumns} initialSortKey="id" emptyMessage="No research runs yet." />
        </SectionCard>
        <SectionCard title="Hypotheses" description="Hypotheses generated for this project.">
          <DataTable data={hypotheses.data ?? []} columns={hypColumns} initialSortKey="priority" emptyMessage="No hypotheses yet." />
        </SectionCard>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <SectionCard title="Experiments" description="Experiment plans (Phase 0/1 are stubs).">
          <DataTable data={experiments.data ?? []} columns={expColumns} initialSortKey="id" emptyMessage="No experiment plans yet." />
        </SectionCard>
        <SectionCard title="Evidence" description="All evidence records (E0–E7).">
          <DataTable data={evidence.data ?? []} columns={evColumns} initialSortKey="id" emptyMessage="No evidence yet." />
        </SectionCard>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <SectionCard title="Findings" description="Candidate findings (Phase 0/1 are static-research).">
          <DataTable data={findings.data ?? []} columns={fndColumns} initialSortKey="qa" emptyMessage="No findings yet." />
        </SectionCard>
        <SectionCard title="QA reviews" description="Independent reviews by QA Auditor.">
          <DataTable data={qa.data ?? []} columns={qaColumns} initialSortKey="decision" emptyMessage="No QA reviews yet." />
        </SectionCard>
      </div>

      <NewTargetDialog projectId={p.id} open={showUpload} onOpenChange={setShowUpload} />
      <StartResearchDialog
        projectId={p.id}
        targetId={startDialog.targetId}
        targetName={startDialog.targetName}
        open={Boolean(startDialog.targetId)}
        onClose={startDialog.close}
        startResearch={startResearch}
      />
    </div>
  )
}

function StartResearchDialog({
  projectId,
  targetId,
  targetName,
  open,
  onClose,
  startResearch,
}: {
  projectId: string
  targetId: string | null
  targetName: string | null
  open: boolean
  onClose: () => void
  startResearch: ReturnType<typeof useStartResearch>
}) {
  const [error, setError] = useState<string | null>(null)
  if (!open || !targetId) return null
  const onStart = async () => {
    setError(null)
    try {
      const run = await startResearch.mutateAsync({ projectId, targetId })
      onClose()
      window.location.href = `/research/runs/${run.research_id}`
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Start failed')
    }
  }
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="w-full max-w-md rounded-lg border border-white/10 bg-card p-5 shadow-2xl">
        <div className="mb-3 flex items-start gap-2">
          <GitBranch className="mt-0.5 h-4 w-4 text-primary" />
          <div>
            <h3 className="text-sm font-semibold">Start research on {targetName ?? targetId}</h3>
            <p className="mt-1 text-xs text-muted-foreground">
              Runs the full LangGraph pipeline: planner → recon → reverse → hypothesis → ranking →
              evidence → QA → reporter. Phase 0/1 returns a static-research report synchronously.
            </p>
          </div>
        </div>
        {error && <p className="mb-2 text-[11px] text-rose-400">{error}</p>}
        <div className="mt-4 flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button onClick={onStart} disabled={startResearch.isPending}>
            {startResearch.isPending ? 'Starting…' : 'Start research'}
          </Button>
        </div>
      </div>
    </div>
  )
}
