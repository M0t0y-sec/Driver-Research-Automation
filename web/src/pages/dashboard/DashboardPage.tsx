import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Bug,
  Boxes,
  FlaskConical,
  Lightbulb,
  Plus,
  ShieldCheck,
  Target as TargetIcon,
} from 'lucide-react'
import { useDashboard, useResearchList, usePendingApprovals } from '@/hooks/queries'
import { PageHeader } from '@/components/common/PageHeader'
import { KpiCard, SectionCard, MetricRow } from '@/components/common/KpiCard'
import { CardGridSkeleton, ErrorView, LoadingView } from '@/components/common/StateViews'
import { DataTable, type Column } from '@/components/common/DataTable'
import { RunStatusBadge, ToolRunStatusBadge } from '@/components/common/StatusBadge'
import { IdLink } from '@/components/common/IdLink'
import { Button } from '@/components/ui/button'
import { NewProjectDialog } from '@/components/common/NewProjectDialog'
import { NewTargetDialog } from '@/components/common/NewTargetDialog'
import { formatRelative } from '@/lib/utils'
import type { ResearchRun, Approval } from '@/types'

export default function DashboardPage() {
  const navigate = useNavigate()
  const { data: stats, isLoading, isError, refetch } = useDashboard()
  const { data: runs } = useResearchList()
  const { data: pending } = usePendingApprovals()
  const [showNewProject, setShowNewProject] = useState(false)
  const [showNewTarget, setShowNewTarget] = useState(false)

  if (isLoading) {
    return (
      <div className="space-y-6">
        <LoadingView rows={2} />
        <CardGridSkeleton count={5} />
      </div>
    )
  }
  if (isError || !stats) {
    return <ErrorView message="Dashboard statistics unavailable." onRetry={() => refetch()} />
  }

  const runColumns: Column<ResearchRun>[] = [
    {
      key: 'id',
      header: 'Run',
      render: (r) => <IdLink id={r.research_id} label={r.research_id} />,
      sortValue: (r) => r.research_id,
    },
    {
      key: 'project',
      header: 'Project',
      render: (r) => <IdLink id={r.project_id} />,
      sortValue: (r) => r.project_id,
    },
    {
      key: 'target',
      header: 'Target',
      render: (r) => <IdLink id={r.target_id} />,
      sortValue: (r) => r.target_id,
    },
    { key: 'phase', header: 'Phase', render: (r) => <span className="text-xs">{r.current_phase || '—'}</span>, sortValue: (r) => r.current_phase },
    { key: 'node', header: 'Node', render: (r) => <span className="text-xs text-muted-foreground">{r.current_node || '—'}</span>, sortValue: (r) => r.current_node },
    { key: 'status', header: 'Status', render: (r) => <RunStatusBadge status={r.status} spin={r.status === 'running'} />, sortValue: (r) => r.status },
  ]

  const approvalColumns: Column<Approval>[] = [
    {
      key: 'tool',
      header: 'Tool',
      render: (a) => <span className="font-mono text-xs">{a.tool}</span>,
      sortValue: (a) => a.tool,
    },
    {
      key: 'risk',
      header: 'Risk',
      render: (a) => <ToolRunStatusBadge status="needs_approval" />,
      sortValue: (a) => a.risk_level,
    },
    {
      key: 'requester',
      header: 'Requester',
      render: (a) => <span className="text-xs">{a.requester}</span>,
      sortValue: (a) => a.requester,
    },
    {
      key: 'when',
      header: 'Submitted',
      render: (a) => <span className="text-xs text-muted-foreground">{formatRelative(a.created_at)}</span>,
      sortValue: (a) => new Date(a.created_at).getTime(),
    },
  ]

  const activeRuns = (runs ?? []).filter((r) => r.status === 'running' || r.status === 'paused' || r.status === 'waiting_approval')
  const recentRuns = (runs ?? []).slice(0, 8)

  return (
    <div className="space-y-6">
      <PageHeader
        title="DRA — Security Research Overview"
        subtitle="Static research platform with evidence-driven findings, isolated Lab, and detection evaluation."
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => setShowNewTarget(true)}>
              <TargetIcon className="h-4 w-4" /> Upload sample
            </Button>
            <Button size="sm" onClick={() => setShowNewProject(true)}>
              <Plus className="h-4 w-4" /> New project
            </Button>
          </div>
        }
      />

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5">
        <KpiCard label="Projects" value={String(stats.projects).padStart(2, '0')} icon={<Boxes className="h-4 w-4" />} onClick={() => navigate('/projects')} />
        <KpiCard label="Hypotheses" value={String(stats.hypotheses).padStart(2, '0')} sub="across all projects" icon={<Lightbulb className="h-4 w-4" />} onClick={() => navigate('/hypotheses')} />
        <KpiCard label="Tool runs" value={String(stats.tool_runs).padStart(2, '0')} sub={`${stats.research_runs} research runs`} icon={<FlaskConical className="h-4 w-4" />} onClick={() => navigate('/experiments')} />
        <KpiCard label="Findings" value={String(stats.findings).padStart(2, '0')} sub={`${stats.qa_reviews} QA reviews`} icon={<Bug className="h-4 w-4" />} onClick={() => navigate('/findings')} />
        <KpiCard label="Pending Approvals" value={String(stats.pending_approvals).padStart(2, '0')} sub="HIGH/EXTREME risk" icon={<ShieldCheck className="h-4 w-4" />} onClick={() => navigate('/approvals')} />
      </div>

      <SectionCard
        title="Active research runs"
        description={`${activeRuns.length} running, ${(runs ?? []).length} total`}
        actions={<Button variant="ghost" size="sm" onClick={() => navigate('/research/runs')}>View all</Button>}
      >
        <DataTable
          data={recentRuns}
          columns={runColumns}
          initialSortKey="phase"
          onRowClick={(r) => navigate(`/research/runs/${r.research_id}`)}
          emptyMessage="No research runs yet — create a project and upload a sample to start."
        />
      </SectionCard>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <SectionCard
            title="Pending approvals"
            description="Tool requests waiting for human review."
            actions={<Button variant="ghost" size="sm" onClick={() => navigate('/approvals')}>Approval center</Button>}
          >
            <DataTable
              data={(pending ?? []).slice(0, 6)}
              columns={approvalColumns}
              initialSortKey="when"
              emptyMessage="No pending approvals."
            />
          </SectionCard>
        </div>
        <SectionCard title="Aggregate" description="Counts across all projects.">
          <div className="space-y-0">
            <MetricRow label="Targets" value={stats.targets} />
            <MetricRow label="Research runs" value={stats.research_runs} />
            <MetricRow label="Hypotheses" value={stats.hypotheses} />
            <MetricRow label="Evidence" value={stats.evidence} />
            <MetricRow label="Findings" value={stats.findings} />
            <MetricRow label="QA reviews" value={stats.qa_reviews} />
            <MetricRow label="Tool runs" value={stats.tool_runs} />
            <MetricRow label="Pending approvals" value={stats.pending_approvals} />
          </div>
        </SectionCard>
      </div>

      <NewProjectDialog open={showNewProject} onOpenChange={setShowNewProject} />
      <NewTargetDialog open={showNewTarget} onOpenChange={setShowNewTarget} />
    </div>
  )
}
