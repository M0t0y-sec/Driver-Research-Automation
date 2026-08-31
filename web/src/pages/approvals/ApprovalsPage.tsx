import { useState } from 'react'
import { useApprovals, usePendingApprovals, useDecideApproval, useProjects } from '@/hooks/queries'
import { PageHeader } from '@/components/common/PageHeader'
import { DataTable, type Column } from '@/components/common/DataTable'
import { SectionCard } from '@/components/common/KpiCard'
import { LoadingView, ErrorView } from '@/components/common/StateViews'
import { ToolRunStatusBadge, RiskBadge } from '@/components/common/StatusBadge'
import { CopyableText } from '@/components/common/IdLink'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { formatRelative } from '@/lib/utils'
import { toast } from '@/components/common/Toaster'
import { ShieldCheck, ShieldX } from 'lucide-react'
import type { Approval } from '@/types'

export default function ApprovalsPage() {
  const projects = useProjects()
  const [projectFilter, setProjectFilter] = useState<string>('')
  const all = useApprovals(projectFilter || undefined)
  const pending = usePendingApprovals(projectFilter || undefined)
  const decide = useDecideApproval()
  const [reasonByApproval, setReasonByApproval] = useState<Record<string, string>>({})

  if (all.isLoading || pending.isLoading) return <LoadingView />
  if (all.isError) return <ErrorView onRetry={() => all.refetch()} />

  const onDecide = async (a: Approval, decision: 'approved' | 'rejected') => {
    try {
      await decide.mutateAsync({
        id: a.id,
        decision,
        decided_by: 'security_researcher',
        notes: reasonByApproval[a.id],
      })
      toast(`Approval ${decision}`)
    } catch (e) {
      toast(e instanceof Error ? e.message : 'Failed')
    }
  }

  const pendingColumns: Column<Approval>[] = [
    { key: 'tool', header: 'Tool', render: (a) => <span className="font-mono text-xs">{a.tool}</span>, sortValue: (a) => a.tool },
    { key: 'risk', header: 'Risk', render: (a) => <RiskBadge risk={a.risk_level} />, sortValue: (a) => a.risk_level },
    { key: 'requester', header: 'Requester', render: (a) => <span className="text-xs">{a.requester}</span>, sortValue: (a) => a.requester },
    { key: 'just', header: 'Justification', render: (a) => <span className="line-clamp-1 max-w-[18rem] text-xs text-muted-foreground">{a.justification}</span> },
    { key: 'params', header: 'Parameters', render: (a) => <CopyableText value={JSON.stringify(a.parameters).slice(0, 60) + '…'} className="max-w-[12rem]" /> },
    {
      key: 'decide',
      header: 'Decision',
      align: 'right',
      className: 'whitespace-nowrap',
      render: (a) => (
        <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
          <Input
            value={reasonByApproval[a.id] ?? ''}
            onChange={(e) => setReasonByApproval((s) => ({ ...s, [a.id]: e.target.value }))}
            placeholder="note…"
            className="h-7 w-28 text-xs"
            title="Optional note saved with your decision"
          />
          <Button size="sm" variant="outline" onClick={() => onDecide(a, 'rejected')} className="h-7 px-2 text-xs">
            <ShieldX className="mr-1 h-3.5 w-3.5 text-rose-400" /> Reject
          </Button>
          <Button size="sm" onClick={() => onDecide(a, 'approved')} className="h-7 px-2 text-xs">
            <ShieldCheck className="mr-1 h-3.5 w-3.5 text-emerald-400" /> Approve
          </Button>
        </div>
      ),
    },
  ]

  const allColumns: Column<Approval>[] = [
    { key: 'tool', header: 'Tool', render: (a) => <span className="font-mono text-xs">{a.tool}</span>, sortValue: (a) => a.tool },
    { key: 'risk', header: 'Risk', render: (a) => <RiskBadge risk={a.risk_level} />, sortValue: (a) => a.risk_level },
    { key: 'requester', header: 'Requester', render: (a) => <span className="text-xs">{a.requester}</span>, sortValue: (a) => a.requester },
    { key: 'decision', header: 'Decision', render: (a) => <ToolRunStatusBadge status={a.decision === 'pending' ? 'needs_approval' : a.decision === 'approved' || a.decision === 'auto_approved' ? 'succeeded' : a.decision === 'rejected' ? 'blocked_by_policy' : 'cancelled'} />, sortValue: (a) => a.decision },
    { key: 'decided_by', header: 'Decided by', render: (a) => <span className="text-xs">{a.decided_by ?? '—'}</span>, sortValue: (a) => a.decided_by ?? '' },
    { key: 'when', header: 'Decided at', render: (a) => <span className="text-xs text-muted-foreground">{a.decided_at ? formatRelative(a.decided_at) : formatRelative(a.created_at)}</span>, sortValue: (a) => a.decided_at ? new Date(a.decided_at).getTime() : new Date(a.created_at).getTime() },
  ]

  return (
    <div className="space-y-4">
      <PageHeader
        title="Approval Center"
        subtitle="HIGH / EXTREME risk tool calls awaiting human review."
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

      <SectionCard
        title="Pending"
        description={`${(pending.data ?? []).length} HIGH/EXTREME tool calls awaiting decision`}
      >
        <DataTable
          data={pending.data ?? []}
          columns={pendingColumns}
          emptyMessage="No pending approvals."
        />
      </SectionCard>

      <SectionCard title="History" description="All approval records, most recent first.">
        <DataTable
          data={all.data ?? []}
          columns={allColumns}
          initialSortKey="when"
          emptyMessage="No approval history yet."
        />
      </SectionCard>
    </div>
  )
}
