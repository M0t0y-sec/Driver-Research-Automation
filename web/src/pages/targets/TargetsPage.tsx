import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTargets, useProjects } from '@/hooks/queries'
import { PageHeader } from '@/components/common/PageHeader'
import { DataTable, type Column } from '@/components/common/DataTable'
import { IdLink } from '@/components/common/IdLink'
import { LoadingView, ErrorView, EmptyView } from '@/components/common/StateViews'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { NewTargetDialog } from '@/components/common/NewTargetDialog'
import { formatRelative } from '@/lib/utils'
import type { Target as TargetType } from '@/types'
import { Plus, UploadCloud } from 'lucide-react'

export default function TargetsPage() {
  const navigate = useNavigate()
  const projects = useProjects()
  const [projectFilter, setProjectFilter] = useState<string>('')
  const targets = useTargets(projectFilter || undefined)
  const [showUpload, setShowUpload] = useState(false)

  if (targets.isLoading) return <LoadingView />
  if (targets.isError) return <ErrorView onRetry={() => targets.refetch()} />

  const authorizedCount = (projects.data ?? []).filter((p) => p.authorized_use).length

  const columns: Column<TargetType>[] = [
    { key: 'id', header: 'ID', render: (t) => <IdLink id={t.id} />, sortValue: (t) => t.id },
    { key: 'name', header: 'Name', render: (t) => <span className="font-medium">{t.name}</span>, sortValue: (t) => t.name },
    { key: 'project', header: 'Project', render: (t) => <IdLink id={t.project_id} />, sortValue: (t) => t.project_id },
    { key: 'sha', header: 'SHA-256', render: (t) => <span className="font-mono text-[10px] text-muted-foreground">{t.sha256.slice(0, 24)}…</span>, sortValue: (t) => t.sha256 },
    { key: 'size', header: 'Size', align: 'right', render: (t) => <span className="font-mono text-xs">{t.size} B</span>, sortValue: (t) => t.size },
    { key: 'type', header: 'File', render: (t) => <Badge className="border-white/10 bg-white/[0.04] text-muted-foreground uppercase font-mono text-[10px]">{t.file_type}</Badge>, sortValue: (t) => t.file_type },
    { key: 'submitted', header: 'Submitted', render: (t) => <span className="text-xs text-muted-foreground">{formatRelative(t.submitted_at)}</span>, sortValue: (t) => new Date(t.submitted_at).getTime() },
  ]

  return (
    <div className="space-y-4">
      <PageHeader
        title="Targets"
        subtitle="All uploaded driver samples"
        actions={
          <div className="flex items-center gap-2">
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
            <Button
              size="sm"
              onClick={() => setShowUpload(true)}
              disabled={authorizedCount === 0}
              title={authorizedCount === 0 ? 'Create an authorized project first' : undefined}
            >
              <Plus className="h-3.5 w-3.5" /> Upload
            </Button>
          </div>
        }
      />
      {(targets.data ?? []).length === 0 ? (
        <EmptyView
          title="No samples uploaded yet"
          message={authorizedCount === 0 ? 'Create an authorized project to enable uploads.' : 'Upload a driver sample to begin research.'}
          action={
            <Button onClick={() => setShowUpload(true)} disabled={authorizedCount === 0}>
              <UploadCloud className="h-4 w-4" /> Upload your first sample
            </Button>
          }
        />
      ) : (
        <DataTable
          data={targets.data ?? []}
          columns={columns}
          initialSortKey="submitted"
          onRowClick={(row) => navigate(`/targets/${row.id}`)}
        />
      )}
      <NewTargetDialog open={showUpload} onOpenChange={setShowUpload} />
    </div>
  )
}
