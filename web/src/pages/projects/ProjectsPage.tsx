import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, Boxes } from 'lucide-react'
import { useProjects } from '@/hooks/queries'
import { PageHeader } from '@/components/common/PageHeader'
import { DataTable, type Column } from '@/components/common/DataTable'
import { IdLink } from '@/components/common/IdLink'
import { LoadingView, ErrorView, EmptyView } from '@/components/common/StateViews'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { NewProjectDialog } from '@/components/common/NewProjectDialog'
import { formatRelative } from '@/lib/utils'
import type { Project } from '@/types'

const columns: Column<Project>[] = [
  {
    key: 'id',
    header: 'ID',
    render: (r) => <IdLink id={r.id} />,
    sortValue: (r) => r.id,
  },
  {
    key: 'name',
    header: 'Name',
    render: (r) => <span className="font-medium">{r.name}</span>,
    sortValue: (r) => r.name,
  },
  {
    key: 'authorized',
    header: 'Authorization',
    render: (r) =>
      r.authorized_use ? (
        <Badge className="border-emerald-500/30 bg-emerald-500/10 text-emerald-300">
          Authorized
        </Badge>
      ) : (
        <Badge className="border-border bg-secondary text-muted-foreground">No</Badge>
      ),
    sortValue: (r) => (r.authorized_use ? 1 : 0),
  },
  {
    key: 'auth_ref',
    header: 'Auth ref',
    render: (r) => <span className="font-mono text-xs text-muted-foreground">{r.authorization_ref ?? '—'}</span>,
    sortValue: (r) => r.authorization_ref ?? '',
  },
  {
    key: 'tags',
    header: 'Tags',
    render: (r) =>
      r.tags.length > 0 ? (
        <div className="flex flex-wrap gap-1">
          {r.tags.map((t) => (
            <Badge key={t} className="border-white/10 bg-white/[0.04] text-muted-foreground">
              {t}
            </Badge>
          ))}
        </div>
      ) : (
        <span className="text-xs text-muted-foreground">—</span>
      ),
  },
  {
    key: 'created',
    header: 'Created',
    render: (r) => <span className="text-xs text-muted-foreground">{formatRelative(r.created_at)}</span>,
    sortValue: (r) => new Date(r.created_at).getTime(),
  },
]

export default function ProjectsPage() {
  const navigate = useNavigate()
  const { data, isLoading, isError, refetch } = useProjects()
  const [open, setOpen] = useState(false)

  if (isLoading) return <LoadingView />
  if (isError) return <ErrorView onRetry={() => refetch()} />

  return (
    <div className="space-y-4">
      <PageHeader
        title="Projects"
        subtitle="All research projects in this workspace"
        actions={
          <Button size="sm" onClick={() => setOpen(true)}>
            <Plus className="h-3.5 w-3.5" /> New project
          </Button>
        }
      />
      {(data ?? []).length === 0 ? (
        <EmptyView
          title="No projects yet"
          message="Start by creating an authorized research project."
          action={
            <Button onClick={() => setOpen(true)}>
              <Boxes className="h-4 w-4" /> Create your first project
            </Button>
          }
        />
      ) : (
        <DataTable
          data={data ?? []}
          columns={columns}
          initialSortKey="created"
          onRowClick={(row) => navigate(`/projects/${row.id}`)}
        />
      )}
      <NewProjectDialog open={open} onOpenChange={setOpen} />
    </div>
  )
}
