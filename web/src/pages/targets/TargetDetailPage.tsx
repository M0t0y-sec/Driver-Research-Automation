import { Link, useParams } from 'react-router-dom'
import { useTarget, useStartResearch } from '@/hooks/queries'
import { PageHeader } from '@/components/common/PageHeader'
import { SectionCard, MetricRow } from '@/components/common/KpiCard'
import { ErrorView, LoadingView } from '@/components/common/StateViews'
import { Button } from '@/components/ui/button'
import { IdLink } from '@/components/common/IdLink'
import { Activity, ExternalLink, FileText } from 'lucide-react'
import { useState } from 'react'

export default function TargetDetailPage() {
  const { id } = useParams<{ id: string }>()
  const target = useTarget(id)
  const start = useStartResearch()
  const [error, setError] = useState<string | null>(null)

  if (target.isLoading) return <LoadingView rows={3} />
  if (target.isError || !target.data) return <ErrorView message="Target not found." onRetry={() => target.refetch()} />
  const t = target.data

  const onStart = async () => {
    setError(null)
    try {
      const run = await start.mutateAsync({ projectId: t.project_id, targetId: t.id })
      window.location.href = `/research/runs/${run.research_id}`
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Start failed')
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader title={t.name} subtitle={t.id} backButton />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <SectionCard title="Identity" description="File & submission metadata.">
          <MetricRow label="ID" value={<IdLink id={t.id} />} />
          <MetricRow label="Project" value={<IdLink id={t.project_id} />} />
          <MetricRow label="Display name" value={t.name} />
          <MetricRow label="File type" value={<span className="uppercase font-mono text-xs">{t.file_type}</span>} />
          <MetricRow label="Size" value={`${t.size} B`} />
          <MetricRow label="Authorized" value={t.authorized_use ? 'Yes' : 'No'} />
          <MetricRow label="Submitted" value={t.submitted_at} />
        </SectionCard>

        <SectionCard title="SHA-256" description="Content hash; the canonical id of the sample.">
          <pre className="break-all rounded-md border border-white/5 bg-white/[0.03] p-3 font-mono text-[11px] leading-relaxed">
            {t.sha256}
          </pre>
          <div className="mt-3 text-[11px] text-muted-foreground">
            Stored at: <code className="font-mono">{t.path}</code>
          </div>
        </SectionCard>

        <SectionCard
          title="Actions"
          description="Run the full LangGraph pipeline against this target."
          actions={
            <Button onClick={onStart} disabled={start.isPending || !t.authorized_use}>
              <Activity className="h-4 w-4" />
              {start.isPending ? 'Starting…' : 'Start research'}
            </Button>
          }
        >
          <p className="text-xs text-muted-foreground">
            Phase 0/1 returns a static-research report synchronously. The result links here from the
            Research Run page.
          </p>
          {error && <p className="mt-3 text-[11px] text-rose-400">{error}</p>}
          {!t.authorized_use && (
            <p className="mt-3 rounded-md border border-warning/30 bg-warning/5 px-3 py-2 text-[11px] text-warning">
              This target's project is not marked authorized. The Tool Gateway will block all high-risk
              tool calls.
            </p>
          )}
        </SectionCard>
      </div>
    </div>
  )
}
