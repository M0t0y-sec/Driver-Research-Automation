import { useHealth } from '@/hooks/queries'
import { PageHeader } from '@/components/common/PageHeader'
import { SectionCard, MetricRow } from '@/components/common/KpiCard'
import { LoadingView, ErrorView } from '@/components/common/StateViews'
import { Card } from '@/components/ui/card'

export default function SettingsPage() {
  const health = useHealth()
  if (health.isLoading) return <LoadingView />
  if (health.isError || !health.data) return <ErrorView onRetry={() => health.refetch()} />
  const h = health.data

  return (
    <div className="space-y-6">
      <PageHeader
        title="System"
        subtitle="Backend health, paths, and version."
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <SectionCard title="Health" description="What the server reports about itself.">
          <MetricRow label="Status" value={<span className={h.status === 'ok' ? 'text-emerald-400' : 'text-rose-400'}>{h.status}</span>} />
          <MetricRow label="Version" value={<span className="font-mono text-xs">{h.version}</span>} />
          <MetricRow label="LangGraph" value={h.langgraph} />
          <MetricRow label="Auth mode" value={h.auth_mode} />
          <MetricRow label="LLM provider" value={h.llm_provider} />
          <MetricRow label="Lab provider" value={h.lab_provider} />
        </SectionCard>

        <SectionCard title="Paths" description="Where the platform reads / writes.">
          <MetricRow label="Data dir" value={<code className="font-mono text-[11px]">{h.data_dir}</code>} />
          <MetricRow label="Artifacts dir" value={<code className="font-mono text-[11px]">{h.artifacts_dir}</code>} />
        </SectionCard>
      </div>

      <SectionCard title="Architecture" description="Source of truth lives in the integration plan.">
        <p className="text-xs text-muted-foreground">
          The frontend is a Vite + React + TypeScript SPA that talks to the FastAPI server through the
          <code className="mx-1 rounded bg-white/[0.05] px-1 py-0.5 font-mono text-[11px]">/api</code>
          proxy. State is owned by TanStack Query; auth is Phase 2+. The full design is in
          <code className="mx-1 rounded bg-white/[0.05] px-1 py-0.5 font-mono text-[11px]">DRA — Driver Research Automation 整合方案 v2.md</code>.
        </p>
      </SectionCard>
    </div>
  )
}
