import { Link, useParams, useSearchParams } from 'react-router-dom'
import { useFinding, useFindingChain, useFindingReplay } from '@/hooks/queries'
import { PageHeader } from '@/components/common/PageHeader'
import { SectionCard, MetricRow } from '@/components/common/KpiCard'
import { ErrorView, LoadingView } from '@/components/common/StateViews'
import { FindingStatusBadge, QADecisionBadge, SeverityBadge } from '@/components/common/StatusBadge'
import { IdLink } from '@/components/common/IdLink'
import { LineageGraph } from '@/components/common/LineageGraph'
import { LineageList } from '@/components/common/LineageChips'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Link2, ListTree, Repeat } from 'lucide-react'
import type { ReactNode } from 'react'

function asReactNode(v: unknown): ReactNode {
  if (v === null || v === undefined) return '—'
  if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') return String(v)
  return JSON.stringify(v)
}

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>()
  const [searchParams] = useSearchParams()
  const tabFromUrl = searchParams.get('tab') || 'overview'
  const f = useFinding(id)
  const chain = useFindingChain(id)
  const replay = useFindingReplay(id)

  if (f.isLoading) return <LoadingView />
  if (f.isError || !f.data) return <ErrorView message="Finding not found." onRetry={() => f.refetch()} />
  const finding = f.data

  return (
    <div className="space-y-6">
      <PageHeader
        title={finding.title}
        subtitle={finding.summary}
        backButton
        actions={
          <div className="flex items-center gap-2">
            <Button asChild size="sm" variant="outline" className="h-7 text-xs">
              <Link to={`/findings/${finding.id}/evidence-chain`} title="Open evidence chain in full view">
                <Link2 className="mr-1 h-3.5 w-3.5" /> Evidence chain
              </Link>
            </Button>
            <Button asChild size="sm" variant="outline" className="h-7 text-xs">
              <Link to={`/findings/${finding.id}/replay-bundle`} title="Open replay bundle">
                <Repeat className="mr-1 h-3.5 w-3.5" /> Replay
              </Link>
            </Button>
            <Button asChild size="sm" variant="ghost" className="h-7 text-xs">
              <Link to={`/findings/${finding.id}?tab=lineage`} title="Jump to lineage tab">
                <ListTree className="mr-1 h-3.5 w-3.5" /> Lineage
              </Link>
            </Button>
            <SeverityBadge severity={finding.severity} />
            <FindingStatusBadge status={finding.status} />
            <QADecisionBadge decision={(finding.qa_status || 'inconclusive') as 'pass' | 'retry' | 'reject' | 'inconclusive'} />
          </div>
        }
      />

      <Tabs defaultValue={tabFromUrl} key={tabFromUrl}>
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="repro">Reproduction</TabsTrigger>
          <TabsTrigger value="evidence">Evidence chain</TabsTrigger>
          <TabsTrigger value="lineage">Lineage</TabsTrigger>
          <TabsTrigger value="qa">QA</TabsTrigger>
          <TabsTrigger value="replay">Replay</TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            <SectionCard title="Identity" description="What this finding represents.">
              <MetricRow label="ID" value={<IdLink id={finding.id} />} />
              <MetricRow label="Project" value={<IdLink id={finding.project_id} />} />
              <MetricRow label="Target" value={<IdLink id={finding.target_id} />} />
              <MetricRow label="Class" value={finding.vulnerability_class} />
              <MetricRow label="CWE" value={finding.cwe.length > 0 ? finding.cwe.join(', ') : '—'} />
              <MetricRow label="Severity" value={<SeverityBadge severity={finding.severity} />} />
              <MetricRow label="Attack vector" value={finding.attack_vector} />
              <MetricRow label="Required privilege" value={finding.required_privilege} />
              <MetricRow label="User interaction" value={finding.user_interaction} />
              <MetricRow label="Confidence" value={finding.confidence} />
              <MetricRow label="Disclosure status" value={finding.disclosure_status} />
            </SectionCard>

            <SectionCard title="Root cause / impact" description="Cross-link IDs (Phase 0/1 are stubs).">
              <MetricRow label="Root cause" value={finding.root_cause_id ? <IdLink id={finding.root_cause_id} /> : '—'} />
              <MetricRow label="Impact" value={finding.impact_id ? <IdLink id={finding.impact_id} /> : '—'} />
              <MetricRow label="Exploitability" value={finding.exploitability_id ? <IdLink id={finding.exploitability_id} /> : '—'} />
              <MetricRow label="Trigger condition" value={finding.trigger_condition ?? '—'} />
            </SectionCard>

            <SectionCard title="Counts" description="Linked entities in the chain.">
              <MetricRow label="Evidence" value={finding.evidence_ids.length} />
              <MetricRow label="Crashes" value={finding.crash_ids.length} />
              <MetricRow label="Experiments" value={finding.experiment_ids.length} />
              <MetricRow label="Executions" value={finding.execution_ids.length} />
              <MetricRow label="Telemetry" value={finding.telemetry_ids.length} />
              <MetricRow label="Lineage" value={finding.lineage_ids.length} />
              <MetricRow label="QA review" value={finding.qa_review_id ? <IdLink id={finding.qa_review_id} /> : '—'} />
            </SectionCard>
          </div>

          {finding.limitations.length > 0 && (
            <SectionCard title="Limitations" description="Explicitly listed by the platform.">
              <ul className="list-disc space-y-1 pl-5 text-xs text-amber-300/90">
                {finding.limitations.map((l, i) => <li key={i}>{l}</li>)}
              </ul>
            </SectionCard>
          )}

          {finding.remediation && (
            <SectionCard title="Remediation" description="Suggested mitigation.">
              <p className="text-sm text-foreground/90">{finding.remediation}</p>
            </SectionCard>
          )}
        </TabsContent>

        <TabsContent value="repro">
          <SectionCard title="Reproduction steps">
            {finding.repro_steps.length > 0 ? (
              <ol className="list-decimal space-y-2 pl-5 text-sm text-foreground/90">
                {finding.repro_steps.map((s, i) => <li key={i}>{s}</li>)}
              </ol>
            ) : (
              <p className="text-xs text-muted-foreground">No reproduction steps recorded.</p>
            )}
          </SectionCard>
        </TabsContent>

        <TabsContent value="evidence">
          {chain.isLoading || !chain.data ? (
            <LoadingView rows={3} />
          ) : (
            <div className="space-y-4">
              <SectionCard title="Evidence" description="Cited by this finding.">
                <LineageList nodes={chain.data.evidences.map((e) => ({ id: e.id, type: 'evidence', label: e.evidence_type }))} />
              </SectionCard>
              <SectionCard title="Evidence detail">
                <div className="space-y-2">
                  {chain.data.evidences.map((e) => (
                    <Card key={e.id} className="p-3">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className="font-mono text-xs text-primary"><IdLink id={e.id} /></div>
                          <div className="mt-1 text-xs text-foreground/80">{e.summary}</div>
                          <div className="mt-1 text-[10px] text-muted-foreground">
                            {e.evidence_type} · producer={e.producer_agent} · tool_version={e.tool_version ?? '—'} · qa={e.qa_status}
                          </div>
                        </div>
                      </div>
                    </Card>
                  ))}
                </div>
              </SectionCard>
            </div>
          )}
        </TabsContent>

        <TabsContent value="lineage">
          {chain.data && chain.data.lineage.nodes.length > 0 ? (
            <LineageGraph lineage={chain.data.lineage} />
          ) : (
            <div className="rounded-lg border border-dashed px-6 py-8 text-center text-xs text-muted-foreground">No lineage nodes.</div>
          )}
        </TabsContent>

        <TabsContent value="qa">
          {chain.data && chain.data.evidences.length > 0 ? (
            <SectionCard title="QA review" description="Rule-based + LLM review.">
              <div className="text-sm text-foreground/90">
                <p>Decision: <span className="font-semibold">{finding.qa_status}</span></p>
                {finding.qa_review_id && (
                  <p className="mt-1 text-xs text-muted-foreground">Review: <IdLink id={finding.qa_review_id} /></p>
                )}
              </div>
            </SectionCard>
          ) : (
            <LoadingView rows={2} />
          )}
        </TabsContent>

        <TabsContent value="replay">
          <SectionCard title="Replay bundle" description="Phase 0/1: replay execution is not implemented.">
            {replay.data ? (
              <div className="space-y-2 text-xs text-muted-foreground">
                <p>{replay.data.replay_supported ? 'Replay is supported.' : 'Replay is not yet supported in this phase.'}</p>
                {typeof replay.data.reason === 'string' && <p className="text-amber-300">{replay.data.reason}</p>}
                <pre className="overflow-x-auto rounded-md border border-white/5 bg-white/[0.03] p-3 font-mono text-[10px]">
                  {JSON.stringify(replay.data, null, 2)}
                </pre>
              </div>
            ) : (
              <LoadingView rows={2} />
            )}
          </SectionCard>
        </TabsContent>
      </Tabs>
    </div>
  )
}
