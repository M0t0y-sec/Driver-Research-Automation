import { useLabHealth, useLabSnapshots, useLabVms } from '@/hooks/queries'
import { PageHeader } from '@/components/common/PageHeader'
import { SectionCard, MetricRow } from '@/components/common/KpiCard'
import { DataTable, type Column } from '@/components/common/DataTable'
import { LoadingView, ErrorView } from '@/components/common/StateViews'
import { CheckCircle2, XCircle, MonitorSmartphone, Camera, Cpu } from 'lucide-react'

interface CheckRow { key: string; value: string }
interface VmRow extends Record<string, unknown> { vm_id: string; state: string; fingerprint: string }
interface SnapRow extends Record<string, unknown> { snapshot_id: string; vm_fingerprint: string }

export default function LabPage() {
  const health = useLabHealth()
  const vms = useLabVms()
  const snaps = useLabSnapshots()

  if (health.isLoading) return <LoadingView />
  if (health.isError) return <ErrorView onRetry={() => health.refetch()} />
  const h = health.data!
  const checks: CheckRow[] = Object.entries(h.checks || {}).map(([k, v]) => ({ key: k, value: String(v) }))

  return (
    <div className="space-y-6">
      <PageHeader
        title="Windows Lab"
        subtitle="Isolated VM pool for executing experiments. Phase 0/1 is mock; real Hyper-V/VMware/libvirt support is Phase 2+."
      />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <SectionCard title="Health" description="Snapshot of the lab provider.">
          <div className="flex items-center gap-2">
            {h.passed ? (
              <CheckCircle2 className="h-5 w-5 text-emerald-400" />
            ) : (
              <XCircle className="h-5 w-5 text-rose-400" />
            )}
            <span className="text-sm font-semibold">{h.passed ? 'PASS' : 'FAIL'}</span>
            <span className="ml-auto font-mono text-xs text-muted-foreground">{h.provider}</span>
          </div>
          <div className="mt-3 space-y-0">
            <MetricRow label="Provider" value={h.provider} />
            <MetricRow label="VM fingerprint" value={<span className="font-mono text-[10px]">{h.vm_fingerprint ?? '—'}</span>} />
            <MetricRow label="Passed" value={h.passed ? 'Yes' : 'No'} />
          </div>
          <p className="mt-3 text-[11px] text-muted-foreground">{h.notes}</p>
        </SectionCard>

        <SectionCard title="Health checks" description="Snapshot integrity / signing / telemetry state.">
          {checks.length > 0 ? (
            <DataTable<CheckRow>
              data={checks}
              columns={[
                { key: 'key', header: 'Check', render: (r) => <span className="font-mono text-xs">{r.key}</span>, sortValue: (r) => r.key },
                { key: 'value', header: 'Value', render: (r) => <span className="font-mono text-xs">{r.value}</span>, sortValue: (r) => r.value },
              ]}
              initialSortKey="key"
              emptyMessage="No health checks."
            />
          ) : (
            <p className="text-xs text-muted-foreground">No checks reported.</p>
          )}
        </SectionCard>

        <SectionCard title="Summary" description="Counts of lab resources.">
          <MetricRow label="VMs ready" value={(vms.data ?? []).length} />
          <MetricRow label="Snapshots" value={(snaps.data ?? []).length} />
          <MetricRow label="Provider" value={h.provider} />
        </SectionCard>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <SectionCard title="VMs" description="Available VMs in the pool.">
          <DataTable<VmRow>
            data={(vms.data ?? []).map((v) => ({ vm_id: v.vm_id, state: v.state, fingerprint: v.fingerprint }))}
            columns={[
              { key: 'id', header: 'VM', render: (v) => <span className="font-mono text-xs">{v.vm_id}</span>, sortValue: (v) => v.vm_id },
              { key: 'state', header: 'State', render: (v) => <span className="text-xs">{v.state}</span>, sortValue: (v) => v.state },
              { key: 'fingerprint', header: 'Fingerprint', render: (v) => <span className="font-mono text-[10px] text-muted-foreground">{v.fingerprint}</span>, sortValue: (v) => v.fingerprint },
            ]}
            initialSortKey="id"
            emptyMessage="No VMs in the pool."
          />
        </SectionCard>

        <SectionCard title="Snapshots" description="Golden / per-experiment snapshots.">
          <DataTable<SnapRow>
            data={(snaps.data ?? []).map((s) => ({ snapshot_id: s.snapshot_id, vm_fingerprint: s.vm_fingerprint }))}
            columns={[
              { key: 'id', header: 'Snapshot', render: (s) => <span className="font-mono text-xs">{s.snapshot_id}</span>, sortValue: (s) => s.snapshot_id },
              { key: 'vm', header: 'Fingerprint', render: (s) => <span className="font-mono text-[10px] text-muted-foreground">{s.vm_fingerprint}</span>, sortValue: (s) => s.vm_fingerprint },
            ]}
            initialSortKey="id"
            emptyMessage="No snapshots."
          />
        </SectionCard>
      </div>
    </div>
  )
}
