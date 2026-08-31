import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import {
  AlertTriangle,
  CheckCircle2,
  CircleDashed,
  Clock,
  CirclePause,
  CircleX,
  Loader2,
  ShieldAlert,
  ShieldQuestion,
} from 'lucide-react'
import type { ReactNode } from 'react'
import {
  type FindingStatus,
  type HypothesisStatus,
  type ToolRunStatus,
  type QADecision,
  type Severity,
  type DetectionVerdict,
  type RiskLevel,
  type EvidenceStrength,
  type AttackActor,
  type Status as RunStatus,
  FINDING_STATUS_META,
  QA_DECISION_META,
  TOOL_RUN_STATUS_META,
  DETECTION_VERDICT_META,
  RISK_META,
  EVIDENCE_STRENGTH_META,
  ATTACK_ACTOR_META,
} from '@/types'

// ---------------------------------------------------------------------------
// Central status system: color is always paired with an icon or dot so state
// is never conveyed by color alone (per accessibility requirement).
// ---------------------------------------------------------------------------

export type StatusTone = 'success' | 'running' | 'warning' | 'danger' | 'neutral' | 'info'

const toneClasses: Record<StatusTone, string> = {
  success: 'border-success/30 bg-success/10 text-success',
  running: 'border-info/30 bg-info/10 text-info',
  warning: 'border-warning/30 bg-warning/10 text-warning',
  danger: 'border-danger/30 bg-danger/10 text-danger',
  neutral: 'border-border bg-secondary text-muted-foreground',
  info: 'border-info/30 bg-info/10 text-info',
}

const toneIcon: Record<StatusTone, ReactNode> = {
  success: <CheckCircle2 className="h-3 w-3" />,
  running: <Loader2 className="h-3 w-3 animate-spin" />,
  warning: <Clock className="h-3 w-3" />,
  danger: <AlertTriangle className="h-3 w-3" />,
  neutral: <CircleDashed className="h-3 w-3" />,
  info: <Loader2 className="h-3 w-3" />,
}

export function StatusBadge({
  status,
  tone,
  className,
  spin = false,
}: {
  status: ReactNode
  tone: StatusTone
  className?: string
  spin?: boolean
}) {
  const icon =
    spin && tone === 'running' ? (
      <Loader2 className="h-3 w-3 animate-spin" />
    ) : (
      toneIcon[tone]
    )
  return (
    <Badge className={cn(toneClasses[tone], 'gap-1', className)}>
      {icon}
      {status}
    </Badge>
  )
}

// ---------- Run / Experiment statuses ----------

export function RunStatusBadge({ status, spin }: { status: RunStatus | string; spin?: boolean }) {
  const map: Record<string, StatusTone> = {
    running: 'running',
    paused: 'warning',
    waiting_approval: 'warning',
    completed: 'success',
    failed: 'danger',
    idle: 'neutral',
    cancelled: 'neutral',
  }
  const tone = map[status] ?? 'neutral'
  return <StatusBadge status={status} tone={tone} spin={spin ?? status === 'running'} />
}

// ---------- Hypothesis statuses ----------

export function HypothesisStatusBadge({ status }: { status: HypothesisStatus | string }) {
  const map: Record<string, StatusTone> = {
    proposed: 'neutral',
    queued: 'info',
    selected: 'info',
    planned: 'info',
    validating: 'running',
    confirmed: 'success',
    rejected: 'danger',
    inconclusive: 'warning',
    needs_human: 'warning',
    archived: 'neutral',
  }
  const tone = map[status] ?? 'neutral'
  return <StatusBadge status={status} tone={tone} spin={status === 'validating'} />
}

// ---------- Experiment statuses ----------

export function ExperimentStatusBadge({ status }: { status: string }) {
  const map: Record<string, StatusTone> = {
    draft: 'neutral',
    needs_approval: 'warning',
    approved: 'info',
    scheduled: 'info',
    preparing: 'info',
    running: 'running',
    collecting: 'info',
    triaging: 'info',
    completed: 'success',
    failed_environment: 'danger',
    failed_target: 'danger',
    failed_telemetry: 'danger',
    inconclusive: 'warning',
    archived: 'neutral',
  }
  const tone = map[status] ?? 'neutral'
  return <StatusBadge status={status} tone={tone} spin={status === 'running'} />
}

// ---------- Finding status ----------

export function FindingStatusBadge({ status }: { status: FindingStatus | string }) {
  const meta = FINDING_STATUS_META[status as FindingStatus] ?? FINDING_STATUS_META.candidate
  return <Badge className={cn(meta.color, 'gap-1 border')}>{meta.label}</Badge>
}

// ---------- QA decision ----------

export function QADecisionBadge({ decision }: { decision: QADecision | string }) {
  const meta = QA_DECISION_META[decision as QADecision] ?? QA_DECISION_META.inconclusive
  return <Badge className={cn(meta.color, 'gap-1 border')}>{meta.label}</Badge>
}

// ---------- Tool run status ----------

export function ToolRunStatusBadge({ status }: { status: ToolRunStatus | string }) {
  const meta = TOOL_RUN_STATUS_META[status as ToolRunStatus] ?? TOOL_RUN_STATUS_META.queued
  return <Badge className={cn(meta.color, 'gap-1 border')}>{meta.label}</Badge>
}

// ---------- Detection verdict ----------

export function DetectionVerdictBadge({ verdict }: { verdict: DetectionVerdict | string }) {
  const meta = DETECTION_VERDICT_META[verdict as DetectionVerdict] ?? DETECTION_VERDICT_META.inconclusive
  return <Badge className={cn(meta.color, 'gap-1 border')}>{meta.label}</Badge>
}

// ---------- Evidence strength ----------

export function EvidenceStrengthBadge({
  strength,
  showLabel = true,
}: {
  strength: EvidenceStrength | string
  showLabel?: boolean
}) {
  const meta = EVIDENCE_STRENGTH_META[strength as EvidenceStrength]
  if (!meta) {
    return <Badge className="border-border bg-secondary text-muted-foreground">{strength}</Badge>
  }
  return (
    <Badge className={cn(meta.color, 'gap-1 border')} title={meta.desc}>
      {showLabel ? meta.label : <span className="font-mono">{strength}</span>}
    </Badge>
  )
}

// ---------- Risk level ----------

export function RiskBadge({ risk }: { risk: RiskLevel | string }) {
  const meta = RISK_META[risk as RiskLevel] ?? RISK_META.low
  return <Badge className={cn(meta.color, 'gap-1 border')}>{meta.label}</Badge>
}

// ---------- Attack actor ----------

export function AttackActorBadge({ actor }: { actor: AttackActor | string }) {
  const meta = ATTACK_ACTOR_META[actor as AttackActor] ?? ATTACK_ACTOR_META.unknown
  return <Badge className={cn(meta.color, 'gap-1 border')}>{meta.label}</Badge>
}

// ---------- Finding severity ----------

const severityClasses: Record<string, string> = {
  critical: 'border-danger/40 bg-danger/15 text-danger',
  high: 'border-danger/30 bg-danger/10 text-red-400',
  medium: 'border-warning/30 bg-warning/10 text-warning',
  low: 'border-info/30 bg-info/10 text-info',
  info: 'border-border bg-secondary text-muted-foreground',
}

const severityIcons: Record<string, ReactNode> = {
  critical: <ShieldAlert className="h-3 w-3" />,
  high: <AlertTriangle className="h-3 w-3" />,
  medium: <AlertTriangle className="h-3 w-3" />,
  low: <CircleDashed className="h-3 w-3" />,
  info: <CircleDashed className="h-3 w-3" />,
}

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  const cls = severityClasses[severity] ?? severityClasses.info
  return (
    <Badge className={cn(cls, 'gap-1 border')}>
      {severityIcons[severity]}
      {severity.toUpperCase()}
    </Badge>
  )
}

// ---------- Confidence / priority meter ----------

export function ConfidenceMeter({ value, label }: { value: number; label?: string }) {
  const pctVal = Math.round(value * 100)
  const tone =
    pctVal >= 85 ? 'bg-success' : pctVal >= 65 ? 'bg-warning' : 'bg-muted-foreground'
  return (
    <div className="flex items-center gap-2">
      <div className="h-1 w-14 overflow-hidden rounded-full bg-secondary">
        <div className={cn('h-full', tone)} style={{ width: `${pctVal}%` }} />
      </div>
      <span className="font-mono text-xs text-muted-foreground">{pctVal}%</span>
      {label && <span className="text-[10px] uppercase text-muted-foreground">{label}</span>}
    </div>
  )
}

export { CirclePause, CircleX, ShieldQuestion }
