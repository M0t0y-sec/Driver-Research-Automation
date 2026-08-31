import { PageHeader } from '@/components/common/PageHeader'
import { SectionCard } from '@/components/common/KpiCard'
import { DataTable, type Column } from '@/components/common/DataTable'
import { Cpu, Brain, FlaskConical, ListChecks, ShieldCheck, Search, Activity, FileText, Lightbulb, GitBranch, Server, Microscope } from 'lucide-react'
import { Link } from 'react-router-dom'

interface AgentCard {
  id: string
  name: string
  role: string
  scope: string
  icon: typeof Cpu
  graphNode: string
}

const AGENTS: AgentCard[] = [
  { id: 'planner', name: 'Planner', role: 'Research planning', scope: 'Decomposes project into phases', icon: ListChecks, graphNode: 'planner' },
  { id: 'recon', name: 'Recon', role: 'Static reconnaissance', scope: 'analyze_pe + static_strings + attack_surface_extract', icon: Search, graphNode: 'recon' },
  { id: 'reverse', name: 'Reverse Engineering', role: 'Helper RE summary', scope: 'Phase 0/1: import / string scrape', icon: GitBranch, graphNode: 'reverse' },
  { id: 'hypothesis', name: 'Hypothesis', role: 'Hypothesis generation + ranking', scope: 'LLM with rule-based score breakdown', icon: Lightbulb, graphNode: 'hypothesis' },
  { id: 'input_generation', name: 'Input Generation', role: 'Test case synthesis', scope: 'Phase 0/1: stub', icon: FileText, graphNode: 'input_generation' },
  { id: 'experiment', name: 'Experiment Planner', role: 'Plan validation experiments', scope: 'Emits ExperimentPlan', icon: FlaskConical, graphNode: 'experiment_planner' },
  { id: 'validation', name: 'Validation', role: 'Execute in Lab', scope: 'Phase 0/1: stub (skipped)', icon: Activity, graphNode: 'validation' },
  { id: 'triage', name: 'Triage', role: 'Crash classification + RCA + impact + exploitability', scope: 'Phase 0/1: stub', icon: Microscope, graphNode: 'triage' },
  { id: 'telemetry', name: 'Telemetry', role: 'Collect behaviour', scope: 'Phase 0/1: stub', icon: Server, graphNode: 'telemetry' },
  { id: 'detection', name: 'Detection', role: 'Visibility / Detection / Robustness', scope: 'Phase 0/1: stub', icon: ShieldCheck, graphNode: 'detection' },
  { id: 'evidence_registrar', name: 'Evidence Registrar', role: 'Write evidence records', scope: 'E0–E7 strength + lineage', icon: Brain, graphNode: 'evidence_registrar' },
  { id: 'qa_auditor', name: 'QA Auditor', role: 'Rule + Evidence + LLM review', scope: 'pass / retry / reject / inconclusive', icon: ShieldCheck, graphNode: 'qa_auditor' },
  { id: 'reporter', name: 'Reporter', role: 'Render final report', scope: 'Persists ResearchReport', icon: FileText, graphNode: 'reporter' },
]

export default function AgentsPage() {
  return (
    <div className="space-y-4">
      <PageHeader title="Agents" subtitle="13 agents in the research graph (11 core + Input Generation + Triage sub-steps)." />
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {AGENTS.map((a) => {
          const Icon = a.icon
          return (
            <Link
              key={a.id}
              to={`/research/runs`}
              className="group rounded-lg border border-white/5 bg-white/[0.02] p-4 transition-colors hover:bg-white/[0.06]"
            >
              <div className="flex items-center gap-2">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  <Icon className="h-4 w-4" />
                </div>
                <div>
                  <div className="text-sm font-semibold">{a.name}</div>
                  <div className="font-mono text-[10px] text-muted-foreground">{a.graphNode}</div>
                </div>
              </div>
              <p className="mt-2 text-xs text-muted-foreground">{a.role}</p>
              <p className="mt-1 text-[11px] text-foreground/80">{a.scope}</p>
            </Link>
          )
        })}
      </div>
    </div>
  )
}
