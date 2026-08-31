// UI design tokens that mirror the server evidence model.
// See "DRA — Driver Research Automation 整合方案 v2.md" §7.11.1.

export const NODE_META: Record<string, { label: string; color: string; ring: string; bg: string; dot: string }> = {
  project: {
    label: 'Project',
    color: 'text-sky-300',
    ring: 'ring-sky-500/40',
    bg: 'bg-sky-500/10',
    dot: 'bg-sky-400',
  },
  target: {
    label: 'Target',
    color: 'text-indigo-300',
    ring: 'ring-indigo-500/40',
    bg: 'bg-indigo-500/10',
    dot: 'bg-indigo-400',
  },
  observation: {
    label: 'Observation',
    color: 'text-cyan-300',
    ring: 'ring-cyan-500/40',
    bg: 'bg-cyan-500/10',
    dot: 'bg-cyan-400',
  },
  attack_surface: {
    label: 'Attack Surface',
    color: 'text-fuchsia-300',
    ring: 'ring-fuchsia-500/40',
    bg: 'bg-fuchsia-500/10',
    dot: 'bg-fuchsia-400',
  },
  hypothesis: {
    label: 'Hypothesis',
    color: 'text-violet-300',
    ring: 'ring-violet-500/40',
    bg: 'bg-violet-500/10',
    dot: 'bg-violet-400',
  },
  experiment: {
    label: 'Experiment',
    color: 'text-amber-300',
    ring: 'ring-amber-500/40',
    bg: 'bg-amber-500/10',
    dot: 'bg-amber-400',
  },
  execution: {
    label: 'Execution',
    color: 'text-orange-300',
    ring: 'ring-orange-500/40',
    bg: 'bg-orange-500/10',
    dot: 'bg-orange-400',
  },
  crash: {
    label: 'Crash',
    color: 'text-rose-300',
    ring: 'ring-rose-500/40',
    bg: 'bg-rose-500/10',
    dot: 'bg-rose-400',
  },
  evidence: {
    label: 'Evidence',
    color: 'text-emerald-300',
    ring: 'ring-emerald-500/40',
    bg: 'bg-emerald-500/10',
    dot: 'bg-emerald-400',
  },
  finding: {
    label: 'Finding',
    color: 'text-fuchsia-300',
    ring: 'ring-fuchsia-500/40',
    bg: 'bg-fuchsia-500/10',
    dot: 'bg-fuchsia-400',
  },
  qa_review: {
    label: 'QA Review',
    color: 'text-teal-300',
    ring: 'ring-teal-500/40',
    bg: 'bg-teal-500/10',
    dot: 'bg-teal-400',
  },
  research: {
    label: 'Research',
    color: 'text-blue-300',
    ring: 'ring-blue-500/40',
    bg: 'bg-blue-500/10',
    dot: 'bg-blue-400',
  },
  visibility: {
    label: 'Visibility',
    color: 'text-yellow-300',
    ring: 'ring-yellow-500/40',
    bg: 'bg-yellow-500/10',
    dot: 'bg-yellow-400',
  },
  detection: {
    label: 'Detection',
    color: 'text-pink-300',
    ring: 'ring-pink-500/40',
    bg: 'bg-pink-500/10',
    dot: 'bg-pink-400',
  },
  robustness: {
    label: 'Robustness',
    color: 'text-lime-300',
    ring: 'ring-lime-500/40',
    bg: 'bg-lime-500/10',
    dot: 'bg-lime-400',
  },
  tool_run: {
    label: 'Tool Run',
    color: 'text-slate-300',
    ring: 'ring-slate-500/40',
    bg: 'bg-slate-500/10',
    dot: 'bg-slate-400',
  },
}

export function metaFor(kind: string) {
  return NODE_META[kind] ?? {
    label: kind,
    color: 'text-slate-300',
    ring: 'ring-slate-500/40',
    bg: 'bg-slate-500/10',
    dot: 'bg-slate-400',
  }
}
