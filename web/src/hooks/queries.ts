import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '@/api/client'

// ---------- Query keys ----------
export const qk = {
  health: ['health'] as const,
  dashboard: ['dashboard'] as const,
  projects: ['projects'] as const,
  project: (id: string) => ['project', id] as const,
  projectLineage: (id: string) => ['project', id, 'lineage'] as const,
  targets: (projectId?: string) => ['targets', projectId ?? null] as const,
  target: (id: string) => ['target', id] as const,
  research: (projectId?: string) => ['research', projectId ?? null] as const,
  researchOne: (id: string) => ['research', id] as const,
  hypotheses: (projectId?: string) => ['hypotheses', projectId ?? null] as const,
  hypothesis: (id: string) => ['hypothesis', id] as const,
  experiments: (projectId?: string) => ['experiments', projectId ?? null] as const,
  experiment: (id: string) => ['experiment', id] as const,
  evidence: (projectId?: string) => ['evidence', projectId ?? null] as const,
  evidenceOne: (id: string) => ['evidence', id] as const,
  findings: (projectId?: string) => ['findings', projectId ?? null] as const,
  finding: (id: string) => ['finding', id] as const,
  findingChain: (id: string) => ['finding', id, 'evidence-chain'] as const,
  findingReplay: (id: string) => ['finding', id, 'replay-bundle'] as const,
  qaReviews: (projectId?: string) => ['qa', projectId ?? null] as const,
  approvals: (projectId?: string) => ['approvals', projectId ?? null] as const,
  pendingApprovals: (projectId?: string) => ['approvals', 'pending', projectId ?? null] as const,
  toolRuns: (projectId?: string) => ['tool-runs', projectId ?? null] as const,
  toolRun: (id: string) => ['tool-run', id] as const,
  visibility: (projectId?: string) => ['visibility', projectId ?? null] as const,
  detection: (projectId?: string) => ['detection', projectId ?? null] as const,
  robustness: (projectId?: string) => ['robustness', projectId ?? null] as const,
  labHealth: ['lab', 'health'] as const,
  labSnapshots: ['lab', 'snapshots'] as const,
  labVms: ['lab', 'vms'] as const,
}

// ---------- Queries ----------
export const useHealth = () =>
  useQuery({ queryKey: qk.health, queryFn: () => api.health(), refetchInterval: 30_000 })

export const useDashboard = () =>
  useQuery({ queryKey: qk.dashboard, queryFn: () => api.dashboard(), refetchInterval: 10_000 })

export const useProjects = () =>
  useQuery({ queryKey: qk.projects, queryFn: () => api.listProjects() })

export const useProject = (id: string | undefined) =>
  useQuery({
    queryKey: id ? qk.project(id) : ['project', 'none'],
    queryFn: () => api.getProject(id!),
    enabled: !!id,
  })

export const useProjectLineage = (id: string | undefined) =>
  useQuery({
    queryKey: id ? qk.projectLineage(id) : ['project', 'none', 'lineage'],
    queryFn: () => api.projectLineage(id!),
    enabled: !!id,
  })

export const useCreateProject = () => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: api.createProject.bind(api),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.projects }),
  })
}

export const useTargets = (projectId?: string) =>
  useQuery({ queryKey: qk.targets(projectId), queryFn: () => api.listTargets(projectId) })

export const useTarget = (id: string | undefined) =>
  useQuery({
    queryKey: id ? qk.target(id) : ['target', 'none'],
    queryFn: () => api.getTarget(id!),
    enabled: !!id,
  })

export const useUploadTarget = () => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: api.uploadTarget.bind(api),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['targets'] })
      qc.invalidateQueries({ queryKey: qk.dashboard })
    },
  })
}

export const useResearchList = (projectId?: string) =>
  useQuery({ queryKey: qk.research(projectId), queryFn: () => api.listResearch(projectId) })

export const useResearch = (id: string | undefined, opts?: { refetchInterval?: number }) =>
  useQuery({
    queryKey: id ? qk.researchOne(id) : ['research', 'none'],
    queryFn: () => api.getResearch(id!),
    enabled: !!id,
    refetchInterval: opts?.refetchInterval,
  })

export const useStartResearch = () => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ projectId, targetId }: { projectId: string; targetId: string }) =>
      api.startResearch(projectId, targetId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['research'] })
      qc.invalidateQueries({ queryKey: qk.dashboard })
    },
  })
}

export const useCancelResearch = () => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.cancelResearch(id),
    onSuccess: (_d, id) => {
      qc.invalidateQueries({ queryKey: qk.researchOne(id) })
      qc.invalidateQueries({ queryKey: ['research'] })
    },
  })
}

export const useHypotheses = (projectId?: string) =>
  useQuery({ queryKey: qk.hypotheses(projectId), queryFn: () => api.listHypotheses(projectId) })

export const useHypothesis = (id: string | undefined) =>
  useQuery({
    queryKey: id ? qk.hypothesis(id) : ['hypothesis', 'none'],
    queryFn: () => api.getHypothesis(id!),
    enabled: !!id,
  })

export const useExperiments = (projectId?: string) =>
  useQuery({ queryKey: qk.experiments(projectId), queryFn: () => api.listExperiments(projectId) })

export const useExperiment = (id: string | undefined) =>
  useQuery({
    queryKey: id ? qk.experiment(id) : ['experiment', 'none'],
    queryFn: () => api.getExperiment(id!),
    enabled: !!id,
  })

export const useEvidence = (projectId?: string) =>
  useQuery({ queryKey: qk.evidence(projectId), queryFn: () => api.listEvidence(projectId) })

export const useEvidenceOne = (id: string | undefined) =>
  useQuery({
    queryKey: id ? qk.evidenceOne(id) : ['evidence', 'none'],
    queryFn: () => api.getEvidence(id!),
    enabled: !!id,
  })

export const useFindings = (projectId?: string) =>
  useQuery({ queryKey: qk.findings(projectId), queryFn: () => api.listFindings(projectId) })

export const useFinding = (id: string | undefined) =>
  useQuery({
    queryKey: id ? qk.finding(id) : ['finding', 'none'],
    queryFn: () => api.getFinding(id!),
    enabled: !!id,
  })

export const useFindingChain = (id: string | undefined) =>
  useQuery({
    queryKey: id ? qk.findingChain(id) : ['finding', 'none', 'chain'],
    queryFn: () => api.findingEvidenceChain(id!),
    enabled: !!id,
  })

export const useFindingReplay = (id: string | undefined) =>
  useQuery({
    queryKey: id ? qk.findingReplay(id) : ['finding', 'none', 'replay'],
    queryFn: () => api.findingReplayBundle(id!),
    enabled: !!id,
  })

export const useQAReviews = (projectId?: string) =>
  useQuery({ queryKey: qk.qaReviews(projectId), queryFn: () => api.listQAReviews(projectId) })

export const useApprovals = (projectId?: string) =>
  useQuery({ queryKey: qk.approvals(projectId), queryFn: () => api.listApprovals(projectId) })

export const usePendingApprovals = (projectId?: string) =>
  useQuery({
    queryKey: qk.pendingApprovals(projectId),
    queryFn: () => api.listPendingApprovals(projectId),
    refetchInterval: 15_000,
  })

export const useDecideApproval = () => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (args: { id: string; decision: 'approved' | 'rejected'; decided_by: string; notes?: string }) =>
      api.decideApproval(args.id, args.decision, args.decided_by, args.notes),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['approvals'] })
    },
  })
}

export const useToolRuns = (projectId?: string) =>
  useQuery({ queryKey: qk.toolRuns(projectId), queryFn: () => api.listToolRuns(projectId) })

export const useToolRun = (id: string | undefined) =>
  useQuery({
    queryKey: id ? qk.toolRun(id) : ['tool-run', 'none'],
    queryFn: () => api.getToolRun(id!),
    enabled: !!id,
  })

export const useVisibility = (projectId?: string) =>
  useQuery({ queryKey: qk.visibility(projectId), queryFn: () => api.listVisibility(projectId) })

export const useDetection = (projectId?: string) =>
  useQuery({ queryKey: qk.detection(projectId), queryFn: () => api.listDetectionResults(projectId) })

export const useRobustness = (projectId?: string) =>
  useQuery({ queryKey: qk.robustness(projectId), queryFn: () => api.listRobustnessResults(projectId) })

export const useLabHealth = () =>
  useQuery({ queryKey: qk.labHealth, queryFn: () => api.labHealth() })

export const useLabSnapshots = () =>
  useQuery({ queryKey: qk.labSnapshots, queryFn: () => api.listSnapshots() })

export const useLabVms = () =>
  useQuery({ queryKey: qk.labVms, queryFn: () => api.listVms() })

export { ApiError }
