// ============================================================================
// Real API client. Replaces the previous mock layer; talks to the FastAPI
// server (see `server/dra/main.py`) via the Vite /api proxy.
// ============================================================================

import type {
  Approval,
  DashboardStats,
  DetectionResult,
  Evidence,
  EvidenceChain,
  EvidenceStrength,
  ExploitabilityAssessment,
  ExperimentPlan,
  Finding,
  HealthStatus,
  Hypothesis,
  LabHealth,
  Lineage,
  Observation,
  AttackSurface,
  Project,
  QAReview,
  ResearchRun,
  RobustnessResult,
  Target,
  ToolRun,
  VisibilityResult,
  HypothesisStatus,
  FindingStatus,
  QADecision,
  ToolRunStatus,
  AttackActor,
  VulnerabilityClass,
  Confidence,
  Severity,
} from '@/types'

// In dev the Vite proxy rewrites /api -> "" and forwards to the FastAPI
// origin. In prod, set VITE_API_BASE.
const BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? '/api'

export class ApiError extends Error {
  status: number
  body: unknown
  constructor(status: number, body: unknown, message: string) {
    super(message)
    this.status = status
    this.body = body
    this.name = 'ApiError'
  }
}

class ApiClient {
  private async request<T>(
    method: string,
    path: string,
    init: RequestInit = {},
  ): Promise<T> {
    const res = await fetch(`${BASE}${path}`, {
      method,
      headers: { Accept: 'application/json', ...(init.headers ?? {}) },
      ...init,
    })
    if (!res.ok) {
      let body: unknown = null
      const text = await res.text()
      try {
        body = text ? JSON.parse(text) : null
      } catch {
        body = text
      }
      const detail =
        (body && typeof body === 'object' && 'detail' in (body as object)
          ? String((body as { detail: unknown }).detail)
          : null) ?? `HTTP ${res.status}`
      throw new ApiError(res.status, body, detail)
    }
    if (res.status === 204) return undefined as unknown as T
    const ct = res.headers.get('content-type') ?? ''
    if (ct.includes('application/json')) return (await res.json()) as T
    return (await res.text()) as unknown as T
  }

  // ---------- Health ----------
  health() {
    return this.request<HealthStatus>('GET', '/health')
  }

  // ---------- Dashboard ----------
  dashboard() {
    return this.request<DashboardStats>('GET', '/dashboard')
  }

  // ---------- Projects ----------
  listProjects() {
    return this.request<Project[]>('GET', '/projects')
  }
  getProject(id: string) {
    return this.request<Project>('GET', `/projects/${id}`)
  }
  createProject(body: {
    name: string
    description?: string
    authorized_use: boolean
    authorization_ref?: string | null
    tags?: string[]
  }) {
    return this.request<Project>('POST', '/projects', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
  }
  projectLineage(id: string) {
    return this.request<Lineage>('GET', `/projects/${id}/lineage`)
  }

  // ---------- Targets ----------
  listTargets(projectId?: string) {
    const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : ''
    return this.request<Target[]>('GET', `/targets${q}`)
  }
  getTarget(id: string) {
    return this.request<Target>('GET', `/targets/${id}`)
  }
  uploadTarget(args: { project_id: string; name: string; file: File }) {
    const fd = new FormData()
    fd.append('project_id', args.project_id)
    fd.append('name', args.name)
    fd.append('file', args.file)
    return this.request<Target>('POST', '/targets', { method: 'POST', body: fd })
  }

  // ---------- Research ----------
  listResearch(projectId?: string) {
    const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : ''
    return this.request<ResearchRun[]>('GET', `/research${q}`)
  }
  getResearch(id: string) {
    return this.request<ResearchRun>('GET', `/research/${id}`)
  }
  startResearch(projectId: string, targetId: string) {
    return this.request<ResearchRun>('POST', '/research/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ project_id: projectId, target_id: targetId }),
    })
  }
  cancelResearch(id: string) {
    return this.request<{ research_id: string; status: string }>(
      'POST',
      `/research/${id}/cancel`,
    )
  }

  // ---------- Hypotheses ----------
  listHypotheses(projectId?: string) {
    const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : ''
    return this.request<Hypothesis[]>('GET', `/hypotheses${q}`)
  }
  getHypothesis(id: string) {
    return this.request<Hypothesis>('GET', `/hypotheses/${id}`)
  }

  // ---------- Experiments ----------
  listExperiments(projectId?: string) {
    const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : ''
    return this.request<ExperimentPlan[]>('GET', `/experiments${q}`)
  }
  getExperiment(id: string) {
    return this.request<ExperimentPlan>('GET', `/experiments/${id}`)
  }

  // ---------- Evidence ----------
  listEvidence(projectId?: string) {
    const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : ''
    return this.request<Evidence[]>('GET', `/evidence${q}`)
  }
  getEvidence(id: string) {
    return this.request<Evidence>('GET', `/evidence/${id}`)
  }

  // ---------- Findings ----------
  listFindings(projectId?: string) {
    const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : ''
    return this.request<Finding[]>('GET', `/findings${q}`)
  }
  getFinding(id: string) {
    return this.request<Finding>('GET', `/findings/${id}`)
  }
  findingEvidenceChain(id: string) {
    return this.request<EvidenceChain>('GET', `/findings/${id}/evidence-chain`)
  }
  findingReplayBundle(id: string) {
    return this.request<Record<string, unknown>>('GET', `/findings/${id}/replay-bundle`)
  }

  // ---------- QA ----------
  listQAReviews(projectId?: string) {
    const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : ''
    return this.request<QAReview[]>('GET', `/qa-reviews${q}`)
  }

  // ---------- Approvals ----------
  listApprovals(projectId?: string) {
    const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : ''
    return this.request<Approval[]>('GET', `/approvals${q}`)
  }
  listPendingApprovals(projectId?: string) {
    const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : ''
    return this.request<Approval[]>('GET', `/approvals/pending${q}`)
  }
  decideApproval(id: string, decision: 'approved' | 'rejected', decided_by: string, notes?: string) {
    const params = new URLSearchParams({ decision, decided_by })
    if (notes) params.set('notes', notes)
    return this.request<Approval>('POST', `/approvals/${id}/decide?${params}`)
  }

  // ---------- Tool runs ----------
  listToolRuns(projectId?: string) {
    const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : ''
    return this.request<ToolRun[]>('GET', `/tool-runs${q}`)
  }
  getToolRun(id: string) {
    return this.request<ToolRun>('GET', `/tool-runs/${id}`)
  }

  // ---------- Detection / Visibility / Robustness ----------
  listVisibility(projectId?: string) {
    const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : ''
    return this.request<VisibilityResult[]>('GET', `/visibility${q}`)
  }
  listDetectionResults(projectId?: string) {
    const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : ''
    return this.request<DetectionResult[]>('GET', `/detection-results${q}`)
  }
  listRobustnessResults(projectId?: string) {
    const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : ''
    return this.request<RobustnessResult[]>('GET', `/robustness-results${q}`)
  }

  // ---------- Lab ----------
  labHealth() {
    return this.request<LabHealth>('GET', '/lab/health')
  }
  listSnapshots() {
    return this.request<Array<{ snapshot_id: string; vm_fingerprint: string }>>(
      'GET',
      '/lab/snapshots',
    )
  }
  listVms() {
    return this.request<Array<{ vm_id: string; state: string; fingerprint: string }>>(
      'GET',
      '/lab/vms',
    )
  }
}

export const api = new ApiClient()

// Re-export the narrower types so pages can import from one place.
export type {
  Approval,
  DashboardStats,
  DetectionResult,
  Evidence,
  EvidenceChain,
  EvidenceStrength,
  ExploitabilityAssessment,
  ExperimentPlan,
  Finding,
  HealthStatus,
  Hypothesis,
  LabHealth,
  Lineage,
  Observation,
  AttackSurface,
  Project,
  QAReview,
  ResearchRun,
  RobustnessResult,
  Target,
  ToolRun,
  VisibilityResult,
  HypothesisStatus,
  FindingStatus,
  QADecision,
  ToolRunStatus,
  AttackActor,
  VulnerabilityClass,
  Confidence,
  Severity,
}
